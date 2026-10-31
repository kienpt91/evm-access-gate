import { randomBytes } from "node:crypto";
import { expect } from "chai";
import { Interface, Wallet, type Signer } from "ethers";
import {
  ACCESS_REGISTRY_READ_ABI,
  ContractAccessReader,
  createAuthService,
  createErc1271Verifier,
  InMemoryNonceStore,
  type AuthConfig,
  type AuthService,
} from "../../src/auth/index.js";
import { DAY, deployWithPlan, DURATION, ethers, HOUR, networkHelpers, PRICE } from "../helpers/chain.js";
import { expectAuthError, TestClock } from "./helpers.js";

const { loadFixture } = networkHelpers;

const CONFIG: AuthConfig = {
  domain: "app.example.com",
  uri: "https://app.example.com",
  chainId: 31337,
  statement: "Sign in to Example. This does not cost gas.",
};

function buildService(registryAddress: string, withErc1271: boolean): AuthService {
  // The login clock is independent from the chain clock: moving the chain forward must not extend or
  // shorten login sessions, it only changes what the contract answers.
  const clock = new TestClock("2026-10-31T10:00:00.000Z");
  return createAuthService(CONFIG, {
    nonceStore: new InMemoryNonceStore(),
    sessionSecret: randomBytes(32),
    accessReader: new ContractAccessReader(registryAddress, ethers.provider, { chainId: CONFIG.chainId }),
    ...(withErc1271
      ? { contractSignatureVerifier: createErc1271Verifier(ethers.provider, { chainId: CONFIG.chainId }) }
      : {}),
    now: clock.now,
  });
}

async function deployStack() {
  const ctx = await deployWithPlan();
  const registryAddress = await ctx.registry.getAddress();
  await ctx.registry.connect(ctx.admin).createPlan(2n, PRICE * 5n, 7n * DAY, 0);
  return { ...ctx, registryAddress, service: buildService(registryAddress, true) };
}

/** The whole browser-wallet flow, with a hardhat signer standing in for the wallet. */
async function signIn(service: AuthService, signer: Signer): Promise<string> {
  const challenge = await service.createChallenge(await signer.getAddress());
  const signature = await signer.signMessage(challenge.message);
  const login = await service.verifyLogin({ message: challenge.message, signature });
  return service.issueSession(login).token;
}

describe("end to end: wallet login and on-chain access", () => {
  it("purchase -> login -> access granted", async () => {
    const { registry, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });

    const token = await signIn(service, alice);
    const grant = await service.requireAccess({ token, planId: 1n });

    expect(grant).to.deep.equal({ address: alice.address, planId: 1n, chainId: 31337 });
  });

  it("signing in without a purchase works, but access is denied", async () => {
    const { bob, service } = await loadFixture(deployStack);
    const token = await signIn(service, bob);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_DENIED");
  });

  it("access is per plan: a plan 1 purchase does not open plan 2", async () => {
    const { registry, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    const token = await signIn(service, alice);

    await service.requireAccess({ token, planId: 1n });
    await expectAuthError(() => service.requireAccess({ token, planId: 2n }), "ACCESS_DENIED");
    await expectAuthError(() => service.requireAccess({ token, planId: 99n }), "ACCESS_DENIED");
  });

  it("access is per wallet: another wallet's session does not inherit it", async () => {
    const { registry, alice, bob, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    const bobToken = await signIn(service, bob);
    await expectAuthError(() => service.requireAccess({ token: bobToken, planId: 1n }), "ACCESS_DENIED");
  });

  it("expired -> denied, even though the session token is still valid", async () => {
    const { registry, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    const token = await signIn(service, alice);

    await networkHelpers.time.increase(DURATION - HOUR);
    await service.requireAccess({ token, planId: 1n });

    await networkHelpers.time.increase(2n * HOUR);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_DENIED");
  });

  it("renewing after expiry brings access back on the same session", async () => {
    const { registry, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    const token = await signIn(service, alice);
    await networkHelpers.time.increase(DURATION + DAY);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_DENIED");

    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await service.requireAccess({ token, planId: 1n });
  });

  it("revoked -> denied on the next request", async () => {
    const { registry, operator, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    const token = await signIn(service, alice);
    await service.requireAccess({ token, planId: 1n });

    await registry.connect(operator).revoke(alice.address, 1n, "chargeback");

    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_DENIED");
  });

  it("an operator grant opens access without a purchase", async () => {
    const { registry, operator, carol, service } = await loadFixture(deployStack);
    const token = await signIn(service, carol);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_DENIED");

    await registry.connect(operator).grant(carol.address, 1n, DAY, "trial");

    await service.requireAccess({ token, planId: 1n });
  });

  it("a paused registry still answers hasAccess for existing holders", async () => {
    const { registry, admin, alice, service } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await registry.connect(admin).pause();
    const token = await signIn(service, alice);
    await service.requireAccess({ token, planId: 1n });
  });

  it("an ERC-1271 smart-contract wallet can sign in when the verifier is enabled", async () => {
    const { registry, operator, alice, registryAddress, service } = await loadFixture(deployStack);
    const wallet = await ethers.deployContract("Erc1271Wallet", [alice.address]);
    const walletAddress = await wallet.getAddress();
    await registry.connect(operator).grant(walletAddress, 1n, DAY, "contract wallet");

    const challenge = await service.createChallenge(walletAddress);
    // The wallet's owner signs; the wallet contract vouches for it.
    const signature = await alice.signMessage(challenge.message);
    const login = await service.verifyLogin({ message: challenge.message, signature });

    expect(login.method).to.equal("erc1271");
    expect(login.address).to.equal(walletAddress);
    const { token } = service.issueSession(login);
    expect((await service.requireAccess({ token, planId: 1n })).address).to.equal(walletAddress);

    // The same flow is rejected by a service without the ERC-1271 verifier.
    const eoaOnly = buildService(registryAddress, false);
    const second = await eoaOnly.createChallenge(walletAddress);
    await expectAuthError(
      async () => eoaOnly.verifyLogin({ message: second.message, signature: await alice.signMessage(second.message) }),
      "INVALID_SIGNATURE",
    );
  });

  it("an ERC-1271 wallet rejects signatures from anyone but its owner", async () => {
    const { alice, bob, service } = await loadFixture(deployStack);
    const wallet = await ethers.deployContract("Erc1271Wallet", [alice.address]);
    const walletAddress = await wallet.getAddress();

    const challenge = await service.createChallenge(walletAddress);
    await expectAuthError(
      async () =>
        service.verifyLogin({ message: challenge.message, signature: await bob.signMessage(challenge.message) }),
      "INVALID_SIGNATURE",
    );
  });

  it("with the verifier enabled, an EOA still needs its own valid ECDSA signature", async () => {
    const { alice, bob, service } = await loadFixture(deployStack);
    const challenge = await service.createChallenge(alice.address);
    await expectAuthError(
      async () =>
        service.verifyLogin({ message: challenge.message, signature: await bob.signMessage(challenge.message) }),
      "INVALID_SIGNATURE",
    );
  });

  it("fails closed when the registry address has no contract", async () => {
    const { alice } = await loadFixture(deployStack);
    const service = buildService(Wallet.createRandom().address, false);
    const token = await signIn(service, alice);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_CHECK_FAILED");
  });

  it("fails closed when the provider is on a different chain than the configuration", async () => {
    const { registry, alice, registryAddress } = await loadFixture(deployStack);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });

    const reader = new ContractAccessReader(registryAddress, ethers.provider, { chainId: 1 });
    await expectAuthError(() => reader.hasAccess(alice.address, 1n), "CHAIN_ID_MISMATCH");

    // Through the service the mismatch can never turn into access, even though the user paid.
    const service = createAuthService(CONFIG, {
      nonceStore: new InMemoryNonceStore(),
      sessionSecret: randomBytes(32),
      accessReader: reader,
    });
    const token = await signIn(service, alice);
    await expectAuthError(() => service.requireAccess({ token, planId: 1n }), "ACCESS_CHECK_FAILED");
  });

  it("the ERC-1271 verifier refuses a provider on another chain", async () => {
    const { alice } = await loadFixture(deployStack);
    const verifier = createErc1271Verifier(ethers.provider, { chainId: 1 });
    await expectAuthError(() => verifier.isValidSignature(alice.address, "hello", "0x1234"), "CHAIN_ID_MISMATCH");
  });

  describe("hostile ERC-1271 wallets", () => {
    const BurnGas = 0;
    const ReturnLarge = 1;
    const Revert = 2;

    it("the burning wallet really does exhaust whatever gas it is given", async () => {
      const hostile = await ethers.deployContract("HostileWallet", [BurnGas]);
      const data = hostile.interface.encodeFunctionData("isValidSignature", [ethers.ZeroHash, "0x"]);
      let failure: unknown;
      try {
        await ethers.provider.call({ to: await hostile.getAddress(), data, gasLimit: 300_000n });
      } catch (err) {
        failure = err;
      }
      expect(failure).to.be.instanceOf(Error);
      expect(String(failure)).to.match(/out of gas/i);
    });

    it("a wallet that burns all its gas is cut off at the gas limit and counts as an invalid signature", async () => {
      const { alice, service } = await loadFixture(deployStack);
      const hostile = await ethers.deployContract("HostileWallet", [BurnGas]);
      const challenge = await service.createChallenge(await hostile.getAddress());

      const started = Date.now();
      await expectAuthError(
        async () =>
          service.verifyLogin({ message: challenge.message, signature: await alice.signMessage(challenge.message) }),
        "INVALID_SIGNATURE",
      );
      // 300,000 gas of hashing takes a few milliseconds; the node's own cap would be 100x larger.
      expect(Date.now() - started).to.be.lessThan(2000);
    });

    it("a wallet that returns far more than a bytes4 is rejected before decoding", async () => {
      const { alice, service } = await loadFixture(deployStack);
      const hostile = await ethers.deployContract("HostileWallet", [ReturnLarge]);
      const challenge = await service.createChallenge(await hostile.getAddress());
      await expectAuthError(
        async () =>
          service.verifyLogin({ message: challenge.message, signature: await alice.signMessage(challenge.message) }),
        "INVALID_SIGNATURE",
      );
    });

    it("a wallet that reverts counts as an invalid signature", async () => {
      const { alice, service } = await loadFixture(deployStack);
      const hostile = await ethers.deployContract("HostileWallet", [Revert]);
      const challenge = await service.createChallenge(await hostile.getAddress());
      await expectAuthError(
        async () =>
          service.verifyLogin({ message: challenge.message, signature: await alice.signMessage(challenge.message) }),
        "INVALID_SIGNATURE",
      );
    });
  });

  it("the hand-written read ABI matches the compiled contract", async () => {
    const { registry } = await loadFixture(deployStack);
    const reader = new Interface(ACCESS_REGISTRY_READ_ABI).getFunction("hasAccess");
    const compiled = registry.interface.getFunction("hasAccess");
    expect(reader?.format("full")).to.equal(compiled?.format("full"));
    expect(reader?.selector).to.equal(compiled?.selector);
  });

  it("ContractAccessReader validates its inputs", async () => {
    const { alice, registryAddress } = await loadFixture(deployStack);
    expect(() => new ContractAccessReader("0x1234", ethers.provider, { chainId: 31337 })).to.throw(/INVALID_CONFIG/);
    expect(() => new ContractAccessReader(registryAddress, ethers.provider, { chainId: 0 })).to.throw(/INVALID_CONFIG/);
    const reader = new ContractAccessReader(registryAddress, ethers.provider, { chainId: 31337 });
    await expectAuthError(() => reader.hasAccess("nope", 1n), "INVALID_ADDRESS");
    await expectAuthError(() => reader.hasAccess(alice.address, -1n), "INVALID_PLAN");
    await expectAuthError(() => reader.hasAccess(alice.address, 1n << 256n), "INVALID_PLAN");
    expect(await reader.hasAccess(alice.address, 1n)).to.equal(false);
  });
});
