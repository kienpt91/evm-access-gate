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
    accessReader: new ContractAccessReader(registryAddress, ethers.provider),
    ...(withErc1271 ? { contractSignatureVerifier: createErc1271Verifier(ethers.provider) } : {}),
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

  it("the hand-written read ABI matches the compiled contract", async () => {
    const { registry } = await loadFixture(deployStack);
    const reader = new Interface(ACCESS_REGISTRY_READ_ABI).getFunction("hasAccess");
    const compiled = registry.interface.getFunction("hasAccess");
    expect(reader?.format("full")).to.equal(compiled?.format("full"));
    expect(reader?.selector).to.equal(compiled?.selector);
  });

  it("ContractAccessReader validates its inputs", async () => {
    const { alice, registryAddress } = await loadFixture(deployStack);
    expect(() => new ContractAccessReader("0x1234", ethers.provider)).to.throw(/INVALID_CONFIG/);
    const reader = new ContractAccessReader(registryAddress, ethers.provider);
    await expectAuthError(() => reader.hasAccess("nope", 1n), "INVALID_ADDRESS");
    await expectAuthError(() => reader.hasAccess(alice.address, -1n), "INVALID_PLAN");
    await expectAuthError(() => reader.hasAccess(alice.address, 1n << 256n), "INVALID_PLAN");
    expect(await reader.hasAccess(alice.address, 1n)).to.equal(false);
  });
});
