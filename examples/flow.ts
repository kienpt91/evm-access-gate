// Full flow on the in-process Hardhat network: deploy, buy access, sign in with a wallet,
// check access, let it expire, renew, revoke. Run with `npm run example`.
import { randomBytes } from "node:crypto";
import { network } from "hardhat";
import {
  AuthError,
  ContractAccessReader,
  createAuthService,
  InMemoryNonceStore,
  type AuthService,
} from "../src/auth/index.js";

const { ethers, networkHelpers } = await network.create();
const [admin, operator, alice, bob] = await ethers.getSigners();
if (!admin || !operator || !alice || !bob) throw new Error("expected four dev accounts");

const DAY = 86_400n;
const PLAN_ID = 1n;
const PRICE = ethers.parseEther("0.01");

function step(title: string): void {
  console.log(`\n== ${title}`);
}

function iso(seconds: bigint | number): string {
  return new Date(Number(seconds) * 1000).toISOString();
}

async function attempt(label: string, action: () => Promise<unknown>): Promise<void> {
  try {
    await action();
    console.log(`${label}: access granted`);
  } catch (err) {
    console.log(`${label}: ${err instanceof AuthError ? err.code : String(err)}`);
  }
}

step("deploy AccessRegistry and create plan 1 (0.01 ETH, 30 days, unlimited)");
const registry = await ethers.deployContract("AccessRegistry", [3600, admin.address]);
const registryAddress = await registry.getAddress();
await registry.connect(admin).grantRole(await registry.OPERATOR_ROLE(), operator.address);
await registry.connect(admin).createPlan(PLAN_ID, PRICE, 30n * DAY, 0);
console.log(`registry:  ${registryAddress}`);
console.log(`admin:     ${admin.address}`);
console.log(`operator:  ${operator.address}`);

step("backend: wire the auth service to the contract");
const service: AuthService = createAuthService(
  {
    domain: "app.example.com",
    uri: "https://app.example.com",
    chainId: 31337,
    statement: "Sign in to Example. This does not cost gas.",
  },
  {
    nonceStore: new InMemoryNonceStore(),
    // Generated for this run. A real service loads a stable secret from its secret manager.
    sessionSecret: randomBytes(32),
    accessReader: new ContractAccessReader(registryAddress, ethers.provider),
  },
);
console.log("auth service ready (chain id 31337, domain app.example.com)");

step("alice buys plan 1: she quotes 0.01 ETH as her maximum price and sends 0.015 ETH (0.005 ETH is refunded)");
const buyTx = await registry.connect(alice).purchase(PLAN_ID, PRICE, { value: ethers.parseEther("0.015") });
const buyReceipt = await buyTx.wait();
const expiry = await registry.expiryOf(alice.address, PLAN_ID);
console.log(`gas used:  ${buyReceipt?.gasUsed}`);
console.log(`expiry:    ${iso(expiry)}`);
console.log(`contract balance: ${ethers.formatEther(await ethers.provider.getBalance(registryAddress))} ETH`);

step("alice signs in: the backend issues a challenge, the wallet signs it");
const challenge = await service.createChallenge(alice.address);
console.log(challenge.message);
const signature = await alice.signMessage(challenge.message);
console.log(`signature: ${signature.slice(0, 22)}...`);
const login = await service.verifyLogin({ message: challenge.message, signature });
const session = service.issueSession(login);
console.log(`verified:  ${login.address} via ${login.method}`);
console.log(`token:     ${session.token.slice(0, 32)}... (expires ${session.expiresAt})`);

step("replaying the same signed message is rejected");
await attempt("second verifyLogin with the same nonce", () =>
  service.verifyLogin({ message: challenge.message, signature }),
);

step("requests with alice's token");
await attempt("plan 1", () => service.requireAccess({ token: session.token, planId: PLAN_ID }));
await attempt("plan 2 (not purchased)", () => service.requireAccess({ token: session.token, planId: 2n }));

step("bob signs in but never bought anything");
const bobChallenge = await service.createChallenge(bob.address);
const bobLogin = await service.verifyLogin({
  message: bobChallenge.message,
  signature: await bob.signMessage(bobChallenge.message),
});
const bobSession = service.issueSession(bobLogin);
await attempt("bob, plan 1", () => service.requireAccess({ token: bobSession.token, planId: PLAN_ID }));

step("31 days pass on the chain; the same session token now fails the on-chain check");
await networkHelpers.time.increase(31n * DAY);
await attempt("alice, plan 1", () => service.requireAccess({ token: session.token, planId: PLAN_ID }));

step("alice renews; access returns without signing in again");
await registry.connect(alice).purchase(PLAN_ID, PRICE, { value: PRICE });
console.log(`new expiry: ${iso(await registry.expiryOf(alice.address, PLAN_ID))}`);
await attempt("alice, plan 1", () => service.requireAccess({ token: session.token, planId: PLAN_ID }));

step("the operator revokes alice's access");
await registry.connect(operator).revoke(alice.address, PLAN_ID, "example revocation");
await attempt("alice, plan 1", () => service.requireAccess({ token: session.token, planId: PLAN_ID }));

step("the admin withdraws the revenue to a treasury address");
const accrued = await registry.accruedRevenue();
await registry.connect(admin).withdrawTo(bob.address, accrued);
console.log(`withdrawn: ${ethers.formatEther(accrued)} ETH, accrued revenue now ${await registry.accruedRevenue()}`);
