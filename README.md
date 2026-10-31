# evm-access-gate

An example of connecting on-chain access rules to a TypeScript backend:

- **`AccessRegistry`**, a Solidity contract that sells time-limited access to named plans for ETH, with operator grants and revokes, a pause switch and revenue accounting.
- **`src/auth/`**, a TypeScript module that lets a user sign in with an Ethereum wallet (EIP-4361 "Sign-In with Ethereum" style messages), hands out a short-lived session token, and checks `hasAccess` on the contract before serving a request.
- Tests that run the whole flow against Hardhat's in-process network, and a script that prints that flow.

## Status, read this first

This is an **educational example project**.

- It is **not audited**, not formally verified, and I have **not deployed it to any network**, test or main.
- I have not run it in production, and the contract has never held real funds. I wrote it to learn and to show how I structure this kind of work; it is not evidence of production Solidity experience.
- No static analyzer (Slither, Mythril, etc.) was run on it. The only checks are the tests described below, the compiler, and my own review.
- Do not deploy it with real funds without an independent audit. See [SECURITY.md](SECURITY.md).
- Gas figures come from Hardhat's local simulated network, not from any live chain.

## Layout

```
contracts/AccessRegistry.sol     the contract (OpenZeppelin AccessControl, Pausable, ReentrancyGuard)
contracts/test/                  test-only contracts: ReentrantBuyer (attacker), Erc1271Wallet, AccessProbe
src/auth/                        wallet login, session tokens, access check (no web framework)
test/registry/                   contract tests
test/auth/                       backend tests, including end-to-end tests against the contract
examples/flow.ts                 prints the full flow on the in-process network
hardhat.config.ts                Hardhat 3, solc-js compiler path, EVM target
```

## Quick start

Needs Node 22 or newer.

```sh
npm ci --ignore-scripts
npm run compile      # compile contracts, generate TypeChain types
npm test             # all tests
npm run typecheck    # compile + tsc
npm run example      # print the full flow
npm run test:gas     # tests with a gas table
npm run coverage     # tests with Solidity line/statement coverage
```

The npm scripts set `HARDHAT_DISABLE_TELEMETRY=true` using POSIX shell syntax, so on Windows run them from WSL or a POSIX shell.

## The contract

`AccessRegistry` stores **plans** and, per user and plan, an **expiry timestamp**. A user has access to a plan while `expiry > block.timestamp`.

| Function | Who | What |
| --- | --- | --- |
| `createPlan(planId, price, duration, maxHolders)` | admin | New plan with an admin-chosen id. Rejects a duplicate id, zero price, zero duration and durations above 3650 days. `maxHolders = 0` means unlimited. |
| `setPlanActive(planId, active)` | admin | Allow or stop new purchases. Existing access is untouched. |
| `setPlanPrice(planId, price)` | admin | Applies to future purchases only; time already bought is never changed. |
| `purchase(planId)` payable | anyone | Buy or extend access for `msg.sender`. |
| `grant(user, planId, duration, reason)` | operator | Free access, added like a purchase. `reason` is at most 140 bytes. |
| `revoke(user, planId, reason)` | operator | Ends access now and frees the user's slot. No refund. |
| `releaseExpired(planId, users[])` | anyone | Frees the capacity slots of lapsed holders (at most 50 addresses per call). |
| `pause()` / `unpause()` | admin | Stops `purchase` only. Grants, revokes, releases and withdrawals keep working. |
| `withdrawTo(to, amount)` | admin | Sends accrued revenue to `to`. |
| `hasAccess(user, planId)`, `expiryOf(user, planId)`, `holdsSlot(user, planId)`, `getPlan(planId)` | view | |

Every state change emits an event. Errors are custom errors (`PlanNotFound`, `PlanFull`, `InsufficientPayment`, `RefundFailed`, ...), so a client can decode them from the ABI.

### Rules worth knowing

**Time.** A purchase or grant adds the duration to `max(now, current expiry)`. Renewing early keeps the remaining time; renewing after a gap does not credit the gap. At `expiry == block.timestamp` access is already over. These boundaries are tested at the exact second.

**Payment.** `purchase` accepts `msg.value >= price` and refunds the difference to the buyer in the same transaction. I chose refunding over rejecting overpayment so a client that rounds up does not fail. The refund is the one place the contract pushes ETH to an arbitrary address, so it is guarded with `ReentrancyGuard` and happens after all state updates. If the refund fails, the purchase reverts, which means a contract buyer that cannot receive ETH must pay the exact price.

**Revenue.** Revenue is only accounted (`accruedRevenue`), never forwarded on purchase. The admin pulls it with `withdrawTo`, which checks `0 < amount <= accruedRevenue`, lowers the counter first, then sends. The contract has no `receive` or `fallback`, so a plain transfer reverts. ETH forced in by other means (for example from a self-destructing contract) is not counted and cannot be withdrawn.

**Capacity.** For a plan with `maxHolders > 0`, a holder occupies a slot from their first purchase or grant until `revoke` or `releaseExpired`. Nothing runs on-chain when time passes, so an expired holder keeps the slot until someone calls `releaseExpired` for them. Until then `activeHolders` over-counts and a full plan can look full to newcomers. Operator grants count against the cap like purchases. For uncapped plans nothing is tracked.

**Roles.** The contract inherits OpenZeppelin `AccessControlDefaultAdminRules`, a subclass of `AccessControl`. `DEFAULT_ADMIN_ROLE` has exactly one holder, cannot be handed out with `grantRole`, and moves in two steps with a delay (`beginDefaultAdminTransfer`, then `acceptDefaultAdminTransfer` after the delay; the delay is a constructor argument). `OPERATOR_ROLE` is managed by the admin; the admin does not hold it by default. One admin account does plan management, pausing and withdrawals, which is a simplification: a real deployment would split these roles and put the admin behind a multisig.

**Secure-coding choices.** Custom errors; checks-effects-interactions in `purchase` and `withdrawTo`; `nonReentrant` on both; `Pausable`; every loop is bounded (`releaseExpired` takes at most 50 addresses); reasons are length-limited; zero addresses, zero amounts and zero durations are rejected. The contract has no `tx.origin`, no `delegatecall` and no `selfdestruct`.

### Compiler and EVM target

| | |
| --- | --- |
| Compiler | `solc` 0.8.38 as the npm package `solc` (solc-js, `0.8.38+commit.1835d247.Emscripten.clang`), pinned in `package.json` and the lockfile |
| How it is used | `hardhat.config.ts` sets `solidity.path` to `node_modules/solc/soljson.js`, so Hardhat never downloads a compiler binary |
| EVM version | `cancun` (set in `hardhat.config.ts`; the in-process network also runs the `cancun` hardfork) |
| Optimizer | on, 200 runs |
| Source pragma | `^0.8.24` |
| OpenZeppelin Contracts | 5.6.1 |

`npm run compile` prints `Compiled N Solidity files with solc 0.8.38 (evm target: cancun)`. The long version and settings are also stored in `artifacts/build-info/*.json`. Compiling through solc-js is slower than a native binary, which does not matter at this size. Hardhat's gas report lists a bytecode size of 9,143 bytes for `AccessRegistry`.

## Backend: `src/auth/`

Plain functions and small interfaces, no web framework. `createAuthService(config, deps)` returns four methods:

```ts
const service = createAuthService(
  { domain: "app.example.com", uri: "https://app.example.com", chainId: 31337,
    statement: "Sign in to Example. This does not cost gas." },
  {
    nonceStore: new InMemoryNonceStore(),
    sessionSecret,                                   // >= 32 bytes, from your secret manager
    accessReader: new ContractAccessReader(registryAddress, provider),
    contractSignatureVerifier: createErc1271Verifier(provider), // optional
  },
);

const { message } = await service.createChallenge(address);        // 1. send `message` to the wallet
const login   = await service.verifyLogin({ message, signature }); // 2. wallet signed it (personal_sign)
const session = service.issueSession(login);                       // 3. short-lived bearer token
await service.requireAccess({ token: session.token, planId: 1n }); // 4. on every protected request
```

**Login message.** `siwe.ts` builds and parses EIP-4361 text itself. The parser is strict: fixed line order, EIP-55 checksummed address, version `1`, canonical chain id, alphanumeric nonce of at least 8 characters, real UTC timestamps, host-name-only domains, absolute URIs, length limits, no `\r`, no trailing content. `formatMessage(parseMessage(text)) === text` holds for everything it accepts, and the example message from the EIP is a test vector.

**`verifyLogin` order.** Parse; then stateless checks (domain, scheme, URI, chain id, expiration present and in the future, `Issued At` not in the future beyond 60 s of skew) so a message for another site never touches the store; then **consume the nonce** (single use, atomic); then check that the nonce was issued for the same address (compared after checksum normalization) and has not expired; then compare the message byte for byte with the one the server issued (this rejects an edited statement, extra resources or changed timestamps even if the user signed them); then verify the signature. The nonce is spent even when the signature is wrong, so a failed attempt needs a new challenge.

**Signatures.** EOAs: EIP-191 `personal_sign`, recovered with `ethers.verifyMessage` and compared with the address after `getAddress` normalization. Smart-contract wallets: ERC-1271 `isValidSignature(bytes32,bytes)` against the EIP-191 hash of the message, only if you pass a `contractSignatureVerifier`; it is tested against a mock wallet in `contracts/test/Erc1271Wallet.sol`. Not supported: ERC-6492 (wallets that are not deployed yet), and wallets whose ERC-1271 check expects a differently wrapped hash (for example Safe's message hash) need their own verifier. ERC-1271 answers depend on chain state, so the same signature can be valid at one time and not another.

**Sessions.** `base64url(claims).base64url(HMAC-SHA256(secret, prefix + base64url(claims)))`, compared with `crypto.timingSafeEqual`. The secret is injected and must be at least 32 bytes; there is no default. Claims: address, chain id, issued-at, expiry (default 15 minutes), random id. Tokens only say who signed in. Whether that wallet currently has access is read from the contract on every `requireAccess` call. Tokens cannot be revoked individually, so keep them short-lived.

**`requireAccess`** verifies the token, then calls the injected `AccessReader`. `ContractAccessReader` implements it over any ethers provider with the single `hasAccess(address,uint256)` function and is checked against the compiled ABI in a test. If the reader throws (RPC down, no contract at the address) the result is `ACCESS_CHECK_FAILED`, never access.

**Errors.** Everything throws `AuthError` with a `code`. A possible HTTP mapping (not implemented here): malformed input (`MALFORMED_MESSAGE`, `TOKEN_MALFORMED`, `INVALID_*`) 400; failed checks (`DOMAIN_MISMATCH`, `NONCE_UNKNOWN`, `INVALID_SIGNATURE`, `TOKEN_EXPIRED`, `TOKEN_INVALID_SIGNATURE`, ...) 401; `ACCESS_DENIED` 403; `ACCESS_CHECK_FAILED` and `STORE_FULL` 503.

**Not included.** HTTP routes, cookies, CORS, rate limiting, a persistent or shared nonce store (`InMemoryNonceStore` is single-process and bounded; a multi-instance deployment needs an atomic `consume` on Redis or a database), reorg handling (`ContractAccessReader` reads the latest block; a service that sells high-value access might wait for confirmations), and key rotation for the session secret.

## Frontend integration

> **Untested in a browser.** The snippet below shows how a browser wallet would take part. The `/auth/challenge` and `/auth/login` routes are hypothetical: this repository has no HTTP layer, so you would wrap `createChallenge` and `verifyLogin` in your own handlers. In the tests a Hardhat signer plays the wallet; that exercises the same `signMessage` call but not an injected provider.

```ts
import { BrowserProvider, type Eip1193Provider } from "ethers";

async function signIn(apiBase: string): Promise<string> {
  const injected = (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
  if (!injected) throw new Error("no wallet found");

  const provider = new BrowserProvider(injected);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();
  const address = await signer.getAddress();

  // The server picks domain, URI, chain id and nonce. The client only checks what it is asked to sign.
  const { message } = await post(`${apiBase}/auth/challenge`, { address });
  const signature = await signer.signMessage(message); // personal_sign

  const { token } = await post(`${apiBase}/auth/login`, { message, signature });
  return token; // send as `Authorization: Bearer <token>` on protected requests
}

async function post(url: string, body: unknown) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.json();
}
```

The wallet shows the message, including the domain. How a given wallet reacts to a domain that differs from the requesting site varies, and I did not test any wallet. The backend does not rely on that: it rejects any message whose domain is not its own.

## Example output

`npm run example` runs this against the in-process network. This is the output of one real run (addresses are Hardhat's well-known development accounts; the nonce, the signature and the times differ between runs):

```
== deploy AccessRegistry and create plan 1 (0.01 ETH, 30 days, unlimited)
registry:  0x5FbDB2315678afecb367f032d93F642f64180aa3
admin:     0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
operator:  0x70997970C51812dc3A010C7d01b50e0d17dc79C8

== backend: wire the auth service to the contract
auth service ready (chain id 31337, domain app.example.com)

== alice buys plan 1, paying 0.015 ETH (0.005 ETH is refunded)
gas used:  131073
expiry:    2026-11-30T01:52:26.000Z
contract balance: 0.01 ETH

== alice signs in: the backend issues a challenge, the wallet signs it
app.example.com wants you to sign in with your Ethereum account:
0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

Sign in to Example. This does not cost gas.

URI: https://app.example.com
Version: 1
Chain ID: 31337
Nonce: 54f02e96f71fb6d9e9565acf3a1ad9f3
Issued At: 2026-10-31T01:52:23.000Z
Expiration Time: 2026-10-31T01:57:23.000Z
signature: 0xcfed06414bb56691afd9...
verified:  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC via eoa
token:     eyJ2IjoxLCJzdWIiOiIweDNDNDRDZERk... (expires 2026-10-31T02:07:23.000Z)

== replaying the same signed message is rejected
second verifyLogin with the same nonce: NONCE_UNKNOWN

== requests with alice's token
plan 1: access granted
plan 2 (not purchased): ACCESS_DENIED

== bob signs in but never bought anything
bob, plan 1: ACCESS_DENIED

== 31 days pass on the chain; the same session token now fails the on-chain check
alice, plan 1: ACCESS_DENIED

== alice renews; access returns without signing in again
new expiry: 2026-12-31T01:52:27.000Z
alice, plan 1: access granted

== the operator revokes alice's access
alice, plan 1: ACCESS_DENIED

== the admin withdraws the revenue to a treasury address
withdrawn: 0.02 ETH, accrued revenue now 0
```

## Tests

`npm test` runs 159 tests (Mocha, TypeScript, Hardhat in-process network). The same count passes on Node 22.22 and Node 24.14 after a clean `npm ci --ignore-scripts`, with networking disabled for the test run.

| Area | File | Tests |
| --- | --- | --- |
| Plan lifecycle, price and active flag, access-control reverts, error selectors | `test/registry/plans.test.ts` | 15 |
| Purchase, renewal math at the second boundaries, overpayment refund, pause | `test/registry/purchase.test.ts` | 16 |
| Grant and revoke, bounded reasons, role administration, two-step admin transfer | `test/registry/operators.test.ts` | 16 |
| Max concurrent holders, slot release, bounded batches | `test/registry/capacity.test.ts` | 12 |
| Withdrawals and accounting (`balance == paid - refunded - withdrawn`), forced ETH | `test/registry/withdraw.test.ts` | 8 |
| Reentrancy attacks on the refund path and the withdraw path | `test/registry/reentrancy.test.ts` | 7 |
| Randomized comparison with a reference model (3 seeds x 250 operations) | `test/registry/invariants.test.ts` | 4 |
| EIP-4361 format and strict parsing | `test/auth/siwe.test.ts` | 15 |
| Nonce store | `test/auth/nonceStore.test.ts` | 6 |
| Session tokens | `test/auth/session.test.ts` | 12 |
| Login, sessions and access checks with a fake reader (replay, expiry, wrong domain, URI or chain id, tampering, wrong signer, ...) | `test/auth/service.test.ts` | 33 |
| Purchase -> login -> access, expiry, revocation, grants, ERC-1271 against the deployed contract | `test/auth/e2e.test.ts` | 15 |

What the contract tests assert, concretely: custom errors and their arguments (and, in a few tests, the raw 4-byte selectors); events and their arguments; purchase and renewal expiry arithmetic including renewal one second before, exactly at, and after expiry; the refund and withdrawal accounting identity after every step of a mixed sequence; that a contract buyer or treasury that re-enters `purchase` from its `receive` function is stopped by the guard with `ReentrancyGuardReentrantCall`, and that the outer call either completes once or reverts whole, depending on whether the attacker swallows the inner failure.

The randomized test uses a seeded PRNG (mulberry32, seeds 11, 2024 and 90210), so a failure can be replayed. After every operation it compares plans, expiries, slots, revenue totals and the contract balance with a TypeScript model. Across the three seeds it performed these operations (printed by the test):

```
grant ok=70, revoke reverts: nothing=37, active change=20, price change=28, purchase ok=64,
purchase ok, refunded=65, purchase reverts: full=36, revoke ok=42, time warp=73, withdraw ok=59,
purchase reverts: inactive=21, release freed a slot=24, grant reverts: full=10, pause toggle=26,
purchase reverts: paused=117, withdraw reverts: too much=4
```

### Coverage

`npm run coverage` uses Hardhat's built-in Solidity coverage (no separate plugin). Output of one run:

```
╔════════════════════════════════════════════════════════════════════════════╗
║ File Coverage                                                              ║
╟───────────────────────────────────┬────────┬─────────────┬─────────────────╢
║ File Path                         │ Line % │ Statement % │ Uncovered Lines ║
╟───────────────────────────────────┼────────┼─────────────┼─────────────────╢
║ contracts/test/Erc1271Wallet.sol  │ 87.50  │ 90.00       │ 19              ║
║ contracts/AccessRegistry.sol      │ 100.00 │ 100.00      │ -               ║
║ contracts/test/AccessProbe.sol    │ 100.00 │ 100.00      │ -               ║
║ contracts/test/ReentrantBuyer.sol │ 94.12  │ 94.44       │ 44              ║
╟───────────────────────────────────┼────────┼─────────────┼─────────────────╢
║ Total                             │ 98.21  │ 98.48       │                 ║
╚═══════════════════════════════════╧════════╧═════════════╧═════════════════╝
```

Line and statement coverage only; the report has no branch figures. 100% line coverage of `AccessRegistry.sol` means every line ran, not that every behavior was checked.

### Gas

`npm run test:gas` prints per-function gas for every call made during the test run. These are the state-changing functions of `AccessRegistry` from one run (units: gas, including the 21,000 base transaction cost; the spread comes from the different scenarios the tests create, for example first purchase versus renewal, with or without a refund). Numbers are from Hardhat's simulated `cancun` network with the optimizer at 200 runs, not from a live chain.

```
║ Function name              │ Min     │ Average │ Median  │ Max     │ #calls       ║
║ createPlan                 │ 71646   │ 71680   │ 71664   │ 72030   │ 24           ║
║ grant                      │ 36891   │ 52925   │ 47040   │ 80537   │ 82           ║
║ grantRole                  │ 51606   │ 51617   │ 51618   │ 51618   │ 9            ║
║ pause                      │ 47044   │ 47044   │ 47044   │ 47044   │ 17           ║
║ purchase                   │ 49224   │ 78007   │ 66324   │ 131073  │ 203          ║
║ releaseExpired             │ 27327   │ 36372   │ 34135   │ 171191  │ 83           ║
║ revoke                     │ 33541   │ 34430   │ 33565   │ 36721   │ 50           ║
║ setPlanActive              │ 28098   │ 29377   │ 28098   │ 30898   │ 24           ║
║ setPlanPrice               │ 30303   │ 32450   │ 33103   │ 33115   │ 30           ║
║ unpause                    │ 25166   │ 25166   │ 25166   │ 25166   │ 14           ║
║ withdrawTo                 │ 48443   │ 51577   │ 48467   │ 122653  │ 67           ║
║ Deployment                 │ 2131354 │ 2131354 │ 2131354 │ 2131354 │ 8            ║
```

The call counts include the randomized test, so they are not a profile of typical use.

## Dependencies and supply chain

- Hardhat 3.21.0 with `@nomicfoundation/hardhat-ethers`, `-mocha`, `-ethers-chai-matchers`, `-network-helpers` and `-typechain`; `ethers` 6.17.0; `mocha` 12.0.3; `chai` 6.3.0; `typescript` 6.0.3; OpenZeppelin Contracts 5.6.1; `solc` 0.8.38. All pinned exactly.
- Every version in the lockfile, direct and transitive, was published on or before the cutoff, 2026-10-24T00:00:00Z, which is 7 days before the date of this change. A checker over `package-lock.json` reports 0 packages too new. Installs use `--ignore-scripts`. `package.json` has one `overrides` entry (`tmp`), explained in [SECURITY.md](SECURITY.md).
- `npm audit --omit=dev` reports 0 vulnerabilities. The full tree reports advisories in development tooling; they are listed in [SECURITY.md](SECURITY.md) with the reason they are not fixed here.
- Test accounts are Hardhat's well-known development accounts or keys generated at run time with `Wallet.createRandom()` and `crypto.randomBytes`. There are no keys or secrets in the repository.

## Known limitations

- No audit, no formal verification, no static analysis, no testnet or mainnet deployment.
- The randomized test compares the contract with a reference model I wrote, so it finds divergence from my understanding of the rules, not flaws in the rules themselves.
- Administrators are trusted: the admin can pause purchases, change prices, deactivate plans and withdraw all revenue, and operators can grant and revoke any access. The only delay is on changing the admin account.
- `block.timestamp` can be nudged by block producers by a few seconds, so second-level boundaries are only exact in the simulated network.
- A revoked buyer is not refunded. Slots of capped plans are freed lazily (see Capacity).
- Hardhat's coverage report covers the Solidity code only (lines and statements, no branch figures); the TypeScript in `src/auth` is tested but its coverage was not measured.
- Gas numbers are from the simulated network with the optimizer at 200 runs; real networks and L2 fee models differ.
- The browser snippet was not run in a browser.

## License

MIT, see [LICENSE](LICENSE).
