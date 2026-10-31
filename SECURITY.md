# Security

## Educational example, not for real funds

This repository is an educational example. The contracts have not been audited, have not been formally verified and are not deployed to any network. **Do not deploy them with real funds without an independent audit.** The backend module is a library of functions, not a hardened service: it has no HTTP layer, no rate limiting and an in-memory nonce store.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"), or email kienphan.dev@gmail.com. Do not open public issues for vulnerabilities. This is a hobby-scale example project, so there is no bounty and no response-time guarantee, but reports are read.

## Known limits that are by design

- **Admin powers.** The contract admin can change prices, deactivate plans, pause purchases and withdraw all accrued revenue, and operators can grant and revoke any access. Only a change of the admin account is delayed. `purchase(planId, maxPrice)` protects a buyer from a price increase mined before their transaction, but not from a price they already agreed to.
- **Capped plans.** Paying holders can take every slot of a capped plan, and slots of expired holders stay taken until `releaseExpired` is called for them.
- **ERC-1271 verification calls untrusted code.** `createChallenge` accepts any address, so `verifyLogin` can be made to call a hostile contract. The verifier limits the call (gas limit, timeout, at most 8 outstanding calls, 32-byte result only) but cannot cancel an in-flight provider request, cannot stop a node from executing the call up to the gas limit, and cannot limit the size of a response. Rate limiting in front of `createChallenge` and `verifyLogin` is required before exposing the module.
- **Challenge flooding.** `InMemoryNonceStore` limits live challenges per address, per client key and in total. A client that varies addresses and IPs can still fill the total (10,000 by default) and block new logins until the challenges expire.
- **The RPC endpoint is trusted.** The reader and verifier check that the provider reports the configured chain id, which catches a misconfigured endpoint. A malicious endpoint can report any chain id and any `hasAccess` result.
- **Sessions** are bearer tokens that cannot be revoked individually; they are short-lived (15 minutes by default) and on-chain access is re-read on every request.

## Dependency policy

- Every dependency version, direct and transitive, was installed with `npm install --before=<cutoff> --ignore-scripts --save-exact`, where the cutoff is 7 days before the change (currently 2026-10-24T00:00:00Z). A version published inside that window is not used, even when it carries an advisory fix.
- All versions are pinned exactly in `package.json`, and `package-lock.json` is committed. It was generated in a clean directory with `npm install --package-lock-only`, so it contains the optional native packages for every platform.
- CI and local setup use `npm ci --ignore-scripts`. No dependency needs an install script to work here.
- The Solidity compiler is the `solc` npm package (solc-js), pinned in the lockfile. Hardhat is configured with the path to its `soljson.js`, so no compiler binary is downloaded at compile time.
- Builds, tests and installs were run in throwaway containers, not on a developer host.
- Hardhat's telemetry is switched off in every npm script (`HARDHAT_DISABLE_TELEMETRY=true`) and is anyway not active in non-interactive or CI runs.
- `.github/dependabot.yml` uses a 7-day cooldown for npm and GitHub Actions, and GitHub Actions in CI are pinned to full commit SHAs.
- `package.json` has one `overrides` entry: `tmp` is raised from the `0.2.6` that `solc` pins to `0.2.7` (published 2026-05-27), because `0.2.6` has an advisory. solc-js only uses `tmp` in its optional SMT-solver helper, which this project does not call. Drop the override once `solc` bumps it.

## Open advisories

`npm audit` on the committed lockfile reports, at the cutoff above:

- `npm audit --omit=dev` (what a consumer of `src/auth` installs: `ethers` and `@openzeppelin/contracts`): 0 vulnerabilities.
- `npm audit` (full tree): 14 affected packages from four advisories, all in development tooling. Fixed versions either do not exist yet or were published after the cutoff:
  - `zod` < 4.6.6 (memory exhaustion on oversized collections), pulled in by Hardhat 3 and its plugins, which pin `zod` 3.x.
  - `glob` and `minimatch` (ReDoS / traversal in glob matching), pulled in by `mocha` and `typechain`.
  - `follow-redirects` 1.16.0-1.16.1, pulled in by `solc` (used by its optional download helper, which this project does not call).

None of these packages handles untrusted input in this project: they run on the developer's machine or in CI against files in this repository. The advisory list is rechecked when dependencies move.
