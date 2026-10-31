import { randomBytes as cryptoRandomBytes } from "node:crypto";
import { getAddress, isAddress, ZeroAddress } from "ethers";
import type { AccessReader } from "./accessReader.js";
import { AuthError } from "./errors.js";
import type { NonceStore } from "./nonceStore.js";
import { assertSessionSecret, signSession, verifySession, type SessionClaims } from "./session.js";
import { isSignatureHex, isValidEoaSignature, type ContractSignatureVerifier } from "./signature.js";
import { formatMessage, parseMessage } from "./siwe.js";

export interface AuthConfig {
  /** Host (and optional port) of the service the user signs in to. Must equal the `domain` in the message. */
  domain: string;
  /** The `URI` field the server puts in every challenge and requires back. */
  uri: string;
  /** Chain the wallet is asked to be on. Also bound into sessions. */
  chainId: number;
  /** One-line statement shown to the user in the wallet. */
  statement: string;
  /** Optional URI scheme prefix of the domain line, `undefined` for none. */
  scheme?: string;
  /** How long a challenge can be answered. Default 300. */
  challengeTtlSeconds?: number;
  /** How long a session token lives. Default 900. */
  sessionTtlSeconds?: number;
  /** Tolerated clock difference when checking `Issued At`. Default 60. */
  clockSkewSeconds?: number;
}

export interface AuthDeps {
  nonceStore: NonceStore;
  /** HMAC key for session tokens, at least 32 bytes. Load it from a secret manager; never hard-code it. */
  sessionSecret: Uint8Array;
  accessReader: AccessReader;
  /** Enables ERC-1271 smart-contract wallets. Without it only EOA signatures are accepted. */
  contractSignatureVerifier?: ContractSignatureVerifier;
  /** Injected for tests. Defaults to the system clock. */
  now?: () => Date;
  /** Injected for tests. Defaults to `node:crypto.randomBytes`. */
  randomBytes?: (size: number) => Uint8Array;
}

export interface Challenge {
  /** The exact text the wallet must sign with `personal_sign`. */
  message: string;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
}

export interface VerifiedLogin {
  /** EIP-55 checksummed address that proved control. */
  address: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  /** `eoa`: ECDSA signature of the address. `erc1271`: accepted by the wallet contract. */
  method: "eoa" | "erc1271";
}

export interface Session {
  token: string;
  claims: SessionClaims;
  /** ISO 8601 time at which the token stops being valid. */
  expiresAt: string;
}

export interface AccessGrant {
  address: string;
  planId: bigint;
  chainId: number;
}

export interface AuthService {
  createChallenge(address: string): Promise<Challenge>;
  verifyLogin(input: { message: string; signature: string }): Promise<VerifiedLogin>;
  issueSession(login: VerifiedLogin): Session;
  requireAccess(input: { token: string; planId: bigint }): Promise<AccessGrant>;
}

const MAX_UINT256 = (1n << 256n) - 1n;
const NONCE_BYTES = 16;

export function createAuthService(config: AuthConfig, deps: AuthDeps): AuthService {
  const challengeTtl = config.challengeTtlSeconds ?? 300;
  const sessionTtl = config.sessionTtlSeconds ?? 900;
  const skewMs = (config.clockSkewSeconds ?? 60) * 1000;
  const now = deps.now ?? (() => new Date());
  const randomBytes = deps.randomBytes ?? cryptoRandomBytes;

  for (const [name, value] of [
    ["challengeTtlSeconds", challengeTtl],
    ["sessionTtlSeconds", sessionTtl],
  ] as const) {
    if (!Number.isInteger(value) || value < 1) throw new AuthError("INVALID_CONFIG", `${name} must be a positive integer`);
  }
  if (!Number.isInteger(skewMs) || skewMs < 0) throw new AuthError("INVALID_CONFIG", "clockSkewSeconds must be >= 0");
  assertSessionSecret(deps.sessionSecret);
  try {
    // Reject a bad domain, URI, chain id or statement now instead of on the first request.
    formatMessage(baseMessage(config, ZeroAddress, "00000000", "1970-01-01T00:00:00.000Z", "1970-01-01T00:05:00.000Z"));
  } catch (err) {
    throw new AuthError("INVALID_CONFIG", `invalid login message settings: ${String(err)}`, { cause: err });
  }

  const nowSeconds = () => Math.floor(now().getTime() / 1000);

  return {
    async createChallenge(address) {
      if (typeof address !== "string" || !isAddress(address)) {
        throw new AuthError("INVALID_ADDRESS", "address must be a valid Ethereum address");
      }
      const checksummed = getAddress(address);

      const bytes = randomBytes(NONCE_BYTES);
      if (bytes.length !== NONCE_BYTES) throw new AuthError("INVALID_CONFIG", "randomBytes returned the wrong length");
      const nonce = Buffer.from(bytes).toString("hex");

      const issuedMs = nowSeconds() * 1000;
      const expiresMs = issuedMs + challengeTtl * 1000;
      const issuedAt = new Date(issuedMs).toISOString();
      const expirationTime = new Date(expiresMs).toISOString();

      const message = formatMessage(baseMessage(config, checksummed, nonce, issuedAt, expirationTime));
      await deps.nonceStore.issue(nonce, { address: checksummed, issuedAt, expirationTime, expiresAtMs: expiresMs });
      return { message, nonce, issuedAt, expirationTime };
    },

    async verifyLogin(input) {
      const { message, signature } = input;
      if (typeof message !== "string" || typeof signature !== "string") {
        throw new AuthError("MALFORMED_MESSAGE", "message and signature must be strings");
      }
      const parsed = parseMessage(message);

      // Checks that need no state come first, so a message for another site never touches the store.
      if (parsed.scheme !== config.scheme || parsed.domain !== config.domain) {
        throw new AuthError("DOMAIN_MISMATCH", `message is for ${parsed.domain}, expected ${config.domain}`);
      }
      if (parsed.uri !== config.uri) throw new AuthError("URI_MISMATCH", "unexpected URI");
      if (parsed.chainId !== config.chainId) {
        throw new AuthError("CHAIN_ID_MISMATCH", `message is for chain ${parsed.chainId}, expected ${config.chainId}`);
      }
      if (parsed.expirationTime === undefined) throw new AuthError("MISSING_EXPIRATION", "message has no Expiration Time");

      const nowMs = now().getTime();
      if (nowMs >= Date.parse(parsed.expirationTime)) throw new AuthError("CHALLENGE_EXPIRED", "challenge expired");
      if (Date.parse(parsed.issuedAt) > nowMs + skewMs) throw new AuthError("NOT_YET_VALID", "Issued At is in the future");
      if (parsed.notBefore !== undefined && Date.parse(parsed.notBefore) > nowMs + skewMs) {
        throw new AuthError("NOT_YET_VALID", "Not Before is in the future");
      }
      if (!isSignatureHex(signature)) throw new AuthError("INVALID_SIGNATURE", "signature is not a hex string");

      // From here on the nonce is spent, whether or not the signature turns out to be valid.
      const record = await deps.nonceStore.consume(parsed.nonce);
      if (record === undefined) throw new AuthError("NONCE_UNKNOWN", "nonce is unknown or was already used");
      if (record.address.toLowerCase() !== parsed.address.toLowerCase()) {
        throw new AuthError("ADDRESS_MISMATCH", "challenge was issued for a different address");
      }
      if (nowMs >= record.expiresAtMs) throw new AuthError("CHALLENGE_EXPIRED", "challenge expired");

      // The server knows exactly what it issued; anything else (edited statement, extra resources,
      // changed timestamps) is rejected even if the signer signed it.
      const expected = formatMessage(
        baseMessage(config, record.address, parsed.nonce, record.issuedAt, record.expirationTime),
      );
      if (message !== expected) throw new AuthError("MESSAGE_MISMATCH", "message differs from the issued challenge");

      let method: VerifiedLogin["method"] | undefined;
      if (isValidEoaSignature(record.address, message, signature)) {
        method = "eoa";
      } else if (
        deps.contractSignatureVerifier !== undefined &&
        (await deps.contractSignatureVerifier.isValidSignature(record.address, message, signature))
      ) {
        method = "erc1271";
      }
      if (method === undefined) throw new AuthError("INVALID_SIGNATURE", "signature does not match the address");

      return { address: record.address, chainId: config.chainId, nonce: parsed.nonce, issuedAt: record.issuedAt, method };
    },

    issueSession(login) {
      const { token, claims } = signSession(deps.sessionSecret, {
        address: login.address,
        chainId: login.chainId,
        nowSeconds: nowSeconds(),
        ttlSeconds: sessionTtl,
      });
      return { token, claims, expiresAt: new Date(claims.exp * 1000).toISOString() };
    },

    async requireAccess({ token, planId }) {
      const claims = verifySession(deps.sessionSecret, token, nowSeconds());
      if (claims.chainId !== config.chainId) {
        throw new AuthError("CHAIN_ID_MISMATCH", "session was issued for another chain");
      }
      if (typeof planId !== "bigint" || planId < 0n || planId > MAX_UINT256) {
        throw new AuthError("INVALID_PLAN", "planId must be a uint256 bigint");
      }

      let allowed: boolean;
      try {
        allowed = await deps.accessReader.hasAccess(claims.sub, planId);
      } catch (err) {
        // Fail closed: if the chain cannot be read, nobody gets in.
        throw new AuthError("ACCESS_CHECK_FAILED", "could not read access from the registry", { cause: err });
      }
      if (!allowed) throw new AuthError("ACCESS_DENIED", `no active access to plan ${planId}`);
      return { address: claims.sub, planId, chainId: claims.chainId };
    },
  };
}

function baseMessage(config: AuthConfig, address: string, nonce: string, issuedAt: string, expirationTime: string) {
  return {
    ...(config.scheme !== undefined ? { scheme: config.scheme } : {}),
    domain: config.domain,
    address,
    statement: config.statement,
    uri: config.uri,
    version: "1" as const,
    chainId: config.chainId,
    nonce,
    issuedAt,
    expirationTime,
  };
}
