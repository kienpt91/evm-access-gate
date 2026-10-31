import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { getAddress } from "ethers";
import { AuthError } from "./errors.js";

/**
 * Short-lived bearer token proving that a wallet signed in.
 *
 *   token = base64url(JSON claims) "." base64url(HMAC-SHA256(secret, PREFIX + base64url(JSON claims)))
 *
 * Symmetric, so only the service that holds the secret can verify it. It says nothing about
 * on-chain access: that is looked up on every request by `requireAccess`.
 */
export interface SessionClaims {
  v: 1;
  /** EIP-55 checksummed wallet address. */
  sub: string;
  chainId: number;
  /** Issued at, seconds since the epoch. */
  iat: number;
  /** Expires at, seconds since the epoch. The token is invalid from this second on. */
  exp: number;
  /** Random identifier, useful for logs. */
  jti: string;
}

export const MIN_SECRET_BYTES = 32;
const MAX_TOKEN_LENGTH = 2048;
const MAC_PREFIX = "evm-access-gate/session/v1.";
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export function assertSessionSecret(secret: Uint8Array): void {
  if (!(secret instanceof Uint8Array) || secret.length < MIN_SECRET_BYTES) {
    throw new AuthError("INVALID_CONFIG", `session secret must be at least ${MIN_SECRET_BYTES} bytes`);
  }
}

function mac(secret: Uint8Array, payload: string): Buffer {
  return createHmac("sha256", secret).update(MAC_PREFIX).update(payload).digest();
}

export interface IssueSessionInput {
  address: string;
  chainId: number;
  nowSeconds: number;
  ttlSeconds: number;
}

export function signSession(secret: Uint8Array, input: IssueSessionInput): { token: string; claims: SessionClaims } {
  assertSessionSecret(secret);
  if (!Number.isInteger(input.ttlSeconds) || input.ttlSeconds < 1) {
    throw new AuthError("INVALID_CONFIG", "session ttl must be a positive number of seconds");
  }
  const claims: SessionClaims = {
    v: 1,
    sub: getAddress(input.address),
    chainId: input.chainId,
    iat: input.nowSeconds,
    exp: input.nowSeconds + input.ttlSeconds,
    jti: randomBytes(12).toString("base64url"),
  };
  const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  return { token: `${payload}.${mac(secret, payload).toString("base64url")}`, claims };
}

function malformed(reason: string): never {
  throw new AuthError("TOKEN_MALFORMED", reason);
}

/** Only the canonical base64url spelling is accepted, so one byte string has one token spelling. */
function decodeCanonical(text: string): Buffer {
  if (!BASE64URL.test(text)) malformed("not base64url");
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) malformed("non-canonical base64url");
  return bytes;
}

function parseClaims(json: string): SessionClaims {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return malformed("payload is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return malformed("payload is not an object");
  const { v, sub, chainId, iat, exp, jti, ...rest }: Record<string, unknown> = Object.fromEntries(
    Object.entries(value),
  );
  if (Object.keys(rest).length > 0) malformed("unexpected claim");
  if (v !== 1) malformed("unsupported version");
  if (typeof sub !== "string") return malformed("sub must be a string");
  let normalized: string;
  try {
    normalized = getAddress(sub);
  } catch {
    return malformed("sub is not an address");
  }
  if (normalized !== sub) malformed("sub is not in checksum case");
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) malformed("invalid chainId");
  if (typeof iat !== "number" || !Number.isSafeInteger(iat)) malformed("invalid iat");
  if (typeof exp !== "number" || !Number.isSafeInteger(exp) || exp <= iat) malformed("invalid exp");
  if (typeof jti !== "string" || jti.length === 0 || jti.length > 64) malformed("invalid jti");
  return { v: 1, sub, chainId, iat, exp, jti };
}

/**
 * Checks the MAC in constant time, then the claims, then the expiry.
 * Throws `TOKEN_MALFORMED`, `TOKEN_INVALID_SIGNATURE` or `TOKEN_EXPIRED`.
 */
export function verifySession(secret: Uint8Array, token: string, nowSeconds: number): SessionClaims {
  assertSessionSecret(secret);
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_LENGTH) malformed("bad token length");
  const [payload, providedMac, extra] = token.split(".");
  if (!payload || !providedMac || extra !== undefined) malformed("expected two non-empty parts");
  if (!BASE64URL.test(payload)) malformed("payload is not base64url");

  const provided = decodeCanonical(providedMac);
  const expected = mac(secret, payload);
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new AuthError("TOKEN_INVALID_SIGNATURE", "signature does not match");
  }

  const claims = parseClaims(decodeCanonical(payload).toString("utf8"));
  if (nowSeconds >= claims.exp) throw new AuthError("TOKEN_EXPIRED", "token expired");
  if (claims.iat > nowSeconds + 60) malformed("issued in the future");
  return claims;
}
