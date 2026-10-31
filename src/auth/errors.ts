/**
 * Every failure of the auth module is an `AuthError` with a stable `code`.
 * Callers map codes to HTTP statuses (or anything else); messages are for logs, not for end users.
 */
export type AuthErrorCode =
  // configuration and input
  | "INVALID_CONFIG"
  | "INVALID_ADDRESS"
  | "INVALID_PLAN"
  // login message
  | "MALFORMED_MESSAGE"
  | "DOMAIN_MISMATCH"
  | "URI_MISMATCH"
  | "CHAIN_ID_MISMATCH"
  | "MISSING_EXPIRATION"
  | "CHALLENGE_EXPIRED"
  | "NOT_YET_VALID"
  | "NONCE_UNKNOWN"
  | "ADDRESS_MISMATCH"
  | "MESSAGE_MISMATCH"
  | "INVALID_SIGNATURE"
  | "STORE_FULL"
  // session token
  | "TOKEN_MALFORMED"
  | "TOKEN_INVALID_SIGNATURE"
  | "TOKEN_EXPIRED"
  // access check
  | "ACCESS_DENIED"
  | "ACCESS_CHECK_FAILED";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string, options?: { cause?: unknown }) {
    super(`${code}: ${message}`, options);
    this.name = "AuthError";
    this.code = code;
  }
}
