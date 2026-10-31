export { AuthError, type AuthErrorCode } from "./errors.js";
export { assertValidMessage, formatMessage, parseMessage, MAX_MESSAGE_LENGTH, type SiweMessage } from "./siwe.js";
export { InMemoryNonceStore, type NonceRecord, type NonceStore, type InMemoryNonceStoreOptions } from "./nonceStore.js";
export { signSession, verifySession, MIN_SECRET_BYTES, type SessionClaims } from "./session.js";
export { createErc1271Verifier, isValidEoaSignature, type ContractSignatureVerifier } from "./signature.js";
export { ContractAccessReader, ACCESS_REGISTRY_READ_ABI, type AccessReader } from "./accessReader.js";
export {
  createAuthService,
  type AccessGrant,
  type AuthConfig,
  type AuthDeps,
  type AuthService,
  type Challenge,
  type Session,
  type VerifiedLogin,
} from "./service.js";
