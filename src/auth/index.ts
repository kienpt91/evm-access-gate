export { AuthError, type AuthErrorCode } from "./errors.js";
export { assertValidMessage, formatMessage, parseMessage, MAX_MESSAGE_LENGTH, type SiweMessage } from "./siwe.js";
export { InMemoryNonceStore, type NonceRecord, type NonceStore, type InMemoryNonceStoreOptions } from "./nonceStore.js";
export { signSession, verifySession, MIN_SECRET_BYTES, type SessionClaims } from "./session.js";
export {
  createErc1271Verifier,
  isValidEoaSignature,
  type ContractSignatureVerifier,
  type Erc1271VerifierOptions,
} from "./signature.js";
export { createChainGuard } from "./chainGuard.js";
export {
  ContractAccessReader,
  ACCESS_REGISTRY_READ_ABI,
  type AccessReader,
  type ContractAccessReaderOptions,
} from "./accessReader.js";
export {
  createAuthService,
  type AccessGrant,
  type AuthConfig,
  type ChallengeOptions,
  type AuthDeps,
  type AuthService,
  type Challenge,
  type Session,
  type VerifiedLogin,
} from "./service.js";
