import type { Provider } from "ethers";
import { AuthError } from "./errors.js";

/**
 * Returns a function that checks, once, that `provider` is connected to `expectedChainId`.
 * A success is remembered; a failure (wrong chain or an unreachable node) is not, so the next call
 * asks again.
 *
 * This catches a misconfigured RPC endpoint, for example a testnet URL behind a mainnet config. It
 * is not a defense against a malicious RPC endpoint, which can report any chain id it likes.
 */
export function createChainGuard(
  provider: Pick<Provider, "getNetwork">,
  expectedChainId: number,
): () => Promise<void> {
  if (!Number.isSafeInteger(expectedChainId) || expectedChainId < 1) {
    throw new AuthError("INVALID_CONFIG", "chainId must be a positive integer");
  }
  let confirmed = false;
  return async () => {
    if (confirmed) return;
    const { chainId } = await provider.getNetwork();
    if (chainId !== BigInt(expectedChainId)) {
      throw new AuthError("CHAIN_ID_MISMATCH", `provider is on chain ${chainId}, expected ${expectedChainId}`);
    }
    confirmed = true;
  };
}
