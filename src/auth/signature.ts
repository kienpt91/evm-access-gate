import { getAddress, hashMessage, Interface, verifyMessage, type Provider } from "ethers";
import { createChainGuard } from "./chainGuard.js";
import { AuthError } from "./errors.js";

const SIGNATURE_HEX = /^0x(?:[0-9a-fA-F]{2}){1,4096}$/;

export function isSignatureHex(value: string): boolean {
  return SIGNATURE_HEX.test(value);
}

/**
 * EIP-191 `personal_sign` check for externally owned accounts: recover the signer of `message` and
 * compare it with `address`. Both sides are normalized with `getAddress`, so letter case never matters.
 * Returns false for any malformed signature instead of throwing.
 */
export function isValidEoaSignature(address: string, message: string, signature: string): boolean {
  try {
    return getAddress(verifyMessage(message, signature)) === getAddress(address);
  } catch {
    return false;
  }
}

/**
 * Checks a signature on behalf of a smart-contract wallet. Implementations ask the wallet itself
 * (ERC-1271), so the answer depends on the chain state at the time of the call. They may throw
 * `AuthError("VERIFIER_UNAVAILABLE")` when they cannot answer in time.
 */
export interface ContractSignatureVerifier {
  isValidSignature(address: string, message: string, signature: string): Promise<boolean>;
}

export interface Erc1271VerifierOptions {
  /** Chain the wallets live on; checked against the provider on first use. Same value as `AuthConfig.chainId`. */
  chainId: number;
  /** Give up waiting after this many milliseconds. Default 3000. */
  timeoutMs?: number;
  /** Gas limit put on the `eth_call`. Default 300000. */
  gasLimit?: bigint;
  /** Calls allowed to be outstanding at once, counting timed-out calls until they really finish. Default 8. */
  maxConcurrent?: number;
}

const ERC1271_MAGIC_VALUE = "0x1626ba7e";
/** A `bytes4` return value is ABI-encoded as exactly one 32-byte word: "0x" + 64 hex characters. */
const EXPECTED_RESULT_LENGTH = 66;
const erc1271 = new Interface(["function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)"]);

/**
 * ERC-1271 over any ethers provider. `hash` is the EIP-191 hash of the sign-in message, which is
 * what wallets receive for `personal_sign`. Wallets that wrap the hash differently (for example
 * Safe's message hash) need their own verifier. ERC-6492 (wallets that are not deployed yet) is not
 * supported.
 *
 * The address is chosen by an anonymous caller, so the contract behind it is untrusted code. The
 * bounds below limit what one request can cost; they do not make the path free:
 * - `gasLimit` is sent with the `eth_call`. Nodes execute the call up to that limit (or their own
 *   lower cap), so a hostile wallet can still use that much CPU on the node per call.
 * - `timeoutMs` stops this function from waiting. `provider.call` takes no abort signal, so the
 *   underlying request keeps running until the provider's own timeout.
 * - `maxConcurrent` counts a call until it really settles, which bounds the work this process has
 *   outstanding; callers over the limit get `VERIFIER_UNAVAILABLE`.
 * - A result that is not exactly one 32-byte word is rejected before decoding, but the bytes have
 *   already been transferred by then; the provider API has no response-size limit.
 * Any revert, bad result or call failure counts as "invalid". Timeouts, too many outstanding calls
 * and an unreachable node or wrong chain throw `AuthError`.
 */
export function createErc1271Verifier(
  provider: Pick<Provider, "call" | "getNetwork">,
  options: Erc1271VerifierOptions,
): ContractSignatureVerifier {
  const timeoutMs = options.timeoutMs ?? 3000;
  const gasLimit = options.gasLimit ?? 300_000n;
  const maxConcurrent = options.maxConcurrent ?? 8;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new AuthError("INVALID_CONFIG", "timeoutMs must be a positive integer");
  if (gasLimit < 1n) throw new AuthError("INVALID_CONFIG", "gasLimit must be positive");
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) throw new AuthError("INVALID_CONFIG", "maxConcurrent must be a positive integer");

  const assertChain = createChainGuard(provider, options.chainId);
  let outstanding = 0;

  async function check(address: string, message: string, signature: string): Promise<boolean> {
    try {
      await assertChain();
    } catch (err) {
      if (err instanceof AuthError) throw err;
      throw new AuthError("VERIFIER_UNAVAILABLE", "could not confirm the provider's chain id", { cause: err });
    }
    try {
      const data = erc1271.encodeFunctionData("isValidSignature", [hashMessage(message), signature]);
      const result = await provider.call({ to: getAddress(address), data, gasLimit });
      if (result.length !== EXPECTED_RESULT_LENGTH) return false;
      const [magic] = erc1271.decodeFunctionResult("isValidSignature", result);
      return magic === ERC1271_MAGIC_VALUE;
    } catch {
      return false;
    }
  }

  return {
    async isValidSignature(address, message, signature) {
      if (outstanding >= maxConcurrent) {
        throw new AuthError("VERIFIER_UNAVAILABLE", `${maxConcurrent} ERC-1271 checks are already outstanding`);
      }
      outstanding += 1;
      const pending = check(address, message, signature);
      // Released when the call really finishes, not when the caller stops waiting.
      const release = () => {
        outstanding -= 1;
      };
      pending.then(release, release);

      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new AuthError("VERIFIER_UNAVAILABLE", `ERC-1271 check timed out after ${timeoutMs} ms`)),
          timeoutMs,
        );
      });
      try {
        return await Promise.race([pending, timeout]);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
