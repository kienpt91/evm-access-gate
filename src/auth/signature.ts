import { getAddress, hashMessage, Interface, verifyMessage, type Provider } from "ethers";

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
 * (ERC-1271), so the answer depends on the chain state at the time of the call.
 */
export interface ContractSignatureVerifier {
  isValidSignature(address: string, message: string, signature: string): Promise<boolean>;
}

const ERC1271_MAGIC_VALUE = "0x1626ba7e";
const erc1271 = new Interface(["function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)"]);

/**
 * ERC-1271 over any ethers provider. `hash` is the EIP-191 hash of the sign-in message, which is
 * what wallets receive for `personal_sign`. Wallets that wrap the hash differently (for example
 * Safe's message hash) need their own verifier. ERC-6492 (wallets that are not deployed yet) is not
 * supported. Any call failure, empty result or other return value counts as "invalid".
 */
export function createErc1271Verifier(provider: Pick<Provider, "call">): ContractSignatureVerifier {
  return {
    async isValidSignature(address, message, signature) {
      try {
        const data = erc1271.encodeFunctionData("isValidSignature", [hashMessage(message), signature]);
        const result = await provider.call({ to: getAddress(address), data });
        const [magic] = erc1271.decodeFunctionResult("isValidSignature", result);
        return magic === ERC1271_MAGIC_VALUE;
      } catch {
        return false;
      }
    },
  };
}
