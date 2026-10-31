import { Contract, getAddress, isAddress, type ContractRunner } from "ethers";
import { AuthError } from "./errors.js";

/** Answers "does this wallet currently have access to this plan?". */
export interface AccessReader {
  hasAccess(user: string, planId: bigint): Promise<boolean>;
}

/** The only function of AccessRegistry this module needs. */
export const ACCESS_REGISTRY_READ_ABI = [
  "function hasAccess(address user, uint256 planId) view returns (bool)",
] as const;

const MAX_UINT256 = (1n << 256n) - 1n;

/** Reads `AccessRegistry.hasAccess` over any ethers provider. The result reflects the latest block. */
export class ContractAccessReader implements AccessReader {
  readonly #registry: Contract;

  constructor(registryAddress: string, provider: ContractRunner) {
    if (!isAddress(registryAddress)) throw new AuthError("INVALID_CONFIG", "registry address is not an address");
    this.#registry = new Contract(getAddress(registryAddress), ACCESS_REGISTRY_READ_ABI, provider);
  }

  async hasAccess(user: string, planId: bigint): Promise<boolean> {
    if (!isAddress(user)) throw new AuthError("INVALID_ADDRESS", "user is not an address");
    if (typeof planId !== "bigint" || planId < 0n || planId > MAX_UINT256) {
      throw new AuthError("INVALID_PLAN", "planId must be a uint256");
    }
    const allowed: unknown = await this.#registry.getFunction("hasAccess")(getAddress(user), planId);
    return allowed === true;
  }
}
