import { network } from "hardhat";
import type { ContractTransactionResponse } from "ethers";
import type { AccessProbe, AccessRegistry } from "../../types/ethers-contracts/index.js";

// One in-process network for the whole mocha run. Tests isolate themselves with `loadFixture`,
// which reverts the chain to the snapshot taken when the fixture first ran.
export const connection = await network.create();
export const { ethers, networkHelpers } = connection;

export const MINUTE = 60n;
export const HOUR = 3600n;
export const DAY = 86_400n;

export const ADMIN_DELAY = 3600;
export const PRICE = ethers.parseEther("0.01");
export const DURATION = 30n * DAY;

export const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
export const OPERATOR_ROLE = ethers.id("OPERATOR_ROLE");

export async function deployRegistry() {
  const [admin, operator, alice, bob, carol, treasury, outsider] = await ethers.getSigners();
  if (!admin || !operator || !alice || !bob || !carol || !treasury || !outsider) {
    throw new Error("expected at least 7 signers from the in-process network");
  }
  const registry = await ethers.deployContract("AccessRegistry", [ADMIN_DELAY, admin.address]);
  await registry.waitForDeployment();
  await registry.connect(admin).grantRole(OPERATOR_ROLE, operator.address);
  return { registry, admin, operator, alice, bob, carol, treasury, outsider };
}

/** Same as `deployRegistry` plus plan 1: price PRICE, duration DURATION, unlimited. */
export async function deployWithPlan() {
  const ctx = await deployRegistry();
  await ctx.registry.connect(ctx.admin).createPlan(1n, PRICE, DURATION, 0);
  return ctx;
}

export async function latest(): Promise<bigint> {
  return BigInt(await networkHelpers.time.latest());
}

/** Send a transaction that must be mined with exactly this block timestamp. */
export async function sendAt(
  timestamp: bigint,
  send: () => Promise<ContractTransactionResponse>,
): Promise<{ tx: ContractTransactionResponse; blockTimestamp: bigint }> {
  await networkHelpers.time.setNextBlockTimestamp(timestamp);
  const tx = await send();
  const receipt = await tx.wait();
  if (!receipt) throw new Error("no receipt");
  const block = await ethers.provider.getBlock(receipt.blockNumber);
  if (!block) throw new Error("no block");
  return { tx, blockTimestamp: BigInt(block.timestamp) };
}

/**
 * Mine a block at `timestamp`, then report what `hasAccess` returned inside that block.
 * Deploy the probe before the first call: a deployment mines a block of its own.
 */
export async function accessAt(
  probe: AccessProbe,
  registry: AccessRegistry,
  user: string,
  planId: bigint,
  timestamp: bigint,
): Promise<boolean> {
  await networkHelpers.time.setNextBlockTimestamp(timestamp);
  await (await probe.observe(await registry.getAddress(), user, planId)).wait();
  const seen = await probe.lastTimestamp();
  if (seen !== timestamp) throw new Error(`probe ran at ${seen}, expected ${timestamp}`);
  return probe.lastHasAccess();
}

/** First four bytes of the revert data of a call that is expected to fail. */
export async function revertSelector(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (err) {
    // Hardhat reports the raw revert data in `data`; ethers reports it the same way on CALL_EXCEPTION.
    if (typeof err === "object" && err !== null && "data" in err) {
      const data = err.data;
      if (typeof data === "string" && data.length >= 10) return data.slice(0, 10);
    }
    throw new Error(`call reverted without revert data: ${String(err)}`);
  }
  throw new Error("call did not revert");
}
