import { expect } from "chai";
import {
  DAY,
  deployWithPlan,
  DURATION,
  ethers,
  latest,
  networkHelpers,
  PRICE,
  sendAt,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;

// Mirrors ReentrantBuyer.Mode.
const Mode = { Accept: 0, Reject: 1, ReenterPurchase: 2, ReenterPurchaseSwallow: 3 } as const;

async function deployAttacker() {
  const ctx = await deployWithPlan();
  const attacker = await ethers.deployContract("ReentrantBuyer", [await ctx.registry.getAddress(), 1n]);
  await attacker.waitForDeployment();
  return { ...ctx, attacker };
}

describe("AccessRegistry reentrancy", () => {
  const guardSelector = ethers.id("ReentrancyGuardReentrantCall()").slice(0, 10);

  it("refund path: a re-entering purchase is rejected by the guard, the outer purchase is accounted once", async () => {
    const { registry, attacker } = await loadFixture(deployAttacker);
    await attacker.setMode(Mode.ReenterPurchaseSwallow);
    const t = (await latest()) + 10n;
    const extra = PRICE * 3n;

    await sendAt(t, () => attacker.buy(1n, PRICE, { value: PRICE + extra }));

    expect(await attacker.receiveCalls()).to.equal(1n);
    expect(await attacker.reenterSucceeded()).to.equal(false);
    expect(await attacker.reenterErrorSelector()).to.equal(guardSelector);
    // One purchase worth of time, one price of revenue, the rest refunded to the attacker.
    expect(await registry.expiryOf(await attacker.getAddress(), 1n)).to.equal(t + DURATION);
    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalRefunded()).to.equal(extra);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(PRICE);
    expect(await ethers.provider.getBalance(await attacker.getAddress())).to.equal(extra);
  });

  it("refund path: if the attacker lets the failure bubble up, the whole purchase reverts", async () => {
    const { registry, attacker } = await loadFixture(deployAttacker);
    await attacker.setMode(Mode.ReenterPurchase);
    const extra = PRICE * 2n;

    await expect(attacker.buy(1n, PRICE, { value: PRICE + extra }))
      .to.be.revertedWithCustomError(registry, "RefundFailed")
      .withArgs(await attacker.getAddress(), extra);

    expect(await registry.hasAccess(await attacker.getAddress(), 1n)).to.equal(false);
    expect(await registry.accruedRevenue()).to.equal(0n);
    expect(await registry.totalReceived()).to.equal(0n);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(0n);
  });

  it("an exact payment never calls back into the buyer", async () => {
    const { registry, attacker } = await loadFixture(deployAttacker);
    await attacker.setMode(Mode.ReenterPurchase);

    await attacker.buy(1n, PRICE, { value: PRICE });

    expect(await attacker.receiveCalls()).to.equal(0n);
    expect(await registry.hasAccess(await attacker.getAddress(), 1n)).to.equal(true);
  });

  it("a buyer that rejects ETH can only buy with the exact price", async () => {
    const { registry, attacker } = await loadFixture(deployAttacker);
    await attacker.setMode(Mode.Reject);

    await expect(attacker.buy(1n, PRICE, { value: PRICE + 1n })).to.be.revertedWithCustomError(registry, "RefundFailed");
    await attacker.buy(1n, PRICE, { value: PRICE });
    expect(await registry.hasAccess(await attacker.getAddress(), 1n)).to.equal(true);
  });

  it("withdraw path: a treasury that re-enters purchase is blocked and the withdrawal completes once", async () => {
    const { registry, admin, alice, attacker } = await loadFixture(deployAttacker);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE * 2n }); // revenue PRICE, refund to alice
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await attacker.setMode(Mode.ReenterPurchaseSwallow);
    const amount = PRICE;

    await registry.connect(admin).withdrawTo(await attacker.getAddress(), amount);

    expect(await attacker.reenterSucceeded()).to.equal(false);
    expect(await attacker.reenterErrorSelector()).to.equal(guardSelector);
    expect(await registry.hasAccess(await attacker.getAddress(), 1n)).to.equal(false);
    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalWithdrawn()).to.equal(amount);
    expect(await ethers.provider.getBalance(await attacker.getAddress())).to.equal(amount);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(PRICE);
  });

  it("withdraw path: if the treasury lets the blocked re-entry bubble up, the withdrawal reverts", async () => {
    const { registry, admin, alice, attacker } = await loadFixture(deployAttacker);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await attacker.setMode(Mode.ReenterPurchase);

    await expect(registry.connect(admin).withdrawTo(await attacker.getAddress(), PRICE))
      .to.be.revertedWithCustomError(registry, "WithdrawFailed")
      .withArgs(await attacker.getAddress(), PRICE);

    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalWithdrawn()).to.equal(0n);
  });

  it("the guard resets after a blocked attack: normal purchases keep working", async () => {
    const { registry, alice, attacker } = await loadFixture(deployAttacker);
    await attacker.setMode(Mode.ReenterPurchaseSwallow);
    await attacker.buy(1n, PRICE, { value: PRICE * 2n });

    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    await networkHelpers.time.increase(DAY);
    await attacker.buy(1n, PRICE, { value: PRICE }); // renewal by the attacker contract itself
    expect(await registry.accruedRevenue()).to.equal(PRICE * 3n);
  });
});
