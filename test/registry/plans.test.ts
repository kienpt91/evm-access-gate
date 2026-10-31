import { expect } from "chai";
import {
  DAY,
  DEFAULT_ADMIN_ROLE,
  DURATION,
  ethers,
  latest,
  networkHelpers,
  PRICE,
  revertSelector,
  sendAt,
  deployRegistry,
  deployWithPlan,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;

describe("AccessRegistry plans", () => {
  it("creates a plan, stores it and emits PlanCreated", async () => {
    const { registry, admin } = await loadFixture(deployRegistry);

    await expect(registry.connect(admin).createPlan(7n, PRICE, DURATION, 25))
      .to.emit(registry, "PlanCreated")
      .withArgs(7n, PRICE, DURATION, 25n);

    const plan = await registry.getPlan(7n);
    expect(plan.price).to.equal(PRICE);
    expect(plan.duration).to.equal(DURATION);
    expect(plan.maxHolders).to.equal(25n);
    expect(plan.activeHolders).to.equal(0n);
    expect(plan.active).to.equal(true);
  });

  it("accepts any plan id, including zero and the largest uint256", async () => {
    const { registry, admin } = await loadFixture(deployRegistry);
    await registry.connect(admin).createPlan(0n, PRICE, DURATION, 0);
    await registry.connect(admin).createPlan(ethers.MaxUint256, PRICE, DURATION, 0);
    expect((await registry.getPlan(0n)).duration).to.equal(DURATION);
    expect((await registry.getPlan(ethers.MaxUint256)).duration).to.equal(DURATION);
  });

  it("rejects a duplicate plan id and keeps the original plan", async () => {
    const { registry, admin } = await loadFixture(deployWithPlan);
    await expect(registry.connect(admin).createPlan(1n, PRICE * 2n, DAY, 3))
      .to.be.revertedWithCustomError(registry, "PlanAlreadyExists")
      .withArgs(1n);
    const plan = await registry.getPlan(1n);
    expect(plan.price).to.equal(PRICE);
    expect(plan.duration).to.equal(DURATION);
  });

  it("rejects a zero duration", async () => {
    const { registry, admin } = await loadFixture(deployRegistry);
    await expect(registry.connect(admin).createPlan(1n, PRICE, 0, 0))
      .to.be.revertedWithCustomError(registry, "InvalidDuration")
      .withArgs(0n);
  });

  it("accepts MAX_DURATION and rejects one second more", async () => {
    const { registry, admin } = await loadFixture(deployRegistry);
    const max = await registry.MAX_DURATION();
    expect(max).to.equal(3650n * DAY);
    await registry.connect(admin).createPlan(1n, PRICE, max, 0);
    await expect(registry.connect(admin).createPlan(2n, PRICE, max + 1n, 0))
      .to.be.revertedWithCustomError(registry, "InvalidDuration")
      .withArgs(max + 1n);
  });

  it("rejects a zero price", async () => {
    const { registry, admin } = await loadFixture(deployRegistry);
    await expect(registry.connect(admin).createPlan(1n, 0, DURATION, 0)).to.be.revertedWithCustomError(
      registry,
      "InvalidPrice",
    );
  });

  it("only the default admin can create plans", async () => {
    const { registry, operator, alice } = await loadFixture(deployRegistry);
    for (const caller of [operator, alice]) {
      await expect(registry.connect(caller).createPlan(1n, PRICE, DURATION, 0))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, DEFAULT_ADMIN_ROLE);
    }
  });

  it("setPlanActive toggles purchases and emits PlanActiveChanged", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);

    await expect(registry.connect(admin).setPlanActive(1n, false))
      .to.emit(registry, "PlanActiveChanged")
      .withArgs(1n, false);
    await expect(registry.connect(alice).purchase(1n, { value: PRICE }))
      .to.be.revertedWithCustomError(registry, "PlanInactive")
      .withArgs(1n);

    await expect(registry.connect(admin).setPlanActive(1n, true))
      .to.emit(registry, "PlanActiveChanged")
      .withArgs(1n, true);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
  });

  it("deactivating a plan does not remove access that was already bought", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    await registry.connect(admin).setPlanActive(1n, false);
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
  });

  it("setPlanPrice emits old and new price and rejects zero", async () => {
    const { registry, admin } = await loadFixture(deployWithPlan);
    await expect(registry.connect(admin).setPlanPrice(1n, PRICE * 3n))
      .to.emit(registry, "PlanPriceChanged")
      .withArgs(1n, PRICE, PRICE * 3n);
    expect((await registry.getPlan(1n)).price).to.equal(PRICE * 3n);
    await expect(registry.connect(admin).setPlanPrice(1n, 0)).to.be.revertedWithCustomError(
      registry,
      "InvalidPrice",
    );
  });

  it("a price change does not touch time that was already bought", async () => {
    const { registry, admin, alice, bob } = await loadFixture(deployWithPlan);
    const t = (await latest()) + 100n;
    await sendAt(t, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const expiryBefore = await registry.expiryOf(alice.address, 1n);
    expect(expiryBefore).to.equal(t + DURATION);

    await registry.connect(admin).setPlanPrice(1n, PRICE * 10n);

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(expiryBefore);
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    // New purchases pay the new price.
    await expect(registry.connect(bob).purchase(1n, { value: PRICE }))
      .to.be.revertedWithCustomError(registry, "InsufficientPayment")
      .withArgs(PRICE, PRICE * 10n);
    await registry.connect(bob).purchase(1n, { value: PRICE * 10n });
  });

  it("plan management and price changes are admin only", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    for (const caller of [operator, alice]) {
      await expect(registry.connect(caller).setPlanActive(1n, false))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, DEFAULT_ADMIN_ROLE);
      await expect(registry.connect(caller).setPlanPrice(1n, PRICE))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, DEFAULT_ADMIN_ROLE);
    }
  });

  it("unknown plans: getPlan, setters and purchase revert, hasAccess is false", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);
    await expect(registry.getPlan(99n)).to.be.revertedWithCustomError(registry, "PlanNotFound").withArgs(99n);
    await expect(registry.connect(admin).setPlanActive(99n, true))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
    await expect(registry.connect(admin).setPlanPrice(99n, PRICE))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
    await expect(registry.connect(alice).purchase(99n, { value: PRICE }))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
    expect(await registry.hasAccess(alice.address, 99n)).to.equal(false);
    expect(await registry.expiryOf(alice.address, 99n)).to.equal(0n);
  });

  it("the constructor rejects the zero address as default admin", async () => {
    const { registry } = await loadFixture(deployRegistry);
    await expect(ethers.deployContract("AccessRegistry", [3600, ethers.ZeroAddress]))
      .to.be.revertedWithCustomError(registry, "AccessControlInvalidDefaultAdmin")
      .withArgs(ethers.ZeroAddress);
  });

  it("reverts carry the custom error selectors from the ABI", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const selector = (name: string) => registry.interface.getError(name)?.selector;

    expect(await revertSelector(registry.connect(alice).createPlan.staticCall(1n, PRICE, DURATION, 0))).to.equal(
      selector("AccessControlUnauthorizedAccount"),
    );
    expect(await revertSelector(registry.getPlan.staticCall(99n))).to.equal(selector("PlanNotFound"));
    expect(await revertSelector(registry.connect(alice).purchase.staticCall(99n, { value: PRICE }))).to.equal(
      selector("PlanNotFound"),
    );
    expect(await revertSelector(registry.connect(alice).purchase.staticCall(1n, { value: PRICE - 1n }))).to.equal(
      selector("InsufficientPayment"),
    );
  });
});
