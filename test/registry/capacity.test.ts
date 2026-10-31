import { expect } from "chai";
import {
  DAY,
  deployRegistry,
  DURATION,
  ethers,
  networkHelpers,
  PRICE,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;
const CAPPED = 2n;
const CAP = 2;

async function deployCapped() {
  const ctx = await deployRegistry();
  await ctx.registry.connect(ctx.admin).createPlan(CAPPED, PRICE, DURATION, CAP);
  await ctx.registry.connect(ctx.admin).createPlan(1n, PRICE, DURATION, 0);
  return ctx;
}

describe("AccessRegistry max concurrent holders", () => {
  it("lets purchases fill the cap and rejects the next buyer with PlanFull", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });

    await expect(registry.connect(carol).purchase(CAPPED, PRICE, { value: PRICE }))
      .to.be.revertedWithCustomError(registry, "PlanFull")
      .withArgs(CAPPED, CAP);

    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(2n);
    expect(await registry.hasAccess(carol.address, CAPPED)).to.equal(false);
    expect(await registry.accruedRevenue()).to.equal(PRICE * 2n);
  });

  it("a current holder can renew when the plan is full", async () => {
    const { registry, alice, bob } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    const before = await registry.expiryOf(alice.address, CAPPED);

    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });

    expect(await registry.expiryOf(alice.address, CAPPED)).to.equal(before + DURATION);
    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(2n);
  });

  it("expired holders keep their slot until it is released", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION + 1n);

    expect(await registry.hasAccess(alice.address, CAPPED)).to.equal(false);
    await expect(registry.connect(carol).purchase(CAPPED, PRICE, { value: PRICE })).to.be.revertedWithCustomError(
      registry,
      "PlanFull",
    );
  });

  it("anyone can release expired slots, which emits SlotReleased and frees capacity", async () => {
    const { registry, alice, bob, carol, outsider } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION + 1n);

    await expect(registry.connect(outsider).releaseExpired(CAPPED, [alice.address, bob.address]))
      .to.emit(registry, "SlotReleased")
      .withArgs(CAPPED, alice.address)
      .and.to.emit(registry, "SlotReleased")
      .withArgs(CAPPED, bob.address);

    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(0n);
    expect(await registry.holdsSlot(alice.address, CAPPED)).to.equal(false);
    // The lapsed expiry is still readable after the release.
    expect(await registry.expiryOf(alice.address, CAPPED)).to.be.greaterThan(0n);
    await registry.connect(carol).purchase(CAPPED, PRICE, { value: PRICE });
    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(1n);
  });

  it("releaseExpired skips active holders, non-holders and duplicates, and returns the count", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION / 2n);
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION / 2n + 1n); // alice lapsed, bob still active

    const list = [alice.address, alice.address, bob.address, carol.address];
    expect(await registry.releaseExpired.staticCall(CAPPED, list)).to.equal(1n);
    await registry.releaseExpired(CAPPED, list);

    expect(await registry.holdsSlot(alice.address, CAPPED)).to.equal(false);
    expect(await registry.holdsSlot(bob.address, CAPPED)).to.equal(true);
    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(1n);
  });

  it("a released holder that buys again takes a slot again", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION + 1n);
    await registry.releaseExpired(CAPPED, [alice.address]);
    await registry.connect(carol).purchase(CAPPED, PRICE, { value: PRICE }); // takes the free slot

    await expect(registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE }))
      .to.be.revertedWithCustomError(registry, "PlanFull")
      .withArgs(CAPPED, CAP);
  });

  it("bounds the releaseExpired batch at MAX_RELEASE_BATCH", async () => {
    const { registry } = await loadFixture(deployCapped);
    const max = Number(await registry.MAX_RELEASE_BATCH());
    expect(max).to.equal(50);

    const users = Array.from({ length: max + 1 }, () => ethers.Wallet.createRandom().address);
    await registry.releaseExpired(CAPPED, users.slice(0, max));
    await expect(registry.releaseExpired(CAPPED, users))
      .to.be.revertedWithCustomError(registry, "BatchTooLarge")
      .withArgs(max + 1, max);
  });

  it("releaseExpired reverts for an unknown plan", async () => {
    const { registry, alice } = await loadFixture(deployCapped);
    await expect(registry.releaseExpired(99n, [alice.address]))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
  });

  it("revoke frees the slot at once", async () => {
    const { registry, operator, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });

    await registry.connect(operator).revoke(alice.address, CAPPED, "freeing a seat");

    expect(await registry.holdsSlot(alice.address, CAPPED)).to.equal(false);
    expect((await registry.getPlan(CAPPED)).activeHolders).to.equal(1n);
    await registry.connect(carol).purchase(CAPPED, PRICE, { value: PRICE });
  });

  it("operator grants count against the cap", async () => {
    const { registry, operator, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(operator).grant(alice.address, CAPPED, DAY, "a");
    await registry.connect(operator).grant(bob.address, CAPPED, DAY, "b");

    await expect(registry.connect(operator).grant(carol.address, CAPPED, DAY, "c"))
      .to.be.revertedWithCustomError(registry, "PlanFull")
      .withArgs(CAPPED, CAP);
    // Extending an existing holder is fine.
    await registry.connect(operator).grant(alice.address, CAPPED, DAY, "a again");
  });

  it("a plan with maxHolders = 0 is unlimited and does not track slots", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    for (const user of [alice, bob, carol]) {
      await registry.connect(user).purchase(1n, PRICE, { value: PRICE });
      expect(await registry.holdsSlot(user.address, 1n)).to.equal(false);
    }
    expect((await registry.getPlan(1n)).activeHolders).to.equal(0n);
  });

  it("caps are per plan: a full plan does not affect another plan", async () => {
    const { registry, alice, bob, carol } = await loadFixture(deployCapped);
    await registry.connect(alice).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(bob).purchase(CAPPED, PRICE, { value: PRICE });
    await registry.connect(carol).purchase(1n, PRICE, { value: PRICE });
    expect(await registry.hasAccess(carol.address, 1n)).to.equal(true);
  });
});
