import { expect } from "chai";
import {
  accessAt,
  DAY,
  DEFAULT_ADMIN_ROLE,
  deployWithPlan,
  DURATION,
  ethers,
  latest,
  networkHelpers,
  PRICE,
  sendAt,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;

describe("AccessRegistry purchase and renewal", () => {
  it("an exact payment grants access for the plan duration and emits Purchased", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t = (await latest()) + 50n;

    await networkHelpers.time.setNextBlockTimestamp(t);
    await expect(registry.connect(alice).purchase(1n, { value: PRICE }))
      .to.emit(registry, "Purchased")
      .withArgs(1n, alice.address, PRICE, t + DURATION)
      .and.not.to.emit(registry, "Refunded");

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t + DURATION);
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalReceived()).to.equal(PRICE);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(PRICE);
  });

  it("reverts when the payment is below the price, including zero", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    await expect(registry.connect(alice).purchase(1n, { value: PRICE - 1n }))
      .to.be.revertedWithCustomError(registry, "InsufficientPayment")
      .withArgs(PRICE - 1n, PRICE);
    await expect(registry.connect(alice).purchase(1n))
      .to.be.revertedWithCustomError(registry, "InsufficientPayment")
      .withArgs(0n, PRICE);
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(false);
  });

  it("refunds an overpayment in the same transaction and emits Refunded", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const extra = ethers.parseEther("0.5");

    await expect(registry.connect(alice).purchase(1n, { value: PRICE + extra }))
      .to.emit(registry, "Refunded")
      .withArgs(alice.address, extra);

    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(PRICE);
    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalRefunded()).to.equal(extra);
  });

  it("moves exactly the price from the buyer to the contract when overpaying", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const extra = ethers.parseEther("1");
    await expect(registry.connect(alice).purchase(1n, { value: PRICE + extra })).to.changeEtherBalances(
      ethers,
      [alice, registry],
      [-PRICE, PRICE],
    );
  });

  it("a renewal before expiry adds the duration to the current expiry", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const firstExpiry = t0 + DURATION;

    const t1 = t0 + 10n * DAY;
    await sendAt(t1, () => registry.connect(alice).purchase(1n, { value: PRICE }));

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(firstExpiry + DURATION);
  });

  it("a renewal one second before expiry keeps that last second", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const firstExpiry = t0 + DURATION;

    await sendAt(firstExpiry - 1n, () => registry.connect(alice).purchase(1n, { value: PRICE }));

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(firstExpiry + DURATION);
  });

  it("a renewal at exactly the expiry second starts from that second", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const firstExpiry = t0 + DURATION;

    await sendAt(firstExpiry, () => registry.connect(alice).purchase(1n, { value: PRICE }));

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(firstExpiry + DURATION);
  });

  it("a renewal after expiry starts from the renewal time, the gap is not credited", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const firstExpiry = t0 + DURATION;

    const t1 = firstExpiry + 5n * DAY;
    await sendAt(t1, () => registry.connect(alice).purchase(1n, { value: PRICE }));

    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t1 + DURATION);
  });

  it("hasAccess is true up to expiry - 1 and false from the expiry second on", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    const expiry = t0 + DURATION;
    const probe = await ethers.deployContract("AccessProbe");

    expect(await accessAt(probe, registry, alice.address, 1n, expiry - 1n)).to.equal(true);
    expect(await accessAt(probe, registry, alice.address, 1n, expiry)).to.equal(false);
    expect(await accessAt(probe, registry, alice.address, 1n, expiry + 1n)).to.equal(false);
  });

  it("expiryOf keeps reporting the past expiry after access has lapsed", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    const t0 = (await latest()) + 10n;
    await sendAt(t0, () => registry.connect(alice).purchase(1n, { value: PRICE }));
    await networkHelpers.time.increaseTo(t0 + DURATION + DAY);

    expect(await registry.hasAccess(alice.address, 1n)).to.equal(false);
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t0 + DURATION);
  });

  it("keeps expiries separate per user and per plan", async () => {
    const { registry, admin, alice, bob } = await loadFixture(deployWithPlan);
    await registry.connect(admin).createPlan(2n, PRICE * 2n, 7n * DAY, 0);

    await registry.connect(alice).purchase(1n, { value: PRICE });
    await registry.connect(bob).purchase(2n, { value: PRICE * 2n });

    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    expect(await registry.hasAccess(alice.address, 2n)).to.equal(false);
    expect(await registry.hasAccess(bob.address, 1n)).to.equal(false);
    expect(await registry.hasAccess(bob.address, 2n)).to.equal(true);
  });

  it("buying is always for msg.sender, never for another address", async () => {
    const { registry, alice, bob } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    expect(await registry.expiryOf(bob.address, 1n)).to.equal(0n);
  });

  it("pause blocks purchases with EnforcedPause and unpause restores them", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);

    await expect(registry.connect(admin).pause()).to.emit(registry, "Paused").withArgs(admin.address);
    expect(await registry.paused()).to.equal(true);
    await expect(registry.connect(alice).purchase(1n, { value: PRICE })).to.be.revertedWithCustomError(
      registry,
      "EnforcedPause",
    );

    await expect(registry.connect(admin).unpause()).to.emit(registry, "Unpaused").withArgs(admin.address);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
  });

  it("pause keeps existing access valid and keeps operator and admin actions working", async () => {
    const { registry, admin, operator, alice, bob, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    await registry.connect(admin).pause();

    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    await registry.connect(operator).grant(bob.address, 1n, DAY, "paused-period grant");
    expect(await registry.hasAccess(bob.address, 1n)).to.equal(true);
    await registry.connect(operator).revoke(bob.address, 1n, "paused-period revoke");
    await registry.connect(admin).withdrawTo(treasury.address, PRICE);
    expect(await registry.accruedRevenue()).to.equal(0n);
  });

  it("only the default admin can pause and unpause", async () => {
    const { registry, admin, operator, alice } = await loadFixture(deployWithPlan);
    for (const caller of [operator, alice]) {
      await expect(registry.connect(caller).pause())
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, DEFAULT_ADMIN_ROLE);
    }
    await registry.connect(admin).pause();
    await expect(registry.connect(alice).unpause())
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(alice.address, DEFAULT_ADMIN_ROLE);
    await expect(registry.connect(admin).pause()).to.be.revertedWithCustomError(registry, "EnforcedPause");
  });

  it("rejects plain ETH transfers: there is no receive or fallback function", async () => {
    const { registry, alice } = await loadFixture(deployWithPlan);
    await expect(
      alice.sendTransaction({ to: await registry.getAddress(), value: 1n }),
    ).to.be.revertedWithoutReason(ethers);
    await expect(
      alice.sendTransaction({ to: await registry.getAddress(), value: 1n, data: "0x12345678" }),
    ).to.be.revertedWithoutReason(ethers);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(0n);
  });
});
