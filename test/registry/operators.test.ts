import { expect } from "chai";
import {
  ADMIN_DELAY,
  DAY,
  DEFAULT_ADMIN_ROLE,
  deployWithPlan,
  DURATION,
  ethers,
  latest,
  networkHelpers,
  OPERATOR_ROLE,
  PRICE,
  sendAt,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;

describe("AccessRegistry operators: grant and revoke", () => {
  it("grant gives free access for the given duration and emits AccessGranted", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    const t = (await latest()) + 20n;

    await networkHelpers.time.setNextBlockTimestamp(t);
    await expect(registry.connect(operator).grant(alice.address, 1n, 7n * DAY, "support credit"))
      .to.emit(registry, "AccessGranted")
      .withArgs(1n, alice.address, operator.address, 7n * DAY, t + 7n * DAY, "support credit");

    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t + 7n * DAY);
    expect(await registry.accruedRevenue()).to.equal(0n);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(0n);
  });

  it("grant stacks on top of a purchase like a renewal does", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    const t = (await latest()) + 20n;
    await sendAt(t, () => registry.connect(alice).purchase(1n, PRICE, { value: PRICE }));
    await registry.connect(operator).grant(alice.address, 1n, 3n * DAY, "");
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t + DURATION + 3n * DAY);
  });

  it("grant works on an inactive plan", async () => {
    const { registry, admin, operator, alice } = await loadFixture(deployWithPlan);
    await registry.connect(admin).setPlanActive(1n, false);
    await registry.connect(operator).grant(alice.address, 1n, DAY, "legacy plan");
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(true);
  });

  it("grant validates user, plan and duration", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await expect(registry.connect(operator).grant(ethers.ZeroAddress, 1n, DAY, "x")).to.be.revertedWithCustomError(
      registry,
      "InvalidAddress",
    );
    await expect(registry.connect(operator).grant(alice.address, 99n, DAY, "x"))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
    await expect(registry.connect(operator).grant(alice.address, 1n, 0, "x"))
      .to.be.revertedWithCustomError(registry, "InvalidDuration")
      .withArgs(0n);
    const tooLong = (await registry.MAX_DURATION()) + 1n;
    await expect(registry.connect(operator).grant(alice.address, 1n, tooLong, "x"))
      .to.be.revertedWithCustomError(registry, "InvalidDuration")
      .withArgs(tooLong);
  });

  it("reasons are bounded to 140 bytes for grant and revoke", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    const max = Number(await registry.MAX_REASON_LENGTH());
    expect(max).to.equal(140);

    await registry.connect(operator).grant(alice.address, 1n, DAY, "a".repeat(max));
    await expect(registry.connect(operator).grant(alice.address, 1n, DAY, "a".repeat(max + 1)))
      .to.be.revertedWithCustomError(registry, "ReasonTooLong")
      .withArgs(max + 1, max);
    await expect(registry.connect(operator).revoke(alice.address, 1n, "a".repeat(max + 1)))
      .to.be.revertedWithCustomError(registry, "ReasonTooLong")
      .withArgs(max + 1, max);
    await registry.connect(operator).revoke(alice.address, 1n, "a".repeat(max));
  });

  it("the reason limit counts bytes, not characters", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    // 71 two-byte characters = 142 bytes.
    const reason = "é".repeat(71);
    expect(ethers.toUtf8Bytes(reason).length).to.equal(142);
    await expect(registry.connect(operator).grant(alice.address, 1n, DAY, reason))
      .to.be.revertedWithCustomError(registry, "ReasonTooLong")
      .withArgs(142n, 140n);
  });

  it("revoke ends access immediately, clears the expiry and emits AccessRevoked", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    const t = (await latest()) + 20n;
    await sendAt(t, () => registry.connect(alice).purchase(1n, PRICE, { value: PRICE }));

    await expect(registry.connect(operator).revoke(alice.address, 1n, "chargeback"))
      .to.emit(registry, "AccessRevoked")
      .withArgs(1n, alice.address, operator.address, t + DURATION, "chargeback");

    expect(await registry.hasAccess(alice.address, 1n)).to.equal(false);
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(0n);
  });

  it("revoke does not refund and does not change revenue", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await expect(registry.connect(operator).revoke(alice.address, 1n, "abuse")).to.changeEtherBalances(
      ethers,
      [alice, registry],
      [0n, 0n],
    );
    expect(await registry.accruedRevenue()).to.equal(PRICE);
  });

  it("revoke also ends access that came from a grant, and a later purchase starts from now", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await registry.connect(operator).grant(alice.address, 1n, 100n * DAY, "promo");
    await registry.connect(operator).revoke(alice.address, 1n, "promo ended");
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(false);

    const t = (await latest()) + 5n;
    await sendAt(t, () => registry.connect(alice).purchase(1n, PRICE, { value: PRICE }));
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(t + DURATION);
  });

  it("revoke reverts when there is nothing to revoke or the plan is unknown", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await expect(registry.connect(operator).revoke(alice.address, 1n, "x"))
      .to.be.revertedWithCustomError(registry, "NothingToRevoke")
      .withArgs(alice.address, 1n);
    await expect(registry.connect(operator).revoke(alice.address, 99n, "x"))
      .to.be.revertedWithCustomError(registry, "PlanNotFound")
      .withArgs(99n);
  });

  it("revoke of an already lapsed holder still clears the record", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, PRICE, { value: PRICE });
    await networkHelpers.time.increase(DURATION + 1n);
    expect(await registry.hasAccess(alice.address, 1n)).to.equal(false);
    await registry.connect(operator).revoke(alice.address, 1n, "cleanup");
    expect(await registry.expiryOf(alice.address, 1n)).to.equal(0n);
  });

  it("grant and revoke need OPERATOR_ROLE, even for the default admin", async () => {
    const { registry, admin, alice, bob } = await loadFixture(deployWithPlan);
    for (const caller of [alice, admin]) {
      await expect(registry.connect(caller).grant(bob.address, 1n, DAY, "x"))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, OPERATOR_ROLE);
      await expect(registry.connect(caller).revoke(bob.address, 1n, "x"))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, OPERATOR_ROLE);
    }
  });

  it("the admin manages operators: the role admin of OPERATOR_ROLE is DEFAULT_ADMIN_ROLE", async () => {
    const { registry, admin, operator, alice, bob } = await loadFixture(deployWithPlan);
    expect(await registry.getRoleAdmin(OPERATOR_ROLE)).to.equal(DEFAULT_ADMIN_ROLE);
    expect(await registry.hasRole(OPERATOR_ROLE, operator.address)).to.equal(true);

    await expect(registry.connect(admin).grantRole(OPERATOR_ROLE, alice.address))
      .to.emit(registry, "RoleGranted")
      .withArgs(OPERATOR_ROLE, alice.address, admin.address);
    await registry.connect(alice).grant(bob.address, 1n, DAY, "new operator");

    await expect(registry.connect(admin).revokeRole(OPERATOR_ROLE, alice.address))
      .to.emit(registry, "RoleRevoked")
      .withArgs(OPERATOR_ROLE, alice.address, admin.address);
    await expect(registry.connect(alice).grant(bob.address, 1n, DAY, "x"))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(alice.address, OPERATOR_ROLE);
  });

  it("an operator cannot grant or revoke roles, and an operator can renounce its own role", async () => {
    const { registry, operator, alice } = await loadFixture(deployWithPlan);
    await expect(registry.connect(operator).grantRole(OPERATOR_ROLE, alice.address))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(operator.address, DEFAULT_ADMIN_ROLE);
    await expect(registry.connect(operator).revokeRole(OPERATOR_ROLE, operator.address))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(operator.address, DEFAULT_ADMIN_ROLE);

    await registry.connect(operator).renounceRole(OPERATOR_ROLE, operator.address);
    expect(await registry.hasRole(OPERATOR_ROLE, operator.address)).to.equal(false);
  });

  it("the default admin role cannot be handed out with grantRole", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);
    await expect(registry.connect(admin).grantRole(DEFAULT_ADMIN_ROLE, alice.address)).to.be.revertedWithCustomError(
      registry,
      "AccessControlEnforcedDefaultAdminRules",
    );
  });

  it("the default admin moves in two steps and only after the delay", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);
    expect(await registry.defaultAdmin()).to.equal(admin.address);
    expect(await registry.defaultAdminDelay()).to.equal(BigInt(ADMIN_DELAY));

    await registry.connect(admin).beginDefaultAdminTransfer(alice.address);
    await expect(registry.connect(alice).acceptDefaultAdminTransfer()).to.be.revertedWithCustomError(
      registry,
      "AccessControlEnforcedDefaultAdminDelay",
    );

    await networkHelpers.time.increase(ADMIN_DELAY + 1);
    await registry.connect(alice).acceptDefaultAdminTransfer();

    expect(await registry.defaultAdmin()).to.equal(alice.address);
    expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.equal(false);
    await registry.connect(alice).createPlan(5n, PRICE, DURATION, 0);
    await expect(registry.connect(admin).createPlan(6n, PRICE, DURATION, 0))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(admin.address, DEFAULT_ADMIN_ROLE);
  });
});
