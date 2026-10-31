import { expect } from "chai";
import {
  DEFAULT_ADMIN_ROLE,
  deployWithPlan,
  ethers,
  networkHelpers,
  PRICE,
} from "../helpers/chain.js";

const { loadFixture } = networkHelpers;

describe("AccessRegistry revenue and withdrawals", () => {
  it("withdrawTo sends the amount, updates accounting and emits Withdrawn", async () => {
    const { registry, admin, alice, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });

    await expect(registry.connect(admin).withdrawTo(treasury.address, PRICE / 4n))
      .to.emit(registry, "Withdrawn")
      .withArgs(treasury.address, PRICE / 4n, admin.address);

    expect(await registry.accruedRevenue()).to.equal(PRICE - PRICE / 4n);
    expect(await registry.totalWithdrawn()).to.equal(PRICE / 4n);
    expect(await ethers.provider.getBalance(await registry.getAddress())).to.equal(PRICE - PRICE / 4n);
  });

  it("moves ETH from the contract to the chosen address, not to the admin", async () => {
    const { registry, admin, alice, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    await expect(registry.connect(admin).withdrawTo(treasury.address, PRICE)).to.changeEtherBalances(
      ethers,
      [registry, treasury, admin],
      [-PRICE, PRICE, 0n],
    );
  });

  it("can withdraw everything, then rejects any further amount", async () => {
    const { registry, admin, alice, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    await registry.connect(admin).withdrawTo(treasury.address, PRICE);

    expect(await registry.accruedRevenue()).to.equal(0n);
    await expect(registry.connect(admin).withdrawTo(treasury.address, 1n))
      .to.be.revertedWithCustomError(registry, "InsufficientRevenue")
      .withArgs(1n, 0n);
  });

  it("rejects an amount above the accrued revenue, a zero amount and the zero address", async () => {
    const { registry, admin, alice, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });

    await expect(registry.connect(admin).withdrawTo(treasury.address, PRICE + 1n))
      .to.be.revertedWithCustomError(registry, "InsufficientRevenue")
      .withArgs(PRICE + 1n, PRICE);
    await expect(registry.connect(admin).withdrawTo(treasury.address, 0n)).to.be.revertedWithCustomError(
      registry,
      "ZeroAmount",
    );
    await expect(registry.connect(admin).withdrawTo(ethers.ZeroAddress, PRICE)).to.be.revertedWithCustomError(
      registry,
      "InvalidAddress",
    );
    expect(await registry.accruedRevenue()).to.equal(PRICE);
  });

  it("only the default admin can withdraw", async () => {
    const { registry, operator, alice, treasury } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    for (const caller of [operator, alice, treasury]) {
      await expect(registry.connect(caller).withdrawTo(caller.address, PRICE))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(caller.address, DEFAULT_ADMIN_ROLE);
    }
  });

  it("keeps balance == paid - refunded - withdrawn through mixed activity", async () => {
    const { registry, admin, alice, bob, carol, treasury } = await loadFixture(deployWithPlan);
    const registryAddress = await registry.getAddress();
    let paid = 0n;
    let refunded = 0n;
    let withdrawn = 0n;

    const buy = async (buyer: typeof alice, extra: bigint) => {
      await registry.connect(buyer).purchase(1n, { value: PRICE + extra });
      paid += PRICE + extra;
      refunded += extra;
    };
    const check = async () => {
      const expected = paid - refunded - withdrawn;
      expect(await ethers.provider.getBalance(registryAddress)).to.equal(expected);
      expect(await registry.accruedRevenue()).to.equal(expected);
      expect(await registry.totalReceived()).to.equal(paid - refunded);
      expect(await registry.totalRefunded()).to.equal(refunded);
      expect(await registry.totalWithdrawn()).to.equal(withdrawn);
    };

    await buy(alice, 0n);
    await check();
    await buy(bob, 12_345n);
    await check();
    await registry.connect(admin).withdrawTo(treasury.address, PRICE / 2n);
    withdrawn += PRICE / 2n;
    await check();
    await buy(carol, ethers.parseEther("3"));
    await buy(alice, 1n);
    await check();
    await registry.connect(admin).withdrawTo(treasury.address, PRICE);
    withdrawn += PRICE;
    await check();
  });

  it("ETH forced into the contract is not accounted and cannot be withdrawn", async () => {
    const { registry, admin, alice, treasury } = await loadFixture(deployWithPlan);
    const registryAddress = await registry.getAddress();
    await registry.connect(alice).purchase(1n, { value: PRICE });

    // Same effect as a self-destructing contract sending ETH here.
    const forced = ethers.parseEther("5");
    await networkHelpers.setBalance(registryAddress, PRICE + forced);

    expect(await registry.accruedRevenue()).to.equal(PRICE);
    await expect(registry.connect(admin).withdrawTo(treasury.address, PRICE + 1n))
      .to.be.revertedWithCustomError(registry, "InsufficientRevenue")
      .withArgs(PRICE + 1n, PRICE);
    await registry.connect(admin).withdrawTo(treasury.address, PRICE);
    expect(await ethers.provider.getBalance(registryAddress)).to.equal(forced);
  });

  it("a withdrawal to a receiver that rejects ETH reverts and leaves accounting unchanged", async () => {
    const { registry, admin, alice } = await loadFixture(deployWithPlan);
    await registry.connect(alice).purchase(1n, { value: PRICE });
    const rejecting = await ethers.deployContract("ReentrantBuyer", [await registry.getAddress(), 1n]);
    await rejecting.setMode(1); // Reject

    await expect(registry.connect(admin).withdrawTo(await rejecting.getAddress(), PRICE))
      .to.be.revertedWithCustomError(registry, "WithdrawFailed")
      .withArgs(await rejecting.getAddress(), PRICE);

    expect(await registry.accruedRevenue()).to.equal(PRICE);
    expect(await registry.totalWithdrawn()).to.equal(0n);
  });
});
