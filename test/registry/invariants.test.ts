import { expect } from "chai";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  DAY,
  deployRegistry,
  ethers,
  latest,
  networkHelpers,
  sendAt,
} from "../helpers/chain.js";
import { Prng } from "../helpers/prng.js";

const { loadFixture } = networkHelpers;

const SEEDS = [11, 2024, 90210];
const OPERATIONS_PER_SEED = 250;
const PLAN_IDS = [1n, 2n, 3n];
const BASE_PRICE = ethers.parseEther("0.01");

interface ModelPlan {
  price: bigint;
  duration: bigint;
  maxHolders: number;
  holders: number;
  active: boolean;
}

/** Plain TypeScript model of what the contract is supposed to do. */
class Model {
  plans = new Map<bigint, ModelPlan>();
  expiry = new Map<string, bigint>();
  slots = new Set<string>();
  accrued = 0n;
  received = 0n;
  refunded = 0n;
  withdrawn = 0n;
  paused = false;

  static key(planId: bigint, user: string): string {
    return `${planId}:${user}`;
  }

  plan(planId: bigint): ModelPlan {
    const plan = this.plans.get(planId);
    if (!plan) throw new Error(`model has no plan ${planId}`);
    return plan;
  }

  /** Mirrors AccessRegistry._extend; returns the revert name when the plan is full. */
  extend(planId: bigint, user: string, duration: bigint, now: bigint): "PlanFull" | undefined {
    const plan = this.plan(planId);
    const key = Model.key(planId, user);
    const current = this.expiry.get(key) ?? 0n;
    const needsSlot = plan.maxHolders !== 0 && !this.slots.has(key);
    if (needsSlot && plan.holders >= plan.maxHolders) return "PlanFull";
    if (needsSlot) {
      this.slots.add(key);
      plan.holders += 1;
    }
    this.expiry.set(key, (current > now ? current : now) + duration);
    return undefined;
  }
}

describe("AccessRegistry randomized invariants", () => {
  const seen = new Map<string, number>();
  const count = (name: string) => seen.set(name, (seen.get(name) ?? 0) + 1);

  for (const seed of SEEDS) {
    it(`matches the reference model for ${OPERATIONS_PER_SEED} random operations (seed ${seed})`, async () => {
      const { registry, admin, operator, alice, bob, carol, outsider, treasury } = await loadFixture(deployRegistry);
      const users: HardhatEthersSigner[] = [alice, bob, carol, outsider];
      const registryAddress = await registry.getAddress();
      const prng = new Prng(seed);
      const model = new Model();

      const specs: Array<[bigint, bigint, number]> = [
        [1n, 30n * DAY, 0],
        [2n, 7n * DAY, 3],
        [3n, 90n * DAY, 1],
      ];
      for (const [planId, duration, maxHolders] of specs) {
        await registry.connect(admin).createPlan(planId, BASE_PRICE * planId, duration, maxHolders);
        model.plans.set(planId, {
          price: BASE_PRICE * planId,
          duration,
          maxHolders,
          holders: 0,
          active: true,
        });
      }

      const nextTimestamp = async () => (await latest()) + 1n + BigInt(prng.pick([0, 0, 1, 5, 3600, 2 * 86400, 20 * 86400]));

      const purchase = async () => {
        const user = prng.pick(users);
        const planId = prng.pick(PLAN_IDS);
        const plan = model.plan(planId);
        const extra = prng.pick([0n, 0n, 1n, 12_345n, BASE_PRICE]);
        // One purchase in ten quotes a price one wei too low, as if the price rose after signing.
        const quoted = prng.next() < 0.1 ? plan.price - 1n : plan.price;
        const send = () => registry.connect(user).purchase(planId, quoted, { value: plan.price + extra });

        if (model.paused) {
          count("purchase reverts: paused");
          await expect(send()).to.be.revertedWithCustomError(registry, "EnforcedPause");
          return;
        }
        if (!plan.active) {
          count("purchase reverts: inactive");
          await expect(send()).to.be.revertedWithCustomError(registry, "PlanInactive");
          return;
        }
        if (quoted < plan.price) {
          count("purchase reverts: above max");
          await expect(send())
            .to.be.revertedWithCustomError(registry, "PriceAboveMax")
            .withArgs(plan.price, quoted);
          return;
        }
        const key = Model.key(planId, user.address);
        const needsSlot = plan.maxHolders !== 0 && !model.slots.has(key);
        if (needsSlot && plan.holders >= plan.maxHolders) {
          count("purchase reverts: full");
          await expect(send()).to.be.revertedWithCustomError(registry, "PlanFull");
          return;
        }
        const ts = await nextTimestamp();
        const { blockTimestamp } = await sendAt(ts, send);
        expect(blockTimestamp).to.equal(ts);
        model.extend(planId, user.address, plan.duration, ts);
        model.accrued += plan.price;
        model.received += plan.price;
        model.refunded += extra;
        count(extra > 0n ? "purchase ok, refunded" : "purchase ok");
      };

      const grant = async () => {
        const user = prng.pick(users);
        const planId = prng.pick(PLAN_IDS);
        const duration = BigInt(prng.int(1, 40)) * DAY;
        const send = () => registry.connect(operator).grant(user.address, planId, duration, "random");
        const key = Model.key(planId, user.address);
        const plan = model.plan(planId);
        if (plan.maxHolders !== 0 && !model.slots.has(key) && plan.holders >= plan.maxHolders) {
          count("grant reverts: full");
          await expect(send()).to.be.revertedWithCustomError(registry, "PlanFull");
          return;
        }
        const ts = await nextTimestamp();
        await sendAt(ts, send);
        model.extend(planId, user.address, duration, ts);
        count("grant ok");
      };

      const revoke = async () => {
        const user = prng.pick(users);
        const planId = prng.pick(PLAN_IDS);
        const key = Model.key(planId, user.address);
        const send = () => registry.connect(operator).revoke(user.address, planId, "random");
        if ((model.expiry.get(key) ?? 0n) === 0n) {
          count("revoke reverts: nothing");
          await expect(send()).to.be.revertedWithCustomError(registry, "NothingToRevoke");
          return;
        }
        await send();
        model.expiry.delete(key);
        if (model.slots.delete(key)) model.plan(planId).holders -= 1;
        count("revoke ok");
      };

      const release = async () => {
        const planId = prng.pick(PLAN_IDS);
        const batch = Array.from({ length: prng.int(1, 6) }, () => prng.pick(users));
        const ts = await nextTimestamp();
        await sendAt(ts, () => registry.connect(outsider).releaseExpired(planId, batch.map((u) => u.address)));
        for (const user of batch) {
          const key = Model.key(planId, user.address);
          if (model.slots.has(key) && (model.expiry.get(key) ?? 0n) <= ts) {
            model.slots.delete(key);
            model.plan(planId).holders -= 1;
            count("release freed a slot");
          }
        }
      };

      const withdraw = async () => {
        if (model.accrued === 0n || prng.next() < 0.1) {
          count("withdraw reverts: too much");
          await expect(registry.connect(admin).withdrawTo(treasury.address, model.accrued + 1n))
            .to.be.revertedWithCustomError(registry, "InsufficientRevenue")
            .withArgs(model.accrued + 1n, model.accrued);
          return;
        }
        const amount = BigInt(prng.int(1, 100)) * (model.accrued / 100n) || model.accrued;
        await registry.connect(admin).withdrawTo(treasury.address, amount);
        model.accrued -= amount;
        model.withdrawn += amount;
        count("withdraw ok");
      };

      const setPrice = async () => {
        const planId = prng.pick(PLAN_IDS);
        const price = BASE_PRICE * BigInt(prng.int(1, 5));
        await registry.connect(admin).setPlanPrice(planId, price);
        model.plan(planId).price = price;
        count("price change");
      };

      const setActive = async () => {
        const planId = prng.pick(PLAN_IDS);
        const active = prng.next() < 0.7;
        await registry.connect(admin).setPlanActive(planId, active);
        model.plan(planId).active = active;
        count("active change");
      };

      const setPaused = async () => {
        if (model.paused) {
          await registry.connect(admin).unpause();
        } else {
          await registry.connect(admin).pause();
        }
        model.paused = !model.paused;
        count("pause toggle");
      };

      const warp = async () => {
        await networkHelpers.time.increase(BigInt(prng.int(1, 45)) * DAY);
        count("time warp");
      };

      const actions: Array<[number, () => Promise<void>]> = [
        [40, purchase],
        [12, grant],
        [10, revoke],
        [10, release],
        [8, withdraw],
        [4, setPrice],
        [4, setActive],
        [3, setPaused],
        [9, warp],
      ];
      const totalWeight = actions.reduce((sum, [weight]) => sum + weight, 0);
      const chooseAction = () => {
        let roll = prng.int(1, totalWeight);
        for (const [weight, action] of actions) {
          if (roll <= weight) return action;
          roll -= weight;
        }
        throw new Error("unreachable");
      };

      const assertMatchesModel = async () => {
        const now = await latest();
        const balance = await ethers.provider.getBalance(registryAddress);
        expect(balance, "balance == paid - refunded - withdrawn").to.equal(
          model.received - model.withdrawn,
        );
        expect(await registry.accruedRevenue()).to.equal(model.accrued);
        expect(model.accrued).to.equal(model.received - model.withdrawn);
        expect(await registry.totalReceived()).to.equal(model.received);
        expect(await registry.totalRefunded()).to.equal(model.refunded);
        expect(await registry.totalWithdrawn()).to.equal(model.withdrawn);

        for (const planId of PLAN_IDS) {
          const plan = model.plan(planId);
          const onChain = await registry.getPlan(planId);
          expect(onChain.price).to.equal(plan.price);
          expect(onChain.active).to.equal(plan.active);
          expect(onChain.activeHolders).to.equal(BigInt(plan.holders));
          if (plan.maxHolders !== 0) expect(plan.holders).to.be.at.most(plan.maxHolders);

          for (const user of users) {
            const key = Model.key(planId, user.address);
            const expected = model.expiry.get(key) ?? 0n;
            expect(await registry.expiryOf(user.address, planId)).to.equal(expected);
            expect(await registry.holdsSlot(user.address, planId)).to.equal(model.slots.has(key));
            // `eth_call` may run in the latest or the next block; skip the one-second ambiguity.
            if (expected > now + 5n || expected + 5n < now) {
              expect(await registry.hasAccess(user.address, planId)).to.equal(expected > now);
            }
          }
        }
      };

      for (let i = 0; i < OPERATIONS_PER_SEED; i++) {
        await chooseAction()();
        await assertMatchesModel();
      }
    });
  }

  it("exercised every kind of operation across the seeds", () => {
    const required = [
      "purchase ok",
      "purchase ok, refunded",
      "purchase reverts: full",
      "purchase reverts: paused",
      "purchase reverts: inactive",
      "purchase reverts: above max",
      "grant ok",
      "revoke ok",
      "release freed a slot",
      "withdraw ok",
      "withdraw reverts: too much",
      "price change",
      "time warp",
    ];
    for (const name of required) expect(seen.get(name) ?? 0, name).to.be.greaterThan(0);
    // Printed so the run documents how much was actually covered.
    console.log(`      operations: ${[...seen].map(([name, n]) => `${name}=${n}`).join(", ")}`);
  });
});
