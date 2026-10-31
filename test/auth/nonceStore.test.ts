import { expect } from "chai";
import { Wallet } from "ethers";
import { InMemoryNonceStore, type NonceRecord } from "../../src/auth/index.js";
import { expectAuthError } from "./helpers.js";

const ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const OTHER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

function record(expiresAtMs: number, extra: Partial<NonceRecord> = {}): NonceRecord {
  return {
    address: ADDRESS,
    issuedAt: "2026-10-31T10:00:00.000Z",
    expirationTime: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
    ...extra,
  };
}

describe("InMemoryNonceStore", () => {
  it("hands a nonce out exactly once", async () => {
    const store = new InMemoryNonceStore();
    await store.issue("nonce0001", record(1000));

    expect(await store.consume("nonce0001")).to.deep.equal(record(1000));
    expect(await store.consume("nonce0001")).to.equal(undefined);
    expect(store.size).to.equal(0);
  });

  it("returns undefined for an unknown nonce", async () => {
    const store = new InMemoryNonceStore();
    expect(await store.consume("never-issued")).to.equal(undefined);
  });

  it("only one of two concurrent consumers wins", async () => {
    const store = new InMemoryNonceStore();
    await store.issue("nonce0001", record(1000));
    const results = await Promise.all([store.consume("nonce0001"), store.consume("nonce0001")]);
    expect(results.filter((r) => r !== undefined)).to.have.length(1);
  });

  it("refuses to overwrite a live nonce", async () => {
    const store = new InMemoryNonceStore();
    await store.issue("nonce0001", record(1000));
    await expectAuthError(() => store.issue("nonce0001", record(2000)), "STORE_FULL");
    expect(await store.consume("nonce0001")).to.deep.equal(record(1000));
  });

  it("is bounded: when full it prunes expired entries, then refuses new ones", async () => {
    let now = 0;
    const store = new InMemoryNonceStore({ maxEntries: 2, now: () => now });
    await store.issue("nonce0001", record(100));
    await store.issue("nonce0002", record(200));
    await expectAuthError(() => store.issue("nonce0003", record(300)), "STORE_FULL");

    now = 150; // nonce0001 expired
    await store.issue("nonce0003", record(300));
    expect(store.size).to.equal(2);
    expect(await store.consume("nonce0001")).to.equal(undefined);
    expect(await store.consume("nonce0002")).to.not.equal(undefined);
  });

  it("rejects a non-positive size limit", () => {
    expect(() => new InMemoryNonceStore({ maxEntries: 0 })).to.throw(/maxEntries/);
    expect(() => new InMemoryNonceStore({ maxPerAddress: 0 })).to.throw(/maxPerAddress/);
    expect(() => new InMemoryNonceStore({ maxPerClient: 1.5 })).to.throw(/maxPerClient/);
  });

  it("limits live challenges per address, and consuming one frees a place", async () => {
    const store = new InMemoryNonceStore({ maxPerAddress: 2, now: () => 0 });
    await store.issue("nonce0001", record(1000));
    await store.issue("nonce0002", record(1000));
    await expectAuthError(() => store.issue("nonce0003", record(1000)), "TOO_MANY_CHALLENGES");
    expect(store.size).to.equal(2);

    // Another address is not affected.
    await store.issue("nonce0004", record(1000, { address: OTHER_ADDRESS }));

    await store.consume("nonce0001");
    await store.issue("nonce0003", record(1000));
    expect(store.size).to.equal(3);
  });

  it("the address quota ignores letter case", async () => {
    const store = new InMemoryNonceStore({ maxPerAddress: 1, now: () => 0 });
    await store.issue("nonce0001", record(1000));
    await expectAuthError(
      () => store.issue("nonce0002", record(1000, { address: ADDRESS.toLowerCase() })),
      "TOO_MANY_CHALLENGES",
    );
  });

  it("expired challenges do not count against an address", async () => {
    let now = 0;
    const store = new InMemoryNonceStore({ maxPerAddress: 1, now: () => now });
    await store.issue("nonce0001", record(100));
    await expectAuthError(() => store.issue("nonce0002", record(300)), "TOO_MANY_CHALLENGES");

    now = 100; // nonce0001 expires exactly now
    await store.issue("nonce0002", record(300));
    expect(store.size).to.equal(1);
    expect(await store.consume("nonce0001")).to.equal(undefined);
  });

  it("limits live challenges per client key, across many addresses", async () => {
    const store = new InMemoryNonceStore({ maxPerClient: 3, now: () => 0 });
    const addresses = [ADDRESS, OTHER_ADDRESS, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "0x90F79bf6EB2c4f870365E785982E1f101E93b906"];
    for (const [i, address] of addresses.slice(0, 3).entries()) {
      await store.issue(`nonce000${i}`, record(1000, { address, clientKey: "203.0.113.7" }));
    }
    await expectAuthError(
      () => store.issue("nonce0009", record(1000, { address: addresses[3] ?? ADDRESS, clientKey: "203.0.113.7" })),
      "TOO_MANY_CHALLENGES",
    );
    // Other clients, and records without a client key, are not limited by it.
    await store.issue("nonce0010", record(1000, { address: addresses[3] ?? ADDRESS, clientKey: "203.0.113.8" }));
    await store.issue("nonce0011", record(1000, { address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65" }));
  });

  it("a rejected issue leaves no trace: no half-updated quota", async () => {
    const store = new InMemoryNonceStore({ maxPerClient: 1, now: () => 0 });
    await store.issue("nonce0001", record(1000, { clientKey: "client-a" }));
    // Fails on the client quota; the address quota must not have been charged.
    await expectAuthError(
      () => store.issue("nonce0002", record(1000, { address: OTHER_ADDRESS, clientKey: "client-a" })),
      "TOO_MANY_CHALLENGES",
    );
    await store.issue("nonce0003", record(1000, { address: OTHER_ADDRESS, clientKey: "client-b" }));
    expect(store.size).to.equal(2);
  });

  it("consuming cleans every index, so quotas are fully released", async () => {
    const store = new InMemoryNonceStore({ maxPerAddress: 1, maxPerClient: 1, now: () => 0 });
    for (let i = 0; i < 20; i++) {
      await store.issue(`nonce${String(i).padStart(4, "0")}`, record(1000, { clientKey: "client-a" }));
      await store.consume(`nonce${String(i).padStart(4, "0")}`);
    }
    expect(store.size).to.equal(0);
  });

  it("the total cap still applies when every address and client is different", async () => {
    const store = new InMemoryNonceStore({ maxEntries: 3, now: () => 0 });
    for (let i = 0; i < 3; i++) {
      await store.issue(`nonce000${i}`, record(1000, { address: Wallet.createRandom().address, clientKey: `client-${i}` }));
    }
    await expectAuthError(
      () => store.issue("nonce0009", record(1000, { address: Wallet.createRandom().address, clientKey: "client-9" })),
      "STORE_FULL",
    );
  });
});
