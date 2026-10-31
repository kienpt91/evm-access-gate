import { expect } from "chai";
import { InMemoryNonceStore, type NonceRecord } from "../../src/auth/index.js";
import { expectAuthError } from "./helpers.js";

const ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

function record(expiresAtMs: number): NonceRecord {
  return {
    address: ADDRESS,
    issuedAt: "2026-10-31T10:00:00.000Z",
    expirationTime: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
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
  });
});
