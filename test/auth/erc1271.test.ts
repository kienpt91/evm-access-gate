import { expect } from "chai";
import { setImmediate as nextEventLoopTurn } from "node:timers/promises";
import { AbiCoder, Interface, Network, Wallet, type TransactionRequest } from "ethers";
import { createChainGuard, createErc1271Verifier, type Erc1271VerifierOptions } from "../../src/auth/index.js";
import { expectAuthError } from "./helpers.js";

const MAGIC_WORD = new AbiCoder().encode(["bytes4"], ["0x1626ba7e"]);
const WRONG_WORD = new AbiCoder().encode(["bytes4"], ["0xffffffff"]);
const SELECTOR = new Interface(["function isValidSignature(bytes32,bytes)"]).getFunction("isValidSignature")?.selector;

/** A provider whose `call` and `getNetwork` are scripted by the test. */
class FakeProvider {
  calls: TransactionRequest[] = [];
  networkCalls = 0;
  chainId = 31337n;
  networkFailure: Error | undefined;
  onCall: (tx: TransactionRequest) => Promise<string> = async () => MAGIC_WORD;

  async call(tx: TransactionRequest): Promise<string> {
    this.calls.push(tx);
    return this.onCall(tx);
  }

  async getNetwork(): Promise<Network> {
    this.networkCalls += 1;
    if (this.networkFailure) throw this.networkFailure;
    return new Network("fake", this.chainId);
  }
}

function setup(options: Partial<Erc1271VerifierOptions> = {}) {
  const provider = new FakeProvider();
  const verifier = createErc1271Verifier(provider, { chainId: 31337, ...options });
  return { provider, verifier, wallet: Wallet.createRandom().address };
}

describe("ERC-1271 verifier bounds", () => {
  it("accepts exactly the magic value and sends isValidSignature with the EIP-191 hash", async () => {
    const { provider, verifier, wallet } = setup();
    expect(await verifier.isValidSignature(wallet, "hello", "0x1234")).to.equal(true);
    expect(provider.calls).to.have.length(1);
    expect(provider.calls[0]?.to).to.equal(wallet);
    expect(provider.calls[0]?.data?.startsWith(SELECTOR ?? "?")).to.equal(true);
  });

  it("puts a gas limit on the call (300000 by default, configurable)", async () => {
    const first = setup();
    await first.verifier.isValidSignature(first.wallet, "hello", "0x1234");
    expect(first.provider.calls[0]?.gasLimit).to.equal(300_000n);

    const second = setup({ gasLimit: 50_000n });
    await second.verifier.isValidSignature(second.wallet, "hello", "0x1234");
    expect(second.provider.calls[0]?.gasLimit).to.equal(50_000n);
  });

  it("rejects any other return value, including a wrong magic value and oversized or empty results", async () => {
    const { provider, verifier, wallet } = setup();
    for (const result of [WRONG_WORD, "0x", `0x${"00".repeat(31)}`, `${MAGIC_WORD}${"00".repeat(32)}`, `0x${"00".repeat(4096)}`]) {
      provider.onCall = async () => result;
      expect(await verifier.isValidSignature(wallet, "hello", "0x1234"), result.slice(0, 20)).to.equal(false);
    }
  });

  it("treats a failing call as an invalid signature", async () => {
    const { provider, verifier, wallet } = setup();
    provider.onCall = async () => {
      throw new Error("execution reverted");
    };
    expect(await verifier.isValidSignature(wallet, "hello", "0x1234")).to.equal(false);
  });

  // This test needs the real timer: the code under test races its own setTimeout against the call.
  it("gives up after the timeout with VERIFIER_UNAVAILABLE", async () => {
    const { provider, verifier, wallet } = setup({ timeoutMs: 20 });
    provider.onCall = () => Promise.withResolvers<string>().promise; // never answers
    const started = Date.now();
    await expectAuthError(() => verifier.isValidSignature(wallet, "hello", "0x1234"), "VERIFIER_UNAVAILABLE");
    expect(Date.now() - started).to.be.lessThan(1000);
  });

  it("limits outstanding calls, and a timed-out call keeps its slot until it really finishes", async () => {
    const { provider, verifier, wallet } = setup({ timeoutMs: 20, maxConcurrent: 2 });
    const gates = [Promise.withResolvers<string>(), Promise.withResolvers<string>()];
    let started = 0;
    provider.onCall = () => gates[started++]?.promise ?? Promise.resolve(MAGIC_WORD);

    // Two calls hang and time out. Neither slot is free yet because the node has not answered.
    await expectAuthError(() => verifier.isValidSignature(wallet, "a", "0x1234"), "VERIFIER_UNAVAILABLE");
    await expectAuthError(() => verifier.isValidSignature(wallet, "b", "0x1234"), "VERIFIER_UNAVAILABLE");
    expect(provider.calls).to.have.length(2);

    // A third caller is turned away without any call being made.
    await expectAuthError(() => verifier.isValidSignature(wallet, "c", "0x1234"), "VERIFIER_UNAVAILABLE");
    expect(provider.calls).to.have.length(2);

    // When the node finally answers, the slots come back.
    gates[0]?.resolve(WRONG_WORD);
    gates[1]?.resolve(WRONG_WORD);
    await nextEventLoopTurn();
    expect(await verifier.isValidSignature(wallet, "d", "0x1234")).to.equal(true);
  });

  it("frees the slot after a normal answer, so sequential calls never hit the limit", async () => {
    const { verifier, wallet } = setup({ maxConcurrent: 1 });
    for (let i = 0; i < 5; i++) expect(await verifier.isValidSignature(wallet, `m${i}`, "0x1234")).to.equal(true);
  });

  it("checks the provider's chain once and remembers a success", async () => {
    const { provider, verifier, wallet } = setup();
    await verifier.isValidSignature(wallet, "a", "0x1234");
    await verifier.isValidSignature(wallet, "b", "0x1234");
    expect(provider.networkCalls).to.equal(1);
  });

  it("refuses a provider on another chain, without making the wallet call", async () => {
    const { provider, verifier, wallet } = setup();
    provider.chainId = 1n;
    await expectAuthError(() => verifier.isValidSignature(wallet, "a", "0x1234"), "CHAIN_ID_MISMATCH");
    expect(provider.calls).to.have.length(0);
  });

  it("reports an unreachable node as VERIFIER_UNAVAILABLE and asks again next time", async () => {
    const { provider, verifier, wallet } = setup();
    provider.networkFailure = new Error("connection refused");
    await expectAuthError(() => verifier.isValidSignature(wallet, "a", "0x1234"), "VERIFIER_UNAVAILABLE");
    provider.networkFailure = undefined;
    expect(await verifier.isValidSignature(wallet, "a", "0x1234")).to.equal(true);
  });

  it("rejects invalid options", () => {
    const provider = new FakeProvider();
    for (const bad of [{ chainId: 0 }, { timeoutMs: 0 }, { timeoutMs: 1.5 }, { gasLimit: 0n }, { maxConcurrent: 0 }]) {
      expect(() => createErc1271Verifier(provider, { chainId: 31337, ...bad }), JSON.stringify(bad, (_k, v) => (typeof v === "bigint" ? String(v) : v))).to.throw(
        /INVALID_CONFIG/,
      );
    }
  });
});

describe("chain guard", () => {
  it("passes on the expected chain and fails otherwise", async () => {
    const provider = new FakeProvider();
    await createChainGuard(provider, 31337)();
    await expectAuthError(() => createChainGuard(provider, 1)(), "CHAIN_ID_MISMATCH");
  });

  it("does not remember a failure", async () => {
    const provider = new FakeProvider();
    const guard = createChainGuard(provider, 31337);
    provider.chainId = 5n;
    await expectAuthError(() => guard(), "CHAIN_ID_MISMATCH");
    provider.chainId = 31337n;
    await guard();
  });
});
