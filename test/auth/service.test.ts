import { randomBytes } from "node:crypto";
import { expect } from "chai";
import { Wallet } from "ethers";
import {
  createAuthService,
  formatMessage,
  InMemoryNonceStore,
  parseMessage,
  type AccessReader,
  type AuthConfig,
  type AuthDeps,
  type AuthService,
  type SiweMessage,
} from "../../src/auth/index.js";
import { expectAuthError, TestClock } from "./helpers.js";

const START = "2026-10-31T10:00:00.000Z";
const CONFIG: AuthConfig = {
  domain: "app.example.com",
  uri: "https://app.example.com",
  chainId: 31337,
  statement: "Sign in to Example. This does not cost gas.",
};

class FakeReader implements AccessReader {
  calls: Array<{ user: string; planId: bigint }> = [];
  allowed = true;
  failure: Error | undefined;

  async hasAccess(user: string, planId: bigint): Promise<boolean> {
    this.calls.push({ user, planId });
    if (this.failure) throw this.failure;
    return this.allowed;
  }
}

interface Harness {
  clock: TestClock;
  store: InMemoryNonceStore;
  reader: FakeReader;
  secret: Uint8Array;
  service: AuthService;
}

function setup(overrides: Partial<AuthDeps> = {}, config: AuthConfig = CONFIG): Harness {
  const clock = new TestClock(START);
  const store = new InMemoryNonceStore({ now: () => clock.now().getTime() });
  const reader = new FakeReader();
  const secret = randomBytes(32);
  const service = createAuthService(config, {
    nonceStore: store,
    sessionSecret: secret,
    accessReader: reader,
    now: clock.now,
    ...overrides,
  });
  return { clock, store, reader, secret, service };
}

/** Parses a challenge, changes fields, and formats it again (used to forge messages). */
function edit(message: string, changes: Partial<SiweMessage>): string {
  return formatMessage({ ...parseMessage(message), ...changes });
}

describe("wallet login: createChallenge", () => {
  it("issues an EIP-4361 message bound to the address, domain, chain, a random nonce and an expiry", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();

    const challenge = await service.createChallenge(wallet.address);
    const parsed = parseMessage(challenge.message);

    expect(parsed.domain).to.equal(CONFIG.domain);
    expect(parsed.uri).to.equal(CONFIG.uri);
    expect(parsed.chainId).to.equal(CONFIG.chainId);
    expect(parsed.address).to.equal(wallet.address);
    expect(parsed.statement).to.equal(CONFIG.statement);
    expect(parsed.nonce).to.equal(challenge.nonce);
    expect(challenge.nonce).to.match(/^[0-9a-f]{32}$/);
    expect(parsed.issuedAt).to.equal(START);
    expect(parsed.expirationTime).to.equal("2026-10-31T10:05:00.000Z");
    expect(challenge.expirationTime).to.equal(parsed.expirationTime);
  });

  it("accepts any letter case for the address and writes the checksum form", async () => {
    const { service } = setup();
    const { address } = Wallet.createRandom();
    for (const variant of [address, address.toLowerCase(), `0x${address.slice(2).toUpperCase()}`]) {
      const { message } = await service.createChallenge(variant);
      expect(parseMessage(message).address).to.equal(address);
    }
  });

  it("rejects values that are not addresses, including a wrong checksum", async () => {
    const { service } = setup();
    const { address } = Wallet.createRandom();
    const wrongChecksum = address.replace(/[a-f]/i, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));
    for (const bad of ["", "0x", "0x1234", address.slice(0, -1), `${address}00`, " " + address, "vitalik.eth", wrongChecksum]) {
      await expectAuthError(() => service.createChallenge(bad), "INVALID_ADDRESS");
    }
    await expectAuthError(() => service.createChallenge(undefined as unknown as string), "INVALID_ADDRESS");
  });

  it("never repeats a nonce", async () => {
    const { service } = setup();
    const addresses = Array.from({ length: 200 }, () => `0x${randomBytes(20).toString("hex")}`);
    const nonces = new Set<string>();
    for (const address of addresses) nonces.add((await service.createChallenge(address)).nonce);
    expect(nonces.size).to.equal(200);
  });

  it("surfaces a full nonce store", async () => {
    const clock = new TestClock(START);
    const store = new InMemoryNonceStore({ maxEntries: 1, now: () => clock.now().getTime() });
    const { service } = setup({ nonceStore: store, now: clock.now });
    const { address } = Wallet.createRandom();
    await service.createChallenge(address);
    await expectAuthError(() => service.createChallenge(address), "STORE_FULL");
  });

  it("limits live challenges per address, so one wallet cannot fill the store", async () => {
    const clock = new TestClock(START);
    const store = new InMemoryNonceStore({ maxPerAddress: 2, now: () => clock.now().getTime() });
    const { service } = setup({ nonceStore: store, now: clock.now });
    const { address } = Wallet.createRandom();
    await service.createChallenge(address);
    await service.createChallenge(address);
    await expectAuthError(() => service.createChallenge(address), "TOO_MANY_CHALLENGES");
    // A different wallet is unaffected, and the quota comes back when challenges expire.
    await service.createChallenge(Wallet.createRandom().address);
    clock.advanceSeconds(300);
    await service.createChallenge(address);
  });

  it("limits live challenges per client key when the caller provides one", async () => {
    const clock = new TestClock(START);
    const store = new InMemoryNonceStore({ maxPerClient: 2, now: () => clock.now().getTime() });
    const { service } = setup({ nonceStore: store, now: clock.now });
    await service.createChallenge(Wallet.createRandom().address, { clientKey: "203.0.113.7" });
    await service.createChallenge(Wallet.createRandom().address, { clientKey: "203.0.113.7" });
    await expectAuthError(
      () => service.createChallenge(Wallet.createRandom().address, { clientKey: "203.0.113.7" }),
      "TOO_MANY_CHALLENGES",
    );
    await service.createChallenge(Wallet.createRandom().address, { clientKey: "203.0.113.8" });
    await service.createChallenge(Wallet.createRandom().address); // no key, no client quota
  });

  it("rejects an invalid client key", async () => {
    const { service } = setup();
    const { address } = Wallet.createRandom();
    for (const clientKey of ["", "x".repeat(129), 7 as unknown as string]) {
      await expectAuthError(() => service.createChallenge(address, { clientKey }), "INVALID_CONFIG");
    }
  });
});

describe("wallet login: verifyLogin", () => {
  it("accepts a challenge signed by the address and returns the checksummed address", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message, nonce } = await service.createChallenge(wallet.address.toLowerCase());

    const login = await service.verifyLogin({ message, signature: await wallet.signMessage(message) });

    expect(login).to.deep.equal({
      address: wallet.address,
      chainId: CONFIG.chainId,
      nonce,
      issuedAt: START,
      method: "eoa",
    });
  });

  it("a nonce works once: replaying the same signed message fails", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const signature = await wallet.signMessage(message);

    await service.verifyLogin({ message, signature });
    await expectAuthError(() => service.verifyLogin({ message, signature }), "NONCE_UNKNOWN");
  });

  it("only one of two concurrent attempts with the same message succeeds", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const signature = await wallet.signMessage(message);

    const results = await Promise.allSettled([
      service.verifyLogin({ message, signature }),
      service.verifyLogin({ message, signature }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).to.have.length(1);
    expect(results.filter((r) => r.status === "rejected")).to.have.length(1);
  });

  it("rejects an unknown nonce", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const forged = edit(message, { nonce: "0123456789abcdef0123456789abcdef" });
    await expectAuthError(
      async () => service.verifyLogin({ message: forged, signature: await wallet.signMessage(forged) }),
      "NONCE_UNKNOWN",
    );
  });

  it("rejects an expired challenge, with the boundary at the expiration second", async () => {
    const { service, clock } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const signature = await wallet.signMessage(message);

    clock.advanceSeconds(300); // exactly the expiration time
    await expectAuthError(() => service.verifyLogin({ message, signature }), "CHALLENGE_EXPIRED");
  });

  it("accepts a challenge answered one second before it expires", async () => {
    const { service, clock } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    clock.advanceSeconds(299);
    await service.verifyLogin({ message, signature: await wallet.signMessage(message) });
  });

  it("rejects a message for another domain without spending the nonce", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);

    const phishing = edit(message, { domain: "evil.example.net" });
    await expectAuthError(
      async () => service.verifyLogin({ message: phishing, signature: await wallet.signMessage(phishing) }),
      "DOMAIN_MISMATCH",
    );
    // The honest message still works.
    await service.verifyLogin({ message, signature: await wallet.signMessage(message) });
  });

  it("rejects a message with a scheme prefix, a different port, or another URI", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const cases: Array<[Partial<SiweMessage>, "DOMAIN_MISMATCH" | "URI_MISMATCH"]> = [
      [{ scheme: "https" }, "DOMAIN_MISMATCH"],
      [{ domain: "app.example.com:8443" }, "DOMAIN_MISMATCH"],
      [{ uri: "https://app.example.com/other" }, "URI_MISMATCH"],
      [{ uri: "https://evil.example.net" }, "URI_MISMATCH"],
    ];
    for (const [changes, code] of cases) {
      const forged = edit(message, changes);
      await expectAuthError(
        async () => service.verifyLogin({ message: forged, signature: await wallet.signMessage(forged) }),
        code,
      );
    }
  });

  it("rejects a message for another chain id", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const forged = edit(message, { chainId: 1 });
    await expectAuthError(
      async () => service.verifyLogin({ message: forged, signature: await wallet.signMessage(forged) }),
      "CHAIN_ID_MISMATCH",
    );
  });

  it("rejects any change to the issued text, even when the signer signed the changed text", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const changes: Array<Partial<SiweMessage>> = [
      { statement: "Send all your funds to me." },
      { expirationTime: "2026-10-31T23:59:59.000Z" },
      { issuedAt: "2026-10-31T10:00:01.000Z" },
      { resources: ["https://app.example.com/admin"] },
      { requestId: "x" },
    ];
    for (const change of changes) {
      const { message } = await service.createChallenge(wallet.address);
      const forged = edit(message, change);
      await expectAuthError(
        async () => service.verifyLogin({ message: forged, signature: await wallet.signMessage(forged) }),
        "MESSAGE_MISMATCH",
      );
    }
  });

  it("rejects a tampered message that still carries the original signature", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const signature = await wallet.signMessage(message);
    const tampered = message.replace("This does not cost gas.", "This costs gas.");

    await expectAuthError(() => service.verifyLogin({ message: tampered, signature }), "MESSAGE_MISMATCH");
  });

  it("rejects a signature from another account and spends the nonce", async () => {
    const { service } = setup();
    const victim = Wallet.createRandom();
    const attacker = Wallet.createRandom();
    const { message } = await service.createChallenge(victim.address);
    const signature = await attacker.signMessage(message);

    await expectAuthError(() => service.verifyLogin({ message, signature }), "INVALID_SIGNATURE");
    await expectAuthError(
      async () => service.verifyLogin({ message, signature: await victim.signMessage(message) }),
      "NONCE_UNKNOWN",
    );
  });

  it("rejects a nonce that was issued for a different address", async () => {
    const { service } = setup();
    const victim = Wallet.createRandom();
    const attacker = Wallet.createRandom();
    const { message } = await service.createChallenge(victim.address);

    // The attacker swaps in their own address and signs it with their own key.
    const swapped = edit(message, { address: attacker.address });
    await expectAuthError(
      async () => service.verifyLogin({ message: swapped, signature: await attacker.signMessage(swapped) }),
      "ADDRESS_MISMATCH",
    );
  });

  it("rejects malformed signatures", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const valid = async () => {
      const { message } = await service.createChallenge(wallet.address);
      return { message, signature: await wallet.signMessage(message) };
    };
    for (const bad of ["", "0x", "0x1234", "not hex", `0x${"00".repeat(65)}`, `0x${"ff".repeat(65)}`]) {
      const { message } = await valid();
      await expectAuthError(() => service.verifyLogin({ message, signature: bad }), "INVALID_SIGNATURE");
    }
    const { message, signature } = await valid();
    // 63 bytes. (Dropping only the `v` byte leaves a 64-byte EIP-2098 compact signature, which is valid half the time.)
    await expectAuthError(() => service.verifyLogin({ message, signature: signature.slice(0, -4) }), "INVALID_SIGNATURE");
  });

  it("rejects a message without an expiration time and one issued in the future", async () => {
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    const { expirationTime: _drop, ...rest } = parseMessage(message);
    const noExpiry = formatMessage(rest);
    await expectAuthError(
      async () => service.verifyLogin({ message: noExpiry, signature: await wallet.signMessage(noExpiry) }),
      "MISSING_EXPIRATION",
    );

    const future = edit(message, { issuedAt: "2026-10-31T10:02:00.000Z" });
    await expectAuthError(
      async () => service.verifyLogin({ message: future, signature: await wallet.signMessage(future) }),
      "NOT_YET_VALID",
    );
  });

  it("rejects malformed messages and wrong input types", async () => {
    const { service } = setup();
    await expectAuthError(() => service.verifyLogin({ message: "hello", signature: "0x00" }), "MALFORMED_MESSAGE");
    await expectAuthError(
      () => service.verifyLogin({ message: 5 as unknown as string, signature: "0x00" }),
      "MALFORMED_MESSAGE",
    );
  });

  it("does not accept a smart-contract wallet unless a verifier is configured", async () => {
    // Without a contractSignatureVerifier an invalid ECDSA signature is simply invalid.
    const { service } = setup();
    const wallet = Wallet.createRandom();
    const { message } = await service.createChallenge(wallet.address);
    await expectAuthError(() => service.verifyLogin({ message, signature: `0x${"11".repeat(65)}` }), "INVALID_SIGNATURE");
  });
});

describe("wallet login: sessions and access checks", () => {
  async function login(ctx: Harness) {
    const wallet = Wallet.createRandom();
    const { message } = await ctx.service.createChallenge(wallet.address);
    const verified = await ctx.service.verifyLogin({ message, signature: await wallet.signMessage(message) });
    return { wallet, session: ctx.service.issueSession(verified) };
  }

  it("issues a token that lives for the configured session time", async () => {
    const ctx = setup();
    const { wallet, session } = await login(ctx);
    expect(session.claims.sub).to.equal(wallet.address);
    expect(session.claims.chainId).to.equal(CONFIG.chainId);
    expect(session.claims.exp - session.claims.iat).to.equal(900);
    expect(session.expiresAt).to.equal("2026-10-31T10:15:00.000Z");
  });

  it("requireAccess asks the reader for the session's address and the plan", async () => {
    const ctx = setup();
    const { wallet, session } = await login(ctx);

    const grant = await ctx.service.requireAccess({ token: session.token, planId: 7n });

    expect(grant).to.deep.equal({ address: wallet.address, planId: 7n, chainId: CONFIG.chainId });
    expect(ctx.reader.calls).to.deep.equal([{ user: wallet.address, planId: 7n }]);
  });

  it("requireAccess denies when the reader says no", async () => {
    const ctx = setup();
    const { session } = await login(ctx);
    ctx.reader.allowed = false;
    await expectAuthError(() => ctx.service.requireAccess({ token: session.token, planId: 1n }), "ACCESS_DENIED");
  });

  it("requireAccess fails closed when the reader throws", async () => {
    const ctx = setup();
    const { session } = await login(ctx);
    ctx.reader.failure = new Error("rpc down");
    await expectAuthError(() => ctx.service.requireAccess({ token: session.token, planId: 1n }), "ACCESS_CHECK_FAILED");
  });

  it("requireAccess rejects plan ids that are not uint256 bigints, without asking the reader", async () => {
    const ctx = setup();
    const { session } = await login(ctx);
    for (const bad of [-1n, 1n << 256n, 1 as unknown as bigint, "1" as unknown as bigint]) {
      await expectAuthError(() => ctx.service.requireAccess({ token: session.token, planId: bad }), "INVALID_PLAN");
    }
    expect(ctx.reader.calls).to.have.length(0);
  });

  it("requireAccess rejects an expired token, with the boundary at exp", async () => {
    const ctx = setup();
    const { session } = await login(ctx);
    ctx.clock.advanceSeconds(899);
    await ctx.service.requireAccess({ token: session.token, planId: 1n });
    ctx.clock.advanceSeconds(1);
    await expectAuthError(() => ctx.service.requireAccess({ token: session.token, planId: 1n }), "TOKEN_EXPIRED");
  });

  it("requireAccess rejects tampered and foreign tokens without asking the reader", async () => {
    const ctx = setup();
    const { session } = await login(ctx);
    const [payload, mac] = session.token.split(".") as [string, string];
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    const otherAddress = Wallet.createRandom().address;
    const swapped = Buffer.from(JSON.stringify({ ...claims, sub: otherAddress })).toString("base64url");

    await expectAuthError(
      () => ctx.service.requireAccess({ token: `${swapped}.${mac}`, planId: 1n }),
      "TOKEN_INVALID_SIGNATURE",
    );
    const other = setup(); // different random secret
    await expectAuthError(
      () => other.service.requireAccess({ token: session.token, planId: 1n }),
      "TOKEN_INVALID_SIGNATURE",
    );
    await expectAuthError(() => ctx.service.requireAccess({ token: "", planId: 1n }), "TOKEN_MALFORMED");
    expect(ctx.reader.calls).to.have.length(0);
    expect(other.reader.calls).to.have.length(0);
  });

  it("requireAccess rejects a token issued for another chain id", async () => {
    const secret = randomBytes(32);
    const mainnetLike = setup({ sessionSecret: secret }, { ...CONFIG, chainId: 1 });
    const local = setup({ sessionSecret: secret });
    const wallet = Wallet.createRandom();
    const { message } = await mainnetLike.service.createChallenge(wallet.address);
    const verified = await mainnetLike.service.verifyLogin({ message, signature: await wallet.signMessage(message) });
    const { token } = mainnetLike.service.issueSession(verified);

    await expectAuthError(() => local.service.requireAccess({ token, planId: 1n }), "CHAIN_ID_MISMATCH");
  });

  it("honors custom challenge and session lifetimes", async () => {
    const ctx = setup({}, { ...CONFIG, challengeTtlSeconds: 60, sessionTtlSeconds: 30 });
    const wallet = Wallet.createRandom();
    const { message, expirationTime } = await ctx.service.createChallenge(wallet.address);
    expect(expirationTime).to.equal("2026-10-31T10:01:00.000Z");
    const verified = await ctx.service.verifyLogin({ message, signature: await wallet.signMessage(message) });
    expect(ctx.service.issueSession(verified).claims.exp - ctx.service.issueSession(verified).claims.iat).to.equal(30);
  });
});

describe("auth service configuration", () => {
  it("refuses a weak session secret", () => {
    expect(() => setup({ sessionSecret: randomBytes(16) })).to.throw(/INVALID_CONFIG/);
  });

  it("refuses an invalid domain, URI, chain id, statement or lifetime up front", () => {
    const bad: Array<Partial<AuthConfig>> = [
      { domain: "https://app.example.com" },
      { uri: "/relative" },
      { chainId: 0 },
      { statement: "two\nlines" },
      { challengeTtlSeconds: 0 },
      { sessionTtlSeconds: 1.5 },
      { clockSkewSeconds: -1 },
    ];
    for (const change of bad) expect(() => setup({}, { ...CONFIG, ...change }), JSON.stringify(change)).to.throw(/INVALID_CONFIG/);
  });
});
