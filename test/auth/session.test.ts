import { createHmac, randomBytes } from "node:crypto";
import { expect } from "chai";
import { AuthError, signSession, verifySession, MIN_SECRET_BYTES } from "../../src/auth/index.js";
import { expectAuthErrorSync } from "./helpers.js";

const ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const NOW = 1_800_000_000;
// Generated at run time; no key material in the repository.
const secret = randomBytes(32);
const otherSecret = randomBytes(32);

function issue(ttlSeconds = 900) {
  return signSession(secret, { address: ADDRESS, chainId: 31337, nowSeconds: NOW, ttlSeconds });
}

/** Builds a token with a valid MAC over arbitrary claims, to test claim validation. */
function forge(claims: unknown): string {
  const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const mac = createHmac("sha256", secret).update("evm-access-gate/session/v1.").update(payload).digest("base64url");
  return `${payload}.${mac}`;
}

const GOOD_CLAIMS = { v: 1, sub: ADDRESS, chainId: 31337, iat: NOW, exp: NOW + 900, jti: "abc" };

describe("session tokens", () => {
  it("round-trips the claims", () => {
    const { token, claims } = issue();
    expect(claims.sub).to.equal(ADDRESS);
    expect(claims.exp).to.equal(NOW + 900);
    expect(verifySession(secret, token, NOW + 1)).to.deep.equal(claims);
  });

  it("normalizes the address to checksum case when issuing", () => {
    const { claims } = signSession(secret, {
      address: ADDRESS.toLowerCase(),
      chainId: 1,
      nowSeconds: NOW,
      ttlSeconds: 60,
    });
    expect(claims.sub).to.equal(ADDRESS);
  });

  it("is valid until exp - 1 and expired from exp on", () => {
    const { token, claims } = issue();
    expect(verifySession(secret, token, claims.exp - 1).sub).to.equal(ADDRESS);
    expectAuthErrorSync(() => verifySession(secret, token, claims.exp), "TOKEN_EXPIRED");
    expectAuthErrorSync(() => verifySession(secret, token, claims.exp + 3600), "TOKEN_EXPIRED");
  });

  it("rejects a token signed with another secret", () => {
    const { token } = issue();
    expectAuthErrorSync(() => verifySession(otherSecret, token, NOW), "TOKEN_INVALID_SIGNATURE");
  });

  it("rejects a tampered payload even when the expiry is extended", () => {
    const { token, claims } = issue();
    const [, mac] = token.split(".");
    const payload = Buffer.from(JSON.stringify({ ...claims, exp: claims.exp + 86_400 }), "utf8").toString("base64url");
    expectAuthErrorSync(() => verifySession(secret, `${payload}.${mac}`, NOW), "TOKEN_INVALID_SIGNATURE");
  });

  it("rejects a tampered MAC, one flipped character at a time", () => {
    const { token } = issue();
    const [payload, mac] = token.split(".");
    expect(mac).to.have.length(43);
    for (const index of [0, 10, 20, 42]) {
      const flipped = mac!.slice(0, index) + (mac![index] === "A" ? "B" : "A") + mac!.slice(index + 1);
      // The last character carries padding bits: a flip may be non-canonical, which is also rejected.
      let code: string | undefined;
      try {
        verifySession(secret, `${payload}.${flipped}`, NOW);
      } catch (err) {
        if (err instanceof AuthError) code = err.code;
      }
      expect(code).to.be.oneOf(["TOKEN_INVALID_SIGNATURE", "TOKEN_MALFORMED"]);
    }
  });

  it("rejects malformed tokens", () => {
    const { token } = issue();
    const [payload, mac] = token.split(".") as [string, string];
    for (const bad of ["", "abc", `${payload}`, `${payload}.${mac}.x`, `${payload}..`, `.${mac}`, `${payload}.`, `${payload}.${mac}=`, `${payload} .${mac}`, "a".repeat(5000)]) {
      expectAuthErrorSync(() => verifySession(secret, bad, NOW), "TOKEN_MALFORMED");
    }
  });

  it("rejects a non-canonical spelling of the MAC", () => {
    const { token } = issue();
    const [payload, mac] = token.split(".") as [string, string];
    // The 43rd character only uses its top 4 bits; setting the unused bits keeps the same bytes.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastValue = alphabet.indexOf(mac[42]!);
    const alias = alphabet[lastValue ^ 1]!;
    expect(Buffer.from(mac.slice(0, 42) + alias, "base64url").equals(Buffer.from(mac, "base64url"))).to.equal(true);
    expectAuthErrorSync(() => verifySession(secret, `${payload}.${mac.slice(0, 42)}${alias}`, NOW), "TOKEN_MALFORMED");
  });

  it("rejects claims with the right MAC but the wrong shape", () => {
    expect(verifySession(secret, forge(GOOD_CLAIMS), NOW).sub).to.equal(ADDRESS);
    const bad: unknown[] = [
      { ...GOOD_CLAIMS, v: 2 },
      { ...GOOD_CLAIMS, sub: ADDRESS.toLowerCase() },
      { ...GOOD_CLAIMS, sub: "not an address" },
      { ...GOOD_CLAIMS, sub: 5 },
      { ...GOOD_CLAIMS, chainId: "31337" },
      { ...GOOD_CLAIMS, chainId: 0 },
      { ...GOOD_CLAIMS, iat: 1.5 },
      { ...GOOD_CLAIMS, exp: NOW },
      { ...GOOD_CLAIMS, jti: "" },
      { ...GOOD_CLAIMS, admin: true },
      { v: 1 },
      [],
      null,
      "text",
    ];
    for (const claims of bad) expectAuthErrorSync(() => verifySession(secret, forge(claims), NOW), "TOKEN_MALFORMED");
  });

  it("rejects a token issued far in the future", () => {
    const { token } = signSession(secret, { address: ADDRESS, chainId: 1, nowSeconds: NOW + 3600, ttlSeconds: 900 });
    expectAuthErrorSync(() => verifySession(secret, token, NOW), "TOKEN_MALFORMED");
  });

  it("refuses short secrets and non-positive lifetimes", () => {
    const short = randomBytes(MIN_SECRET_BYTES - 1);
    expectAuthErrorSync(() => signSession(short, { address: ADDRESS, chainId: 1, nowSeconds: NOW, ttlSeconds: 60 }), "INVALID_CONFIG");
    expectAuthErrorSync(() => verifySession(short, "a.b", NOW), "INVALID_CONFIG");
    expectAuthErrorSync(() => signSession(secret, { address: ADDRESS, chainId: 1, nowSeconds: NOW, ttlSeconds: 0 }), "INVALID_CONFIG");
  });

  it("gives every token its own jti", () => {
    expect(issue().claims.jti).to.not.equal(issue().claims.jti);
  });
});
