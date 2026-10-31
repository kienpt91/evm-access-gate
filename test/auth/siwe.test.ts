import { expect } from "chai";
import { AuthError, formatMessage, parseMessage, type SiweMessage } from "../../src/auth/index.js";
import { expectAuthErrorSync } from "./helpers.js";

// The example message from EIP-4361.
const EIP_EXAMPLE = [
  "service.org wants you to sign in with your Ethereum account:",
  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  "",
  "I accept the ServiceOrg Terms of Service: https://service.org/tos",
  "",
  "URI: https://service.org/login",
  "Version: 1",
  "Chain ID: 1",
  "Nonce: 32891757",
  "Issued At: 2021-09-30T16:25:24.000Z",
  "Resources:",
  "- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
  "- https://example.com/my-web2-claim.json",
].join("\n");

const BASE: SiweMessage = {
  domain: "app.example.com",
  address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  statement: "Sign in to Example.",
  uri: "https://app.example.com",
  version: "1",
  chainId: 31337,
  nonce: "abcDEF1234567890",
  issuedAt: "2026-10-31T10:00:00.000Z",
  expirationTime: "2026-10-31T10:05:00.000Z",
};

function expectMalformed(text: string): void {
  expectAuthErrorSync(() => parseMessage(text), "MALFORMED_MESSAGE");
}

function withLine(text: string, from: string, to: string): string {
  expect(text).to.contain(from);
  return text.replace(from, to);
}

describe("EIP-4361 message format", () => {
  it("parses the example from the EIP and formats it back byte for byte", () => {
    const parsed = parseMessage(EIP_EXAMPLE);
    expect(parsed).to.deep.equal({
      domain: "service.org",
      address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      statement: "I accept the ServiceOrg Terms of Service: https://service.org/tos",
      uri: "https://service.org/login",
      version: "1",
      chainId: 1,
      nonce: "32891757",
      issuedAt: "2021-09-30T16:25:24.000Z",
      resources: [
        "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
        "https://example.com/my-web2-claim.json",
      ],
    });
    expect(formatMessage(parsed)).to.equal(EIP_EXAMPLE);
  });

  it("formats and parses a message with every optional field", () => {
    const full: SiweMessage = {
      ...BASE,
      scheme: "https",
      notBefore: "2026-10-31T09:59:00Z",
      requestId: "req-42",
      resources: ["https://app.example.com/a", "https://app.example.com/b"],
    };
    const text = formatMessage(full);
    expect(text.split("\n")[0]).to.equal("https://app.example.com wants you to sign in with your Ethereum account:");
    expect(parseMessage(text)).to.deep.equal(full);
    expect(formatMessage(parseMessage(text))).to.equal(text);
  });

  it("formats a message without a statement with two empty lines before the URI", () => {
    const { statement: _statement, ...withoutStatement } = BASE;
    const text = formatMessage(withoutStatement);
    const lines = text.split("\n");
    expect(lines.slice(1, 5)).to.deep.equal([BASE.address, "", "", `URI: ${BASE.uri}`]);
    expect(parseMessage(text)).to.deep.equal(withoutStatement);
  });

  it("accepts a domain with a port", () => {
    const text = formatMessage({ ...BASE, domain: "localhost:3000", uri: "http://localhost:3000" });
    expect(parseMessage(text).domain).to.equal("localhost:3000");
  });

  it("rejects an address that is not in EIP-55 checksum case", () => {
    const text = formatMessage(BASE);
    expectMalformed(withLine(text, BASE.address, BASE.address.toLowerCase()));
    expectMalformed(withLine(text, BASE.address, "0xc02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")); // one letter flipped
    expectMalformed(withLine(text, BASE.address, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc"));
  });

  it("rejects a version other than 1", () => {
    expectMalformed(withLine(formatMessage(BASE), "Version: 1", "Version: 2"));
    expectMalformed(withLine(formatMessage(BASE), "Version: 1", "Version: 01"));
  });

  it("rejects invalid chain ids", () => {
    const text = formatMessage(BASE);
    for (const bad of ["0", "-1", "01", "1.5", "abc", "", "1234567890123456"]) {
      expectMalformed(withLine(text, "Chain ID: 31337", `Chain ID: ${bad}`));
    }
  });

  it("rejects nonces that are too short or not alphanumeric", () => {
    const text = formatMessage(BASE);
    for (const bad of ["abc1234", "abcd-efgh12", "abcd efgh12", ""]) {
      expectMalformed(withLine(text, `Nonce: ${BASE.nonce}`, `Nonce: ${bad}`));
    }
  });

  it("rejects timestamps that are not strict UTC calendar times", () => {
    const text = formatMessage(BASE);
    const bad = [
      "2026-10-31T10:00:00+00:00",
      "2026-10-31 10:00:00Z",
      "2026-10-31T10:00:00",
      "2026-02-30T10:00:00Z",
      "2026-13-01T10:00:00Z",
      "2026-10-31T24:00:00Z",
      "2026-10-31T10:60:00Z",
      "2026-10-31T10:00:00.1234Z",
      "yesterday",
    ];
    for (const value of bad) expectMalformed(withLine(text, `Issued At: ${BASE.issuedAt}`, `Issued At: ${value}`));
    expectMalformed(withLine(text, `Expiration Time: ${BASE.expirationTime}`, "Expiration Time: 2026-02-30T10:00:00Z"));
  });

  it("rejects wrong domains: userinfo, paths, spaces, bad ports", () => {
    const text = formatMessage(BASE);
    for (const bad of ["user@app.example.com", "app.example.com/path", "-bad.example.com", "app..example.com", "app.example.com:99999", "app.example.com:"]) {
      expectMalformed(text.replace(BASE.domain, bad));
    }
  });

  it("rejects relative or malformed URIs", () => {
    const text = formatMessage(BASE);
    expectMalformed(withLine(text, `URI: ${BASE.uri}`, "URI: /login"));
    expectMalformed(withLine(text, `URI: ${BASE.uri}`, "URI: not a uri"));
    expectMalformed(withLine(text, `URI: ${BASE.uri}`, "URI: "));
  });

  it("rejects missing, reordered, repeated and extra lines", () => {
    const text = formatMessage(BASE);
    expectMalformed(withLine(text, "Version: 1\n", ""));
    expectMalformed(withLine(text, "Version: 1\nChain ID: 31337", "Chain ID: 31337\nVersion: 1"));
    expectMalformed(`${text}\nExpiration Time: ${BASE.expirationTime}`);
    expectMalformed(`${text}\nExtra: line`);
    expectMalformed(`${text}\n`);
    expectMalformed(`\n${text}`);
    expectMalformed(withLine(text, "wants you to sign in with your Ethereum account:", "wants you to sign in with your Ethereum Account:"));
    expectMalformed("");
  });

  it("rejects carriage returns and oversized messages", () => {
    expectMalformed(formatMessage(BASE).replaceAll("\n", "\r\n"));
    expectMalformed(`${formatMessage(BASE)}\n- ${"a".repeat(5000)}`);
  });

  it("rejects resources that are not absolute URIs and rejects too many", () => {
    const text = formatMessage({ ...BASE, resources: ["https://app.example.com/a"] });
    expectMalformed(withLine(text, "- https://app.example.com/a", "- relative/path"));
    const many = Array.from({ length: 17 }, (_, i) => `https://app.example.com/${i}`);
    expect(() => formatMessage({ ...BASE, resources: many })).to.throw(AuthError);
  });

  it("formatMessage validates its input too: no newline injection through the statement", () => {
    expect(() => formatMessage({ ...BASE, statement: "hello\nURI: https://evil.example" })).to.throw(AuthError);
    expect(() => formatMessage({ ...BASE, statement: "" })).to.throw(AuthError);
    expect(() => formatMessage({ ...BASE, address: BASE.address.toLowerCase() })).to.throw(AuthError);
    expect(() => formatMessage({ ...BASE, nonce: "short" })).to.throw(AuthError);
  });
});
