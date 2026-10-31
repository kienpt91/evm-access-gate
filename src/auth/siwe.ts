import { getAddress } from "ethers";
import { AuthError } from "./errors.js";

/**
 * EIP-4361 (Sign-In with Ethereum) message: build and strict parse.
 *
 * Timestamps are kept as the exact strings that appear in the message, so
 * `formatMessage(parseMessage(text)) === text` for every message the parser accepts.
 *
 * Deliberate restrictions on top of the ABNF in the EIP:
 * - the address must already be EIP-55 checksummed;
 * - the domain is a host name (letters, digits, dots, hyphens) with an optional port, no userinfo
 *   and no IP literal;
 * - timestamps are UTC, `YYYY-MM-DDTHH:mm:ss[.fff]Z`, and must be real calendar times;
 * - the statement is one line (the EIP forbids line feeds in it);
 * - messages and every free-text field have a length limit.
 */
export interface SiweMessage {
  scheme?: string;
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: "1";
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

export const MAX_MESSAGE_LENGTH = 4096;
const MAX_STATEMENT_LENGTH = 1024;
const MAX_URI_LENGTH = 2048;
const MAX_RESOURCES = 16;

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const DOMAIN = new RegExp(`^${LABEL}(?:\\.${LABEL})*(?::(\\d{1,5}))?$`);
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const CHAIN_ID = /^[1-9][0-9]{0,14}$/;
const NONCE = /^[A-Za-z0-9]{8,128}$/;
const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const REQUEST_ID = /^[A-Za-z0-9\-._~!$&'()*+,;=:@%]{0,256}$/;
// Printable ASCII only, which also rules out spaces, line breaks and control characters.
const URI_CHARS = /^[\x21-\x7e]+$/;
const HEADER = /^(?:([^\s:/]+):\/\/)?(\S+) wants you to sign in with your Ethereum account:$/;

function fail(message: string): never {
  throw new AuthError("MALFORMED_MESSAGE", message);
}

function checkDomain(domain: string): void {
  const match = DOMAIN.exec(domain);
  if (domain.length > 253 || !match) fail(`invalid domain "${domain}"`);
  const port = match[1];
  if (port !== undefined && Number(port) > 65535) fail(`invalid port in domain "${domain}"`);
}

function checkUri(value: string, field: string): void {
  if (value.length > MAX_URI_LENGTH || !URI_CHARS.test(value)) fail(`invalid ${field}`);
  try {
    // Absolute URIs only: `new URL` throws for relative references.
    new URL(value);
  } catch {
    fail(`${field} is not an absolute URI`);
  }
}

/** True for strict, real UTC timestamps; the numeric parts must survive a trip through Date. */
function isTimestamp(value: string): boolean {
  const match = TIMESTAMP.exec(value);
  if (!match) return false;
  const [, y, mo, d, h, mi, s, frac] = match;
  const ms = Number((frac ?? "").padEnd(3, "0") || "0");
  const date = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms));
  return (
    date.getUTCFullYear() === Number(y) &&
    date.getUTCMonth() === Number(mo) - 1 &&
    date.getUTCDate() === Number(d) &&
    date.getUTCHours() === Number(h) &&
    date.getUTCMinutes() === Number(mi) &&
    date.getUTCSeconds() === Number(s) &&
    date.getUTCMilliseconds() === ms
  );
}

/** True only for `0x` + 40 hex characters whose letter case is exactly the EIP-55 checksum. */
function isChecksummedAddress(value: string): boolean {
  if (!ADDRESS.test(value)) return false;
  try {
    return getAddress(value) === value;
  } catch {
    return false; // mixed case with a wrong checksum: ethers throws
  }
}

function checkTimestamp(value: string, field: string): void {
  if (!isTimestamp(value)) fail(`invalid ${field} "${value}"`);
}

/** Validates every field. Throws `AuthError("MALFORMED_MESSAGE")` on the first problem. */
export function assertValidMessage(m: SiweMessage): void {
  if (m.scheme !== undefined && !SCHEME.test(m.scheme)) fail("invalid scheme");
  checkDomain(m.domain);
  if (!isChecksummedAddress(m.address)) {
    fail("address must be a 20-byte hex string in EIP-55 checksum case");
  }
  if (m.statement !== undefined) {
    if (m.statement.length === 0 || m.statement.length > MAX_STATEMENT_LENGTH) fail("invalid statement length");
    if (/[\r\n\u0000-\u001f\u007f]/.test(m.statement)) fail("statement must be a single line without control characters");
  }
  checkUri(m.uri, "URI");
  if (m.version !== "1") fail("version must be 1");
  if (!Number.isSafeInteger(m.chainId) || !CHAIN_ID.test(String(m.chainId))) fail("invalid chain id");
  if (!NONCE.test(m.nonce)) fail("nonce must be 8 to 128 alphanumeric characters");
  checkTimestamp(m.issuedAt, "Issued At");
  if (m.expirationTime !== undefined) checkTimestamp(m.expirationTime, "Expiration Time");
  if (m.notBefore !== undefined) checkTimestamp(m.notBefore, "Not Before");
  if (m.requestId !== undefined && !REQUEST_ID.test(m.requestId)) fail("invalid request id");
  if (m.resources !== undefined) {
    if (m.resources.length > MAX_RESOURCES) fail("too many resources");
    m.resources.forEach((resource, i) => checkUri(resource, `resource ${i}`));
  }
}

/** Builds the exact text a wallet signs. Validates the fields first. */
export function formatMessage(m: SiweMessage): string {
  assertValidMessage(m);
  const lines = [
    `${m.scheme !== undefined ? `${m.scheme}://` : ""}${m.domain} wants you to sign in with your Ethereum account:`,
    m.address,
    "",
  ];
  if (m.statement !== undefined) lines.push(m.statement);
  lines.push(
    "",
    `URI: ${m.uri}`,
    `Version: ${m.version}`,
    `Chain ID: ${m.chainId}`,
    `Nonce: ${m.nonce}`,
    `Issued At: ${m.issuedAt}`,
  );
  if (m.expirationTime !== undefined) lines.push(`Expiration Time: ${m.expirationTime}`);
  if (m.notBefore !== undefined) lines.push(`Not Before: ${m.notBefore}`);
  if (m.requestId !== undefined) lines.push(`Request ID: ${m.requestId}`);
  if (m.resources !== undefined) {
    lines.push("Resources:", ...m.resources.map((resource) => `- ${resource}`));
  }
  return lines.join("\n");
}

/** Reads `Label: value` at the cursor, or returns undefined if the next line has another label. */
class Reader {
  #index = 0;

  constructor(private readonly lines: string[]) {}

  get position(): number {
    return this.#index;
  }

  peek(): string | undefined {
    return this.lines[this.#index];
  }

  next(): string | undefined {
    return this.lines[this.#index++];
  }

  field(label: string): string | undefined {
    const line = this.peek();
    const prefix = `${label}: `;
    if (line === undefined || !line.startsWith(prefix)) return undefined;
    this.#index++;
    return line.slice(prefix.length);
  }

  required(label: string): string {
    const value = this.field(label);
    if (value === undefined) fail(`expected "${label}:" line`);
    return value;
  }
}

/** Parses and validates EIP-4361 text. Throws `AuthError("MALFORMED_MESSAGE")` on any deviation. */
export function parseMessage(text: string): SiweMessage {
  if (text.length > MAX_MESSAGE_LENGTH) fail("message too long");
  if (text.includes("\r")) fail("carriage returns are not allowed");

  const reader = new Reader(text.split("\n"));
  const header = HEADER.exec(reader.next() ?? "");
  if (!header) fail("first line must be '<domain> wants you to sign in with your Ethereum account:'");
  const scheme = header[1];
  const domain = header[2] ?? "";

  const address = reader.next();
  if (address === undefined) fail("missing address line");
  if (reader.next() !== "") fail("expected an empty line after the address");

  let statement: string | undefined;
  const afterBlank = reader.next();
  if (afterBlank === undefined) fail("unexpected end of message");
  if (afterBlank === "") {
    // No statement: the address block is followed by two empty lines.
  } else {
    statement = afterBlank;
    if (reader.next() !== "") fail("expected an empty line after the statement");
  }

  const uri = reader.required("URI");
  const version = reader.required("Version");
  const chainIdText = reader.required("Chain ID");
  const nonce = reader.required("Nonce");
  const issuedAt = reader.required("Issued At");
  const expirationTime = reader.field("Expiration Time");
  const notBefore = reader.field("Not Before");
  const requestId = reader.field("Request ID");

  let resources: string[] | undefined;
  if (reader.peek() === "Resources:") {
    reader.next();
    resources = [];
    for (let line = reader.peek(); line !== undefined && line.startsWith("- "); line = reader.peek()) {
      resources.push(line.slice(2));
      reader.next();
    }
  }
  if (reader.peek() !== undefined) fail(`unexpected content at line ${reader.position + 1}`);

  if (version !== "1") fail("version must be 1");
  if (!CHAIN_ID.test(chainIdText)) fail("invalid chain id");

  const message: SiweMessage = {
    domain,
    address,
    uri,
    version: "1",
    chainId: Number(chainIdText),
    nonce,
    issuedAt,
  };
  if (scheme !== undefined) message.scheme = scheme;
  if (statement !== undefined) message.statement = statement;
  if (expirationTime !== undefined) message.expirationTime = expirationTime;
  if (notBefore !== undefined) message.notBefore = notBefore;
  if (requestId !== undefined) message.requestId = requestId;
  if (resources !== undefined) message.resources = resources;

  assertValidMessage(message);
  return message;
}
