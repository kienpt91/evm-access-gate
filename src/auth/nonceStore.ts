import { AuthError } from "./errors.js";

/** What the server remembers about a challenge it issued. */
export interface NonceRecord {
  /** EIP-55 checksummed address the challenge was issued for. */
  address: string;
  /** `Issued At` of the message, as the exact string in the message. */
  issuedAt: string;
  /** `Expiration Time` of the message, as the exact string in the message. */
  expirationTime: string;
  /** The expiration as epoch milliseconds, used for pruning. */
  expiresAtMs: number;
  /**
   * Who asked for the challenge, as far as the HTTP layer knows (typically the client IP). Used only
   * to limit how many live challenges one client can hold. Optional.
   */
  clientKey?: string;
}

/**
 * Storage for challenge nonces. `consume` MUST be atomic: of two concurrent calls with the same
 * nonce, at most one gets the record. A database implementation would use
 * `DELETE ... WHERE nonce = ? RETURNING ...` or a Redis `GETDEL`.
 */
export interface NonceStore {
  /**
   * Remember a freshly issued nonce. Throws `AuthError("TOO_MANY_CHALLENGES")` when the address or
   * client already holds its quota of live challenges, and `AuthError("STORE_FULL")` when the store
   * as a whole is full.
   */
  issue(nonce: string, record: NonceRecord): Promise<void>;
  /** Remove and return the record for `nonce`, or `undefined` if unknown or already consumed. */
  consume(nonce: string): Promise<NonceRecord | undefined>;
}

export interface InMemoryNonceStoreOptions {
  /** Hard limit on stored nonces, so unauthenticated challenge requests cannot exhaust memory. Default 10000. */
  maxEntries?: number;
  /** Live challenges one address may hold. Default 5. */
  maxPerAddress?: number;
  /** Live challenges one `clientKey` may hold. Default 20. Only applies to records that carry a key. */
  maxPerClient?: number;
  /** Clock used to decide which entries may be pruned. Defaults to `Date.now`. */
  now?: () => number;
}

function positiveInteger(name: string, value: number): number {
  if (!Number.isInteger(value) || value < 1) throw new AuthError("INVALID_CONFIG", `${name} must be a positive integer`);
  return value;
}

/**
 * Single-process store. Fine for tests and a single instance; use a shared store behind a load balancer.
 *
 * Three bounds apply, all enforced at `issue`, and expired entries are pruned before one is
 * reported as exceeded: per address, per client key, and in total. The per-address and per-client
 * limits stop one wallet or one client from using up the store. They cannot stop an attacker who
 * varies both (any address is accepted and clients can come from many IPs), so the total cap stays
 * and a real rate limiter in front of `createChallenge` is still needed.
 */
export class InMemoryNonceStore implements NonceStore {
  readonly #entries = new Map<string, NonceRecord>();
  readonly #byAddress = new Map<string, Set<string>>();
  readonly #byClient = new Map<string, Set<string>>();
  readonly #maxEntries: number;
  readonly #maxPerAddress: number;
  readonly #maxPerClient: number;
  readonly #now: () => number;

  constructor(options: InMemoryNonceStoreOptions = {}) {
    this.#maxEntries = positiveInteger("maxEntries", options.maxEntries ?? 10_000);
    this.#maxPerAddress = positiveInteger("maxPerAddress", options.maxPerAddress ?? 5);
    this.#maxPerClient = positiveInteger("maxPerClient", options.maxPerClient ?? 20);
    this.#now = options.now ?? Date.now;
  }

  get size(): number {
    return this.#entries.size;
  }

  async issue(nonce: string, record: NonceRecord): Promise<void> {
    if (this.#entries.has(nonce)) {
      // 128 random bits never collide in practice; refusing keeps `issue` from overwriting a live record.
      throw new AuthError("STORE_FULL", "nonce already present");
    }
    const addressKey = record.address.toLowerCase();
    if (this.#isFull(this.#byAddress.get(addressKey), this.#maxPerAddress)) {
      throw new AuthError("TOO_MANY_CHALLENGES", `address already has ${this.#maxPerAddress} live challenges`);
    }
    if (record.clientKey !== undefined && this.#isFull(this.#byClient.get(record.clientKey), this.#maxPerClient)) {
      throw new AuthError("TOO_MANY_CHALLENGES", `client already has ${this.#maxPerClient} live challenges`);
    }
    if (this.#entries.size >= this.#maxEntries) this.#pruneExpired();
    if (this.#entries.size >= this.#maxEntries) {
      throw new AuthError("STORE_FULL", `more than ${this.#maxEntries} live challenges`);
    }

    // Every check passed: update all indexes together.
    this.#entries.set(nonce, record);
    this.#index(this.#byAddress, addressKey, nonce);
    if (record.clientKey !== undefined) this.#index(this.#byClient, record.clientKey, nonce);
  }

  async consume(nonce: string): Promise<NonceRecord | undefined> {
    const record = this.#entries.get(nonce);
    if (record !== undefined) this.#remove(nonce, record);
    return record;
  }

  /** True if `live` is at its limit even after dropping the expired nonces in it. */
  #isFull(live: Set<string> | undefined, limit: number): boolean {
    if (live === undefined || live.size < limit) return false;
    const now = this.#now();
    for (const nonce of [...live]) {
      const record = this.#entries.get(nonce);
      if (record !== undefined && record.expiresAtMs <= now) this.#remove(nonce, record);
    }
    return live.size >= limit;
  }

  #index(index: Map<string, Set<string>>, key: string, nonce: string): void {
    let live = index.get(key);
    if (live === undefined) {
      live = new Set();
      index.set(key, live);
    }
    live.add(nonce);
  }

  #unindex(index: Map<string, Set<string>>, key: string, nonce: string): void {
    const live = index.get(key);
    if (live === undefined) return;
    live.delete(nonce);
    if (live.size === 0) index.delete(key);
  }

  #remove(nonce: string, record: NonceRecord): void {
    this.#entries.delete(nonce);
    this.#unindex(this.#byAddress, record.address.toLowerCase(), nonce);
    if (record.clientKey !== undefined) this.#unindex(this.#byClient, record.clientKey, nonce);
  }

  #pruneExpired(): void {
    const now = this.#now();
    for (const [nonce, record] of [...this.#entries]) {
      if (record.expiresAtMs <= now) this.#remove(nonce, record);
    }
  }
}
