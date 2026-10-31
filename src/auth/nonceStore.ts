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
}

/**
 * Storage for challenge nonces. `consume` MUST be atomic: of two concurrent calls with the same
 * nonce, at most one gets the record. A database implementation would use
 * `DELETE ... WHERE nonce = ? RETURNING ...` or a Redis `GETDEL`.
 */
export interface NonceStore {
  /** Remember a freshly issued nonce. Throws `AuthError("STORE_FULL")` if it cannot. */
  issue(nonce: string, record: NonceRecord): Promise<void>;
  /** Remove and return the record for `nonce`, or `undefined` if unknown or already consumed. */
  consume(nonce: string): Promise<NonceRecord | undefined>;
}

export interface InMemoryNonceStoreOptions {
  /** Hard limit on stored nonces, so unauthenticated challenge requests cannot exhaust memory. */
  maxEntries?: number;
  /** Clock used to decide which entries may be pruned. Defaults to `Date.now`. */
  now?: () => number;
}

/** Single-process store. Fine for tests and a single instance; use a shared store behind a load balancer. */
export class InMemoryNonceStore implements NonceStore {
  readonly #entries = new Map<string, NonceRecord>();
  readonly #maxEntries: number;
  readonly #now: () => number;

  constructor(options: InMemoryNonceStoreOptions = {}) {
    this.#maxEntries = options.maxEntries ?? 10_000;
    this.#now = options.now ?? Date.now;
    if (!Number.isInteger(this.#maxEntries) || this.#maxEntries < 1) {
      throw new AuthError("INVALID_CONFIG", "maxEntries must be a positive integer");
    }
  }

  get size(): number {
    return this.#entries.size;
  }

  async issue(nonce: string, record: NonceRecord): Promise<void> {
    if (this.#entries.has(nonce)) {
      // 128 random bits never collide in practice; refusing keeps `issue` from overwriting a live record.
      throw new AuthError("STORE_FULL", "nonce already present");
    }
    if (this.#entries.size >= this.#maxEntries) this.#pruneExpired();
    if (this.#entries.size >= this.#maxEntries) {
      throw new AuthError("STORE_FULL", `more than ${this.#maxEntries} live challenges`);
    }
    this.#entries.set(nonce, record);
  }

  async consume(nonce: string): Promise<NonceRecord | undefined> {
    const record = this.#entries.get(nonce);
    this.#entries.delete(nonce);
    return record;
  }

  #pruneExpired(): void {
    const now = this.#now();
    for (const [nonce, record] of this.#entries) {
      if (record.expiresAtMs <= now) this.#entries.delete(nonce);
    }
  }
}
