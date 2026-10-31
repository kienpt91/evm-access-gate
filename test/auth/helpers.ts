import { expect } from "chai";
import { AuthError, type AuthErrorCode } from "../../src/auth/index.js";

/** Runs `action` and asserts that it fails with an `AuthError` carrying exactly this code. */
export async function expectAuthError(action: () => unknown, code: AuthErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await action();
  } catch (err) {
    caught = err;
  }
  expect(caught, `expected AuthError ${code}, but nothing was thrown`).to.be.instanceOf(AuthError);
  if (caught instanceof AuthError) expect(caught.code, caught.message).to.equal(code);
}

/** Same, for synchronous code. */
export function expectAuthErrorSync(action: () => unknown, code: AuthErrorCode): void {
  let caught: unknown;
  try {
    action();
  } catch (err) {
    caught = err;
  }
  expect(caught, `expected AuthError ${code}, but nothing was thrown`).to.be.instanceOf(AuthError);
  if (caught instanceof AuthError) expect(caught.code, caught.message).to.equal(code);
}

/** A clock the tests can move. */
export class TestClock {
  #ms: number;

  constructor(startIso: string) {
    this.#ms = Date.parse(startIso);
  }

  now = (): Date => new Date(this.#ms);

  advanceSeconds(seconds: number): void {
    this.#ms += seconds * 1000;
  }
}
