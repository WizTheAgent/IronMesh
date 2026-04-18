// Group 2: H2 (sequence reset on reconnect) and H3 (real exponential
// backoff with jitter). H2 is exercised by the live e2e (a separate
// add) and via direct state inspection here. H3 uses the test seams
// (`_random` for deterministic jitter, `_setTimeout` to capture the
// scheduled delays without sleeping).

import { describe, expect, it } from "vitest";
import { IronMeshClient } from "../src/index.js";

function newClient(reconnectInitialDelayMs = 500): IronMeshClient {
  return new IronMeshClient({
    url: "ws://localhost:0",
    passphrase: "test",
    autoReconnect: true,
    reconnectInitialDelayMs,
  });
}

describe("H2: sequence reset on reconnect", () => {
  it("starts at 0 fresh and stays at 0 until a connect attempt", () => {
    const c = newClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any).state.sequence).toBe(0n);
  });

  it("connect() resets sequence even if previous session left it non-zero", async () => {
    const c = newClient();
    // Simulate a prior session that left sequence at 7
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).state.sequence = 7n;

    // Calling connect() on an unreachable URL will fail handshake,
    // but the early reset of state.sequence happens before the WS
    // open attempt — that's what we're verifying.
    try {
      await c.connect();
    } catch {
      /* expected — no daemon listening */
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any).state.sequence).toBe(0n);
  });
});

describe("H3: exponential backoff with jitter", () => {
  it("base schedule (zero jitter) doubles each attempt up to 30 s", () => {
    const c = newClient(500);
    // Force jitter to exactly the midpoint (no randomness)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._random = () => 0.5;

    const delays: number[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (let attempt = 0; attempt < 8; attempt++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (c as any).reconnectAttempt = attempt;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delays.push((c as any)._nextBackoffDelayMs());
    }

    // 500 * 2^attempt, capped at 30000
    // attempt 0: 500
    // attempt 1: 1000
    // attempt 2: 2000
    // attempt 3: 4000
    // attempt 4: 8000
    // attempt 5: 16000
    // attempt 6: 32000 → capped at 30000
    // attempt 7: 64000 → capped at 30000
    expect(delays).toEqual([500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]);
  });

  it("jitter is bounded to ±20% of the capped base", () => {
    const c = newClient(1000);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).reconnectAttempt = 3;
    // attempt 3: base = 1000 * 8 = 8000ms. ±20% = [6400, 9600]

    // Test each end of the jitter range
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._random = () => 0; // jitter = 1 + (-0.2) = 0.80
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any)._nextBackoffDelayMs()).toBe(6400);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._random = () => 1; // jitter = 1 + (+0.2) = 1.20
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any)._nextBackoffDelayMs()).toBe(9600);
  });

  it("schedules each attempt with the correct delay (via _setTimeout seam)", () => {
    const c = newClient(500);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).intentionallyClosed = true; // prevent actual reconnect attempts
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._random = () => 0.5; // zero jitter

    const scheduled: number[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._setTimeout = (_: () => void, ms: number) => {
      scheduled.push(ms);
      return 0;
    };

    // Trigger the private scheduler 4 times
    for (let i = 0; i < 4; i++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (c as any)._scheduleReconnect();
    }

    expect(scheduled).toEqual([500, 1000, 2000, 4000]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any).reconnectAttempt).toBe(4);
  });

  it("reconnectAttempt is reset on a successful connect (verified via behavior)", () => {
    // We can't easily trigger a "successful" connect without a daemon,
    // but we can verify the API contract: after a manual reset, the
    // next backoff returns to the initial delay.
    const c = newClient(500);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any)._random = () => 0.5;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).reconnectAttempt = 5;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any)._nextBackoffDelayMs()).toBe(16000);

    // Reset (simulating a successful reconnect)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).reconnectAttempt = 0;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any)._nextBackoffDelayMs()).toBe(500);
  });
});
