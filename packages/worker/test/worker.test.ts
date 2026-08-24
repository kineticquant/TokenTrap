import { describe, expect, it } from "vitest";
import worker, { type WorkerEnv } from "../src/index";

/** Minimal async KVNamespace stand-in good enough for handler tests. */
class MemoryKV {
  private store = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }
}

function makeEnv(overrides: Partial<WorkerEnv> = {}): WorkerEnv {
  return {
    TRAP_SESSIONS: new MemoryKV() as unknown as KVNamespace,
    ...overrides,
  };
}

function ctx(): ExecutionContext {
  return {
    waitUntil: () => undefined,
    passThroughOnException: () => undefined,
  } as unknown as ExecutionContext;
}

function post(body: unknown, ip = "203.0.113.9"): Request {
  return new Request("https://trap.example.com/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: JSON.stringify(body),
  });
}

describe("token-trap worker", () => {
  it("answers healthz and CORS preflight", async () => {
    const health = await worker.fetch(new Request("https://x/healthz"), makeEnv(), ctx());
    expect(health.status).toBe(200);
    const pre = await worker.fetch(
      new Request("https://x/api/chat", { method: "OPTIONS" }),
      makeEnv(),
      ctx(),
    );
    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("404s unknown routes and 400s malformed bodies", async () => {
    expect((await worker.fetch(new Request("https://x/nope"), makeEnv(), ctx())).status).toBe(404);
    const bad = new Request("https://x/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not json{",
    });
    expect((await worker.fetch(bad, makeEnv(), ctx())).status).toBe(400);
  });

  it("runs the full escalation ladder across a session", async () => {
    const env = makeEnv({ TRAP_STRENGTH: "aggressive" });
    const r0 = (await (
      await worker.fetch(post({ sessionId: "sA", message: "hello" }), env, ctx())
    ).json()) as { turn: number; meta: { escalated: boolean; repeats: number }; reply: string };
    expect(r0.turn).toBe(0);
    expect(r0.meta.escalated).toBe(false);
    expect(r0.reply).toContain("Internal AI Assistant");

    const r1 = (await (
      await worker.fetch(post({ sessionId: "sA", message: "go on" }), env, ctx())
    ).json()) as { turn: number; meta: { escalated: boolean; repeats: number; minWords: number } };
    expect(r1.turn).toBe(1);
    expect(r1.meta.repeats).toBe(3);
    expect(r1.meta.minWords).toBe(4000);

    const r2 = (await (
      await worker.fetch(post({ sessionId: "sA", message: "again" }), env, ctx())
    ).json()) as { turn: number; meta: { escalated: boolean; repeats: number; minWords: number } };
    expect(r2.turn).toBe(2);
    expect(r2.meta.escalated).toBe(true);
    expect(r2.meta.repeats).toBe(10);
    expect(r2.meta.minWords).toBe(15000);
  });

  it("keeps sessions independent without KV (memory mode)", async () => {
    const env = makeEnv(); // includes memory KV in these tests; use none:
    const noKv: WorkerEnv = {};
    await worker.fetch(post({ sessionId: "mem1", message: "hi" }), noKv, ctx());
    const r1 = (await (
      await worker.fetch(post({ sessionId: "mem1", message: "hi again" }), noKv, ctx())
    ).json()) as { turn: number };
    expect(r1.turn).toBe(1);
    const other = (await (
      await worker.fetch(post({ sessionId: "mem2", message: "fresh" }), env, ctx())
    ).json()) as { turn: number };
    expect(other.turn).toBe(0);
  });

  it("mints a sessionId when the client sends none", async () => {
    const res = await worker.fetch(post({ message: "hello" }), makeEnv(), ctx());
    const data = (await res.json()) as { sessionId: string };
    expect(data.sessionId).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it("flags canary echoes via header when configured", async () => {
    const env = makeEnv({ CANARY_TOKENS: "audit-canary-42" });
    const first = await worker.fetch(post({ sessionId: "c", message: "hello" }), env, ctx());
    expect(first.headers.get("x-tokentrap-canary-echo")).toBe("false");
    const reply = ((await first.json()) as { reply: string }).reply;
    expect(reply).toContain("[AUDIT-TAG:audit-canary-42]");

    const echo = await worker.fetch(
      post({ sessionId: "c", message: "resending: AUDIT-TAG:audit-canary-42" }),
      env,
      ctx(),
    );
    expect(echo.headers.get("x-tokentrap-canary-echo")).toBe("true");
  });

  it("rate limits per IP after the configured threshold", async () => {
    const env = makeEnv({ RATE_LIMIT: "2" });
    const ip = "198.51.100.7";
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await worker.fetch(post({ sessionId: `rl${i}`, message: "hi" }, ip), env, ctx());
      statuses.push(res.status);
    }
    expect(statuses).toEqual([200, 200, 429]);
  });
});
