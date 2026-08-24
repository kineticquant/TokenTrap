import { afterEach, describe, expect, it, vi } from "vitest";
import { TokenTrap } from "../src/TokenTrap";

const G = globalThis as { document?: unknown };

describe("TokenTrap headless client-side mode", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete G.document;
  });

  it("escalates across turns without any backend", async () => {
    const trap = new TokenTrap({ showUI: false });
    const r0 = await trap.send("hello");
    expect(r0.meta.turn).toBe(0);
    expect(r0.meta.escalated).toBe(false);

    const r1 = await trap.send("continue");
    expect(r1.meta.turn).toBe(1);
    expect(r1.meta.repeats).toBe(3);

    const r2 = await trap.send("again");
    expect(r2.meta.turn).toBe(2);
    expect(r2.meta.escalated).toBe(true);

    const snap = trap.getSession();
    expect(snap.turns.length).toBe(6);
    expect(snap.lastMeta?.escalated).toBe(true);
    trap.destroy();
  });

  it("fires onInteraction for user and assistant events", async () => {
    const onInteraction = vi.fn();
    const trap = new TokenTrap({ showUI: false, onInteraction });
    await trap.send("hi there");
    const kinds = onInteraction.mock.calls.map((c) => (c[0] as { kind: string }).kind);
    expect(kinds).toEqual(["user", "assistant"]);
    trap.destroy();
  });

  it("rejects empty messages", async () => {
    const trap = new TokenTrap({ showUI: false });
    await expect(trap.send("   ")).rejects.toThrow(/non-empty/);
    trap.destroy();
  });

  it("throws a helpful error in UI mode without a container", () => {
    G.document = {};
    expect(() => new TokenTrap({})).toThrow(/no usable `container`/);
  });
});

describe("TokenTrap apiEndpoint mode", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete G.document;
  });

  it("posts to <apiEndpoint>/api/chat and surfaces the backend reply", async () => {
    const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
      expect(String(url)).toBe("https://trap.example.com/api/chat");
      const body = JSON.parse(String(init?.body)) as { sessionId: string; message: string };
      expect(body.message).toBe("hi");
      expect(body.sessionId).toBeTruthy();
      return new Response(
        JSON.stringify({
          sessionId: body.sessionId,
          reply: "TRAP PAYLOAD FROM BACKEND",
          turn: 0,
          meta: {
            turn: 0,
            strength: "aggressive",
            repeats: 0,
            minWords: 0,
            injectionDetected: false,
            matchedKeywords: [],
            escalated: false,
            ref: "",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const trap = new TokenTrap({ showUI: false, apiEndpoint: "https://trap.example.com/" });
    const res = await trap.send("hi");
    expect(res.reply).toBe("TRAP PAYLOAD FROM BACKEND");
    expect(fetchMock).toHaveBeenCalledOnce();
    trap.destroy();
  });

  it("surfaces backend errors with context", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 503, statusText: "Service Unavailable" })),
    );
    const trap = new TokenTrap({ showUI: false, apiEndpoint: "https://trap.example.com" });
    await expect(trap.send("hi")).rejects.toThrow(/503 Service Unavailable/);
    trap.destroy();
  });
});
