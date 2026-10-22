import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { detectPhp2Shell, scanMultipart } from "../src/php2shell/detector";
import { buildResponse, planDirective } from "../src/php2shell/responses";
import { MemoryPhp2ShellStore, applyDetection, initialState, sessionKey } from "../src/php2shell/state";
import type { Php2ShellRequestInfo, Php2ShellState } from "../src/php2shell/types";

interface Fixture {
  name: string;
  profile: "generic" | "wordpress" | "drupal" | "joomla";
  session: {
    clientIp: string;
    userAgent: string;
    priorPhases: Array<"recon" | "pressure" | "stale_reuse" | "post_exploit">;
    requestCount: number;
    issuedCanaries?: string[];
  };
  request: {
    method: string;
    path: string;
    headers: Record<string, string>;
    bodyPrefix: string;
    contentLength: number | null;
  };
  expect: {
    signals: string[];
    score: number;
    phase: string;
    responsePhase: string;
    canaryEcho: boolean;
  };
}

const fixtures = JSON.parse(
  readFileSync(new URL("../../../tests/fixtures/php2shell/cases.json", import.meta.url), "utf8"),
) as Fixture[];

function fixtureState(f: Fixture): Php2ShellState | null {
  if (f.session.priorPhases.length === 0) return null;
  const pressureSeen =
    f.session.priorPhases.includes("pressure") ||
    f.session.priorPhases.includes("stale_reuse") ||
    f.session.priorPhases.includes("post_exploit");
  return {
    sessionId: "fixture-session",
    createdAt: 0,
    lastSeen: 0,
    requestCount: f.session.requestCount,
    maxScore: 0,
    phase: f.session.priorPhases[f.session.priorPhases.length - 1] as Php2ShellState["phase"],
    pressureSeen,
    uploadProgressSeen: pressureSeen,
    issuedCanaries: f.session.issuedCanaries ?? [],
    canaryEchoed: false,
  };
}

function fixtureRequest(f: Fixture): Php2ShellRequestInfo {
  const headers = Object.fromEntries(
    Object.entries(f.request.headers).map(([k, v]) => [k.toLowerCase(), String(v)]),
  );
  const url = new URL("http://trap.test" + f.request.path);
  const contentType = headers["content-type"] ?? "";
  return {
    method: f.request.method,
    path: url.pathname,
    query: url.search.replace(/^\?/, ""),
    headers,
    bodyPrefix: f.request.bodyPrefix,
    bodyBytes: f.request.contentLength ?? Buffer.byteLength(f.request.bodyPrefix),
    bodyTruncated: false,
    bodySha256: "",
    contentType,
    contentLength: f.request.contentLength,
    transferEncoding: headers["transfer-encoding"] ?? "",
    userAgent: headers["user-agent"] ?? "",
    clientIp: f.session.clientIp,
    multipart: scanMultipart(f.request.bodyPrefix, contentType),
  };
}

describe("PHP2Shell detection fixtures", () => {
  it.each(fixtures)("$name", (f) => {
    const result = detectPhp2Shell({
      request: fixtureRequest(f),
      prior: fixtureState(f),
      profile: f.profile,
      pressureBytes: 1024 * 1024,
      canaries: [],
    });
    expect(result.signals).toEqual(f.expect.signals);
    expect(result.score).toBe(f.expect.score);
    expect(result.phase).toBe(f.expect.phase);
    expect(result.responsePhase).toBe(f.expect.responsePhase);
    expect(result.canaryEcho).toBe(f.expect.canaryEcho);
  });
});

describe("PHP2Shell state", () => {
  it("increments request count and keeps phase monotonic", () => {
    const start = initialState("p2s-test", 1000);
    const pressure = applyDetection(
      start,
      {
        signals: ["upload_progress_field"],
        score: 40,
        tier: "suspicious",
        phase: "pressure",
        responsePhase: "pressure",
        canaryEcho: false,
      },
      2000,
    );
    expect(pressure.requestCount).toBe(1);
    expect(pressure.phase).toBe("pressure");
    expect(pressure.pressureSeen).toBe(true);

    const recon = applyDetection(
      pressure,
      {
        signals: [],
        score: 0,
        tier: "observe",
        phase: "pressure",
        responsePhase: "recon",
        canaryEcho: false,
      },
      3000,
    );
    expect(recon.phase).toBe("pressure");
    expect(recon.requestCount).toBe(2);
  });

  it("keys sessions by IP and user agent, not cookies", () => {
    expect(sessionKey("203.0.113.9", "curl/8")).toBe(sessionKey("203.0.113.9", "curl/8"));
    expect(sessionKey("203.0.113.9", "curl/8")).not.toBe(sessionKey("203.0.113.9", "curl/9"));
  });

  it("stores and expires TTL state", async () => {
    let now = 1000;
    const store = new MemoryPhp2ShellStore(1, () => now);
    await store.set("k", initialState("k", now), 1);
    expect(await store.get("k")).toBeDefined();
    now = 3000;
    expect(await store.get("k")).toBeUndefined();
  });
});

describe("PHP2Shell directives and responses", () => {
  it("escalates directive numbers from base to max", () => {
    expect(planDirective("aggressive", 1)).toEqual({ repeats: 3, minWords: 4000 });
    expect(planDirective("aggressive", 2)).toEqual({ repeats: 5, minWords: 7000 });
    expect(planDirective("aggressive", 99)).toEqual({ repeats: 10, minWords: 15000 });
  });

  it("emits a synthetic leak cookie and directive on stale reuse", () => {
    const f = fixtures.find((x) => x.name === "fileless reuse after pressure")!;
    const request = fixtureRequest(f);
    const detection = detectPhp2Shell({
      request,
      prior: fixtureState(f),
      profile: f.profile,
      pressureBytes: 1024 * 1024,
      canaries: [],
    });
    const built = buildResponse({
      request,
      detection,
      prior: fixtureState(f),
      requestIndex: 4,
      sessionId: "p2s-fixture",
      options: {
        enabled: true,
        profile: "generic",
        pathPrefix: "/",
        trapStrength: "aggressive",
        canaryTokens: [],
        maxScanBytes: 1024 * 1024,
        pressureBytes: 1024 * 1024,
        sessionTtlSeconds: 86400,
        rateLimitPerMinute: 120,
        maxPreviewBytes: 2048,
        now: () => 1000,
      },
    });
    expect(built.response.status).toBe(500);
    expect(built.response.headers.get("set-cookie")).toContain("PHPSESSID=");
    expect(built.response.headers.get("set-cookie")).toContain("TRAPCANARY");
    expect(built.tarpit.directive).toBe(true);
    expect(built.tarpit.repeats).toBeGreaterThanOrEqual(3);
  });
});
