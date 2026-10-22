import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { detectPhp2Shell, scanMultipart } from "../src/php2shell/detector";
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
