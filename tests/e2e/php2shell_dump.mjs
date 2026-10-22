import { readFileSync } from "node:fs";
import { detectPhp2Shell, scanMultipart } from "../../packages/widget/dist/php2shell.js";

const cases = JSON.parse(
  readFileSync(new URL("../fixtures/php2shell/cases.json", import.meta.url), "utf8"),
);

function priorFor(c) {
  const phases = c.session.priorPhases ?? [];
  if (phases.length === 0) return null;
  const pressure = phases.some((p) => ["pressure", "stale_reuse", "post_exploit"].includes(p));
  return {
    sessionId: "fixture-session",
    createdAt: 0,
    lastSeen: 0,
    requestCount: c.session.requestCount ?? 0,
    maxScore: 0,
    phase: phases[phases.length - 1],
    pressureSeen: pressure,
    uploadProgressSeen: pressure,
    issuedCanaries: c.session.issuedCanaries ?? [],
    canaryEchoed: false,
  };
}

function requestFor(c) {
  const headers = Object.fromEntries(
    Object.entries(c.request.headers).map(([k, v]) => [k.toLowerCase(), String(v)]),
  );
  const url = new URL("http://trap.test" + c.request.path);
  const contentType = headers["content-type"] ?? "";
  return {
    method: c.request.method,
    path: url.pathname,
    query: url.search.replace(/^\?/, ""),
    headers,
    bodyPrefix: c.request.bodyPrefix,
    bodyBytes: c.request.contentLength ?? Buffer.byteLength(c.request.bodyPrefix),
    bodyTruncated: false,
    bodySha256: "",
    contentType,
    contentLength: c.request.contentLength,
    transferEncoding: headers["transfer-encoding"] ?? "",
    userAgent: headers["user-agent"] ?? "",
    clientIp: c.session.clientIp,
    multipart: scanMultipart(c.request.bodyPrefix, contentType),
  };
}

const results = cases.map((c) => {
  const result = detectPhp2Shell({
    request: requestFor(c),
    prior: priorFor(c),
    profile: c.profile,
    pressureBytes: 1024 * 1024,
    canaries: [],
  });
  return {
    name: c.name,
    signals: result.signals,
    score: result.score,
    phase: result.phase,
    responsePhase: result.responsePhase,
    canaryEcho: result.canaryEcho,
  };
});

process.stdout.write(JSON.stringify(results, null, 2));
