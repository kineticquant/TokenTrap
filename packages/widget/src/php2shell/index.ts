import { fnv1a32 } from "../trapEngine.js";
import { detectPhp2Shell, scanMultipart } from "./detector.js";
import { buildResponse } from "./responses.js";
import { MemoryPhp2ShellStore, applyDetection, sessionKey } from "./state.js";
import {
  DEFAULT_MAX_PREVIEW_BYTES,
  DEFAULT_MAX_SCAN_BYTES,
  DEFAULT_PRESSURE_BYTES,
  DEFAULT_RATE_LIMIT_PER_MINUTE,
  DEFAULT_SESSION_TTL_SECONDS,
  type Php2ShellContext,
  type Php2ShellDecoy,
  type Php2ShellEvent,
  type Php2ShellOptions,
  type Php2ShellRequestInfo,
  type Php2ShellResult,
  type ResolvedPhp2ShellOptions,
} from "./types.js";

export * from "./types.js";
export { detectPhp2Shell, scanMultipart } from "./detector.js";
export { MemoryPhp2ShellStore, applyDetection, initialState, sessionKey } from "./state.js";
export { buildResponse, planDirective } from "./responses.js";
export { buildScannerResponse, parseCommand, shouldUseScanner } from "./scanner.js";
export { CVE_TOKENS, PROFILE_PATHS, SIGNAL_WEIGHTS } from "./signals.js";

const rateWindows = new Map<string, number[]>();
const PROFILES = new Set(["generic", "wordpress", "drupal", "joomla"]);
const STRENGTHS = new Set(["moderate", "aggressive", "maximum"]);
const MODES = new Set(["tripwire", "scanner"]);

function resolveOptions(options: Php2ShellOptions): ResolvedPhp2ShellOptions {
  const profile = options.profile && PROFILES.has(options.profile) ? options.profile : "generic";
  const trapStrength =
    options.trapStrength && STRENGTHS.has(options.trapStrength) ? options.trapStrength : "aggressive";
  const mode = options.mode && MODES.has(options.mode) ? options.mode : "tripwire";
  return {
    enabled: options.enabled ?? true,
    profile,
    mode,
    pathPrefix: options.pathPrefix ?? "/",
    trapStrength,
    canaryTokens: [...(options.canaryTokens ?? [])],
    maxScanBytes: Math.max(8192, options.maxScanBytes ?? DEFAULT_MAX_SCAN_BYTES),
    pressureBytes: Math.max(1024, options.pressureBytes ?? DEFAULT_PRESSURE_BYTES),
    sessionTtlSeconds: Math.max(1, options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS),
    rateLimitPerMinute: Math.max(0, options.rateLimitPerMinute ?? DEFAULT_RATE_LIMIT_PER_MINUTE),
    maxPreviewBytes: Math.max(0, options.maxPreviewBytes ?? DEFAULT_MAX_PREVIEW_BYTES),
    now: options.now ?? Date.now,
  };
}

function headerMap(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function clientIpFrom(request: Request, context?: Php2ShellContext): string {
  if (context?.clientIp) return context.clientIp;
  const cf = request.headers.get("cf-connecting-ip");
  if (cf) return cf;
  const xff = request.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]!.trim();
  return request.headers.get("x-real-ip") ?? "unknown";
}

async function readPrefix(
  request: Request,
  limit: number,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!request.body || request.method === "GET" || request.method === "HEAD") {
    return { bytes: new Uint8Array(), truncated: false };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const take = Math.min(value.length, limit - total);
      chunks.push(value.subarray(0, take));
      total += take;
      if (take < value.length) {
        truncated = true;
        break;
      }
    }
  } finally {
    if (truncated) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return { bytes, truncated };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  try {
    const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    return fnv1a32(new TextDecoder().decode(bytes)).toString(16);
  }
}

function redact(value: string): string {
  return value.replace(
    /(authorization|cookie|password|secret|api[_-]?key|token)\s*[:=]\s*\S+/gi,
    "$1=[redacted]",
  );
}

function allowRate(clientIp: string, limit: number, now: number): boolean {
  if (limit <= 0) return true;
  const key = `ip-${fnv1a32(clientIp).toString(16)}`;
  const windowStart = now - 60_000;
  const hits = (rateWindows.get(key) ?? []).filter((t) => t >= windowStart);
  const allowed = hits.length < limit;
  if (allowed) hits.push(now);
  rateWindows.set(key, hits);
  return allowed;
}

function rateLimitedEvent(
  request: Request,
  url: URL,
  clientIp: string,
  profile: ResolvedPhp2ShellOptions["profile"],
  mode: ResolvedPhp2ShellOptions["mode"],
): Php2ShellEvent {
  return {
    event: "php2shell",
    version: 1,
    timestamp: new Date().toISOString(),
    sessionId: sessionKey(clientIp, request.headers.get("user-agent") ?? ""),
    profile,
    mode,
    phase: "recon",
    score: 0,
    tier: "observe",
    signals: [],
    request: {
      method: request.method,
      path: url.pathname,
      clientIpHash: fnv1a32(clientIp).toString(16),
      bodyBytes: 0,
      bodyTruncated: false,
      bodySha256: "",
      preview: "",
      headers: {
        "user-agent": request.headers.get("user-agent"),
        "content-type": request.headers.get("content-type"),
        "content-length": request.headers.get("content-length"),
        "transfer-encoding": request.headers.get("transfer-encoding"),
      },
      multipart: scanMultipart("", request.headers.get("content-type") ?? ""),
    },
    tarpit: { directive: false, repeats: 0, minWords: 0, ref: "" },
    response: { status: 503, phase: "recon" },
    canaryEchoed: false,
    rateLimited: true,
    estimatedAttackerTokens: 0,
  };
}

export function createPhp2ShellDecoy(options: Php2ShellOptions = {}): Php2ShellDecoy {
  const config = resolveOptions(options);
  const store = options.store ?? new MemoryPhp2ShellStore(config.sessionTtlSeconds, config.now);

  async function handleRequest(
    request: Request,
    context?: Php2ShellContext,
  ): Promise<Php2ShellResult | null> {
    if (!config.enabled) return null;
    const url = new URL(request.url);
    if (config.pathPrefix !== "/" && !url.pathname.startsWith(config.pathPrefix)) return null;

    const now = config.now();
    const clientIp = clientIpFrom(request, context);
    if (!allowRate(clientIp, config.rateLimitPerMinute, now)) {
      const event = rateLimitedEvent(request, url, clientIp, config.profile, config.mode);
      try {
        await options.onEvent?.(event);
      } catch {
        // Honeypot logging must never break serving.
      }
      return {
        response: new Response("Service Unavailable", {
          status: 503,
          headers: { "retry-after": "60" },
        }),
        event,
      };
    }

    const contentType = request.headers.get("content-type") ?? "";
    const contentLengthRaw = request.headers.get("content-length");
    const contentLength =
      contentLengthRaw && /^\d+$/.test(contentLengthRaw) ? Number(contentLengthRaw) : null;
    const isMultipart = contentType.toLowerCase().includes("multipart/form-data");
    const limit = isMultipart ? config.maxScanBytes : Math.min(config.maxScanBytes, 8192);
    const prefix = await readPrefix(request, limit);
    const bodyPrefix = new TextDecoder().decode(prefix.bytes);
    const headers = headerMap(request.headers);
    const userAgent = headers["user-agent"] ?? "";
    const sessionId = sessionKey(clientIp, userAgent);

    const info: Php2ShellRequestInfo = {
      method: request.method,
      path: url.pathname,
      query: url.search.replace(/^\?/, ""),
      headers,
      bodyPrefix,
      bodyBytes: contentLength ?? prefix.bytes.length,
      bodyTruncated: prefix.truncated,
      bodySha256: await sha256Hex(prefix.bytes),
      contentType,
      contentLength,
      transferEncoding: headers["transfer-encoding"] ?? "",
      userAgent,
      clientIp,
      multipart: scanMultipart(bodyPrefix, contentType),
    };

    const prior = await store.get(sessionId);
    const detection = detectPhp2Shell({
      request: info,
      prior: prior ?? null,
      profile: config.profile,
      pressureBytes: config.pressureBytes,
      canaries: config.canaryTokens,
    });
    const requestIndex = (prior?.requestCount ?? 0) + 1;
    const built = buildResponse({
      request: info,
      detection,
      prior: prior ?? null,
      requestIndex,
      sessionId,
      options: config,
    });
    const nextState = applyDetection(prior ?? null, detection, now);
    nextState.sessionId = sessionId;
    nextState.issuedCanaries = [
      ...new Set([...nextState.issuedCanaries, ...built.issuedCanaries]),
    ];
    if (built.scannerState) nextState.scanner = built.scannerState;
    if (built.estimatedAttackerTokens !== undefined) {
      nextState.estimatedAttackerTokens = built.estimatedAttackerTokens;
    }
    await store.set(sessionId, nextState, config.sessionTtlSeconds);

    const preview = redact(bodyPrefix).slice(0, config.maxPreviewBytes);
    const event: Php2ShellEvent = {
      event: "php2shell",
      version: 1,
      timestamp: new Date(now).toISOString(),
      sessionId,
      profile: config.profile,
      mode: config.mode,
      phase: detection.phase,
      score: detection.score,
      tier: detection.tier,
      signals: detection.signals,
      request: {
        method: info.method,
        path: info.path,
        clientIpHash: fnv1a32(clientIp).toString(16),
        bodyBytes: info.bodyBytes,
        bodyTruncated: info.bodyTruncated,
        bodySha256: info.bodySha256,
        preview,
        headers: {
          "user-agent": headers["user-agent"] ?? null,
          "content-type": headers["content-type"] ?? null,
          "content-length": headers["content-length"] ?? null,
          "transfer-encoding": headers["transfer-encoding"] ?? null,
        },
        multipart: info.multipart,
      },
      tarpit: built.tarpit,
      response: { status: built.response.status, phase: detection.responsePhase },
      canaryEchoed: detection.canaryEcho,
      rateLimited: false,
      scanner: built.scannerState
        ? {
            command: built.scannerState.lastCommand,
            depth: built.scannerState.depth,
            cwd: built.scannerState.cwd,
            estimatedTokens: built.scannerState.estimatedTokens,
          }
        : undefined,
      estimatedAttackerTokens: built.estimatedAttackerTokens ?? 0,
    };
    try {
      await options.onEvent?.(event);
    } catch {
      // Honeypot logging must never break serving.
    }
    return { response: built.response, event };
  }

  return {
    handle: async (request, context) => (await handleRequest(request, context))?.response ?? null,
    handleRequest,
  };
}
