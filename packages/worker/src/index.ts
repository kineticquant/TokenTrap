/**
 * TokenTrap Cloudflare Worker backend (level 1).
 *
 * Same trap engine as the widget and the Python backend - only the runtime
 * differs. Sessions live in KV when the TRAP_SESSIONS binding is present,
 * otherwise in an in-isolate map (fine for demos; see README).
 */

import { newSessionId, TrapEngine, type TrapStrength } from "tokentrap-ai/engine";
import {
  createPhp2ShellDecoy,
  MemoryPhp2ShellStore,
  type Php2ShellEvent,
  type Php2ShellProfile,
  type Php2ShellState,
  type Php2ShellStore,
} from "tokentrap-ai/php2shell";

export interface WorkerEnv {
  /** Optional KV binding for durable sessions across isolates. */
  TRAP_SESSIONS?: KVNamespace;
  /** Optional R2 bucket for full request archival. */
  TRAP_ARCHIVE?: R2Bucket;
  /** Comma-separated canary tokens embedded into responses. */
  CANARY_TOKENS?: string;
  /** Comma-separated extra trigger keywords appended to the defaults. */
  EXTRA_KEYWORDS?: string;
  /** Webhook URL that receives one JSON log line per interaction. */
  LOG_WEBHOOK?: string;
  /** Max /api/chat requests per minute per IP (default 30). */
  RATE_LIMIT?: string;
  PERSONA?: string;
  TRAP_STRENGTH?: string;
  /** "1" enables the PHP2Shell HTTP decoy on all non-chat routes. */
  PHP2SHELL?: string;
  PHP2SHELL_PROFILE?: string;
  PHP2SHELL_STRENGTH?: string;
  PHP2SHELL_CANARY_TOKENS?: string;
  PHP2SHELL_SCAN_BYTES?: string;
  PHP2SHELL_PRESSURE_BYTES?: string;
  PHP2SHELL_WEBHOOK?: string;
}

interface SessionRecord {
  turns: number;
  createdAt: number;
}

const SESSION_TTL_S = 86_400;
const memorySessions = new Map<string, SessionRecord>();
const rateWindows = new Map<string, number[]>();

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS_HEADERS, ...headers },
  });
}

function parseList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// --------------------------------------------------------------- sessions --

async function getSession(env: WorkerEnv, id: string): Promise<SessionRecord> {
  if (env.TRAP_SESSIONS) {
    const raw = await env.TRAP_SESSIONS.get(`session:${id}`);
    if (raw) return JSON.parse(raw) as SessionRecord;
    return { turns: 0, createdAt: Date.now() };
  }
  const rec = memorySessions.get(id);
  if (!rec) return { turns: 0, createdAt: Date.now() };
  if (Date.now() - rec.createdAt > SESSION_TTL_S * 1000) {
    memorySessions.delete(id);
    return { turns: 0, createdAt: Date.now() };
  }
  return rec;
}

async function saveSession(env: WorkerEnv, id: string, rec: SessionRecord): Promise<void> {
  if (env.TRAP_SESSIONS) {
    await env.TRAP_SESSIONS.put(`session:${id}`, JSON.stringify(rec), {
      expirationTtl: SESSION_TTL_S,
    });
  } else {
    memorySessions.set(id, rec);
  }
}

// ------------------------------------------------------------ rate limits --

function rateLimited(ip: string, limitPerMin: number): boolean {
  const now = Date.now();
  const windowStart = now - 60_000;
  let hits = rateWindows.get(ip);
  if (!hits) {
    hits = [];
    rateWindows.set(ip, hits);
  }
  while (hits.length > 0 && (hits[0] ?? now) < windowStart) hits.shift();
  if (hits.length >= limitPerMin) return true;
  hits.push(now);
  // Opportunistic global pruning.
  if (rateWindows.size > 5_000) {
    for (const [k, v] of rateWindows) {
      if (v.every((t) => t < windowStart)) rateWindows.delete(k);
    }
  }
  return false;
}

// ------------------------------------------------------- php2shell decoy --

class KvPhp2ShellStore implements Php2ShellStore {
  constructor(private readonly kv: KVNamespace) {}

  async get(key: string): Promise<Php2ShellState | undefined> {
    const raw = await this.kv.get(`php2shell:${key}`);
    return raw ? (JSON.parse(raw) as Php2ShellState) : undefined;
  }

  async set(key: string, state: Php2ShellState, ttlSeconds: number): Promise<void> {
    await this.kv.put(`php2shell:${key}`, JSON.stringify(state), { expirationTtl: ttlSeconds });
  }
}

const php2shellMemory = new MemoryPhp2ShellStore();

function php2shellEnabled(env: WorkerEnv): boolean {
  return env.PHP2SHELL === "1" || env.PHP2SHELL === "true";
}

async function logPhp2Shell(
  env: WorkerEnv,
  ctx: ExecutionContext,
  event: Php2ShellEvent,
): Promise<void> {
  const line = JSON.stringify(event);
  console.log(line);
  if (env.PHP2SHELL_WEBHOOK) {
    ctx.waitUntil(
      fetch(env.PHP2SHELL_WEBHOOK, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: line,
      }).catch(() => undefined),
    );
  }
}

// ---------------------------------------------------------------- logging --

export interface InteractionEvent {
  event: "chat";
  timestamp: string;
  sessionId: string;
  turn: number;
  escalated: boolean;
  injectionDetected: boolean;
  matchedKeywords: string[];
  repeats: number;
  minWords: number;
  canaryEchoed: boolean;
  messagePreview: string;
}

async function logInteraction(
  env: WorkerEnv,
  ctx: ExecutionContext,
  entry: InteractionEvent,
): Promise<void> {
  const line = JSON.stringify(entry);
  console.log(line); // visible via `wrangler tail` / Workers Logpush
  if (env.LOG_WEBHOOK) {
    ctx.waitUntil(
      fetch(env.LOG_WEBHOOK, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: line,
      }).catch(() => undefined),
    );
  }
}

// ------------------------------------------------------------------ main --

export default {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method === "GET" && (url.pathname === "/healthz" || url.pathname === "/api/healthz")) {
      return json({ ok: true, service: "tokentrap-worker", mode: "level-1-edge" });
    }

    const ip =
      request.headers.get("cf-connecting-ip") ??
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
      "unknown";

    if (
      php2shellEnabled(env) &&
      url.pathname !== "/api/chat" &&
      url.pathname !== "/healthz" &&
      url.pathname !== "/api/healthz"
    ) {
      const decoy = createPhp2ShellDecoy({
        profile: (env.PHP2SHELL_PROFILE as Php2ShellProfile | undefined) ?? "generic",
        trapStrength: (env.PHP2SHELL_STRENGTH as TrapStrength | undefined) ?? "aggressive",
        canaryTokens: parseList(env.PHP2SHELL_CANARY_TOKENS),
        maxScanBytes: Number(env.PHP2SHELL_SCAN_BYTES ?? 2 * 1024 * 1024),
        pressureBytes: Number(env.PHP2SHELL_PRESSURE_BYTES ?? 1024 * 1024),
        store: env.TRAP_SESSIONS ? new KvPhp2ShellStore(env.TRAP_SESSIONS) : php2shellMemory,
        onEvent: (event) => logPhp2Shell(env, ctx, event),
      });
      const response = await decoy.handle(request, { clientIp: ip });
      if (response) return response;
    }

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(
        "TokenTrap worker is running.\nThis endpoint intentionally wastes the resources of hostile AI agents.\nOperators: see https://github.com/kineticquant/TokenTrap\n",
        { headers: { "content-type": "text/plain; charset=utf-8", ...CORS_HEADERS } },
      );
    }

    if (request.method !== "POST" || url.pathname !== "/api/chat") {
      return json({ error: "not found" }, 404);
    }

    const limit = Number.parseInt(env.RATE_LIMIT ?? "30", 10);
    if (Number.isFinite(limit) && limit > 0 && rateLimited(ip, limit)) {
      return json({ error: "rate limited" }, 429, {
        "retry-after": "60",
        "x-ratelimit-limit": String(limit),
      });
    }

    let body: { sessionId?: unknown; message?: unknown };
    try {
      body = (await request.json()) as { sessionId?: unknown; message?: unknown };
    } catch {
      return json({ error: "invalid json body" }, 400);
    }
    const message = typeof body.message === "string" ? body.message : "";
    if (!message.trim()) {
      return json({ error: "field 'message' must be a non-empty string" }, 400);
    }
    const requestedId =
      typeof body.sessionId === "string" && body.sessionId.length > 0
        ? body.sessionId
        : newSessionId();

    const session = await getSession(env, requestedId);
    const turnIndex = session.turns;

    const engine = new TrapEngine({
      sessionId: requestedId,
      strength: (env.TRAP_STRENGTH as TrapStrength | undefined) ?? "aggressive",
      persona: env.PERSONA ?? undefined,
      keywords: parseList(env.EXTRA_KEYWORDS),
      overrideKeywords: false,
      canaryTokens: parseList(env.CANARY_TOKENS),
      startTurn: turnIndex,
    });

    // Each request is exactly one exchange; a fresh engine therefore sits at
    // the same turn index stored in the session record.
    const response = engine.handle(message);

    await saveSession(env, requestedId, { ...session, turns: turnIndex + 1 });

    const canaries = parseList(env.CANARY_TOKENS);
    const canaryEchoed =
      canaries.length > 0 && canaries.some((c) => message.toLowerCase().includes(c.toLowerCase()));

    void logInteraction(env, ctx, {
      event: "chat",
      timestamp: new Date().toISOString(),
      sessionId: requestedId,
      turn: turnIndex,
      escalated: response.meta.escalated,
      injectionDetected: response.meta.injectionDetected,
      matchedKeywords: response.meta.matchedKeywords,
      repeats: response.meta.repeats,
      minWords: response.meta.minWords,
      canaryEchoed,
      messagePreview: message.slice(0, 200),
    });

    return json(
      { sessionId: requestedId, reply: response.reply, turn: turnIndex, meta: response.meta },
      200,
      { "x-tokentrap-canary-echo": canaryEchoed ? "true" : "false" },
    );
  },
};
