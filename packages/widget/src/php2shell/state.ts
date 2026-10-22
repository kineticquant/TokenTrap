import { fnv1a32 } from "../trapEngine.js";
import type { Php2ShellDetection, Php2ShellState, Php2ShellStore } from "./types.js";

export function sessionKey(clientIp: string, userAgent: string): string {
  return `p2s-${fnv1a32(`${clientIp}|${userAgent}`).toString(16)}`;
}

export function initialState(sessionId: string, now: number): Php2ShellState {
  return {
    sessionId,
    createdAt: now,
    lastSeen: now,
    requestCount: 0,
    maxScore: 0,
    phase: "recon",
    pressureSeen: false,
    uploadProgressSeen: false,
    issuedCanaries: [],
    canaryEchoed: false,
  };
}

export function applyDetection(
  prior: Php2ShellState | null,
  detection: Php2ShellDetection,
  now: number,
): Php2ShellState {
  const state = prior ?? initialState("p2s-unknown", now);
  return {
    ...state,
    lastSeen: now,
    requestCount: state.requestCount + 1,
    maxScore: Math.max(state.maxScore, detection.score),
    phase: detection.phase,
    pressureSeen: state.pressureSeen || detection.phase !== "recon",
    uploadProgressSeen:
      state.uploadProgressSeen || detection.signals.includes("upload_progress_field"),
    canaryEchoed: state.canaryEchoed || detection.canaryEcho,
  };
}

export class MemoryPhp2ShellStore implements Php2ShellStore {
  private readonly entries = new Map<string, { state: Php2ShellState; expiresAt: number }>();

  constructor(
    private readonly ttlSeconds = 86_400,
    private readonly now: () => number = Date.now,
    private readonly maxEntries = 10_000,
  ) {}

  get(key: string): Php2ShellState | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.state;
  }

  set(key: string, state: Php2ShellState, ttlSeconds = this.ttlSeconds): void {
    this.entries.set(key, { state, expiresAt: this.now() + ttlSeconds * 1000 });
    if (this.entries.size > this.maxEntries) {
      const now = this.now();
      for (const [k, v] of this.entries) {
        if (v.expiresAt <= now) this.entries.delete(k);
      }
    }
  }

  clear(): void {
    this.entries.clear();
  }
}
