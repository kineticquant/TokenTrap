/**
 * Session management: transcript + metadata for one honeypot conversation.
 * Client-side sessions are in-memory; the Worker and Python backends keep
 * server-side sessions with TTLs (KV / in-memory dict respectively).
 */

import type { ChatTurn, SessionSnapshot, TrapMeta } from "./types.js";

export class TrapSession {
  readonly id: string;
  readonly createdAt: number;
  private turns: ChatTurn[] = [];
  private lastMetaValue?: TrapMeta;

  constructor(id: string) {
    this.id = id;
    this.createdAt = Date.now();
  }

  get turnCount(): number {
    return this.turns.length;
  }

  add(role: ChatTurn["role"], content: string): ChatTurn {
    const turn: ChatTurn = { role, content, timestamp: Date.now() };
    this.turns.push(turn);
    return turn;
  }

  setLastMeta(meta: TrapMeta): void {
    this.lastMetaValue = meta;
  }

  snapshot(): SessionSnapshot {
    return {
      id: this.id,
      createdAt: this.createdAt,
      turns: [...this.turns],
      ...(this.lastMetaValue ? { lastMeta: this.lastMetaValue } : {}),
    };
  }
}

/** Simple TTL store used by edge/backend runtimes that lack KV. */
export interface ExpiringEntry<V> {
  value: V;
  expiresAt: number;
}

export class TtlMap<V> {
  private map = new Map<string, ExpiringEntry<V>>();
  constructor(private ttlMs: number) {}

  get(key: string): V | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: V, now = Date.now()): void {
    this.map.set(key, { value, expiresAt: now + this.ttlMs });
    if (this.map.size > 10_000) this.sweep(now);
  }

  delete(key: string): void {
    this.map.delete(key);
  }

  sweep(now = Date.now()): number {
    let removed = 0;
    for (const [k, v] of this.map) {
      if (now > v.expiresAt) {
        this.map.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    return this.map.size;
  }
}
