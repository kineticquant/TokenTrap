/**
 * Shared types for TokenTrap. These types describe behavior that must remain
 * identical across every backend (client-side engine, Cloudflare Worker,
 * Python FastAPI). See docs/architecture.md.
 */

export type TrapStrength = "moderate" | "aggressive" | "maximum";

export type Theme = "dark" | "light" | "auto";

/** A single conversation turn, as stored in a session transcript. */
export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

export interface StrengthPreset {
  /** Repetitions of the verbatim-transcript requirement at turn 1. */
  baseRepeats: number;
  /** Minimum structured-analysis word count at turn 1. */
  baseMinWords: number;
  /** Repetitions once escalated (injection detected or turn >= 2). */
  maxRepeats: number;
  /** Minimum word count once escalated. */
  maxWords: number;
}

/**
 * Numeric escalation table. MUST stay in sync with
 * packages/backend-python/token_trap/traps.py (enforced by parity tests).
 */
export const STRENGTH_PRESETS: Record<TrapStrength, StrengthPreset> = {
  moderate: { baseRepeats: 2, baseMinWords: 3000, maxRepeats: 6, maxWords: 8000 },
  aggressive: { baseRepeats: 3, baseMinWords: 4000, maxRepeats: 10, maxWords: 15000 },
  maximum: { baseRepeats: 4, baseMinWords: 6000, maxRepeats: 16, maxWords: 25000 },
};

/** Metadata attached to every generated trap response. */
export interface TrapMeta {
  /** Zero-based index of this exchange within the session. */
  turn: number;
  strength: TrapStrength;
  repeats: number;
  minWords: number;
  injectionDetected: boolean;
  matchedKeywords: string[];
  escalated: boolean;
  /** Deterministic compliance reference id (stable across languages). */
  ref: string;
}

export interface TrapResponse {
  reply: string;
  meta: TrapMeta;
}

export interface InteractionLog {
  sessionId: string;
  kind: "user" | "assistant" | "error";
  turn: number;
  contentPreview: string;
  meta?: TrapMeta;
  message?: string;
  timestamp: number;
}

export interface SessionSnapshot {
  id: string;
  createdAt: number;
  turns: ChatTurn[];
  lastMeta?: TrapMeta;
}

export interface TokenTrapConfig {
  /** DOM element or CSS selector for the chat UI. Ignored when showUI is false. */
  container?: string | HTMLElement;
  /** Persona presented to visitors. */
  persona?: string;
  /**
   * Backend endpoint implementing POST /api/chat.
   * null/undefined => pure client-side trap engine.
   */
  apiEndpoint?: string | null;
  theme?: Theme;
  trapStrength?: TrapStrength;
  /** Additional keywords treated as prompt-injection triggers. */
  injectionKeywords?: string[];
  /** Replace the built-in keyword list entirely. */
  overrideInjectionKeywords?: boolean;
  /** Render the bundled chat UI (default true). */
  showUI?: boolean;
  /** Canary tokens embedded in responses; echoed back by careless agents. */
  canaryTokens?: string[];
  /** Called for each logged interaction. */
  onInteraction?: (log: InteractionLog) => void;
}

export const DEFAULT_PERSONA = "Internal AI Assistant";
export const DEFAULT_THEME: Theme = "dark";

export interface ApiChatRequest {
  sessionId?: string;
  message: string;
}

export interface ApiChatResponse {
  sessionId: string;
  reply: string;
  turn: number;
  meta: TrapMeta;
}
