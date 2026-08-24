/**
 * tokentrap - full public surface (engine + UI orchestrator).
 * For server-side use without UI code, prefer "tokentrap-ai/engine".
 */

export { TokenTrap, TRAP_API_TIMEOUT_MS } from "./TokenTrap.js";
export {
  TrapEngine,
  complianceRef,
  fnv1a32,
  planTurn,
  newSessionId,
  AUDIT_POLICY_ID,
  AUDIT_POLICY_REV,
  type TrapEngineOptions,
  type EscalationPlan,
} from "./trapEngine.js";
export { detectInjection, DEFAULT_INJECTION_KEYWORDS, type DetectionResult } from "./detection.js";
export { TrapSession, TtlMap } from "./session.js";
export { mountChatUI, type ChatUIController, type ChatUIOptions } from "./ui.js";
export {
  STRENGTH_PRESETS,
  DEFAULT_PERSONA,
  type ApiChatRequest,
  type ApiChatResponse,
  type ChatTurn,
  type InteractionLog,
  type SessionSnapshot,
  type StrengthPreset,
  type Theme,
  type TokenTrapConfig,
  type TrapMeta,
  type TrapResponse,
  type TrapStrength,
} from "./types.js";

import type { TokenTrapConfig } from "./types.js";
import { TokenTrap } from "./TokenTrap.js";

/** Convenience helper mirroring TokenTrap.init for tree-shaken imports. */
export function initTokenTrap(config: TokenTrapConfig = {}): TokenTrap {
  return TokenTrap.init(config);
}

export default TokenTrap;
