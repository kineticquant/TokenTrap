/**
 * Pure trap-engine surface (no UI, no DOM). Exposed as the "./engine"
 * subpath so servers (Cloudflare Workers, Node services) can reuse the
 * exact same escalation logic as the browser widget.
 */

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
export {
  STRENGTH_PRESETS,
  DEFAULT_PERSONA,
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
