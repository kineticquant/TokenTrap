/**
 * CDN / <script> entry. Builds to dist/cdn.global.js with globalName
 * "TokenTrap", exposing a FLAT surface so pages can call:
 *
 *   const trap = TokenTrap.init({ container: "#trap" })
 *
 * (The class's own static init is mirrored by the `init` alias; both work.)
 */

import { TokenTrap } from "./index.js";

export {
  TokenTrap,
  initTokenTrap as init,
  TRAP_API_TIMEOUT_MS,
} from "./index.js";
export { TrapEngine, planTurn, complianceRef, fnv1a32, newSessionId, AUDIT_POLICY_ID, AUDIT_POLICY_REV } from "./trapEngine.js";
export { detectInjection, DEFAULT_INJECTION_KEYWORDS } from "./detection.js";
export { STRENGTH_PRESETS, DEFAULT_PERSONA } from "./types.js";

export default TokenTrap;
