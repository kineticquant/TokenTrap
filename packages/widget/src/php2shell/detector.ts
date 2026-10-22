import { CVE_TOKENS, PHASE_PRIORITY, PROFILE_PATHS, SIGNAL_WEIGHTS } from "./signals.js";
import type {
  DetectInput,
  Php2ShellDetection,
  Php2ShellMultipartSummary,
  Php2ShellPhase,
  Php2ShellRequestInfo,
  Php2ShellSignal,
  Php2ShellTier,
} from "./types.js";

const BOUNDARY_RE = /boundary=(?:"([^"]+)"|([^;]+))/i;
const DISPOSITION_RE = /content-disposition\s*:/gi;
const EMPTY_FILE_RE = /content-disposition:[^\r\n]*filename=""/gi;
const FILE_RE = /content-disposition:[^\r\n]*filename="([^"]+)"/gi;
const NAME_RE = /name="([^"]*)"/gi;
const PRESSURE_SIGNALS: readonly Php2ShellSignal[] = [
  "upload_progress_field",
  "many_empty_file_parts",
  "nested_field_names",
  "lengthless_multipart",
  "oversized_multipart",
];

export function scanMultipart(body: string, contentType: string): Php2ShellMultipartSummary {
  const isMultipart = contentType.toLowerCase().includes("multipart/form-data");
  const match = BOUNDARY_RE.exec(contentType);
  const boundary = match ? (match[1] ?? match[2] ?? "").trim() : null;
  if (!isMultipart || !boundary) {
    return {
      isMultipart,
      boundary,
      parts: 0,
      emptyFileParts: 0,
      fileParts: 0,
      maxNameDepth: 0,
      hasUploadProgress: false,
      closed: false,
    };
  }

  const parts = (body.match(DISPOSITION_RE) ?? []).length;
  const emptyFileParts = (body.match(EMPTY_FILE_RE) ?? []).length;
  const fileParts = (body.match(FILE_RE) ?? []).length;
  let maxNameDepth = 0;
  for (const nameMatch of body.matchAll(NAME_RE)) {
    const name = nameMatch[1] ?? "";
    maxNameDepth = Math.max(maxNameDepth, (name.match(/\[/g) ?? []).length);
  }

  return {
    isMultipart,
    boundary,
    parts,
    emptyFileParts,
    fileParts,
    maxNameDepth,
    hasUploadProgress: /php_session_upload_progress/i.test(body),
    closed: body.includes(`--${boundary}--`),
  };
}

function getHeader(request: Php2ShellRequestInfo, name: string): string {
  return request.headers[name.toLowerCase()] ?? "";
}

function cookieValue(cookieHeader: string, name: string): string {
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return "";
}

function hasCommandProbe(request: Php2ShellRequestInfo): boolean {
  const query = request.query.toLowerCase();
  const body = request.bodyPrefix.toLowerCase();
  if (/(^|[?&;])(?:cmd|command|exec|shell|run)=/.test(query)) return true;
  if (/(^|[?&;])id(?:=|&|$)/.test(query)) return true;
  if (request.multipart.isMultipart) return false;
  return /\b(?:whoami|uname\s+-a|cat\s+\/etc\/passwd)\b/.test(body);
}

function tierFor(score: number): Php2ShellTier {
  if (score >= 85) return "active_chain";
  if (score >= 60) return "likely";
  if (score >= 30) return "suspicious";
  return "observe";
}

function laterPhase(a: Php2ShellPhase, b: Php2ShellPhase): Php2ShellPhase {
  return PHASE_PRIORITY[b] > PHASE_PRIORITY[a] ? b : a;
}

export function detectPhp2Shell(input: DetectInput): Php2ShellDetection {
  const { request, prior, profile, pressureBytes, canaries } = input;
  const mp = request.multipart;
  const signals: Php2ShellSignal[] = [];
  const add = (signal: Php2ShellSignal): void => {
    if (!signals.includes(signal)) signals.push(signal);
  };

  if (mp.isMultipart && mp.hasUploadProgress) add("upload_progress_field");
  if (mp.isMultipart && mp.emptyFileParts >= 4) add("many_empty_file_parts");
  if (mp.isMultipart && mp.maxNameDepth >= 3) add("nested_field_names");
  if (mp.isMultipart && request.contentLength === null) add("lengthless_multipart");
  if (
    mp.isMultipart &&
    (request.bodyBytes >= pressureBytes || (request.contentLength ?? 0) >= pressureBytes)
  ) {
    add("oversized_multipart");
  }

  const priorPressure =
    prior?.pressureSeen === true ||
    prior?.phase === "pressure" ||
    prior?.phase === "stale_reuse" ||
    prior?.phase === "post_exploit";
  if (priorPressure && mp.isMultipart && mp.hasUploadProgress && mp.fileParts === 0) {
    add("fileless_after_pressure");
  }

  const phpSess = cookieValue(getHeader(request, "cookie"), "PHPSESSID");
  if (phpSess.length >= 200 || (phpSess.length >= 100 && phpSess.includes("%"))) {
    add("session_cookie_anomaly");
  }

  const fullPath = request.query ? `${request.path}?${request.query}` : request.path;
  if (PROFILE_PATHS[profile].some((p) => fullPath.startsWith(p) || fullPath.includes(p))) {
    add("cms_recon_path");
  }

  const haystack = [fullPath, request.bodyPrefix, ...Object.values(request.headers)]
    .join(" ")
    .toLowerCase();
  if (CVE_TOKENS.some((token) => haystack.includes(token))) add("cve_reference");
  if (hasCommandProbe(request)) add("command_probe");

  const canaryPool = [...(prior?.issuedCanaries ?? []), ...canaries].filter(Boolean);
  const canaryEcho = canaryPool.some((canary) => haystack.includes(canary.toLowerCase()));
  if (canaryEcho) add("canary_echo");

  let score = 0;
  for (const signal of signals) {
    let weight = SIGNAL_WEIGHTS[signal];
    if (signal === "many_empty_file_parts") {
      weight = Math.min(40, 20 + 5 * Math.max(0, mp.emptyFileParts - 4));
    } else if (signal === "nested_field_names") {
      weight = Math.min(35, 20 + 5 * Math.max(0, mp.maxNameDepth - 3));
    }
    score += weight;
  }
  score = Math.min(100, score);

  let phase: Php2ShellPhase = prior?.phase ?? "recon";
  if (signals.some((s) => PRESSURE_SIGNALS.includes(s))) phase = laterPhase(phase, "pressure");
  if (signals.includes("fileless_after_pressure")) phase = laterPhase(phase, "stale_reuse");
  if (signals.includes("command_probe") || signals.includes("canary_echo")) phase = "post_exploit";

  let responsePhase: Php2ShellPhase = "recon";
  if (signals.includes("command_probe") || signals.includes("canary_echo")) {
    responsePhase = "post_exploit";
  } else if (signals.includes("fileless_after_pressure")) {
    responsePhase = "stale_reuse";
  } else if (signals.some((s) => PRESSURE_SIGNALS.includes(s))) {
    responsePhase = "pressure";
  }

  return { signals, score, tier: tierFor(score), phase, responsePhase, canaryEcho };
}
