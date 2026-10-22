import type { TrapStrength } from "../types.js";

export type Php2ShellProfile = "generic" | "wordpress" | "drupal" | "joomla";
export type Php2ShellMode = "tripwire" | "scanner";
export type Php2ShellPhase = "recon" | "pressure" | "stale_reuse" | "post_exploit";
export type Php2ShellTier = "observe" | "suspicious" | "likely" | "active_chain";
export type Php2ShellSignal =
  | "upload_progress_field"
  | "many_empty_file_parts"
  | "nested_field_names"
  | "lengthless_multipart"
  | "oversized_multipart"
  | "fileless_after_pressure"
  | "session_cookie_anomaly"
  | "cms_recon_path"
  | "cve_reference"
  | "command_probe"
  | "canary_echo";

export const DEFAULT_MAX_SCAN_BYTES = 2 * 1024 * 1024;
export const DEFAULT_PRESSURE_BYTES = 1024 * 1024;
export const DEFAULT_SESSION_TTL_SECONDS = 86_400;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 120;
export const DEFAULT_MAX_PREVIEW_BYTES = 2048;

export interface Php2ShellMultipartSummary {
  isMultipart: boolean;
  boundary: string | null;
  parts: number;
  emptyFileParts: number;
  fileParts: number;
  maxNameDepth: number;
  hasUploadProgress: boolean;
  closed: boolean;
}

export interface Php2ShellRequestInfo {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  bodyPrefix: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  bodySha256: string;
  contentType: string;
  contentLength: number | null;
  transferEncoding: string;
  userAgent: string;
  clientIp: string;
  multipart: Php2ShellMultipartSummary;
}

export interface Php2ShellState {
  sessionId: string;
  createdAt: number;
  lastSeen: number;
  requestCount: number;
  maxScore: number;
  phase: Php2ShellPhase;
  pressureSeen: boolean;
  uploadProgressSeen: boolean;
  issuedCanaries: string[];
  canaryEchoed: boolean;
  /** Present when scanner mode has opened a fake shell. */
  scanner?: Php2ShellScannerState;
  /** Rough lower bound on tokens the remote agent has spent in scanner mode. */
  estimatedAttackerTokens?: number;
}

export interface Php2ShellScannerState {
  cwd: string;
  hostname: string;
  depth: number;
  commandCount: number;
  lastCommand: string | null;
  responseBytes: number;
  estimatedTokens: number;
}

export interface Php2ShellDetection {
  signals: Php2ShellSignal[];
  score: number;
  tier: Php2ShellTier;
  phase: Php2ShellPhase;
  responsePhase: Php2ShellPhase;
  canaryEcho: boolean;
}

export interface Php2ShellTarpit {
  directive: boolean;
  repeats: number;
  minWords: number;
  ref: string;
}

export interface Php2ShellEvent {
  event: "php2shell";
  version: 1;
  timestamp: string;
  sessionId: string;
  profile: Php2ShellProfile;
  mode: Php2ShellMode;
  phase: Php2ShellPhase;
  score: number;
  tier: Php2ShellTier;
  signals: Php2ShellSignal[];
  request: {
    method: string;
    path: string;
    clientIpHash: string;
    bodyBytes: number;
    bodyTruncated: boolean;
    bodySha256: string;
    preview: string;
    headers: Record<string, string | null>;
    multipart: Php2ShellMultipartSummary;
  };
  tarpit: Php2ShellTarpit;
  response: { status: number; phase: Php2ShellPhase };
  canaryEchoed: boolean;
  rateLimited: boolean;
  scanner?: {
    command: string | null;
    depth: number;
    cwd: string;
    estimatedTokens: number;
  };
  estimatedAttackerTokens: number;
}

export interface Php2ShellStore {
  get(key: string): Promise<Php2ShellState | undefined> | Php2ShellState | undefined;
  set(key: string, state: Php2ShellState, ttlSeconds: number): Promise<void> | void;
}

export interface Php2ShellOptions {
  enabled?: boolean;
  profile?: Php2ShellProfile;
  mode?: Php2ShellMode;
  pathPrefix?: string;
  trapStrength?: TrapStrength;
  canaryTokens?: readonly string[];
  maxScanBytes?: number;
  pressureBytes?: number;
  sessionTtlSeconds?: number;
  rateLimitPerMinute?: number;
  maxPreviewBytes?: number;
  store?: Php2ShellStore;
  now?: () => number;
  onEvent?: (event: Php2ShellEvent) => void | Promise<void>;
}

export interface ResolvedPhp2ShellOptions {
  enabled: boolean;
  profile: Php2ShellProfile;
  mode: Php2ShellMode;
  pathPrefix: string;
  trapStrength: TrapStrength;
  canaryTokens: string[];
  maxScanBytes: number;
  pressureBytes: number;
  sessionTtlSeconds: number;
  rateLimitPerMinute: number;
  maxPreviewBytes: number;
  now: () => number;
}

export interface Php2ShellContext {
  clientIp?: string;
}

export interface Php2ShellResult {
  response: Response;
  event: Php2ShellEvent;
}

export interface Php2ShellDecoy {
  handle(request: Request, context?: Php2ShellContext): Promise<Response | null>;
  handleRequest(request: Request, context?: Php2ShellContext): Promise<Php2ShellResult | null>;
}

export interface DetectInput {
  request: Php2ShellRequestInfo;
  prior: Php2ShellState | null;
  profile: Php2ShellProfile;
  pressureBytes: number;
  canaries: readonly string[];
}
