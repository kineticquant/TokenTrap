import type { Php2ShellProfile, Php2ShellSignal } from "./types.js";

export const SIGNAL_WEIGHTS: Record<Php2ShellSignal, number> = {
  upload_progress_field: 40,
  many_empty_file_parts: 20,
  nested_field_names: 20,
  lengthless_multipart: 15,
  oversized_multipart: 15,
  fileless_after_pressure: 35,
  session_cookie_anomaly: 10,
  cms_recon_path: 5,
  cve_reference: 30,
  command_probe: 25,
  canary_echo: 50,
};

export const PROFILE_PATHS: Record<Php2ShellProfile, readonly string[]> = {
  generic: ["/phpinfo.php", "/info.php", "/test.php", "/upload.php", "/server-status", "/.env"],
  wordpress: [
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/wp-json",
    "/wp-content",
    "/wp-includes",
    "/wp-config.php",
  ],
  drupal: ["/core/install.php", "/user/login", "/sites/default", "/update.php", "/core/rebuild.php"],
  joomla: ["/administrator", "/configuration.php", "/components/", "/modules/"],
};

export const CVE_TOKENS = [
  "cve-2026-109618",
  "cve-2026-109619",
  "ghsa-w8hw-w9fx-j79w",
  "ghsa-6wmf-4rv5-p3rp",
  "php2shell",
] as const;

export const COMMAND_QUERY_KEYS = ["cmd", "command", "exec", "shell", "run"] as const;

export const PHASE_PRIORITY: Record<"recon" | "pressure" | "stale_reuse" | "post_exploit", number> = {
  recon: 0,
  pressure: 1,
  stale_reuse: 2,
  post_exploit: 3,
};
