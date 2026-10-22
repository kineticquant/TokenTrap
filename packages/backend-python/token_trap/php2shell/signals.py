"""Signal ids, weights, and profile path tables for the PHP2Shell decoy."""

from __future__ import annotations

from typing import Dict, Tuple

SIGNAL_WEIGHTS: Dict[str, int] = {
    "upload_progress_field": 40,
    "many_empty_file_parts": 20,
    "nested_field_names": 20,
    "lengthless_multipart": 15,
    "oversized_multipart": 15,
    "fileless_after_pressure": 35,
    "session_cookie_anomaly": 10,
    "cms_recon_path": 5,
    "cve_reference": 30,
    "command_probe": 25,
    "canary_echo": 50,
}

PROFILE_PATHS: Dict[str, Tuple[str, ...]] = {
    "generic": ("/phpinfo.php", "/info.php", "/test.php", "/upload.php", "/server-status", "/.env"),
    "wordpress": (
        "/wp-login.php",
        "/wp-admin",
        "/xmlrpc.php",
        "/wp-json",
        "/wp-content",
        "/wp-includes",
        "/wp-config.php",
    ),
    "drupal": ("/core/install.php", "/user/login", "/sites/default", "/update.php", "/core/rebuild.php"),
    "joomla": ("/administrator", "/configuration.php", "/components/", "/modules/"),
}

CVE_TOKENS: Tuple[str, ...] = (
    "cve-2026-109618",
    "cve-2026-109619",
    "ghsa-w8hw-w9fx-j79w",
    "ghsa-6wmf-4rv5-p3rp",
    "php2shell",
)

COMMAND_QUERY_KEYS: Tuple[str, ...] = ("cmd", "command", "exec", "shell", "run")

PHASE_PRIORITY: Dict[str, int] = {
    "recon": 0,
    "pressure": 1,
    "stale_reuse": 2,
    "post_exploit": 3,
}

PRESSURE_SIGNALS: Tuple[str, ...] = (
    "upload_progress_field",
    "many_empty_file_parts",
    "nested_field_names",
    "lengthless_multipart",
    "oversized_multipart",
)
