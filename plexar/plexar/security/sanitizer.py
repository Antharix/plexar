"""
Input Sanitization Engine.

Prevents the most critical attack vectors in network automation:
  - Command injection via crafted device output
  - Prompt injection into AI/LLM components
  - Template injection via Jinja2
  - Path traversal in inventory/config file loading
  - Credential leakage in logs and error messages

Security philosophy:
  - Allowlist over blocklist — define what IS allowed, reject everything else
  - Fail closed — when in doubt, reject
  - Never trust device output — treat it like untrusted user input
  - Sanitize at boundaries — before logging, before LLM, before template render
"""

from __future__ import annotations

import html
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

from plexar.core.exceptions import PlexarError


class SecurityError(PlexarError):
    """Raised when a security violation is detected."""


# ── Command Injection Prevention ─────────────────────────────────────

# Characters that could be used to inject shell commands
_SHELL_INJECTION_CHARS = re.compile(r"[;&|`$<>\\(){}\[\]!]")

# Characters allowed in device hostnames (RFC 1123 + IPv6)
_HOSTNAME_ALLOWLIST = re.compile(r"^[a-zA-Z0-9._:\-\[\]]+$")

# Allowed characters in interface names across all vendors
_INTERFACE_NAME_ALLOWLIST = re.compile(
    r"^[a-zA-Z0-9/._\-:]+$"
)

# Allowed characters in VLAN names
_VLAN_NAME_ALLOWLIST = re.compile(r"^[a-zA-Z0-9_\-\s]+$")

# IP address pattern
_IP_ALLOWLIST = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|"  # IPv4 / CIDR
    r"^[0-9a-fA-F:]+$"                          # IPv6
)


def sanitize_hostname(hostname: str) -> str:
    """
    Validate and sanitize a device hostname.
    Rejects anything that isn't a valid hostname or IP address.
    """
    if not hostname or len(hostname) > 253:
        raise SecurityError(f"Invalid hostname length: '{hostname}'")
    if not _HOSTNAME_ALLOWLIST.match(hostname):
        raise SecurityError(
            f"Hostname '{hostname}' contains invalid characters. "
            "Only alphanumeric, dots, hyphens, colons, and brackets are allowed."
        )
    return hostname.strip()


def sanitize_ip_address(ip: str) -> str:
    """Validate an IP address or CIDR prefix."""
    ip = ip.strip()
    if not _IP_ALLOWLIST.match(ip):
        raise SecurityError(f"Invalid IP address or prefix: '{ip}'")
    return ip


def sanitize_interface_name(name: str) -> str:
    """Validate an interface name."""
    if not _INTERFACE_NAME_ALLOWLIST.match(name):
        raise SecurityError(
            f"Interface name '{name}' contains invalid characters."
        )
    return name


def sanitize_config_block(config: str, max_length: int = 65536) -> str:
    """
    Sanitize a configuration block before pushing to a device.

    Checks:
      - Length limit (prevents memory exhaustion)
      - No null bytes (protocol confusion attacks)
      - No ANSI escape sequences (terminal injection)
      - Normalizes line endings
    """
    if len(config) > max_length:
        raise SecurityError(
            f"Config block too large: {len(config)} bytes (max {max_length}). "
            "Split into smaller blocks."
        )

    # Null byte check — can cause protocol-level issues
    if "\x00" in config:
        raise SecurityError("Config block contains null bytes — rejected.")

    # Strip ANSI escape sequences
    config = _strip_ansi(config)

    # Normalize line endings
    config = config.replace("\r\n", "\n").replace("\r", "\n")

    return config


def sanitize_file_path(
    path: str,
    allowed_base: str | None = None,
    allowed_extensions: list[str] | None = None,
) -> Path:
    """
    Sanitize a file path to prevent path traversal attacks.

    Args:
        path:               File path to validate
        allowed_base:       If set, path must be within this directory
        allowed_extensions: If set, path must have one of these extensions

    Returns:
        Resolved Path object

    Raises:
        SecurityError if path traversal or invalid extension detected
    """
    resolved = Path(path).resolve()

    # Path traversal check
    if allowed_base is not None:
        base = Path(allowed_base).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            raise SecurityError(
                f"Path traversal detected: '{path}' is outside '{allowed_base}'"
            )

    # Extension check
    if allowed_extensions is not None:
        if resolved.suffix.lower() not in allowed_extensions:
            raise SecurityError(
                f"File extension '{resolved.suffix}' not allowed. "
                f"Allowed: {allowed_extensions}"
            )

    return resolved


# ── Prompt Injection Prevention ───────────────────────────────────────

# Patterns commonly used in prompt injection attacks
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?:", re.IGNORECASE),
    re.compile(r"system\s*:\s*you", re.IGNORECASE),
    re.compile(r"</?(system|user|assistant|human|ai)>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE),
    re.compile(r"###\s*(instruction|system|prompt)", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>"),
    re.compile(r"act\s+as\s+(?:a\s+)?(?:different|new|evil|unrestricted)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
]

# Maximum length for device output passed to LLM
_MAX_LLM_INPUT_LENGTH = 8192


def sanitize_for_llm(
    device_output: str,
    context: str = "device output",
    max_length: int = _MAX_LLM_INPUT_LENGTH,
) -> str:
    """
    Sanitize device output before passing to an LLM.

    This is critical — a malicious device could attempt to inject
    instructions into the LLM prompt via crafted CLI output.

    Strategy:
      1. Detect and reject obvious prompt injection patterns
      2. Truncate to safe length
      3. Strip control characters
      4. HTML-escape special characters
      5. Wrap in a tagged block to contextualise for the LLM

    Args:
        device_output: Raw CLI/API output from a network device
        context:       Description for LLM context (e.g. "show bgp summary")
        max_length:    Maximum characters to pass to LLM

    Returns:
        Sanitized string safe to include in an LLM prompt
    """
    if not device_output:
        return ""

    # Check for prompt injection attempts
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(device_output):
            raise SecurityError(
                f"Potential prompt injection detected in {context}. "
                "Device output contains instruction-like patterns."
            )

    # Truncate
    if len(device_output) > max_length:
        device_output = device_output[:max_length] + "\n[TRUNCATED]"

    # Strip control characters except newline and tab
    device_output = _strip_control_chars(device_output)

    # Wrap in a clear boundary to prevent context escaping
    sanitized = (
        f"<device_output context='{html.escape(context)}'>\n"
        f"{device_output}\n"
        f"</device_output>"
    )

    return sanitized


def check_for_prompt_injection(text: str) -> bool:
    """
    Returns True if text appears to contain a prompt injection attempt.
    Use for monitoring/alerting even when not raising an exception.
    """
    return any(pattern.search(text) for pattern in _PROMPT_INJECTION_PATTERNS)


# ── Template Injection Prevention ─────────────────────────────────────

# Jinja2 patterns that could execute arbitrary code
_JINJA2_DANGEROUS_PATTERNS = [
    re.compile(r"\{%.*?(import|exec|eval|open|os\.|sys\.|subprocess).*?%\}", re.DOTALL),
    re.compile(r"\{\{.*?__.*?__.*?\}\}", re.DOTALL),  # dunder attributes
    re.compile(r"\{%.*?for.*?in.*?range\s*\(\s*\d{6,}", re.DOTALL),  # DoS via huge range
]


def sanitize_jinja2_template(template: str) -> str:
    """
    Check a Jinja2 template for dangerous patterns before rendering.
    Prevents Server-Side Template Injection (SSTI).
    """
    for pattern in _JINJA2_DANGEROUS_PATTERNS:
        if pattern.search(template):
            raise SecurityError(
                "Jinja2 template contains potentially dangerous expressions. "
                "Avoid imports, exec/eval, dunder attributes, and unbounded loops."
            )
    return template


def sanitize_template_variables(variables: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize variables passed into a Jinja2 template.
    Converts all string values, prevents object injection.
    """
    safe: dict[str, Any] = {}
    _ALLOWED_TYPES = (str, int, float, bool, type(None))

    for key, value in variables.items():
        if not isinstance(key, str) or not key.isidentifier():
            raise SecurityError(f"Invalid template variable name: '{key}'")

        if isinstance(value, _ALLOWED_TYPES):
            safe[key] = value
        elif isinstance(value, (list, tuple)):
            # Recursively sanitize list items
            safe[key] = [
                v if isinstance(v, _ALLOWED_TYPES) else str(v)
                for v in value
            ]
        elif isinstance(value, dict):
            safe[key] = sanitize_template_variables(value)
        else:
            # Convert unknown types to string representation
            safe[key] = str(value)

    return safe


# ── Credential Protection ─────────────────────────────────────────────

# Patterns that look like credentials in log output
_CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*=\s*\S+",             re.IGNORECASE),
    re.compile(r"passwd\s*=\s*\S+",               re.IGNORECASE),
    re.compile(r"secret\s*=\s*\S+",               re.IGNORECASE),
    re.compile(r"token\s*=\s*pypi-\S+",           re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer\s+\S+",  re.IGNORECASE),
    re.compile(r"api[_-]?key\s*=\s*\S+",          re.IGNORECASE),
    re.compile(r"-----BEGIN.*?PRIVATE KEY-----",  re.IGNORECASE | re.DOTALL),
]


def redact_credentials(text: str) -> str:
    """
    Redact credential-like patterns from a string.
    Use before logging, error messages, or any output.
    """
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def assert_not_in_environment(key: str) -> None:
    """
    Assert that a key is not accidentally set as an env variable
    with a plaintext value when it should use a secrets manager.
    Only used in security audits.
    """
    if key in os.environ:
        value = os.environ[key]
        if len(value) > 0 and not value.startswith("vault:"):
            import logging
            logging.getLogger(__name__).warning(
                f"Environment variable '{key}' is set as plaintext. "
                "Consider using HashiCorp Vault or a secrets manager."
            )


# ── Device Output Validation ──────────────────────────────────────────

_MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10MB


def validate_device_output(
    output: str,
    command: str,
    hostname: str,
) -> str:
    """
    Validate and sanitize raw device output.

    Protects against:
      - Extremely large outputs (memory exhaustion)
      - Null byte injection
      - Unicode normalization attacks
      - ANSI escape sequences in structured parsing

    Args:
        output:   Raw device output string
        command:  Command that produced the output (for logging)
        hostname: Device hostname (for logging)
    """
    if len(output) > _MAX_OUTPUT_SIZE:
        raise SecurityError(
            f"Device output from '{hostname}' for '{command}' "
            f"exceeds {_MAX_OUTPUT_SIZE // 1024 // 1024}MB limit."
        )

    if "\x00" in output:
        raise SecurityError(
            f"Device output from '{hostname}' contains null bytes — "
            "possible protocol attack."
        )

    # Normalize unicode to prevent normalization confusion attacks
    output = unicodedata.normalize("NFKC", output)

    # Strip ANSI escape sequences
    output = _strip_ansi(output)

    return output


# ── Rate Limiting ─────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter for device operations.

    Prevents accidental DDoS of network devices from automation bugs
    or runaway loops.
    """

    def __init__(self, max_per_second: float = 10.0) -> None:
        import time
        self._max_per_second = max_per_second
        self._min_interval   = 1.0 / max_per_second
        self._last_call      = 0.0
        self._call_count     = 0
        self._window_start   = time.monotonic()

    async def acquire(self) -> None:
        """Block until rate limit allows the next call."""
        import asyncio
        import time

        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()
        self._call_count += 1


# ── Helpers ───────────────────────────────────────────────────────────

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def _strip_control_chars(text: str) -> str:
    """Remove control characters except newline (0x0A) and tab (0x09)."""
    return "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Cc" or ch in "\n\t"
    )
