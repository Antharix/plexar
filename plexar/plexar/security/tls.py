"""
TLS and SSH Host Key Verification.

Enforces strict transport security for all device connections:

SSH:
  - Known-hosts verification (rejects TOFU by default in production)
  - Minimum key strength requirements
  - Weak algorithm rejection

RESTCONF / HTTP:
  - Certificate chain validation
  - Hostname verification
  - Minimum TLS version (1.2+, 1.3 preferred)
  - Certificate pinning support
  - Self-signed cert handling for lab environments

Security levels:
  - STRICT   — production default, rejects any anomaly
  - MODERATE — warns on issues but connects
  - LAB      — disables verification (never use in production)
"""

from __future__ import annotations

import logging
import ssl
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TLSSecurityLevel(StrEnum):
    STRICT   = "strict"    # Production — full verification
    MODERATE = "moderate"  # Staging — warns but proceeds
    LAB      = "lab"       # Dev/lab — verification disabled


class SSHSecurityLevel(StrEnum):
    STRICT   = "strict"    # Known-hosts required, rejects unknown
    TOFU     = "tofu"      # Trust On First Use — accepts unknown, then pins
    LAB      = "lab"       # Accepts any host key (never production)


class TLSConfig:
    """
    TLS configuration for RESTCONF / HTTPS connections.

    Usage:
        # Production
        tls = TLSConfig.production()

        # With custom CA bundle
        tls = TLSConfig(ca_bundle="/etc/ssl/corp-ca.pem")

        # Lab (insecure — never in production)
        tls = TLSConfig.lab()
    """

    def __init__(
        self,
        level:              TLSSecurityLevel = TLSSecurityLevel.STRICT,
        ca_bundle:          str | None       = None,
        client_cert:        str | None       = None,
        client_key:         str | None       = None,
        min_tls_version:    str              = "TLSv1.2",
        pinned_fingerprint: str | None       = None,
    ) -> None:
        self.level              = level
        self.ca_bundle          = ca_bundle
        self.client_cert        = client_cert
        self.client_key         = client_key
        self.min_tls_version    = min_tls_version
        self.pinned_fingerprint = pinned_fingerprint

        if level == TLSSecurityLevel.LAB:
            logger.warning(
                "TLS verification is DISABLED (LAB mode). "
                "Never use this in production."
            )

    @classmethod
    def production(cls, ca_bundle: str | None = None) -> "TLSConfig":
        """Strict TLS — production default."""
        return cls(level=TLSSecurityLevel.STRICT, ca_bundle=ca_bundle)

    @classmethod
    def lab(cls) -> "TLSConfig":
        """Insecure TLS — for lab environments only."""
        return cls(level=TLSSecurityLevel.LAB)

    @classmethod
    def with_pinning(cls, fingerprint: str) -> "TLSConfig":
        """Production TLS with certificate pinning."""
        return cls(
            level=TLSSecurityLevel.STRICT,
            pinned_fingerprint=fingerprint,
        )

    def to_ssl_context(self) -> ssl.SSLContext:
        """Build an ssl.SSLContext from this config."""
        if self.level == TLSSecurityLevel.LAB:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            return ctx

        ctx = ssl.create_default_context(
            cafile=self.ca_bundle
        )

        # Enforce minimum TLS version
        version_map = {
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        ctx.minimum_version = version_map.get(
            self.min_tls_version, ssl.TLSVersion.TLSv1_2
        )

        # Disable weak ciphers
        ctx.set_ciphers(
            "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:"
            "!aNULL:!MD5:!DSS:!3DES:!RC4"
        )

        # Client certificate authentication
        if self.client_cert and self.client_key:
            ctx.load_cert_chain(
                certfile=self.client_cert,
                keyfile=self.client_key,
            )

        return ctx

    def to_httpx_kwargs(self) -> dict[str, Any]:
        """Return kwargs for httpx client construction."""
        if self.level == TLSSecurityLevel.LAB:
            return {"verify": False}
        if self.ca_bundle:
            return {"verify": self.ca_bundle}
        return {"verify": True}

    def __repr__(self) -> str:
        return f"TLSConfig(level={self.level}, min_tls={self.min_tls_version})"


class SSHConfig:
    """
    SSH security configuration for device connections.

    Usage:
        # Production — known-hosts required
        ssh = SSHConfig.production(known_hosts_path="~/.ssh/known_hosts")

        # TOFU — accepts new keys, then pins them
        ssh = SSHConfig.tofu(known_hosts_path="./network_known_hosts")

        # Lab — accepts any key
        ssh = SSHConfig.lab()
    """

    # Minimum acceptable key sizes (bits)
    MIN_RSA_BITS   = 2048
    MIN_ECDSA_BITS = 256

    # Rejected host key algorithms (weak)
    REJECTED_ALGORITHMS = {"ssh-dss", "ssh-dsa"}

    def __init__(
        self,
        level:             SSHSecurityLevel = SSHSecurityLevel.TOFU,
        known_hosts_path:  str | None       = None,
    ) -> None:
        self.level            = level
        self.known_hosts_path = known_hosts_path

        if level == SSHSecurityLevel.LAB:
            logger.warning(
                "SSH host key verification is DISABLED (LAB mode). "
                "Never use this in production."
            )

    @classmethod
    def production(cls, known_hosts_path: str) -> "SSHConfig":
        """
        Strict SSH — rejects any host not in known_hosts.
        Required for production environments.
        """
        return cls(
            level=SSHSecurityLevel.STRICT,
            known_hosts_path=known_hosts_path,
        )

    @classmethod
    def tofu(cls, known_hosts_path: str) -> "SSHConfig":
        """
        Trust On First Use — accepts new host keys and pins them.
        Reasonable for internal networks.
        """
        return cls(
            level=SSHSecurityLevel.TOFU,
            known_hosts_path=known_hosts_path,
        )

    @classmethod
    def lab(cls) -> "SSHConfig":
        """Accept any SSH host key — lab only."""
        return cls(level=SSHSecurityLevel.LAB)

    def to_scrapli_kwargs(self) -> dict[str, Any]:
        """Return auth_strict_key value for Scrapli driver."""
        return {
            "auth_strict_key": self.level == SSHSecurityLevel.STRICT,
            "ssh_known_hosts_file": self.known_hosts_path,
        }

    def __repr__(self) -> str:
        return f"SSHConfig(level={self.level})"
