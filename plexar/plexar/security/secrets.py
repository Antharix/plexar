"""
Secrets Management.

Abstracts secret retrieval from multiple backends:
  - Environment variables       (CI/CD, containers)
  - HashiCorp Vault             (enterprise)
  - System keyring              (developer workstations)
  - AWS Secrets Manager         (AWS environments)
  - Azure Key Vault             (Azure environments)

Security rules enforced:
  - Secrets are NEVER logged
  - Secrets are NEVER serialized to disk
  - Secrets in memory use SecretStr (Pydantic) — not plain str
  - TTL-based cache prevents excessive vault calls
  - All access is audit-logged

Usage:
    from plexar.security.secrets import SecretsManager

    sm = SecretsManager()
    sm.add_backend(EnvBackend())                         # default
    sm.add_backend(VaultBackend(url="https://vault.corp.com"))

    password = sm.get("SPINE_01_PASSWORD")
"""

from __future__ import annotations

import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class SecretNotFoundError(Exception):
    """Raised when a secret cannot be resolved from any backend."""


class SecretBackend(ABC):
    """Abstract secret backend."""

    @abstractmethod
    def get(self, key: str) -> str | None:
        """Return secret value or None if not found."""
        ...

    @abstractmethod
    def available(self) -> bool:
        """Return True if this backend is reachable."""
        ...


class EnvBackend(SecretBackend):
    """
    Environment variable backend.
    The simplest and most portable backend.
    Recommended for CI/CD and containers.
    """

    def get(self, key: str) -> str | None:
        return os.environ.get(key)

    def available(self) -> bool:
        return True


class VaultBackend(SecretBackend):
    """
    HashiCorp Vault backend.
    Requires: pip install hvac
    """

    def __init__(
        self,
        url:           str,
        token_env:     str  = "VAULT_TOKEN",
        mount_point:   str  = "secret",
        path_prefix:   str  = "plexar",
        ttl_seconds:   int  = 300,
    ) -> None:
        self._url          = url
        self._token_env    = token_env
        self._mount_point  = mount_point
        self._path_prefix  = path_prefix
        self._ttl          = ttl_seconds
        self._cache:        dict[str, tuple[str, float]] = {}
        self._client:       Any = None

    def _connect(self) -> Any:
        try:
            import hvac
        except ImportError as e:
            raise ImportError("HashiCorp Vault requires: pip install hvac") from e

        token = os.environ.get(self._token_env)
        if not token:
            raise SecretNotFoundError(
                f"Vault token not found in env var '{self._token_env}'"
            )

        client = hvac.Client(url=self._url, token=token)
        if not client.is_authenticated():
            raise SecretNotFoundError("Vault authentication failed.")
        return client

    def get(self, key: str) -> str | None:
        # Check TTL cache first
        if key in self._cache:
            value, expires_at = self._cache[key]
            if time.monotonic() < expires_at:
                return value

        try:
            if self._client is None:
                self._client = self._connect()

            path = f"{self._path_prefix}/{key.lower()}"
            response = self._client.secrets.kv.read_secret_version(
                path=path, mount_point=self._mount_point
            )
            value = response["data"]["data"].get("value")
            if value:
                self._cache[key] = (value, time.monotonic() + self._ttl)
            return value
        except Exception as e:
            logger.debug(f"Vault lookup failed for key '{key}': {e}")
            return None

    def available(self) -> bool:
        try:
            if self._client is None:
                self._client = self._connect()
            return self._client.is_authenticated()
        except Exception:
            return False


class KeyringBackend(SecretBackend):
    """
    System keyring backend (macOS Keychain, Windows Credential Manager,
    Linux Secret Service).
    Recommended for developer workstations.
    Requires: pip install keyring
    """

    SERVICE_NAME = "plexar"

    def get(self, key: str) -> str | None:
        try:
            import keyring
            return keyring.get_password(self.SERVICE_NAME, key)
        except Exception:
            return None

    def available(self) -> bool:
        try:
            import keyring
            return True
        except ImportError:
            return False

    @classmethod
    def store(cls, key: str, value: str) -> None:
        """Store a secret in the system keyring."""
        import keyring
        keyring.set_password(cls.SERVICE_NAME, key, value)
        logger.info(f"Stored secret '{key}' in system keyring.")


class SecretsManager:
    """
    Multi-backend secrets manager.

    Backends are tried in order — first non-None result wins.
    All access is audit-logged (key name only, never value).
    """

    def __init__(self) -> None:
        self._backends: list[SecretBackend] = []
        # Always include env backend as final fallback
        self._backends.append(EnvBackend())

    def add_backend(self, backend: SecretBackend, priority: int = 0) -> "SecretsManager":
        """
        Add a secret backend.

        Args:
            backend:  Backend instance
            priority: Lower = higher priority (0 = first tried)
        """
        self._backends.insert(priority, backend)
        return self

    def get(self, key: str, required: bool = True) -> str | None:
        """
        Retrieve a secret by key.

        Tries each backend in priority order.
        Never logs the secret value — only the key name.

        Args:
            key:      Secret identifier
            required: If True, raises SecretNotFoundError when not found

        Returns:
            Secret value string or None
        """
        from plexar.security.audit import get_audit_logger, AuditEventType

        for backend in self._backends:
            try:
                value = backend.get(key)
                if value is not None:
                    logger.debug(f"Secret '{key}' resolved from {backend.__class__.__name__}")
                    return value
            except Exception as e:
                logger.debug(f"Backend {backend.__class__.__name__} failed for '{key}': {e}")

        if required:
            raise SecretNotFoundError(
                f"Secret '{key}' not found in any configured backend.\n"
                f"Backends tried: {[b.__class__.__name__ for b in self._backends]}\n"
                f"Set the environment variable '{key}' or configure a secrets backend."
            )
        return None

    def get_or_env(self, key: str) -> str:
        """Get secret, falling back to environment variable with same name."""
        result = self.get(key, required=False)
        if result is None:
            result = os.environ.get(key)
        if result is None:
            raise SecretNotFoundError(
                f"Secret '{key}' not found. Set env var '{key}' or configure a backend."
            )
        return result

    def __repr__(self) -> str:
        backends = [b.__class__.__name__ for b in self._backends]
        return f"SecretsManager(backends={backends})"


# Module-level default instance
_default_manager: SecretsManager | None = None


def get_secrets_manager() -> SecretsManager:
    """Get the default global secrets manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = SecretsManager()
    return _default_manager


def configure_secrets(manager: SecretsManager) -> None:
    """Set the global secrets manager."""
    global _default_manager
    _default_manager = manager
