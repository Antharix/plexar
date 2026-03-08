"""
Credential management for Plexar.

Supports multiple secret backends:
  - Environment variables  (recommended for CI/CD)
  - Plain text             (dev/lab only — never in production)
  - HashiCorp Vault        (enterprise)
  - File / .env            (local development)

Usage:
    # From environment variable
    creds = Credentials(username="admin", password_env="DEVICE_PASS")

    # Plaintext (lab only)
    creds = Credentials(username="admin", password="lab123")

    # SSH key
    creds = Credentials(username="admin", ssh_key_env="SSH_PRIVATE_KEY")
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field, model_validator, SecretStr

from plexar.core.exceptions import MissingCredentialError


class Credentials(BaseModel):
    """
    Device credentials with support for multiple secret backends.

    Secret fields accept either a direct value or an environment
    variable name (via the `_env` suffix fields).
    """

    model_config = {"arbitrary_types_allowed": True}

    username: str

    # Password — provide one of these
    password:     SecretStr | None = Field(default=None, description="Plaintext password (lab only)")
    password_env: str        | None = Field(default=None, description="Env var containing password")

    # SSH key — optional, takes precedence over password when set
    ssh_key:        str | None = Field(default=None, description="Path to SSH private key file")
    ssh_key_env:    str | None = Field(default=None, description="Env var containing SSH private key")
    ssh_passphrase: SecretStr | None = Field(default=None, description="SSH key passphrase")

    # Enable / privilege password
    enable_password:     SecretStr | None = Field(default=None)
    enable_password_env: str        | None = Field(default=None)

    @model_validator(mode="after")
    def validate_auth_method(self) -> "Credentials":
        """Ensure at least one authentication method is provided."""
        has_password = self.password is not None or self.password_env is not None
        has_key      = self.ssh_key  is not None or self.ssh_key_env  is not None
        if not has_password and not has_key:
            raise MissingCredentialError(
                f"Credentials for '{self.username}' require either a password or SSH key."
            )
        return self

    def get_password(self) -> str:
        """Resolve password from direct value or environment variable."""
        if self.password is not None:
            return self.password.get_secret_value()
        if self.password_env is not None:
            value = os.environ.get(self.password_env)
            if not value:
                raise MissingCredentialError(
                    f"Environment variable '{self.password_env}' is not set or empty."
                )
            return value
        raise MissingCredentialError("No password configured.")

    def get_ssh_key(self) -> str | None:
        """Resolve SSH key from file path or environment variable."""
        if self.ssh_key_env is not None:
            value = os.environ.get(self.ssh_key_env)
            if not value:
                raise MissingCredentialError(
                    f"Environment variable '{self.ssh_key_env}' is not set or empty."
                )
            return value
        return self.ssh_key

    def get_enable_password(self) -> str | None:
        """Resolve enable/privilege password."""
        if self.enable_password is not None:
            return self.enable_password.get_secret_value()
        if self.enable_password_env is not None:
            return os.environ.get(self.enable_password_env)
        return None

    def has_ssh_key(self) -> bool:
        return self.ssh_key is not None or self.ssh_key_env is not None

    def __repr__(self) -> str:
        return f"Credentials(username={self.username!r}, method={'ssh_key' if self.has_ssh_key() else 'password'})"
