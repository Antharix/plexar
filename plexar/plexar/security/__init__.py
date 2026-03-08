"""
Plexar Security Module.

Provides AI-grade security for network automation:

  sanitizer  — Input sanitization, prompt injection prevention
  audit      — Immutable audit trail for all operations
  secrets    — Multi-backend secrets management
  tls        — TLS/SSH transport security configuration
  rbac       — Role-based access control
"""

from plexar.security.sanitizer import (
    sanitize_hostname, sanitize_ip_address, sanitize_config_block,
    sanitize_for_llm, sanitize_jinja2_template, sanitize_template_variables,
    sanitize_file_path, redact_credentials, validate_device_output,
    check_for_prompt_injection, SecurityError, RateLimiter,
)
from plexar.security.audit import (
    AuditLogger, AuditEvent, AuditEventType, get_audit_logger, audit,
)
from plexar.security.secrets import (
    SecretsManager, SecretBackend, EnvBackend, VaultBackend,
    KeyringBackend, SecretNotFoundError, get_secrets_manager, configure_secrets,
)
from plexar.security.tls import (
    TLSConfig, SSHConfig, TLSSecurityLevel, SSHSecurityLevel,
)
from plexar.security.rbac import (
    Role, PlexarUser, RBACPolicy, require_role, set_current_user, get_current_user,
)
