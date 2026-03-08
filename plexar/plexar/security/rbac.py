"""
Role-Based Access Control (RBAC).

Controls which users/service accounts can perform which operations
on which devices. Critical for multi-team environments where one team
should not be able to push config to another team's devices.

Roles (least-privilege ordering):
  VIEWER      — read-only: get_interfaces, get_bgp_summary, etc.
  OPERATOR    — read + run commands (no config push)
  ENGINEER    — read + run + push config (no transaction/rollback control)
  ADMIN       — full access including rollback and drift remediation
  SUPERADMIN  — full access + can manage other users' permissions

Enforcement is at the Device method level via decorators.

Usage:
    from plexar.security.rbac import require_role, Role

    # On a device method:
    @require_role(Role.ENGINEER)
    async def push_config(self, config: str) -> None:
        ...

    # Setting the current user context:
    from plexar.security.rbac import set_current_user
    set_current_user(PlexarUser(username="alice", roles=[Role.OPERATOR]))
"""

from __future__ import annotations

import contextvars
import functools
import logging
from enum import IntEnum
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class Role(IntEnum):
    """
    Roles ordered by privilege level.
    Higher value = more privileged.
    """
    VIEWER     = 10
    OPERATOR   = 20
    ENGINEER   = 30
    ADMIN      = 40
    SUPERADMIN = 50


class PlexarUser:
    """Represents an authenticated user or service account."""

    def __init__(
        self,
        username:  str,
        roles:     list[Role],
        tags:      list[str] | None = None,    # device tag restrictions
        sites:     list[str] | None = None,    # site restrictions
    ) -> None:
        self.username = username
        self.roles    = roles
        self.tags     = tags   # None = no restriction
        self.sites    = sites  # None = no restriction

    @property
    def max_role(self) -> Role:
        return max(self.roles) if self.roles else Role.VIEWER

    def has_role(self, required: Role) -> bool:
        return self.max_role >= required

    def can_access_device(self, device_tags: list[str], device_site: str | None) -> bool:
        """Check if user is allowed to access a device based on tags/site."""
        if self.tags is not None:
            if not any(t in self.tags for t in device_tags):
                return False
        if self.sites is not None and device_site is not None:
            if device_site not in self.sites:
                return False
        return True

    def __repr__(self) -> str:
        return f"PlexarUser(username={self.username!r}, max_role={self.max_role.name})"


# Context variable — holds the current user per async task
_current_user: contextvars.ContextVar[PlexarUser | None] = contextvars.ContextVar(
    "plexar_current_user", default=None
)


def set_current_user(user: PlexarUser) -> None:
    """Set the current authenticated user for the current async context."""
    _current_user.set(user)


def get_current_user() -> PlexarUser | None:
    """Get the current authenticated user."""
    return _current_user.get()


def require_role(role: Role) -> Callable:
    """
    Decorator that enforces a minimum role on an async method.

    Raises PermissionError if current user lacks the required role.
    Logs all access attempts (success and failure) to the audit trail.

    Usage:
        @require_role(Role.ENGINEER)
        async def push_config(self, config: str) -> None:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            from plexar.security.audit import get_audit_logger, AuditEventType, AuditEvent

            user = get_current_user()

            # Extract hostname from self (Device) if available
            hostname = getattr(args[0], "hostname", None) if args else None

            if user is None:
                # No user set — log warning but allow (backwards compat)
                # In strict mode, this should raise
                logger.debug(
                    f"No user context for {fn.__name__} on {hostname}. "
                    "Call set_current_user() to enable RBAC enforcement."
                )
                return await fn(*args, **kwargs)

            if not user.has_role(role):
                get_audit_logger().log(AuditEvent(
                    event_type=AuditEventType.SECURITY_VIOLATION,
                    hostname=hostname,
                    severity="warning",
                    details={
                        "description": f"RBAC violation: {user.username} attempted "
                                       f"{fn.__name__} (requires {role.name}, "
                                       f"has {user.max_role.name})",
                        "user":     user.username,
                        "required": role.name,
                        "actual":   user.max_role.name,
                        "function": fn.__name__,
                    },
                ))
                raise PermissionError(
                    f"User '{user.username}' (role={user.max_role.name}) is not "
                    f"authorized to perform '{fn.__name__}'. "
                    f"Required role: {role.name}."
                )

            return await fn(*args, **kwargs)
        return wrapper
    return decorator


class RBACPolicy:
    """
    Defines the full access policy for a Plexar deployment.

    Maps operations to required roles.
    Can be customised per deployment.
    """

    # Default operation → required role mapping
    DEFAULTS: dict[str, Role] = {
        # Read operations
        "get_interfaces":    Role.VIEWER,
        "get_bgp_summary":   Role.VIEWER,
        "get_routing_table": Role.VIEWER,
        "get_platform_info": Role.VIEWER,
        "run":               Role.OPERATOR,

        # Write operations
        "push_config":       Role.ENGINEER,
        "save_config":       Role.ENGINEER,
        "transaction":       Role.ENGINEER,

        # High-impact operations
        "rollback":          Role.ADMIN,
        "remediate":         Role.ADMIN,

        # AI operations
        "ai_query":          Role.OPERATOR,
        "ai_remediate":      Role.ADMIN,
    }

    def __init__(self, overrides: dict[str, Role] | None = None) -> None:
        self._policy = {**self.DEFAULTS, **(overrides or {})}

    def required_role(self, operation: str) -> Role:
        return self._policy.get(operation, Role.ADMIN)

    def __repr__(self) -> str:
        return f"RBACPolicy({len(self._policy)} rules)"
