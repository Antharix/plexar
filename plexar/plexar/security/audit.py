"""
Audit Trail Engine.

Every security-sensitive operation in Plexar is logged to an
immutable audit trail. This is critical for:
  - Compliance (SOC2, PCI-DSS, HIPAA for network changes)
  - Incident investigation
  - Change accountability
  - Detecting anomalous automation behaviour

Audit events cover:
  - Device connections (who connected, when, from where)
  - Config pushes (what changed, who triggered it, result)
  - Rollbacks (why, triggered by what failure)
  - Auth failures (credential errors)
  - Security violations (injection attempts, oversized inputs)
  - Drift detection events

The audit log is append-only by design.
Log entries are structured JSON for easy ingestion into SIEM tools.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


logger = logging.getLogger(__name__)


class AuditEventType(StrEnum):
    # Connection events
    DEVICE_CONNECT         = "device.connect"
    DEVICE_DISCONNECT      = "device.disconnect"
    DEVICE_CONNECT_FAILED  = "device.connect.failed"
    AUTH_FAILURE           = "device.auth.failure"

    # Command events
    COMMAND_EXECUTED       = "command.executed"
    COMMAND_FAILED         = "command.failed"

    # Config events
    CONFIG_PUSH            = "config.push"
    CONFIG_PUSH_FAILED     = "config.push.failed"
    CONFIG_ROLLBACK        = "config.rollback"
    CONFIG_ROLLBACK_FAILED = "config.rollback.failed"
    CONFIG_DIFF_COMPUTED   = "config.diff.computed"

    # Transaction events
    TRANSACTION_START      = "transaction.start"
    TRANSACTION_COMMIT     = "transaction.commit"
    TRANSACTION_ROLLBACK   = "transaction.rollback"

    # Validation events
    VALIDATION_PASSED      = "validation.passed"
    VALIDATION_FAILED      = "validation.failed"

    # Drift events
    DRIFT_DETECTED         = "drift.detected"
    DRIFT_REMEDIATED       = "drift.remediated"

    # Security events
    SECURITY_VIOLATION     = "security.violation"
    PROMPT_INJECTION       = "security.prompt_injection"
    RATE_LIMIT_HIT         = "security.rate_limit"
    CREDENTIAL_REDACTED    = "security.credential_redacted"

    # AI events
    AI_QUERY               = "ai.query"
    AI_REMEDIATION         = "ai.remediation"
    AI_REMEDIATION_APPROVED = "ai.remediation.approved"
    AI_REMEDIATION_DENIED  = "ai.remediation.denied"


class AuditEvent:
    """A single immutable audit log entry."""

    def __init__(
        self,
        event_type:  AuditEventType,
        hostname:    str | None   = None,
        user:        str | None   = None,
        details:     dict[str, Any] | None = None,
        severity:    str          = "info",
        correlation_id: str | None = None,
    ) -> None:
        self.event_id      = str(uuid4())
        self.event_type    = event_type
        self.timestamp     = datetime.now(timezone.utc).isoformat()
        self.hostname      = hostname
        self.user          = user or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        self.source_host   = _get_source_host()
        self.pid           = os.getpid()
        self.severity      = severity
        self.details       = details or {}
        self.correlation_id = correlation_id or str(uuid4())

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id":       self.event_id,
            "event_type":     str(self.event_type),
            "timestamp":      self.timestamp,
            "severity":       self.severity,
            "hostname":       self.hostname,
            "user":           self.user,
            "source_host":    self.source_host,
            "pid":            self.pid,
            "correlation_id": self.correlation_id,
            "details":        self.details,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    def __repr__(self) -> str:
        return f"AuditEvent({self.event_type} @ {self.timestamp} on {self.hostname})"


class AuditLogger:
    """
    Append-only audit logger.

    Writes structured JSON audit events to:
      - Python logging (always)
      - File (if configured)
      - Custom sinks (SIEM, Kafka, etc.)

    Thread-safe. Multiple sinks supported.
    """

    _instance: "AuditLogger | None" = None
    _lock = threading.Lock()

    def __init__(
        self,
        log_file:  str | Path | None = None,
        min_level: str               = "info",
    ) -> None:
        self._file_path = Path(log_file) if log_file else None
        self._min_level = min_level
        self._sinks:    list[Any] = []
        self._file_lock = threading.Lock()

        if self._file_path:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_instance(cls) -> "AuditLogger":
        """Get or create the global audit logger singleton."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def configure(
        cls,
        log_file:  str | Path | None = None,
        min_level: str               = "info",
    ) -> "AuditLogger":
        """Configure and return the global audit logger."""
        with cls._lock:
            cls._instance = cls(log_file=log_file, min_level=min_level)
        return cls._instance

    def log(self, event: AuditEvent) -> None:
        """Write an audit event to all configured sinks."""
        entry = event.to_json()

        # Always log to Python logger
        log_fn = {
            "debug":    logger.debug,
            "info":     logger.info,
            "warning":  logger.warning,
            "error":    logger.error,
            "critical": logger.critical,
        }.get(event.severity, logger.info)

        log_fn(f"AUDIT {entry}")

        # Write to file if configured
        if self._file_path:
            with self._file_lock:
                with open(self._file_path, "a") as f:
                    f.write(entry + "\n")

        # Fire custom sinks
        for sink in self._sinks:
            try:
                sink(event)
            except Exception as e:
                logger.error(f"Audit sink error: {e}")

    def add_sink(self, sink: Any) -> None:
        """
        Add a custom audit sink.

        Sink must be callable: sink(event: AuditEvent) -> None

        Example sinks:
            - Kafka producer
            - SIEM webhook
            - Database writer
        """
        self._sinks.append(sink)

    # ── Convenience methods ──────────────────────────────────────────

    def device_connected(self, hostname: str, transport: str, **details: Any) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.DEVICE_CONNECT,
            hostname=hostname,
            details={"transport": transport, **details},
        ))

    def device_connect_failed(self, hostname: str, error: str, **details: Any) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.DEVICE_CONNECT_FAILED,
            hostname=hostname,
            severity="warning",
            details={"error": error, **details},
        ))

    def config_push(
        self,
        hostname: str,
        lines_added: int,
        lines_removed: int,
        correlation_id: str | None = None,
    ) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.CONFIG_PUSH,
            hostname=hostname,
            severity="info",
            details={
                "lines_added":   lines_added,
                "lines_removed": lines_removed,
            },
            correlation_id=correlation_id,
        ))

    def config_rollback(self, hostname: str, reason: str, **details: Any) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.CONFIG_ROLLBACK,
            hostname=hostname,
            severity="warning",
            details={"reason": reason, **details},
        ))

    def security_violation(self, description: str, hostname: str | None = None, **details: Any) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            hostname=hostname,
            severity="critical",
            details={"description": description, **details},
        ))

    def prompt_injection_detected(self, hostname: str, command: str) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.PROMPT_INJECTION,
            hostname=hostname,
            severity="critical",
            details={
                "command": command,
                "message": "Device output contained prompt injection patterns",
            },
        ))

    def drift_detected(self, hostname: str, risk_score: int, changes: dict) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.DRIFT_DETECTED,
            hostname=hostname,
            severity="warning" if risk_score < 50 else "error",
            details={"risk_score": risk_score, "changes": changes},
        ))

    def ai_query(self, query: str, hostname: str | None = None) -> None:
        self.log(AuditEvent(
            event_type=AuditEventType.AI_QUERY,
            hostname=hostname,
            severity="info",
            details={"query_length": len(query)},  # don't log full query
        ))

    def ai_remediation(
        self,
        hostname: str,
        action: str,
        approved: bool,
        approver: str | None = None,
    ) -> None:
        event_type = (
            AuditEventType.AI_REMEDIATION_APPROVED if approved
            else AuditEventType.AI_REMEDIATION_DENIED
        )
        self.log(AuditEvent(
            event_type=event_type,
            hostname=hostname,
            severity="warning",
            details={
                "action":   action,
                "approver": approver,
            },
        ))


# ── Module-level convenience functions ────────────────────────────────

def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return AuditLogger.get_instance()


def audit(
    event_type: AuditEventType,
    hostname:   str | None = None,
    severity:   str        = "info",
    **details:  Any,
) -> None:
    """
    Quick one-liner audit log call.

    Usage:
        from plexar.security.audit import audit, AuditEventType
        audit(AuditEventType.CONFIG_PUSH, hostname="spine-01", lines_added=3)
    """
    get_audit_logger().log(AuditEvent(
        event_type=event_type,
        hostname=hostname,
        severity=severity,
        details=details,
    ))


# ── Helpers ───────────────────────────────────────────────────────────

def _get_source_host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
