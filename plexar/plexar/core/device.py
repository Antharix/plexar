"""
The Universal Device Model.

Device is the central object in Plexar. It represents a single
network device and provides access to all operations — data retrieval,
config push, transactions, and more.

The correct driver is auto-selected based on `platform` and `transport`.

Usage:
    device = Device(
        hostname="spine-01",
        management_ip="10.0.0.1",
        platform=Platform.ARISTA_EOS,
        transport=Transport.SSH,
        credentials=Credentials(username="admin", password_env="DEVICE_PASS"),
        tags=["spine", "dc1"],
    )
    await device.connect()
    interfaces = await device.get_interfaces()
    await device.disconnect()
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncGenerator

from pydantic import BaseModel, Field, field_validator, model_validator

from plexar.core.credentials import Credentials
from plexar.core.enums import Transport, Platform
from plexar.core.exceptions import DriverNotFoundError, ConnectionError

if TYPE_CHECKING:
    from plexar.drivers.base import BaseDriver
    from plexar.models.interfaces import Interface
    from plexar.models.bgp import BGPSummary
    from plexar.models.routing import RoutingTable
    from plexar.models.platform import PlatformInfo
    from plexar.config.transaction import Transaction


class Device(BaseModel):
    """
    A network device.

    This is the primary object in Plexar. Instantiate it, connect,
    then call any get_* or push_* method. The driver layer handles
    all vendor-specific logic transparently.
    """

    model_config = {"arbitrary_types_allowed": True}

    # Identity
    hostname:      str
    management_ip: str | None = None
    port:          int | None = None   # defaults per transport (22/830/443/57400)

    # Driver selection
    platform:  Platform | str
    transport: Transport = Transport.SSH

    # Auth
    credentials: Credentials

    # Metadata
    tags:     list[str]       = Field(default_factory=list)
    metadata: dict[str, Any]  = Field(default_factory=dict)

    # Runtime — not serialised
    _driver:    "BaseDriver | None" = None
    _connected: bool                = False

    # ── Validation ──────────────────────────────────────────────────

    @field_validator("platform", mode="before")
    @classmethod
    def normalise_platform(cls, v: Any) -> str:
        """Accept Platform enum or plain string."""
        return str(v).lower()

    @field_validator("management_ip", mode="before")
    @classmethod
    def coerce_ip(cls, v: Any) -> str | None:
        return str(v) if v is not None else None

    @model_validator(mode="after")
    def _set_default_port(self) -> "Device":
        if self.port is None:
            self.port = {
                Transport.SSH:      22,
                Transport.NETCONF:  830,
                Transport.RESTCONF: 443,
                Transport.GNMI:     57400,
                Transport.SNMP:     161,
            }.get(self.transport, 22)
        return self

    # ── Driver lifecycle ────────────────────────────────────────────

    def _load_driver(self) -> "BaseDriver":
        """
        Auto-discover and instantiate the correct vendor driver.
        Drivers are registered via entry_points in pyproject.toml.
        """
        from plexar.drivers.registry import DriverRegistry
        driver_cls = DriverRegistry.get(self.platform, self.transport)
        if driver_cls is None:
            raise DriverNotFoundError(
                f"No driver registered for platform='{self.platform}' "
                f"transport='{self.transport}'. "
                f"Check 'plexar.drivers' entry_points or install the correct extra."
            )
        return driver_cls(device=self)

    async def connect(self) -> None:
        """Establish connection to the device."""
        if self._connected:
            return
        if self._driver is None:
            object.__setattr__(self, "_driver", self._load_driver())
        try:
            await self._driver.connect()
            object.__setattr__(self, "_connected", True)
            from plexar.security.audit import get_audit_logger
            get_audit_logger().device_connected(self.hostname, str(self.transport))
        except Exception as exc:
            from plexar.security.audit import get_audit_logger
            from plexar.security.sanitizer import redact_credentials
            get_audit_logger().device_connect_failed(
                self.hostname, redact_credentials(str(exc))
            )
            raise

    async def disconnect(self) -> None:
        """Close the device connection."""
        if self._driver and self._connected:
            await self._driver.disconnect()
        object.__setattr__(self, "_connected", False)

    async def reconnect(self) -> None:
        """Disconnect and reconnect."""
        await self.disconnect()
        await self.connect()

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ── Raw command execution ────────────────────────────────────────

    async def run(self, command: str, *, timeout: int = 30) -> str:
        """
        Execute a raw command on the device and return output as a string.

        For structured data, prefer the get_* methods which return
        normalized Pydantic models.
        """
        self._assert_connected()
        from plexar.security.sanitizer import validate_device_output
        from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType
        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.COMMAND_EXECUTED,
            hostname=self.hostname,
            details={"command": command},
        ))
        raw = await self._driver.run(command, timeout=timeout)
        return validate_device_output(raw, command=command, hostname=self.hostname)

    # ── Structured data getters ──────────────────────────────────────

    async def get_interfaces(self) -> list["Interface"]:
        """Return all interfaces as normalized Interface models."""
        self._assert_connected()
        return await self._driver.get_interfaces()

    async def get_bgp_summary(self) -> "BGPSummary":
        """Return BGP peer summary as a normalized BGPSummary model."""
        self._assert_connected()
        return await self._driver.get_bgp_summary()

    async def get_routing_table(self) -> "RoutingTable":
        """Return the RIB as a normalized RoutingTable model."""
        self._assert_connected()
        return await self._driver.get_routing_table()

    async def get_platform_info(self) -> "PlatformInfo":
        """Return device platform, version, and serial info."""
        self._assert_connected()
        return await self._driver.get_platform_info()

    # ── Config operations ────────────────────────────────────────────

    async def push_config(self, config: str) -> None:
        """
        Push a config block to the device.

        For push-with-rollback, use device.transaction() instead.
        """
        self._assert_connected()
        from plexar.security.sanitizer import sanitize_config_block
        from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType
        config = sanitize_config_block(config)
        lines  = config.splitlines()
        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.CONFIG_PUSH,
            hostname=self.hostname,
            details={"lines": len(lines)},
        ))
        await self._driver.push_config(config)

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator["Transaction", None]:
        """
        Context manager for transactional config push with rollback support.

        Usage:
            async with device.transaction() as txn:
                await txn.push(config)
                ok = await txn.verify([...])
                if not ok:
                    await txn.rollback()
        """
        from plexar.config.transaction import Transaction
        txn = Transaction(device=self)
        try:
            yield txn
        except Exception:
            if not txn.committed:
                await txn.rollback()
            raise
        finally:
            await txn.cleanup()

    # ── Context manager support ──────────────────────────────────────

    async def __aenter__(self) -> "Device":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    # ── Helpers ─────────────────────────────────────────────────────

    def _assert_connected(self) -> None:
        if not self._connected or self._driver is None:
            raise ConnectionError(
                f"Device '{self.hostname}' is not connected. "
                f"Call await device.connect() first, or use 'async with device:'."
            )

    # ── Display ─────────────────────────────────────────────────────

    def __repr__(self) -> str:
        status = "connected" if self._connected else "disconnected"
        return (
            f"Device(hostname={self.hostname!r}, "
            f"platform={self.platform!r}, "
            f"transport={self.transport!r}, "
            f"status={status})"
        )

    def __str__(self) -> str:
        return self.hostname
