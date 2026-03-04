"""
Abstract Base Driver.

Every vendor driver must inherit from BaseDriver and implement
all abstract methods. This enforces a consistent interface across
all platforms regardless of how they communicate underneath.

The abstract methods define the contract. The concrete implementations
handle all vendor-specific command syntax, parsing, and quirks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from plexar.core.device import Device
    from plexar.models.interfaces import Interface
    from plexar.models.bgp import BGPSummary
    from plexar.models.routing import RoutingTable
    from plexar.models.platform import PlatformInfo


class BaseDriver(ABC):
    """
    Abstract base for all Plexar vendor drivers.

    Subclass this and implement all abstract methods to add
    support for a new vendor platform.
    """

    #: Platform string(s) this driver handles.
    #: Single string or list of strings (e.g. ["cisco_ios", "cisco_iosxe"])
    platform: str | list[str] = ""

    #: Default transport for this driver
    default_transport: str = "ssh"

    def __init__(self, device: "Device") -> None:
        self.device = device

    # ── Lifecycle ────────────────────────────────────────────────────

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the device."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close the connection."""
        ...

    async def reconnect(self) -> None:
        """Disconnect and reconnect. Default impl calls disconnect then connect."""
        await self.disconnect()
        await self.connect()

    @property
    def is_connected(self) -> bool:
        """Return True if connection is currently active."""
        return False  # subclasses override

    # ── Raw execution ────────────────────────────────────────────────

    @abstractmethod
    async def run(self, command: str, *, timeout: int = 30) -> str:
        """
        Execute a raw command and return the string output.

        The output should be the raw device response with prompt
        stripped. No parsing is performed here.
        """
        ...

    # ── Structured getters ───────────────────────────────────────────
    # All return normalized Pydantic models — never raw strings.

    @abstractmethod
    async def get_interfaces(self) -> list["Interface"]:
        """Return all interfaces as normalized Interface models."""
        ...

    @abstractmethod
    async def get_bgp_summary(self) -> "BGPSummary":
        """Return BGP peer summary as a normalized BGPSummary model."""
        ...

    @abstractmethod
    async def get_routing_table(self) -> "RoutingTable":
        """Return the IPv4 RIB as a normalized RoutingTable model."""
        ...

    @abstractmethod
    async def get_platform_info(self) -> "PlatformInfo":
        """Return device platform, version, serial, and uptime info."""
        ...

    # ── Config operations ────────────────────────────────────────────

    @abstractmethod
    async def push_config(self, config: str) -> None:
        """
        Push a configuration block to the device.

        The config string should be in the device's native format.
        """
        ...

    async def save_config(self) -> None:
        """
        Persist running config to startup config.
        Override if the platform requires an explicit save.
        """
        pass  # many platforms auto-save; override when needed

    async def get_checkpoint(self) -> str:
        """
        Return a checkpoint/snapshot of the current running config.
        Used by the Transaction engine for rollback.
        Default: return running config as string.
        """
        return await self.run("show running-config")

    async def rollback_to_checkpoint(self, checkpoint: str) -> None:
        """
        Roll back to a previously captured checkpoint.
        Subclasses should implement platform-specific rollback.
        """
        raise NotImplementedError(
            f"Driver '{self.__class__.__name__}' does not implement rollback. "
            "Use NETCONF driver for transactional operations."
        )

    # ── Optional capabilities ────────────────────────────────────────
    # Drivers may optionally implement these for richer functionality.

    async def get_lldp_neighbors(self) -> list[dict[str, Any]]:
        """Return LLDP neighbor table. Optional."""
        raise NotImplementedError

    async def get_vlans(self) -> list[dict[str, Any]]:
        """Return VLAN database. Optional."""
        raise NotImplementedError

    async def get_ospf_neighbors(self) -> list[dict[str, Any]]:
        """Return OSPF neighbor table. Optional."""
        raise NotImplementedError

    # ── Driver metadata ──────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"device={self.device.hostname!r}, "
            f"connected={self.is_connected})"
        )
