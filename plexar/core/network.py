"""
The Network object — top-level entrypoint for Plexar.

This is the first object most users will instantiate.

Usage:
    from plexar import Network

    net = Network()
    net.inventory.load("yaml", path="./inventory.yaml")

    leafs = net.devices(role="leaf")

    async with net.pool(max_concurrent=50) as pool:
        results = await pool.map(lambda d: d.get_bgp_summary(), leafs)
"""

from __future__ import annotations

from typing import Any

from plexar.core.device import Device
from plexar.core.inventory import Inventory
from plexar.core.pool import ConnectionPool
from plexar.core.exceptions import DeviceNotFoundError


class Network:
    """
    The top-level Plexar object.

    Holds inventory, provides device queries, and spawns connection pools.
    """

    def __init__(self) -> None:
        self.inventory = Inventory()

    # ── Device access ────────────────────────────────────────────────

    def devices(self, **filters: Any) -> list[Device]:
        """
        Query devices from inventory.

        Passes all kwargs to inventory.filter(). Common filters:
            role="leaf"
            site="dc1"
            tags=["spine"]
            platform="arista_eos"

        Examples:
            net.devices(role="leaf")
            net.devices(tags=["spine", "dc1"])
            net.devices(platform="cisco_nxos", site="dc1")
        """
        return self.inventory.filter(**filters)

    def device(self, hostname: str) -> Device:
        """
        Get a single device by hostname.
        Raises DeviceNotFoundError if not found.
        """
        return self.inventory.get(hostname)

    # ── Pool ─────────────────────────────────────────────────────────

    def pool(
        self,
        max_concurrent: int = 50,
        rate_limit: int | None = None,
        connect_timeout: int = 15,
        command_timeout: int = 30,
        max_retries: int = 2,
    ) -> ConnectionPool:
        """
        Create an async connection pool for concurrent operations.

        Usage:
            async with net.pool(max_concurrent=50) as pool:
                results = await pool.map(lambda d: d.get_bgp_summary(), net.devices())
        """
        return ConnectionPool(
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
            connect_timeout=connect_timeout,
            command_timeout=command_timeout,
            max_retries=max_retries,
        )

    # ── Display ──────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"Network(devices={len(self.inventory)})"
