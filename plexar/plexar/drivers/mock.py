"""
Mock Driver.

A full in-memory driver for unit testing and CI/CD pipelines.
No real network devices are needed.

Usage:
    from plexar.drivers.mock import MockDriver
    from plexar.models.bgp import BGPSummary, BGPPeer
    from plexar.core.enums import BGPState

    mock = MockDriver.build(
        platform="arista_eos",
        bgp_summary=BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.ESTABLISHED, prefixes_received=150),
        ]),
    )

    device = Device(..., platform="arista_eos")
    device._driver = mock           # inject mock directly
    device._connected = True

    bgp = await device.get_bgp_summary()   # returns the mock data
    assert bgp.peers[0].state == BGPState.ESTABLISHED
"""

from __future__ import annotations

from typing import Any, Callable, Coroutine
from unittest.mock import AsyncMock

from plexar.drivers.base import BaseDriver
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.models.interfaces import Interface, InterfaceStats
from plexar.models.routing import RoutingTable, Route
from plexar.models.platform import PlatformInfo
from plexar.core.enums import BGPState, OperState, AdminState


class MockDriver(BaseDriver):
    """
    In-memory mock driver. All responses are configurable.
    Tracks calls for assertion in tests.
    """

    platform = "mock"
    supported_transports = ["ssh", "netconf", "restconf", "gnmi"]

    def __init__(self, device: Any = None, **kwargs: Any) -> None:
        # device may be None in test setup
        if device is not None:
            super().__init__(device)
        else:
            self.device = None  # type: ignore[assignment]

        self._connected = False
        self._responses: dict[str, Any] = {}
        self._call_log:  list[tuple[str, tuple, dict]] = []

        # Connection simulation
        self.connect_should_fail:    bool = False
        self.connect_fail_exception: Exception = ConnectionError("Mock connection failed")

        # Defaults — sensible out of the box
        self._defaults()

    # ── Default responses ────────────────────────────────────────────

    def _defaults(self) -> None:
        self._responses.setdefault("get_interfaces", [
            Interface(
                name="Ethernet1",
                oper_state=OperState.UP,
                admin_state=AdminState.UP,
                description="uplink-to-spine-01",
                mtu=9214,
                speed_mbps=10000,
                mac_address="00:1c:73:ab:cd:01",
            ),
            Interface(
                name="Ethernet2",
                oper_state=OperState.DOWN,
                admin_state=AdminState.UP,
                description="reserved",
                mtu=1500,
                speed_mbps=1000,
            ),
        ])

        self._responses.setdefault("get_bgp_summary", BGPSummary(
            local_as=65001,
            peers=[
                BGPPeer(
                    neighbor_ip="10.0.0.1",
                    remote_as=65000,
                    state=BGPState.ESTABLISHED,
                    prefixes_received=150,
                    uptime_seconds=86400,
                ),
                BGPPeer(
                    neighbor_ip="10.0.0.2",
                    remote_as=65000,
                    state=BGPState.ESTABLISHED,
                    prefixes_received=148,
                    uptime_seconds=86400,
                ),
            ]
        ))

        self._responses.setdefault("get_routing_table", RoutingTable(routes=[
            Route(prefix="0.0.0.0/0", next_hop="10.0.0.1", protocol="bgp", metric=0),
            Route(prefix="10.0.0.0/8", next_hop="10.0.0.1", protocol="bgp", metric=100),
        ]))

        self._responses.setdefault("get_platform_info", PlatformInfo(
            hostname="mock-device",
            platform="mock",
            os_version="MockOS 1.0",
            serial="MOCK123456",
            uptime_seconds=86400,
        ))

        self._responses.setdefault("run", "")
        self._responses.setdefault("push_config", None)

    # ── Configuration ────────────────────────────────────────────────

    def set_response(self, method: str, value: Any) -> "MockDriver":
        """
        Configure the response for a specific method.

        Args:
            method: Method name e.g. "get_bgp_summary"
            value:  The value to return (or Exception to raise)
        """
        self._responses[method] = value
        return self

    def set_run_response(self, command: str, output: str) -> "MockDriver":
        """Configure the output for a specific CLI command."""
        if not isinstance(self._responses.get("run"), dict):
            self._responses["run"] = {}
        self._responses["run"][command] = output  # type: ignore[index]
        return self

    @classmethod
    def build(cls, platform: str = "mock", **responses: Any) -> "MockDriver":
        """
        Factory: create a MockDriver pre-loaded with responses.

        Example:
            mock = MockDriver.build(
                platform="arista_eos",
                get_bgp_summary=BGPSummary(...),
            )
        """
        driver = cls()
        for method, value in responses.items():
            driver.set_response(method, value)
        return driver

    # ── Call tracking ────────────────────────────────────────────────

    def _record(self, method: str, *args: Any, **kwargs: Any) -> None:
        self._call_log.append((method, args, kwargs))

    def was_called(self, method: str) -> bool:
        return any(name == method for name, _, _ in self._call_log)

    def call_count(self, method: str) -> int:
        return sum(1 for name, _, _ in self._call_log if name == method)

    def reset_calls(self) -> None:
        self._call_log.clear()

    # ── BaseDriver implementation ────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._record("connect")
        if self.connect_should_fail:
            raise self.connect_fail_exception
        self._connected = True

    async def disconnect(self) -> None:
        self._record("disconnect")
        self._connected = False

    async def run(self, command: str, *, timeout: int = 30) -> str:
        self._record("run", command)
        responses = self._responses.get("run", "")
        if isinstance(responses, dict):
            return responses.get(command, f"% Unknown command: {command}")
        return str(responses)

    async def get_interfaces(self) -> list[Interface]:
        self._record("get_interfaces")
        return self._get_or_raise("get_interfaces")

    async def get_bgp_summary(self) -> BGPSummary:
        self._record("get_bgp_summary")
        return self._get_or_raise("get_bgp_summary")

    async def get_routing_table(self) -> RoutingTable:
        self._record("get_routing_table")
        return self._get_or_raise("get_routing_table")

    async def get_platform_info(self) -> PlatformInfo:
        self._record("get_platform_info")
        return self._get_or_raise("get_platform_info")

    async def push_config(self, config: str) -> None:
        self._record("push_config", config)
        result = self._responses.get("push_config")
        if isinstance(result, Exception):
            raise result

    # ── Helpers ──────────────────────────────────────────────────────

    def _get_or_raise(self, method: str) -> Any:
        value = self._responses.get(method)
        if isinstance(value, Exception):
            raise value
        return value
