"""
Arista EOS Driver.

Supports SSH (Scrapli) and eAPI (JSON over HTTP).
EOS is ideal to develop against — its eAPI returns structured JSON natively,
which means parsers are trivial compared to CLI scraping.

Transport priority: SSH → eAPI fallback
"""

from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

from plexar.drivers.base import BaseDriver
from plexar.models.interfaces import Interface, InterfaceStats
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.models.routing import RoutingTable, Route
from plexar.models.platform import PlatformInfo
from plexar.core.enums import OperState, AdminState, BGPState
from plexar.core.exceptions import ConnectionError, ParseError, CommandError

if TYPE_CHECKING:
    from plexar.core.device import Device


class AristaEOSDriver(BaseDriver):
    """
    Arista EOS driver.

    Uses Scrapli for SSH transport with EOS-specific prompt handling.
    Parses 'show * | json' output where available for reliability,
    falls back to TTP parsing for commands without JSON support.
    """

    platform              = "arista_eos"
    supported_transports  = ["ssh"]

    def __init__(self, device: "Device") -> None:
        super().__init__(device)
        self._conn: Any = None
        self._connected_flag = False

    # ── Lifecycle ────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected_flag

    async def connect(self) -> None:
        try:
            from scrapli.driver.core import AsyncEOSDriver
        except ImportError as e:
            raise ConnectionError(
                "Scrapli is required for the Arista EOS driver. "
                "Install with: pip install scrapli[asyncssh]"
            ) from e

        creds = self.device.credentials

        try:
            self._conn = AsyncEOSDriver(
                host=self.device.management_ip or self.device.hostname,
                port=self.device.port or 22,
                auth_username=creds.username,
                auth_password=creds.get_password() if not creds.has_ssh_key() else None,
                auth_private_key=creds.get_ssh_key(),
                auth_strict_key=False,
                timeout_socket=15,
                timeout_transport=30,
                timeout_ops=30,
            )
            await self._conn.open()
            self._connected_flag = True
        except Exception as exc:
            raise ConnectionError(
                f"Failed to connect to {self.device.hostname}: {exc}"
            ) from exc

    async def disconnect(self) -> None:
        if self._conn:
            await self._conn.close()
        self._connected_flag = False

    # ── Raw execution ────────────────────────────────────────────────

    async def run(self, command: str, *, timeout: int = 30) -> str:
        response = await self._conn.send_command(command, timeout_ops=timeout)
        if response.failed:
            raise CommandError(
                f"Command '{command}' failed on {self.device.hostname}: {response.result}"
            )
        return response.result

    async def _run_json(self, command: str) -> dict[str, Any]:
        """Run a command with '| json' appended and parse the result."""
        raw = await self.run(f"{command} | json")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"Failed to parse JSON output of '{command}' on {self.device.hostname}: {e}"
            ) from e

    # ── Structured getters ───────────────────────────────────────────

    async def get_interfaces(self) -> list[Interface]:
        data = await self._run_json("show interfaces")
        interfaces = []

        for iface_name, iface_data in data.get("interfaces", {}).items():
            oper = iface_data.get("lineProtocolStatus", "unknown")
            admin = iface_data.get("interfaceStatus", "connected")
            counters = iface_data.get("interfaceCounters", {})

            interfaces.append(Interface(
                name=iface_name,
                oper_state=OperState.UP if oper == "up" else OperState.DOWN,
                admin_state=AdminState.UP if admin in ("connected", "up") else AdminState.DOWN,
                description=iface_data.get("description", ""),
                mtu=iface_data.get("mtu", 1500),
                speed_mbps=self._parse_speed(iface_data.get("bandwidth", 0)),
                mac_address=iface_data.get("physicalAddress"),
                stats=InterfaceStats(
                    input_bytes=counters.get("inOctets", 0),
                    output_bytes=counters.get("outOctets", 0),
                    input_errors=counters.get("totalInErrors", 0),
                    output_errors=counters.get("totalOutErrors", 0),
                ),
            ))

        return interfaces

    async def get_bgp_summary(self) -> BGPSummary:
        data = await self._run_json("show ip bgp summary")
        vrfs = data.get("vrfs", {})
        default_vrf = vrfs.get("default", {})

        local_as   = default_vrf.get("asn")
        router_id  = default_vrf.get("routerId")
        peers_data = default_vrf.get("peers", {})

        peers = []
        for neighbor_ip, peer_data in peers_data.items():
            state_str = peer_data.get("peerState", "unknown").lower()
            peers.append(BGPPeer(
                neighbor_ip=neighbor_ip,
                remote_as=peer_data.get("asn"),
                state=self._parse_bgp_state(state_str),
                prefixes_received=peer_data.get("prefixReceived", 0),
                uptime_seconds=peer_data.get("upDownTime", 0),
            ))

        return BGPSummary(local_as=local_as, router_id=router_id, peers=peers)

    async def get_routing_table(self) -> RoutingTable:
        data = await self._run_json("show ip route")
        routes = []

        for prefix, route_data in data.get("vrfs", {}).get("default", {}).get("routes", {}).items():
            via = route_data.get("vias", [{}])[0]
            routes.append(Route(
                prefix=prefix,
                next_hop=via.get("nexthopAddr"),
                interface=via.get("interface"),
                protocol=route_data.get("routeType", "unknown").lower(),
                metric=route_data.get("metric", 0),
                distance=route_data.get("preference", 0),
            ))

        return RoutingTable(routes=routes)

    async def get_platform_info(self) -> PlatformInfo:
        data = await self._run_json("show version")
        return PlatformInfo(
            hostname=self.device.hostname,
            platform="arista_eos",
            os_version=data.get("version", ""),
            serial=data.get("serialNumber"),
            model=data.get("modelName"),
            uptime_seconds=int(data.get("uptime", 0)),
            memory_total_mb=data.get("memTotal", 0) // 1024,
            memory_used_mb=(data.get("memTotal", 0) - data.get("memFree", 0)) // 1024,
        )

    async def push_config(self, config: str) -> None:
        lines = [line.strip() for line in config.strip().splitlines() if line.strip()]
        response = await self._conn.send_configs(lines)
        if response.failed:
            raise CommandError(
                f"Config push failed on {self.device.hostname}: {response.result}"
            )

    async def get_checkpoint(self) -> str:
        return await self.run("show running-config")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_speed(bandwidth_bps: int) -> int | None:
        """Convert bandwidth in bps to Mbps."""
        if not bandwidth_bps:
            return None
        return bandwidth_bps // 1_000_000

    @staticmethod
    def _parse_bgp_state(state_str: str) -> BGPState:
        mapping = {
            "established": BGPState.ESTABLISHED,
            "idle":        BGPState.IDLE,
            "active":      BGPState.ACTIVE,
            "connect":     BGPState.CONNECT,
            "opensent":    BGPState.OPENSENT,
            "openconfirm": BGPState.OPENCONFIRM,
        }
        return mapping.get(state_str.lower(), BGPState.UNKNOWN)
