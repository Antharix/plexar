"""
Cisco NX-OS Driver.

NX-OS supports both SSH (CLI) and NX-API (JSON over HTTP).
This driver uses SSH via Scrapli as primary transport, with
'| json' output where available for reliable parsing.

Platforms: Nexus 9000, 7000, 5000, 3000 series
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


# NX-OS BGP state string → BGPState mapping
_BGP_STATE_MAP: dict[str, BGPState] = {
    "established": BGPState.ESTABLISHED,
    "idle":        BGPState.IDLE,
    "active":      BGPState.ACTIVE,
    "connect":     BGPState.CONNECT,
    "opensent":    BGPState.OPENSENT,
    "openconfirm": BGPState.OPENCONFIRM,
    "idle (admin)": BGPState.IDLE,
}


class CiscoNXOSDriver(BaseDriver):
    """
    Cisco NX-OS SSH driver.

    Uses Scrapli NXOSDriver with async transport.
    Leverages '| json' structured output wherever NX-OS supports it.
    Falls back to TTP parsing for commands without JSON support.
    """

    platform             = "cisco_nxos"
    supported_transports = ["ssh"]

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
            from scrapli.driver.core import AsyncNXOSDriver
        except ImportError as e:
            raise ConnectionError(
                "Scrapli is required: pip install scrapli[asyncssh]"
            ) from e

        creds = self.device.credentials
        try:
            self._conn = AsyncNXOSDriver(
                host=self.device.management_ip or self.device.hostname,
                port=self.device.port or 22,
                auth_username=creds.username,
                auth_password=creds.get_password() if not creds.has_ssh_key() else None,
                auth_private_key=creds.get_ssh_key(),
                auth_strict_key=False,
                timeout_socket=15,
                timeout_transport=30,
                timeout_ops=60,  # NX-OS can be slower on large outputs
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
        """Append '| json' and parse structured output."""
        raw = await self.run(f"{command} | json")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"JSON parse failed for '{command}' on {self.device.hostname}: {e}"
            ) from e

    # ── Structured getters ───────────────────────────────────────────

    async def get_interfaces(self) -> list[Interface]:
        data = await self._run_json("show interface")
        interfaces = []

        for iface_data in data.get("TABLE_interface", {}).get("ROW_interface", []):
            # NX-OS JSON wraps single results in a dict, multiple in a list
            if isinstance(iface_data, dict):
                iface_data = [iface_data]

        # Re-fetch properly — NX-OS returns ROW_interface as list
        rows = data.get("TABLE_interface", {}).get("ROW_interface", [])
        if isinstance(rows, dict):
            rows = [rows]  # single interface edge case

        for row in rows:
            state_str = row.get("state", "down").lower()
            admin_str = row.get("admin_state", "up").lower()

            interfaces.append(Interface(
                name=row.get("interface", ""),
                oper_state=OperState.UP if state_str == "up" else OperState.DOWN,
                admin_state=AdminState.UP if admin_str == "up" else AdminState.DOWN,
                description=row.get("desc", ""),
                mtu=self._safe_int(row.get("eth_mtu", 1500)),
                speed_mbps=self._parse_nxos_speed(row.get("eth_speed", "")),
                mac_address=row.get("eth_hw_addr"),
                stats=InterfaceStats(
                    input_bytes=self._safe_int(row.get("eth_inbytes", 0)),
                    output_bytes=self._safe_int(row.get("eth_outbytes", 0)),
                    input_errors=self._safe_int(row.get("eth_inerr", 0)),
                    output_errors=self._safe_int(row.get("eth_outerr", 0)),
                    input_drops=self._safe_int(row.get("eth_indrop", 0)),
                ),
            ))

        return interfaces

    async def get_bgp_summary(self) -> BGPSummary:
        data = await self._run_json("show ip bgp summary")

        vrf_data  = data.get("TABLE_vrf", {}).get("ROW_vrf", {})
        if isinstance(vrf_data, list):
            # Multiple VRFs — use default
            vrf_data = next(
                (v for v in vrf_data if v.get("vrf-name-out") == "default"),
                vrf_data[0] if vrf_data else {},
            )

        local_as  = self._safe_int(vrf_data.get("local-as"))
        router_id = vrf_data.get("vrf-router-id")

        peer_rows = vrf_data.get("TABLE_neighbor", {}).get("ROW_neighbor", [])
        if isinstance(peer_rows, dict):
            peer_rows = [peer_rows]

        peers = []
        for row in peer_rows:
            state_str = row.get("state", "unknown").lower()
            peers.append(BGPPeer(
                neighbor_ip=row.get("neighbor-id", ""),
                remote_as=self._safe_int(row.get("remoteas")),
                state=_BGP_STATE_MAP.get(state_str, BGPState.UNKNOWN),
                prefixes_received=self._safe_int(row.get("prefixreceived", 0)),
                uptime_seconds=self._parse_nxos_uptime(row.get("up-down-time", "")),
                description=row.get("neighbor-desc", ""),
            ))

        return BGPSummary(local_as=local_as, router_id=router_id, peers=peers)

    async def get_routing_table(self) -> RoutingTable:
        data = await self._run_json("show ip route")
        routes = []

        prefix_table = data.get("TABLE_vrf", {}).get("ROW_vrf", {})
        if isinstance(prefix_table, list):
            prefix_table = prefix_table[0]

        addrs = prefix_table.get("TABLE_addrf", {}).get("ROW_addrf", {})
        prefix_rows = addrs.get("TABLE_prefix", {}).get("ROW_prefix", [])
        if isinstance(prefix_rows, dict):
            prefix_rows = [prefix_rows]

        for prefix_row in prefix_rows:
            prefix = prefix_row.get("ipprefix", "")
            path_rows = prefix_row.get("TABLE_path", {}).get("ROW_path", [])
            if isinstance(path_rows, dict):
                path_rows = [path_rows]

            for path in path_rows:
                routes.append(Route(
                    prefix=prefix,
                    next_hop=path.get("ipnexthop"),
                    interface=path.get("ifname"),
                    protocol=path.get("clientname", "unknown").lower(),
                    metric=self._safe_int(path.get("metric", 0)),
                    distance=self._safe_int(path.get("pref", 0)),
                    age=self._parse_age_seconds(path.get("uptime", "0")),
                ))

        return RoutingTable(routes=routes)

    async def get_platform_info(self) -> PlatformInfo:
        data = await self._run_json("show version")
        row = data.get("TABLE_sysinfo", {}).get("ROW_sysinfo", {})
        if isinstance(row, list):
            row = row[0]

        return PlatformInfo(
            hostname=self.device.hostname,
            platform="cisco_nxos",
            os_version=row.get("sys_ver_str", ""),
            serial=row.get("proc_board_id"),
            model=row.get("chassis_id"),
            uptime_seconds=self._parse_nxos_uptime(row.get("kern_uptm_str", "")),
            memory_total_mb=self._safe_int(row.get("memory", 0)) // 1024,
        )

    async def push_config(self, config: str) -> None:
        lines = [l.strip() for l in config.strip().splitlines() if l.strip()]
        response = await self._conn.send_configs(lines)
        if response.failed:
            raise CommandError(
                f"Config push failed on {self.device.hostname}: {response.result}"
            )

    async def get_checkpoint(self) -> str:
        return await self.run("show running-config")

    async def rollback_to_checkpoint(self, checkpoint: str) -> None:
        """
        NX-OS rollback: apply saved checkpoint config.
        NX-OS supports native 'rollback running-config checkpoint' but
        we use config replace for maximum compatibility.
        """
        # Write checkpoint to a temp file on the device, then replace
        lines = ["configure replace bootflash:plexar_rollback.cfg"]
        # In production: copy checkpoint to bootflash first
        raise NotImplementedError(
            "NXOS rollback via checkpoint requires bootflash write access. "
            "Use NETCONF driver for transactional rollback."
        )

    async def get_lldp_neighbors(self) -> list[dict[str, Any]]:
        data = await self._run_json("show lldp neighbors detail")
        rows = data.get("TABLE_nbor_detail", {}).get("ROW_nbor_detail", [])
        if isinstance(rows, dict):
            rows = [rows]
        return rows

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _parse_nxos_speed(speed_str: str) -> int | None:
        """Parse NX-OS speed strings like '10 Gb/s', '1000 Mb/s'."""
        if not speed_str:
            return None
        speed_str = speed_str.strip().lower()
        if "gb" in speed_str or "g" in speed_str:
            try:
                return int(float(speed_str.split()[0]) * 1000)
            except (ValueError, IndexError):
                return None
        if "mb" in speed_str or "m" in speed_str:
            try:
                return int(speed_str.split()[0])
            except (ValueError, IndexError):
                return None
        return None

    @staticmethod
    def _parse_nxos_uptime(uptime_str: str) -> int:
        """
        Parse NX-OS uptime strings like '1d2h3m4s' or 'P1DT2H3M4S' into seconds.
        """
        import re
        if not uptime_str:
            return 0
        total = 0
        patterns = [
            (r"(\d+)d",  86400),
            (r"(\d+)h",  3600),
            (r"(\d+)m",  60),
            (r"(\d+)s",  1),
        ]
        for pattern, mult in patterns:
            match = re.search(pattern, uptime_str)
            if match:
                total += int(match.group(1)) * mult
        return total

    @staticmethod
    def _parse_age_seconds(age_str: str) -> int:
        """Parse route age strings."""
        return CiscoNXOSDriver._parse_nxos_uptime(age_str)
