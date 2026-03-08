"""
Cisco IOS / IOS-XE Driver.

Classic IOS doesn't have native JSON output — we use TTP and
NTC-templates for structured parsing of CLI output.

This driver is the hardest to write correctly (screen scraping),
but covers the largest install base.

Platforms: ISR, ASR, Catalyst (IOS-XE), CSR1000v
"""

from __future__ import annotations

import re
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


_BGP_STATE_MAP: dict[str, BGPState] = {
    "established": BGPState.ESTABLISHED,
    "idle":        BGPState.IDLE,
    "active":      BGPState.ACTIVE,
    "connect":     BGPState.CONNECT,
    "opensent":    BGPState.OPENSENT,
    "openconfirm": BGPState.OPENCONFIRM,
}

# TTP template for 'show ip interface brief'
_TTP_IFACE_BRIEF = """
<group name="interfaces*">
{{ name | re("\\S+") }}  {{ ip | re("[\\d.]+|unassigned") }}  {{ ok }} {{ method }}  {{ status | re("up|down|administratively down") }}  {{ protocol | re("up|down") }}
</group>
"""

# TTP template for 'show ip bgp summary'
_TTP_BGP_SUMMARY = """
BGP router identifier {{ router_id }}, local AS number {{ local_as }}
<group name="peers*">
{{ neighbor | re("[\\d.:]+" ) }}  {{ v }}  {{ remote_as }}  {{ updown }}  {{ state_prefix_count | re(".*") }}
</group>
"""

# TTP template for 'show ip route'
_TTP_ROUTE = """
<group name="routes*">
{{ protocol | re("[BCLOSDEIRM*+]") }}{{ space }}  {{ prefix | re("[\\d./]+") }} [{{ distance }}/{{ metric }}] via {{ next_hop | re("[\\d.]+") }}
</group>
"""


class CiscoIOSDriver(BaseDriver):
    """
    Cisco IOS / IOS-XE SSH driver.

    Uses Scrapli IOSXEDriver. Parsing is CLI-based (TTP + regex)
    since classic IOS has no native JSON API.
    """

    platform             = ["cisco_ios", "cisco_iosxe"]
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
            from scrapli.driver.core import AsyncIOSXEDriver
        except ImportError as e:
            raise ConnectionError(
                "Scrapli is required: pip install scrapli[asyncssh]"
            ) from e

        creds = self.device.credentials
        try:
            self._conn = AsyncIOSXEDriver(
                host=self.device.management_ip or self.device.hostname,
                port=self.device.port or 22,
                auth_username=creds.username,
                auth_password=creds.get_password() if not creds.has_ssh_key() else None,
                auth_private_key=creds.get_ssh_key(),
                auth_strict_key=False,
                timeout_socket=15,
                timeout_transport=30,
                timeout_ops=60,
            )
            await self._conn.open()
            # Disable pagination
            await self._conn.send_command("terminal length 0")
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

    # ── Structured getters ───────────────────────────────────────────

    async def get_interfaces(self) -> list[Interface]:
        """
        Parse 'show interfaces' output using TTP.
        Falls back to 'show ip interface brief' for basic status.
        """
        raw = await self.run("show interfaces")
        return self._parse_interfaces_full(raw)

    def _parse_interfaces_full(self, raw: str) -> list[Interface]:
        """
        Parse full 'show interfaces' output with regex.
        IOS output is highly structured — same format since IOS 11.
        """
        interfaces = []

        # Split on interface headers
        iface_blocks = re.split(r"\n(?=\S)", raw)

        for block in iface_blocks:
            if not block.strip():
                continue

            # Interface name and status line
            header = re.match(
                r"^(\S+)\s+is\s+(up|down|administratively down)[^,]*,\s+line protocol is\s+(up|down)",
                block, re.IGNORECASE
            )
            if not header:
                continue

            name       = header.group(1)
            oper_str   = header.group(3).lower()
            admin_str  = header.group(2).lower()

            desc_match  = re.search(r"Description:\s+(.+)", block)
            mtu_match   = re.search(r"MTU\s+(\d+)\s+bytes", block)
            speed_match = re.search(r"(\d+)\s*(?:Mb|Gb)ps", block, re.IGNORECASE)
            mac_match   = re.search(r"address is\s+([0-9a-f.]+)", block, re.IGNORECASE)

            # Counters
            in_pkt   = self._extract_int(r"(\d+) packets input", block)
            out_pkt  = self._extract_int(r"(\d+) packets output", block)
            in_byte  = self._extract_int(r"(\d+) bytes.*input", block)
            out_byte = self._extract_int(r"(\d+) bytes.*output", block)
            in_err   = self._extract_int(r"(\d+) input errors", block)
            out_err  = self._extract_int(r"(\d+) output errors", block)

            # Speed normalisation
            speed_mbps = None
            if speed_match:
                speed_val = int(speed_match.group(1))
                unit = speed_match.group(0).lower()
                speed_mbps = speed_val * 1000 if "gb" in unit else speed_val

            interfaces.append(Interface(
                name=name,
                oper_state=OperState.UP if oper_str == "up" else OperState.DOWN,
                admin_state=AdminState.DOWN if "administratively" in admin_str else AdminState.UP,
                description=desc_match.group(1).strip() if desc_match else "",
                mtu=int(mtu_match.group(1)) if mtu_match else 1500,
                speed_mbps=speed_mbps,
                mac_address=mac_match.group(1) if mac_match else None,
                stats=InterfaceStats(
                    input_packets=in_pkt,
                    output_packets=out_pkt,
                    input_bytes=in_byte,
                    output_bytes=out_byte,
                    input_errors=in_err,
                    output_errors=out_err,
                ),
            ))

        return interfaces

    async def get_bgp_summary(self) -> BGPSummary:
        raw = await self.run("show ip bgp summary")
        return self._parse_bgp_summary(raw)

    def _parse_bgp_summary(self, raw: str) -> BGPSummary:
        local_as   = None
        router_id  = None
        peers      = []

        # Extract router ID and local AS
        header_match = re.search(
            r"BGP router identifier\s+([\d.]+),\s+local AS number\s+(\d+)",
            raw, re.IGNORECASE
        )
        if header_match:
            router_id = header_match.group(1)
            local_as  = int(header_match.group(2))

        # Parse peer table — lines after the header row
        in_table = False
        for line in raw.splitlines():
            if re.match(r"\s*Neighbor\s+V\s+AS", line, re.IGNORECASE):
                in_table = True
                continue
            if not in_table:
                continue

            # Peer row: Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
            parts = line.split()
            if len(parts) < 5:
                continue

            neighbor_ip = parts[0]
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", neighbor_ip):
                continue

            remote_as = self._safe_int(parts[2])
            updown    = parts[8] if len(parts) > 8 else "never"
            state_or_pfx = parts[9] if len(parts) > 9 else "unknown"

            # If last field is a number → established (prefixes received)
            if state_or_pfx.isdigit():
                state = BGPState.ESTABLISHED
                pfx   = int(state_or_pfx)
            else:
                state = _BGP_STATE_MAP.get(state_or_pfx.lower(), BGPState.UNKNOWN)
                pfx   = 0

            peers.append(BGPPeer(
                neighbor_ip=neighbor_ip,
                remote_as=remote_as,
                state=state,
                prefixes_received=pfx,
                uptime_seconds=self._parse_ios_uptime(updown),
            ))

        return BGPSummary(local_as=local_as, router_id=router_id, peers=peers)

    async def get_routing_table(self) -> RoutingTable:
        raw = await self.run("show ip route")
        return self._parse_routing_table(raw)

    def _parse_routing_table(self, raw: str) -> RoutingTable:
        """
        Parse IOS 'show ip route' output.
        Format: C/S/O/B prefix [distance/metric] via next_hop, age, interface
        """
        routes = []
        proto_map = {
            "C": "connected", "S": "static", "O": "ospf",
            "B": "bgp", "R": "rip", "I": "isis",
            "D": "eigrp", "E": "egp", "L": "local",
        }

        for line in raw.splitlines():
            match = re.match(
                r"^([BCLOSDIRME])\*?\s+([\d./]+)\s+\[(\d+)/(\d+)\]\s+via\s+([\d.]+)(?:,\s+\S+)?,\s+(\S+)",
                line.strip()
            )
            if match:
                proto_code = match.group(1)
                routes.append(Route(
                    prefix=match.group(2),
                    protocol=proto_map.get(proto_code, proto_code.lower()),
                    distance=int(match.group(3)),
                    metric=int(match.group(4)),
                    next_hop=match.group(5),
                    interface=match.group(6) if len(match.groups()) > 5 else None,
                ))
            else:
                # Connected / local routes
                match2 = re.match(
                    r"^([CL])\s+([\d./]+)\s+is directly connected,\s+(\S+)", line.strip()
                )
                if match2:
                    proto_code = match2.group(1)
                    routes.append(Route(
                        prefix=match2.group(2),
                        protocol=proto_map.get(proto_code, "connected"),
                        distance=0,
                        metric=0,
                        interface=match2.group(3),
                    ))

        return RoutingTable(routes=routes)

    async def get_platform_info(self) -> PlatformInfo:
        raw = await self.run("show version")
        return self._parse_version(raw)

    def _parse_version(self, raw: str) -> PlatformInfo:
        os_ver   = self._extract_str(r"Cisco IOS.*?Version\s+([\S]+)", raw) or ""
        serial   = self._extract_str(r"Processor board ID\s+(\S+)", raw)
        model    = self._extract_str(r"cisco\s+(\S+)\s+\(", raw)
        uptime   = self._extract_str(r"uptime is\s+(.+)", raw) or ""
        mem_str  = self._extract_str(r"(\d+)K bytes of physical memory", raw)
        mem_mb   = int(mem_str) // 1024 if mem_str else None

        return PlatformInfo(
            hostname=self.device.hostname,
            platform="cisco_ios",
            os_version=os_ver,
            serial=serial,
            model=model,
            uptime_seconds=self._parse_ios_uptime(uptime),
            memory_total_mb=mem_mb,
        )

    async def push_config(self, config: str) -> None:
        lines = [l.strip() for l in config.strip().splitlines() if l.strip()]
        response = await self._conn.send_configs(lines)
        if response.failed:
            raise CommandError(
                f"Config push failed on {self.device.hostname}: {response.result}"
            )

    async def save_config(self) -> None:
        """IOS requires explicit 'write memory' to persist config."""
        await self.run("write memory")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _safe_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _extract_int(pattern: str, text: str) -> int:
        match = re.search(pattern, text, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _extract_str(pattern: str, text: str) -> str | None:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _parse_ios_uptime(uptime_str: str) -> int:
        """Parse IOS uptime: '2 weeks, 3 days, 4 hours, 5 minutes'."""
        total = 0
        for value, unit, mult in [
            (r"(\d+)\s+week",   "week",   604800),
            (r"(\d+)\s+day",    "day",    86400),
            (r"(\d+)\s+hour",   "hour",   3600),
            (r"(\d+)\s+minute", "minute", 60),
        ]:
            match = re.search(value, uptime_str, re.IGNORECASE)
            if match:
                total += int(match.group(1)) * mult
        return total
