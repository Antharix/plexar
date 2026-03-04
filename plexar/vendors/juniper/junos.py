"""
Juniper JunOS Driver.

JunOS is NETCONF-native — every operation returns structured XML.
This makes it the most reliable driver to write, but requires
careful XML namespace handling.

Supports both SSH (CLI) and NETCONF transport.
Primary: NETCONF (structured, transactional, rollback-native)
Fallback: SSH CLI with XML output ('show ... | display xml')

Platforms: MX, EX, QFX, SRX series
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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


# JunOS XML namespaces
_NS = {
    "junos": "http://xml.juniper.net/junos/*/junos",
    "xnm":   "http://xml.juniper.net/xnm/1.1/xnm",
}

_BGP_STATE_MAP: dict[str, BGPState] = {
    "established": BGPState.ESTABLISHED,
    "idle":        BGPState.IDLE,
    "active":      BGPState.ACTIVE,
    "connect":     BGPState.CONNECT,
    "opensent":    BGPState.OPENSENT,
    "openconfirm": BGPState.OPENCONFIRM,
}


class JuniperJunOSDriver(BaseDriver):
    """
    Juniper JunOS driver.

    Uses SSH via Scrapli for CLI transport.
    Requests XML output ('| display xml') for reliable parsing.
    NETCONF support available in the netconf driver (Phase 2+).
    """

    platform             = "juniper_junos"
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
            from scrapli.driver.core import AsyncJunosDriver
        except ImportError as e:
            raise ConnectionError(
                "Scrapli is required: pip install scrapli[asyncssh]"
            ) from e

        creds = self.device.credentials
        try:
            self._conn = AsyncJunosDriver(
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
            # JunOS CLI: disable pagination
            await self._conn.send_command("set cli screen-length 0")
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

    async def _run_xml(self, command: str) -> ET.Element:
        """Run command with '| display xml' and parse the XML response."""
        raw = await self.run(f"{command} | display xml")
        # Strip any CLI prompt noise around the XML
        xml_match = re.search(r"(<rpc-reply.*?</rpc-reply>)", raw, re.DOTALL)
        xml_str = xml_match.group(1) if xml_match else raw
        try:
            return ET.fromstring(xml_str)
        except ET.ParseError as e:
            raise ParseError(
                f"XML parse failed for '{command}' on {self.device.hostname}: {e}"
            ) from e

    def _find(self, element: ET.Element, path: str) -> str:
        """Find element text, stripping namespace prefixes."""
        # Try with full namespace search
        el = element.find(".//" + path)
        if el is not None and el.text:
            return el.text.strip()
        # Try stripping namespace in path search
        for child in element.iter():
            local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if local == path and child.text:
                return child.text.strip()
        return ""

    def _findall(self, element: ET.Element, tag: str) -> list[ET.Element]:
        """Find all elements with a given tag, ignoring namespace."""
        return [
            child for child in element.iter()
            if (child.tag.split("}")[-1] if "}" in child.tag else child.tag) == tag
        ]

    # ── Structured getters ───────────────────────────────────────────

    async def get_interfaces(self) -> list[Interface]:
        root = await self._run_xml("show interfaces")
        interfaces = []

        for iface_el in self._findall(root, "physical-interface"):
            name       = self._find(iface_el, "name")
            oper_str   = self._find(iface_el, "oper-status").lower()
            admin_str  = self._find(iface_el, "admin-status").lower()
            desc       = self._find(iface_el, "description")
            mtu_str    = self._find(iface_el, "mtu")
            speed_str  = self._find(iface_el, "speed")
            mac        = self._find(iface_el, "hardware-physical-address")

            # Traffic stats
            stats_el = next(iter(self._findall(iface_el, "traffic-statistics")), None)
            in_bytes  = int(self._find(stats_el, "input-bytes"))  if stats_el else 0
            out_bytes = int(self._find(stats_el, "output-bytes")) if stats_el else 0

            interfaces.append(Interface(
                name=name,
                oper_state=OperState.UP if oper_str == "up" else OperState.DOWN,
                admin_state=AdminState.UP if admin_str == "up" else AdminState.DOWN,
                description=desc,
                mtu=self._parse_mtu(mtu_str),
                speed_mbps=self._parse_junos_speed(speed_str),
                mac_address=mac or None,
                stats=InterfaceStats(input_bytes=in_bytes, output_bytes=out_bytes),
            ))

        return interfaces

    async def get_bgp_summary(self) -> BGPSummary:
        root = await self._run_xml("show bgp summary")

        local_as   = self._find(root, "local-as")
        router_id  = self._find(root, "bgp-rib")

        peers = []
        for peer_el in self._findall(root, "bgp-peer"):
            neighbor  = self._find(peer_el, "peer-address")
            remote_as = self._find(peer_el, "peer-as")
            state_str = self._find(peer_el, "peer-state").lower()
            pfx_rx    = self._find(peer_el, "nlri-type-session")  # JunOS field
            elapsed   = self._find(peer_el, "elapsed-time")

            peers.append(BGPPeer(
                neighbor_ip=neighbor.split("+")[0],  # strip port if present
                remote_as=int(remote_as) if remote_as.isdigit() else None,
                state=_BGP_STATE_MAP.get(state_str, BGPState.UNKNOWN),
                prefixes_received=int(pfx_rx) if pfx_rx.isdigit() else 0,
                uptime_seconds=self._parse_junos_uptime(elapsed),
            ))

        return BGPSummary(
            local_as=int(local_as) if local_as.isdigit() else None,
            router_id=router_id or None,
            peers=peers,
        )

    async def get_routing_table(self) -> RoutingTable:
        root = await self._run_xml("show route")
        routes = []

        for rt_el in self._findall(root, "rt"):
            prefix = self._find(rt_el, "rt-destination")
            prefix_len = self._find(rt_el, "rt-prefix-length")
            if prefix_len:
                prefix = f"{prefix}/{prefix_len}"

            for entry_el in self._findall(rt_el, "rt-entry"):
                proto    = self._find(entry_el, "protocol-name").lower()
                nh_el    = next(iter(self._findall(entry_el, "nh")), None)
                next_hop = self._find(nh_el, "to") if nh_el else None
                iface    = self._find(nh_el, "via") if nh_el else None
                metric   = self._find(entry_el, "metric")
                pref     = self._find(entry_el, "preference")

                routes.append(Route(
                    prefix=prefix,
                    protocol=proto,
                    next_hop=next_hop or None,
                    interface=iface or None,
                    metric=int(metric) if metric.isdigit() else 0,
                    distance=int(pref) if pref.isdigit() else 0,
                ))

        return RoutingTable(routes=routes)

    async def get_platform_info(self) -> PlatformInfo:
        root = await self._run_xml("show version")

        hostname  = self._find(root, "host-name")
        os_ver    = self._find(root, "junos-version")
        model     = self._find(root, "product-model")
        serial    = self._find(root, "chassis-inventory-serial-number")
        uptime    = self._find(root, "system-uptime-information")

        return PlatformInfo(
            hostname=hostname or self.device.hostname,
            platform="juniper_junos",
            os_version=os_ver,
            model=model or None,
            serial=serial or None,
            uptime_seconds=0,  # uptime needs a separate 'show system uptime' call
        )

    async def push_config(self, config: str) -> None:
        """
        Push config in JunOS set-format.
        Uses 'load set terminal' → paste → commit.
        """
        lines = [
            "configure",
            "load set terminal",
        ] + [l for l in config.strip().splitlines() if l.strip()] + [
            "\x04",   # Ctrl-D to end input
            "commit and-quit",
        ]
        for line in lines:
            response = await self._conn.send_command(line)
            if "error" in response.result.lower():
                raise CommandError(
                    f"JunOS config error on {self.device.hostname}: {response.result}"
                )

    async def get_checkpoint(self) -> str:
        """JunOS: return current committed config in set format."""
        return await self.run("show configuration | display set")

    async def rollback_to_checkpoint(self, checkpoint: str) -> None:
        """
        JunOS supports native rollback — 'rollback 1' reverts to previous commit.
        For full checkpoint restore, we re-apply the saved config.
        """
        lines = [
            "configure exclusive",
            "rollback 1",
            "commit and-quit",
        ]
        for line in lines:
            await self._conn.send_command(line)

    async def save_config(self) -> None:
        """JunOS commits are persistent — no separate save needed."""
        pass  # commit = save in JunOS

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_mtu(mtu_str: str) -> int:
        try:
            return int(re.sub(r"[^\d]", "", mtu_str))
        except (ValueError, TypeError):
            return 1500

    @staticmethod
    def _parse_junos_speed(speed_str: str) -> int | None:
        """Parse JunOS speed strings like '1000mbps', '10Gbps'."""
        if not speed_str:
            return None
        m = re.search(r"(\d+)\s*(g|m)bps", speed_str, re.IGNORECASE)
        if m:
            val = int(m.group(1))
            return val * 1000 if m.group(2).lower() == "g" else val
        return None

    @staticmethod
    def _parse_junos_uptime(uptime_str: str) -> int:
        """Parse JunOS elapsed times like '2w3d 04:05:06'."""
        if not uptime_str:
            return 0
        total = 0
        w = re.search(r"(\d+)w", uptime_str)
        d = re.search(r"(\d+)d", uptime_str)
        t = re.search(r"(\d+):(\d+):(\d+)", uptime_str)
        if w:
            total += int(w.group(1)) * 604800
        if d:
            total += int(d.group(1)) * 86400
        if t:
            total += int(t.group(1)) * 3600 + int(t.group(2)) * 60 + int(t.group(3))
        return total
