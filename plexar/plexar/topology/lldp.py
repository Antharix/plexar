"""
LLDP / CDP Neighbor Discovery.

Connects to devices and parses LLDP (or CDP) neighbor tables
to build physical topology edges.

Vendor-specific parsing:
  - Arista EOS:    show lldp neighbors detail | json
  - Cisco NX-OS:   show lldp neighbors detail | json
  - Cisco IOS:     show lldp neighbors detail (text parsing)
  - Juniper JunOS: show lldp neighbors detail | display json

CDP supported as fallback for Cisco devices that don't run LLDP.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from plexar.core.device import Device

from plexar.topology.graph import TopologyEdge

logger = logging.getLogger(__name__)


class LLDPDiscovery:
    """
    LLDP/CDP-based topology discovery engine.

    Usage:
        discovery = LLDPDiscovery(protocol="lldp")
        edges = await discovery.get_neighbors(device)
    """

    def __init__(self, protocol: str = "lldp") -> None:
        self.protocol = protocol.lower()   # "lldp" | "cdp"

    async def get_neighbors(self, device: "Device") -> list[TopologyEdge]:
        """
        Get all neighbors from a device via LLDP/CDP.
        Returns a list of TopologyEdge objects.
        """
        platform = str(device.platform).lower()

        try:
            async with device:
                if "arista" in platform:
                    return await self._discover_arista(device)
                elif "nxos" in platform:
                    return await self._discover_nxos(device)
                elif "ios" in platform:
                    return await self._discover_ios(device)
                elif "junos" in platform or "juniper" in platform:
                    return await self._discover_junos(device)
                else:
                    logger.warning(f"No LLDP parser for platform '{platform}' on {device.hostname}")
                    return []
        except Exception as exc:
            logger.error(f"LLDP discovery failed on {device.hostname}: {exc}")
            return []

    # ── Arista EOS ────────────────────────────────────────────────────

    async def _discover_arista(self, device: "Device") -> list[TopologyEdge]:
        edges = []
        try:
            raw    = await device.run("show lldp neighbors detail | json")
            data   = json.loads(raw)
            lldp_neighbors = data.get("lldpNeighbors", {})

            for local_iface, neighbors in lldp_neighbors.items():
                for entry in neighbors.get("lldpNeighborInfo", []):
                    remote_host = entry.get("systemName", "").strip()
                    remote_iface = entry.get("neighborInterfaceInfo", {}).get("interfaceId", "")

                    if not remote_host:
                        remote_host = entry.get("chassisId", "unknown")

                    # Normalize interface name
                    remote_host = _normalize_hostname(remote_host)

                    edges.append(TopologyEdge(
                        source=device.hostname,
                        target=remote_host,
                        source_interface=local_iface,
                        target_interface=remote_iface,
                        discovered_via="lldp",
                        metadata={
                            "system_description": entry.get("systemDescription", ""),
                            "capabilities":       entry.get("systemCapabilities", []),
                        },
                    ))
        except json.JSONDecodeError:
            logger.warning(f"{device.hostname}: LLDP JSON parse failed, trying text")
            edges = await self._discover_text_fallback(device)
        except Exception as exc:
            logger.error(f"{device.hostname}: Arista LLDP discovery error: {exc}")

        return edges

    # ── Cisco NX-OS ───────────────────────────────────────────────────

    async def _discover_nxos(self, device: "Device") -> list[TopologyEdge]:
        edges = []
        try:
            raw  = await device.run("show lldp neighbors detail | json")
            data = json.loads(raw)

            table = data.get("TABLE_nbor_detail", {}).get("ROW_nbor_detail", [])
            if isinstance(table, dict):
                table = [table]

            for entry in table:
                remote_host  = entry.get("sys_name", "").strip()
                local_iface  = entry.get("l_port_id", "")
                remote_iface = entry.get("port_id", "")

                if not remote_host:
                    remote_host = entry.get("chassis_id", "unknown")

                edges.append(TopologyEdge(
                    source=device.hostname,
                    target=_normalize_hostname(remote_host),
                    source_interface=local_iface,
                    target_interface=remote_iface,
                    discovered_via="lldp",
                ))
        except json.JSONDecodeError:
            edges = await self._discover_text_fallback(device)
        except Exception as exc:
            logger.error(f"{device.hostname}: NX-OS LLDP discovery error: {exc}")

        return edges

    # ── Cisco IOS / IOS-XE ────────────────────────────────────────────

    async def _discover_ios(self, device: "Device") -> list[TopologyEdge]:
        edges = []
        try:
            # Try CDP first (more common on IOS)
            command = (
                "show cdp neighbors detail"
                if self.protocol == "cdp"
                else "show lldp neighbors detail"
            )
            raw = await device.run(command)

            if self.protocol == "cdp":
                edges = _parse_cdp_detail(device.hostname, raw)
            else:
                edges = _parse_lldp_detail_ios(device.hostname, raw)

        except Exception as exc:
            logger.error(f"{device.hostname}: IOS LLDP/CDP discovery error: {exc}")

        return edges

    # ── Juniper JunOS ─────────────────────────────────────────────────

    async def _discover_junos(self, device: "Device") -> list[TopologyEdge]:
        edges = []
        try:
            raw  = await device.run("show lldp neighbors | display json")
            data = json.loads(raw)

            table = (
                data.get("lldp-neighbors-information", [{}])[0]
                    .get("lldp-neighbor-information", [])
            )

            for entry in table:
                def get(key: str) -> str:
                    v = entry.get(key, [{}])
                    return v[0].get("data", "") if isinstance(v, list) else ""

                remote_host  = get("lldp-remote-system-name")
                local_iface  = get("lldp-local-port-id")
                remote_iface = get("lldp-remote-port-id")

                if not remote_host:
                    remote_host = get("lldp-remote-chassis-id")

                edges.append(TopologyEdge(
                    source=device.hostname,
                    target=_normalize_hostname(remote_host),
                    source_interface=local_iface,
                    target_interface=remote_iface,
                    discovered_via="lldp",
                ))
        except json.JSONDecodeError:
            edges = await self._discover_text_fallback(device)
        except Exception as exc:
            logger.error(f"{device.hostname}: JunOS LLDP discovery error: {exc}")

        return edges

    # ── Text Fallback ─────────────────────────────────────────────────

    async def _discover_text_fallback(self, device: "Device") -> list[TopologyEdge]:
        """Generic text-based LLDP parser for unknown/fallback platforms."""
        try:
            raw   = await device.run("show lldp neighbors")
            return _parse_lldp_brief(device.hostname, raw)
        except Exception as exc:
            logger.debug(f"{device.hostname}: Text LLDP fallback also failed: {exc}")
            return []


# ── Text Parsers ──────────────────────────────────────────────────────

def _parse_cdp_detail(source_hostname: str, output: str) -> list[TopologyEdge]:
    """Parse 'show cdp neighbors detail' output."""
    edges  = []
    blocks = re.split(r"-{10,}", output)

    for block in blocks:
        if not block.strip():
            continue
        device_id   = re.search(r"Device ID:\s*(\S+)",       block)
        local_iface = re.search(r"Interface:\s*(\S+),",      block)
        remote_iface = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)

        if device_id:
            edges.append(TopologyEdge(
                source=source_hostname,
                target=_normalize_hostname(device_id.group(1)),
                source_interface=local_iface.group(1)  if local_iface  else "",
                target_interface=remote_iface.group(1) if remote_iface else "",
                discovered_via="cdp",
            ))
    return edges


def _parse_lldp_detail_ios(source_hostname: str, output: str) -> list[TopologyEdge]:
    """Parse 'show lldp neighbors detail' text output from IOS."""
    edges  = []
    blocks = re.split(r"-{10,}", output)

    for block in blocks:
        if not block.strip():
            continue
        sys_name    = re.search(r"System Name:\s*(\S+)",        block)
        local_iface = re.search(r"Local Intf:\s*(\S+)",         block)
        remote_iface = re.search(r"Port id:\s*(\S+)",           block)
        if sys_name:
            edges.append(TopologyEdge(
                source=source_hostname,
                target=_normalize_hostname(sys_name.group(1)),
                source_interface=local_iface.group(1)  if local_iface  else "",
                target_interface=remote_iface.group(1) if remote_iface else "",
                discovered_via="lldp",
            ))
    return edges


def _parse_lldp_brief(source_hostname: str, output: str) -> list[TopologyEdge]:
    """Parse brief 'show lldp neighbors' output — last resort."""
    edges = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            remote_host  = parts[0]
            local_iface  = parts[1]
            remote_iface = parts[-1]
            if re.match(r"[A-Za-z]", remote_host):
                edges.append(TopologyEdge(
                    source=source_hostname,
                    target=_normalize_hostname(remote_host),
                    source_interface=local_iface,
                    target_interface=remote_iface,
                    discovered_via="lldp",
                ))
    return edges


def _normalize_hostname(hostname: str) -> str:
    """
    Normalize a hostname discovered via LLDP/CDP.
    Strips domain suffixes, trailing dots, port info.
    """
    hostname = hostname.strip().rstrip(".")
    # Strip domain suffix (keep only hostname part)
    if "." in hostname and not _looks_like_ip(hostname):
        hostname = hostname.split(".")[0]
    return hostname.lower()


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))
