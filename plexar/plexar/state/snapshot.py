"""
State Snapshot Engine.

Captures a point-in-time snapshot of a device's full operational state.
Snapshots are:
  - Serializable (JSON)
  - Comparable (compute delta between two snapshots)
  - Storable (write to disk for historical tracking)

Usage:
    snapshot = await StateSnapshot.capture(device)
    snapshot.save("snapshots/spine-01-before.json")

    # Later, after a change:
    after = await StateSnapshot.capture(device)
    delta = snapshot.compare(after)
    print(delta.summary())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.device import Device


@dataclass
class SnapshotDelta:
    """Differences between two snapshots."""
    device_hostname: str
    captured_before: datetime
    captured_after:  datetime
    changes:         dict[str, Any] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def summary(self) -> str:
        if not self.has_changes:
            return f"No state changes on {self.device_hostname}."
        lines = [f"State changes on {self.device_hostname}:"]
        for section, changes in self.changes.items():
            lines.append(f"  {section}:")
            if isinstance(changes, list):
                for change in changes:
                    lines.append(f"    - {change}")
            else:
                lines.append(f"    {changes}")
        return "\n".join(lines)


@dataclass
class StateSnapshot:
    """
    Full operational state snapshot for a single device.

    Captures: interfaces, BGP peers, routing table, platform info.
    """
    hostname:    str
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    platform:    str      = ""

    # State sections
    interfaces:    list[dict[str, Any]] = field(default_factory=list)
    bgp_summary:   dict[str, Any]       = field(default_factory=dict)
    routing_table: list[dict[str, Any]] = field(default_factory=list)
    platform_info: dict[str, Any]       = field(default_factory=dict)

    @classmethod
    async def capture(cls, device: "Device") -> "StateSnapshot":
        """
        Capture a full state snapshot from a live device.

        Runs all getters concurrently for speed.
        """
        import asyncio

        snapshot = cls(hostname=device.hostname, platform=str(device.platform))

        # Run all getters concurrently
        results = await asyncio.gather(
            device.get_interfaces(),
            device.get_bgp_summary(),
            device.get_routing_table(),
            device.get_platform_info(),
            return_exceptions=True,
        )

        interfaces, bgp, routing, platform_info = results

        if not isinstance(interfaces, Exception):
            snapshot.interfaces = [i.model_dump() for i in interfaces]
        if not isinstance(bgp, Exception):
            snapshot.bgp_summary = bgp.model_dump()
        if not isinstance(routing, Exception):
            snapshot.routing_table = [r.model_dump() for r in routing.routes]
        if not isinstance(platform_info, Exception):
            snapshot.platform_info = platform_info.model_dump()

        return snapshot

    def compare(self, other: "StateSnapshot") -> SnapshotDelta:
        """Compute a delta between this snapshot and a later one."""
        changes: dict[str, Any] = {}

        # Interface comparison
        iface_changes = self._compare_interfaces(
            self.interfaces, other.interfaces
        )
        if iface_changes:
            changes["interfaces"] = iface_changes

        # BGP peer comparison
        bgp_changes = self._compare_bgp(
            self.bgp_summary.get("peers", []),
            other.bgp_summary.get("peers", []),
        )
        if bgp_changes:
            changes["bgp"] = bgp_changes

        # Route comparison
        route_changes = self._compare_routes(
            self.routing_table, other.routing_table
        )
        if route_changes:
            changes["routing"] = route_changes

        return SnapshotDelta(
            device_hostname=self.hostname,
            captured_before=self.captured_at,
            captured_after=other.captured_at,
            changes=changes,
        )

    def save(self, path: str | Path) -> None:
        """Serialize snapshot to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str | Path) -> "StateSnapshot":
        """Load snapshot from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(
            hostname=data["hostname"],
            platform=data["platform"],
            captured_at=datetime.fromisoformat(data["captured_at"]),
            interfaces=data.get("interfaces", []),
            bgp_summary=data.get("bgp_summary", {}),
            routing_table=data.get("routing_table", []),
            platform_info=data.get("platform_info", {}),
        )

    def _to_dict(self) -> dict[str, Any]:
        return {
            "hostname":     self.hostname,
            "platform":     self.platform,
            "captured_at":  self.captured_at.isoformat(),
            "interfaces":   self.interfaces,
            "bgp_summary":  self.bgp_summary,
            "routing_table": self.routing_table,
            "platform_info": self.platform_info,
        }

    # ── Delta helpers ────────────────────────────────────────────────

    @staticmethod
    def _compare_interfaces(
        before: list[dict], after: list[dict]
    ) -> list[str]:
        changes = []
        before_map = {i["name"]: i for i in before}
        after_map  = {i["name"]: i for i in after}

        for name, iface in after_map.items():
            if name not in before_map:
                changes.append(f"NEW interface: {name} ({iface.get('oper_state')})")
                continue
            prev = before_map[name]
            if prev.get("oper_state") != iface.get("oper_state"):
                changes.append(
                    f"{name}: oper_state {prev.get('oper_state')} → {iface.get('oper_state')}"
                )
            if prev.get("admin_state") != iface.get("admin_state"):
                changes.append(
                    f"{name}: admin_state {prev.get('admin_state')} → {iface.get('admin_state')}"
                )

        for name in before_map:
            if name not in after_map:
                changes.append(f"REMOVED interface: {name}")

        return changes

    @staticmethod
    def _compare_bgp(
        before_peers: list[dict], after_peers: list[dict]
    ) -> list[str]:
        changes = []
        before_map = {p["neighbor_ip"]: p for p in before_peers}
        after_map  = {p["neighbor_ip"]: p for p in after_peers}

        for ip, peer in after_map.items():
            if ip not in before_map:
                changes.append(f"NEW peer: {ip} ({peer.get('state')})")
                continue
            prev = before_map[ip]
            if prev.get("state") != peer.get("state"):
                changes.append(
                    f"Peer {ip}: state {prev.get('state')} → {peer.get('state')}"
                )

        for ip in before_map:
            if ip not in after_map:
                changes.append(f"REMOVED peer: {ip}")

        return changes

    @staticmethod
    def _compare_routes(
        before_routes: list[dict], after_routes: list[dict]
    ) -> list[str]:
        changes = []
        before_set = {(r["prefix"], r.get("next_hop")) for r in before_routes}
        after_set  = {(r["prefix"], r.get("next_hop")) for r in after_routes}

        added   = after_set - before_set
        removed = before_set - after_set

        for prefix, nh in sorted(added):
            changes.append(f"+ {prefix} via {nh}")
        for prefix, nh in sorted(removed):
            changes.append(f"- {prefix} via {nh}")

        return changes

    def __repr__(self) -> str:
        return (
            f"StateSnapshot(hostname={self.hostname!r}, "
            f"captured_at={self.captured_at.isoformat()}, "
            f"interfaces={len(self.interfaces)}, "
            f"bgp_peers={len(self.bgp_summary.get('peers', []))})"
        )
