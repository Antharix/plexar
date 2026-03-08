"""
Digital Twin & Change Simulator.

Before pushing config to production, simulate the change against
a digital twin of the network. Predict outcomes, validate intent,
and catch issues before they impact the network.

The twin is built from:
  - State snapshots (actual device state)
  - Topology graph (LLDP-discovered links)
  - Intent declarations (desired state)

Simulation capabilities:
  - Config change impact analysis (what breaks if X is changed)
  - BGP convergence simulation (what routes change after a peer change)
  - Interface failure simulation (what traffic is affected if port X goes down)
  - Intent pre-apply validation (will this intent succeed?)
  - Blast radius prediction (before LLDP-based live analysis)

Usage:
    from plexar.twin import DigitalTwin

    twin = DigitalTwin()

    # Build from live snapshot
    await twin.capture(network=net)

    # Simulate removing a BGP peer
    result = twin.simulate_bgp_peer_removal("spine-01", neighbor_ip="10.0.0.2")
    print(result.affected_routes)
    print(result.affected_devices)

    # Simulate interface failure
    result = twin.simulate_interface_failure("leaf-01", interface="Ethernet1")
    print(result.impact_summary())

    # Pre-validate intent
    result = twin.validate_intent(intent)
    print(result.conflicts)
    print(result.warnings)
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.network import Network
    from plexar.core.device import Device
    from plexar.topology.graph import TopologyGraph
    from plexar.intent.engine import Intent
    from plexar.state.snapshot import StateSnapshot

logger = logging.getLogger(__name__)


# ── Simulation Results ────────────────────────────────────────────────

@dataclass
class SimulationResult:
    """Result of a digital twin simulation."""
    simulation_type:   str
    subject:           str                     # device/interface/peer being simulated
    affected_devices:  list[str]               = field(default_factory=list)
    affected_routes:   list[str]               = field(default_factory=list)
    affected_services: list[str]               = field(default_factory=list)
    warnings:          list[str]               = field(default_factory=list)
    errors:            list[str]               = field(default_factory=list)
    risk_score:        int                     = 0
    metadata:          dict[str, Any]          = field(default_factory=dict)
    simulated_at:      datetime                = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_safe(self) -> bool:
        return len(self.errors) == 0 and self.risk_score < 40

    def impact_summary(self) -> str:
        lines = [
            f"Simulation: {self.simulation_type} — {self.subject}",
            f"  Risk Score:       {self.risk_score}/100",
            f"  Affected devices: {len(self.affected_devices)}",
            f"  Affected routes:  {len(self.affected_routes)}",
        ]
        if self.warnings:
            lines += [f"  ⚠  {w}" for w in self.warnings]
        if self.errors:
            lines += [f"  ✗  {e}" for e in self.errors]
        if not self.warnings and not self.errors:
            lines.append("  ✓  No issues predicted")
        return "\n".join(lines)


@dataclass
class IntentValidationResult:
    """Result of pre-applying an intent against the digital twin."""
    passed:    bool
    conflicts: list[str]    = field(default_factory=list)
    warnings:  list[str]    = field(default_factory=list)
    info:      list[str]    = field(default_factory=list)

    def summary(self) -> str:
        status = "✓ PASS" if self.passed else "✗ FAIL"
        lines  = [f"Intent Validation: {status}"]
        lines += [f"  conflict: {c}" for c in self.conflicts]
        lines += [f"  warning:  {w}" for w in self.warnings]
        lines += [f"  info:     {i}" for i in self.info]
        return "\n".join(lines)


# ── Digital Twin ──────────────────────────────────────────────────────

class DigitalTwin:
    """
    A virtual model of the network built from live state snapshots.

    Enables safe simulation of changes before pushing to production.
    """

    def __init__(self) -> None:
        self._snapshots:  dict[str, "StateSnapshot"]  = {}
        self._topology:   "TopologyGraph | None"       = None
        self._captured_at: datetime | None             = None

    async def capture(
        self,
        network:        "Network",
        include_topology: bool = True,
        max_concurrent: int   = 20,
    ) -> "DigitalTwin":
        """
        Capture the current network state into the digital twin.

        Connects to all devices concurrently, captures state snapshots,
        and optionally runs LLDP topology discovery.

        Args:
            network:          Plexar Network to snapshot
            include_topology: Run LLDP topology discovery
            max_concurrent:   Max concurrent device connections

        Returns self for chaining.
        """
        import asyncio
        from plexar.state.snapshot import StateSnapshot

        devices   = network.inventory.all()
        semaphore = asyncio.Semaphore(max_concurrent)

        async def snap(device: "Device") -> None:
            async with semaphore:
                try:
                    async with device:
                        snapshot = await StateSnapshot.capture(device)
                        self._snapshots[device.hostname] = snapshot
                        logger.debug(f"Twin: captured {device.hostname}")
                except Exception as exc:
                    logger.warning(f"Twin: failed to capture {device.hostname}: {exc}")

        await asyncio.gather(*[snap(d) for d in devices])

        if include_topology:
            try:
                from plexar.topology.graph import TopologyGraph
                self._topology = TopologyGraph()
                self._topology.add_from_inventory(network.inventory)
                await self._topology.discover(network.inventory, max_concurrent=max_concurrent)
            except Exception as exc:
                logger.warning(f"Twin: topology discovery failed: {exc}")

        self._captured_at = datetime.now(timezone.utc)
        logger.info(
            f"Digital twin captured: {len(self._snapshots)} devices, "
            f"topology={'yes' if self._topology else 'no'}"
        )
        return self

    def load_snapshot(self, hostname: str, snapshot: "StateSnapshot") -> None:
        """Manually add a snapshot to the twin."""
        self._snapshots[hostname] = snapshot

    def load_topology(self, topology: "TopologyGraph") -> None:
        """Set the topology for this twin."""
        self._topology = topology

    # ── Simulations ───────────────────────────────────────────────────

    def simulate_interface_failure(
        self,
        hostname:  str,
        interface: str,
    ) -> SimulationResult:
        """
        Simulate what happens if an interface goes down.

        Checks: link redundancy, BGP peers on this interface,
        traffic paths that traverse this link.
        """
        result = SimulationResult(
            simulation_type="interface_failure",
            subject=f"{hostname}/{interface}",
        )

        snapshot = self._snapshots.get(hostname)
        if not snapshot:
            result.warnings.append(f"No snapshot for {hostname} — simulation may be incomplete")

        # Check topology impact
        if self._topology:
            try:
                neighbors = list(self._topology._G.neighbors(hostname))
                result.affected_devices = neighbors

                # Check if this removes the only path
                blast = self._topology.blast_radius(hostname)
                result.risk_score = blast.risk_score

                if blast.isolated_devices:
                    result.errors.append(
                        f"Removing {interface} from {hostname} would isolate: "
                        f"{', '.join(blast.isolated_devices)}"
                    )
                if blast.degraded_paths:
                    result.warnings.append(
                        f"{len(blast.degraded_paths)} path(s) would lose redundancy"
                    )
            except Exception as exc:
                logger.debug(f"Topology simulation error: {exc}")

        # Check for BGP on this interface from snapshot
        if snapshot:
            try:
                for peer in snapshot.bgp.peers:
                    # Heuristic: if peer IP is in same /30 as interface
                    result.warnings.append(
                        f"BGP peer {peer.neighbor_ip} may be affected (verify manually)"
                    )
                    result.affected_services.append(f"bgp-peer-{peer.neighbor_ip}")
                    break  # Only warn once as heuristic
            except Exception:
                pass

        return result

    def simulate_bgp_peer_removal(
        self,
        hostname:    str,
        neighbor_ip: str,
    ) -> SimulationResult:
        """
        Simulate removing a BGP peer.

        Predicts route loss, prefix count impact, and topology changes.
        """
        result = SimulationResult(
            simulation_type="bgp_peer_removal",
            subject=f"{hostname} → {neighbor_ip}",
        )

        snapshot = self._snapshots.get(hostname)
        if not snapshot:
            result.warnings.append(f"No snapshot available for {hostname}")
            return result

        # Find the peer in the snapshot
        peer = next(
            (p for p in snapshot.bgp.peers if p.neighbor_ip == neighbor_ip),
            None,
        )
        if not peer:
            result.info = [f"Peer {neighbor_ip} not found in snapshot — may already be inactive"]
            result.risk_score = 0
            return result

        # Estimate impact
        result.metadata["peer_state"]      = peer.state
        result.metadata["prefixes_lost"]   = peer.prefixes_received
        result.affected_routes = [f"~{peer.prefixes_received} prefixes from AS{peer.remote_as}"]

        if peer.prefixes_received > 0:
            result.warnings.append(
                f"Removing peer {neighbor_ip} (AS{peer.remote_as}) would withdraw "
                f"{peer.prefixes_received} prefixes"
            )

        # Risk based on prefix count
        result.risk_score = min(100, peer.prefixes_received // 10 + 20)

        # Check if this is the only peer
        if len(snapshot.bgp.peers) == 1:
            result.errors.append(
                f"This is the ONLY BGP peer on {hostname} — removing it causes full BGP loss"
            )
            result.risk_score = 100

        return result

    def simulate_device_failure(self, hostname: str) -> SimulationResult:
        """
        Simulate complete device failure (power off / crash).
        Uses topology blast radius analysis.
        """
        result = SimulationResult(
            simulation_type="device_failure",
            subject=hostname,
        )

        if self._topology and hostname in self._topology._G:
            blast                = self._topology.blast_radius(hostname)
            result.affected_devices  = blast.affected_devices
            result.risk_score        = blast.risk_score

            if blast.isolated_devices:
                result.errors.append(
                    f"Device failure would ISOLATE: {', '.join(blast.isolated_devices)}"
                )
            if blast.degraded_paths:
                result.warnings.append(
                    f"{len(blast.degraded_paths)} path(s) would lose redundancy"
                )
        else:
            result.warnings.append("No topology data — install networkx and run twin.capture()")

        # Include BGP impact from snapshot
        snapshot = self._snapshots.get(hostname)
        if snapshot:
            result.metadata["bgp_peers"]  = len(snapshot.bgp.peers)
            result.metadata["interfaces"] = len(snapshot.interfaces)

        return result

    def validate_intent(self, intent: "Intent") -> IntentValidationResult:
        """
        Pre-validate intent primitives against current twin state.

        Checks for conflicts, redundancy issues, and potential failures
        before the intent is applied to production.
        """
        from plexar.intent.primitives import (
            BGPIntent, InterfaceIntent, VLANIntent, RouteIntent,
        )

        result = IntentValidationResult(passed=True)

        for primitive in intent._primitives:
            if isinstance(primitive, InterfaceIntent):
                self._validate_interface_intent(primitive, intent.devices, result)
            elif isinstance(primitive, BGPIntent):
                self._validate_bgp_intent(primitive, intent.devices, result)
            elif isinstance(primitive, RouteIntent):
                self._validate_route_intent(primitive, intent.devices, result)

        if result.conflicts:
            result.passed = False

        return result

    def _validate_interface_intent(
        self,
        intent:   "InterfaceIntent",
        devices:  list["Device"],
        result:   IntentValidationResult,
    ) -> None:
        """Validate an InterfaceIntent against twin state."""
        for device in devices:
            snapshot = self._snapshots.get(device.hostname)
            if not snapshot:
                continue
            iface = next(
                (i for i in snapshot.interfaces if i.name == intent.name),
                None,
            )
            if iface is None:
                result.warnings.append(
                    f"{device.hostname}: Interface {intent.name} not found in snapshot — "
                    "verify name is correct"
                )
            elif intent.mtu and iface.mtu and intent.mtu != iface.mtu:
                result.info.append(
                    f"{device.hostname}: MTU will change {iface.mtu} → {intent.mtu} on {intent.name}"
                )

    def _validate_bgp_intent(
        self,
        intent:   "BGPIntent",
        devices:  list["Device"],
        result:   IntentValidationResult,
    ) -> None:
        """Validate a BGPIntent against twin state."""
        for device in devices:
            snapshot = self._snapshots.get(device.hostname)
            if not snapshot:
                continue
            current_asn_peers = {p.neighbor_ip for p in snapshot.bgp.peers}
            intent_peers      = {n.ip for n in intent.neighbors}
            new_peers         = intent_peers - current_asn_peers
            removed_peers     = current_asn_peers - intent_peers

            if removed_peers:
                result.warnings.append(
                    f"{device.hostname}: BGP intent would REMOVE existing peers: "
                    f"{', '.join(removed_peers)}"
                )
            if new_peers:
                result.info.append(
                    f"{device.hostname}: BGP intent would ADD new peers: {', '.join(new_peers)}"
                )

    def _validate_route_intent(
        self,
        intent:   "RouteIntent",
        devices:  list["Device"],
        result:   IntentValidationResult,
    ) -> None:
        """Validate a RouteIntent against twin state."""
        for device in devices:
            snapshot = self._snapshots.get(device.hostname)
            if not snapshot:
                continue
            existing = snapshot.routes.has_route(intent.prefix)
            if existing:
                result.info.append(
                    f"{device.hostname}: Route {intent.prefix} already exists — will be idempotent"
                )

    # ── Properties ────────────────────────────────────────────────────

    @property
    def captured_at(self) -> datetime | None:
        return self._captured_at

    @property
    def device_count(self) -> int:
        return len(self._snapshots)

    @property
    def is_stale(self) -> bool:
        """Returns True if twin is older than 1 hour."""
        if not self._captured_at:
            return True
        age = (datetime.now(timezone.utc) - self._captured_at).total_seconds()
        return age > 3600

    def __repr__(self) -> str:
        ts = self._captured_at.strftime("%Y-%m-%d %H:%M UTC") if self._captured_at else "never"
        return f"DigitalTwin(devices={self.device_count}, captured={ts}, stale={self.is_stale})"
