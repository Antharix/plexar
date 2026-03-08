"""
Topology Graph Engine.

Builds and maintains a graph model of the network using NetworkX.
Nodes are devices, edges are physical/logical connections.

Capabilities:
  - Build from LLDP/CDP discovery (live)
  - Build from inventory + manual links (static)
  - Shortest path between any two devices
  - Blast radius analysis: what breaks if device/link goes down
  - Segment identification (spine/leaf/border/access)
  - Loop detection
  - Redundancy analysis (single points of failure)
  - Export to JSON / D3-compatible format for visualization

Usage:
    from plexar.topology import TopologyGraph

    # Build from live LLDP discovery
    topo = TopologyGraph()
    await topo.discover(inventory=net.inventory)

    # Shortest path
    path = topo.shortest_path("leaf-01", "spine-02")

    # Blast radius
    blast = topo.blast_radius("spine-01")
    print(blast.affected_devices)
    print(blast.redundant_paths)

    # Export for D3 visualization
    json_data = topo.to_d3()
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.device import Device
    from plexar.core.inventory import Inventory

logger = logging.getLogger(__name__)


# ── Data Models ──────────────────────────────────────────────────────

@dataclass
class TopologyNode:
    """A device node in the topology graph."""
    hostname:       str
    platform:       str               = "unknown"
    management_ip:  str               = ""
    role:           str               = "unknown"    # spine/leaf/border/access
    site:           str               = ""
    tags:           list[str]         = field(default_factory=list)
    metadata:       dict[str, Any]    = field(default_factory=dict)
    is_reachable:   bool              = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":             self.hostname,
            "hostname":       self.hostname,
            "platform":       self.platform,
            "management_ip":  self.management_ip,
            "role":           self.role,
            "site":           self.site,
            "tags":           self.tags,
            "is_reachable":   self.is_reachable,
        }


@dataclass
class TopologyEdge:
    """A link between two devices."""
    source:           str              # hostname
    target:           str              # hostname
    source_interface: str              = ""
    target_interface: str              = ""
    link_type:        str              = "ethernet"   # ethernet/lag/optical/logical
    speed_mbps:       int | None       = None
    discovered_via:   str              = "manual"     # lldp/cdp/manual/static
    metadata:         dict[str, Any]   = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source":           self.source,
            "target":           self.target,
            "source_interface": self.source_interface,
            "target_interface": self.target_interface,
            "link_type":        self.link_type,
            "speed_mbps":       self.speed_mbps,
            "discovered_via":   self.discovered_via,
        }


@dataclass
class BlastRadius:
    """Result of blast radius analysis for a device or link removal."""
    subject:            str              # device/link being removed
    affected_devices:   list[str]        = field(default_factory=list)
    isolated_devices:   list[str]        = field(default_factory=list)   # completely cut off
    degraded_paths:     list[tuple[str, str]] = field(default_factory=list)  # paths losing redundancy
    redundant_paths:    list[tuple[str, str]] = field(default_factory=list)  # paths with alt routes
    risk_score:         int              = 0   # 0-100

    def summary(self) -> str:
        lines = [
            f"Blast Radius: {self.subject}",
            f"  Risk Score:      {self.risk_score}/100",
            f"  Affected:        {len(self.affected_devices)} device(s)",
            f"  Isolated:        {len(self.isolated_devices)} device(s) completely cut off",
            f"  Degraded paths:  {len(self.degraded_paths)} path(s) losing redundancy",
        ]
        if self.isolated_devices:
            lines.append(f"  ⚠  Isolated: {', '.join(self.isolated_devices)}")
        return "\n".join(lines)


# ── Graph Engine ─────────────────────────────────────────────────────

class TopologyGraph:
    """
    Network topology graph.
    Wraps NetworkX DiGraph with network-automation-specific methods.
    """

    def __init__(self) -> None:
        try:
            import networkx as nx
            self._G: Any = nx.Graph()
        except ImportError:
            raise ImportError(
                "Topology requires NetworkX: pip install plexar[topology]"
            )
        self._nodes: dict[str, TopologyNode] = {}
        self._edges: list[TopologyEdge]       = []
        self._discovery_log: list[str]        = []

    # ── Building the graph ────────────────────────────────────────────

    def add_node(self, node: TopologyNode) -> None:
        """Add a device node."""
        self._nodes[node.hostname] = node
        self._G.add_node(
            node.hostname,
            **node.to_dict(),
        )

    def add_edge(self, edge: TopologyEdge) -> None:
        """Add a link between two devices."""
        # Auto-create nodes if they don't exist
        for hostname in (edge.source, edge.target):
            if hostname not in self._nodes:
                self.add_node(TopologyNode(hostname=hostname))

        self._edges.append(edge)
        self._G.add_edge(
            edge.source,
            edge.target,
            source_interface=edge.source_interface,
            target_interface=edge.target_interface,
            link_type=edge.link_type,
            speed_mbps=edge.speed_mbps,
            discovered_via=edge.discovered_via,
        )

    def add_from_inventory(self, inventory: "Inventory") -> None:
        """Seed the graph with nodes from the inventory (no links yet)."""
        for device in inventory.all():
            self.add_node(TopologyNode(
                hostname=device.hostname,
                platform=str(device.platform),
                management_ip=device.management_ip or "",
                role=device.metadata.get("role", "unknown"),
                site=device.metadata.get("site", ""),
                tags=list(device.tags),
            ))

    async def discover(
        self,
        inventory: "Inventory",
        max_concurrent: int = 20,
        protocol: str = "lldp",  # "lldp" | "cdp"
    ) -> "TopologyGraph":
        """
        Auto-discover topology via LLDP/CDP.

        Connects to all devices in inventory, runs LLDP/CDP neighbor
        discovery, and builds the full topology graph.

        Args:
            inventory:      Plexar Inventory to discover from
            max_concurrent: Max concurrent device connections
            protocol:       "lldp" or "cdp"

        Returns self for chaining.
        """
        from plexar.topology.lldp import LLDPDiscovery

        self.add_from_inventory(inventory)
        discovery = LLDPDiscovery(protocol=protocol)
        semaphore = asyncio.Semaphore(max_concurrent)

        devices = inventory.all()
        tasks   = [
            self._discover_device(device, discovery, semaphore)
            for device in devices
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for hostname, result in zip([d.hostname for d in devices], results):
            if isinstance(result, Exception):
                logger.warning(f"LLDP discovery failed on {hostname}: {result}")
                self._discovery_log.append(f"FAILED {hostname}: {result}")
                if hostname in self._nodes:
                    self._nodes[hostname].is_reachable = False
            else:
                self._discovery_log.append(f"OK {hostname}: {len(result)} neighbors")

        return self

    async def _discover_device(
        self,
        device: "Device",
        discovery: Any,
        semaphore: asyncio.Semaphore,
    ) -> list[TopologyEdge]:
        """Discover neighbors on a single device and add edges."""
        async with semaphore:
            edges = await discovery.get_neighbors(device)
            for edge in edges:
                # Only add edge if it doesn't already exist (LLDP is bidirectional)
                if not self._G.has_edge(edge.source, edge.target) and \
                   not self._G.has_edge(edge.target, edge.source):
                    self.add_edge(edge)
            return edges

    # ── Graph Analysis ────────────────────────────────────────────────

    def shortest_path(self, source: str, target: str) -> list[str]:
        """
        Find the shortest path between two devices.

        Returns an ordered list of hostnames from source to target.
        Raises NetworkXNoPath if no path exists.
        """
        import networkx as nx
        try:
            return nx.shortest_path(self._G, source=source, target=target)
        except nx.NodeNotFound as e:
            raise ValueError(f"Device not in topology: {e}")
        except nx.NetworkXNoPath:
            raise ValueError(f"No path exists between {source} and {target}")

    def all_paths(
        self,
        source: str,
        target: str,
        cutoff: int = 10,
    ) -> list[list[str]]:
        """Return all simple paths between two devices."""
        import networkx as nx
        return list(nx.all_simple_paths(self._G, source, target, cutoff=cutoff))

    def blast_radius(self, hostname: str) -> BlastRadius:
        """
        Compute blast radius if a device is removed from the topology.

        Identifies:
          - Which devices become completely isolated
          - Which paths lose redundancy (had 2 paths, now have 1)
          - Overall risk score
        """
        import networkx as nx

        if hostname not in self._G:
            raise ValueError(f"Device '{hostname}' not in topology")

        # Build graph without the device
        G_removed = self._G.copy()
        G_removed.remove_node(hostname)

        affected       = list(self._G.neighbors(hostname))
        isolated       = []
        degraded_paths = []
        redundant_paths = []

        # Check connectivity for all pairs
        all_nodes = list(self._G.nodes)
        for node in all_nodes:
            if node == hostname:
                continue
            if not nx.has_path(G_removed, node, all_nodes[0]) if all_nodes[0] != node else False:
                isolated.append(node)

        # Check which connected pairs lose redundancy
        for i, a in enumerate(all_nodes):
            for b in all_nodes[i+1:]:
                if a == hostname or b == hostname:
                    continue
                paths_before = len(list(nx.all_simple_paths(self._G, a, b, cutoff=6)))
                paths_after  = len(list(nx.all_simple_paths(G_removed, a, b, cutoff=6)))
                if paths_before > 1 and paths_after == 1:
                    degraded_paths.append((a, b))
                elif paths_before >= 1 and paths_after >= 2:
                    redundant_paths.append((a, b))

        # Risk score heuristic
        risk = min(100, (
            len(isolated) * 30 +
            len(degraded_paths) * 10 +
            (50 if len(self._G.degree(hostname)) > 4 else 20)  # high-degree = high risk
        ))

        return BlastRadius(
            subject=hostname,
            affected_devices=affected,
            isolated_devices=isolated,
            degraded_paths=degraded_paths,
            redundant_paths=redundant_paths,
            risk_score=risk,
        )

    def single_points_of_failure(self) -> list[str]:
        """
        Find all devices whose removal would partition the network.
        These are articulation points in graph theory.
        """
        import networkx as nx
        return list(nx.articulation_points(self._G))

    def is_connected(self) -> bool:
        """Return True if the topology is fully connected."""
        import networkx as nx
        return nx.is_connected(self._G)

    def segments(self) -> dict[str, list[str]]:
        """
        Return devices grouped by their detected segment/role.
        Based on node degree and metadata:
          spines:  high degree nodes with no edge devices
          leafs:   medium degree nodes
          borders: connected to external (different site/AS)
          access:  leaf-of-leaf
        """
        groups: dict[str, list[str]] = {
            "spine": [], "leaf": [], "border": [], "access": [], "unknown": []
        }
        for hostname, data in self._G.nodes(data=True):
            role = data.get("role", "unknown")
            degree = self._G.degree(hostname)
            if role != "unknown":
                groups.setdefault(role, []).append(hostname)
            elif degree >= 4:
                groups["spine"].append(hostname)
            elif degree >= 2:
                groups["leaf"].append(hostname)
            else:
                groups["access"].append(hostname)
        return {k: v for k, v in groups.items() if v}

    # ── Export ────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Export topology as a dictionary (nodes + edges)."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }

    def to_d3(self) -> dict[str, Any]:
        """
        Export topology in D3.js force-graph format.

        Compatible with:
          - D3 force-directed graph
          - Cytoscape.js
          - Vis.js Network
        """
        nodes = []
        for node in self._nodes.values():
            d = node.to_dict()
            d["group"] = node.role
            nodes.append(d)

        links = []
        for edge in self._edges:
            links.append({
                "source": edge.source,
                "target": edge.target,
                "value":  1,
                "label":  f"{edge.source_interface} ↔ {edge.target_interface}",
                "speed":  edge.speed_mbps,
                "type":   edge.link_type,
            })

        return {"nodes": nodes, "links": links}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_d3(), indent=indent)

    # ── Stats ─────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._nodes)

    def __repr__(self) -> str:
        return (
            f"TopologyGraph({len(self._nodes)} nodes, "
            f"{len(self._edges)} edges, "
            f"connected={self.is_connected()})"
        )
