"""
Plexar Topology Engine.

Auto-discovers network topology via LLDP/CDP and builds
a full graph model for path analysis, blast radius, and visualization.

Usage:
    from plexar.topology import TopologyGraph

    topo = TopologyGraph()
    await topo.discover(inventory=net.inventory)

    path  = topo.shortest_path("leaf-01", "spine-02")
    blast = topo.blast_radius("spine-01")
    spof  = topo.single_points_of_failure()
    d3    = topo.to_d3()
"""

from plexar.topology.graph import (
    TopologyGraph, TopologyNode, TopologyEdge, BlastRadius,
)
from plexar.topology.lldp import LLDPDiscovery

__all__ = [
    "TopologyGraph", "TopologyNode", "TopologyEdge", "BlastRadius",
    "LLDPDiscovery",
]
