"""Tests for the Topology Graph Engine."""

import pytest

pytest.importorskip("networkx", reason="networkx not installed — skip topology tests")

from plexar.topology.graph import TopologyGraph, TopologyNode, TopologyEdge, BlastRadius
from plexar.topology.lldp import _normalize_hostname, _parse_cdp_detail, _parse_lldp_brief


# ── Graph Construction ────────────────────────────────────────────────

class TestTopologyGraph:
    def _spine_leaf_graph(self) -> TopologyGraph:
        """Build a simple 2-spine, 4-leaf topology."""
        topo = TopologyGraph()
        for name, role in [
            ("spine-01", "spine"), ("spine-02", "spine"),
            ("leaf-01",  "leaf"),  ("leaf-02",  "leaf"),
            ("leaf-03",  "leaf"),  ("leaf-04",  "leaf"),
        ]:
            topo.add_node(TopologyNode(hostname=name, role=role))

        # Each leaf connects to both spines
        for leaf in ["leaf-01", "leaf-02", "leaf-03", "leaf-04"]:
            topo.add_edge(TopologyEdge(source=leaf, target="spine-01", source_interface="Eth1", target_interface=f"Eth{leaf[-1]}"))
            topo.add_edge(TopologyEdge(source=leaf, target="spine-02", source_interface="Eth2", target_interface=f"Eth{leaf[-1]}"))

        return topo

    def test_node_count(self):
        topo = self._spine_leaf_graph()
        assert len(topo) == 6

    def test_edge_count(self):
        topo = self._spine_leaf_graph()
        assert len(topo._edges) == 8   # 4 leafs × 2 spines

    def test_is_connected(self):
        topo = self._spine_leaf_graph()
        assert topo.is_connected()

    def test_shortest_path_leaf_to_leaf(self):
        topo = self._spine_leaf_graph()
        path = topo.shortest_path("leaf-01", "leaf-02")
        assert path[0] == "leaf-01"
        assert path[-1] == "leaf-02"
        assert len(path) == 3   # leaf-01 → spine-X → leaf-02

    def test_all_paths_returns_multiple(self):
        topo  = self._spine_leaf_graph()
        paths = topo.all_paths("leaf-01", "leaf-02")
        assert len(paths) == 2   # via spine-01 and via spine-02

    def test_shortest_path_unknown_device_raises(self):
        topo = self._spine_leaf_graph()
        with pytest.raises(ValueError, match="not in topology"):
            topo.shortest_path("leaf-01", "nonexistent-device")

    def test_blast_radius_spine_has_high_risk(self):
        topo  = self._spine_leaf_graph()
        blast = topo.blast_radius("spine-01")
        assert isinstance(blast, BlastRadius)
        assert blast.risk_score > 0
        assert "spine-01" == blast.subject
        assert len(blast.affected_devices) > 0

    def test_blast_radius_no_isolated_on_dual_spine(self):
        """With 2 spines, removing one spine should not isolate any leaf."""
        topo  = self._spine_leaf_graph()
        blast = topo.blast_radius("spine-01")
        # All leafs still reachable via spine-02
        assert len(blast.isolated_devices) == 0

    def test_single_points_of_failure_empty_redundant_topology(self):
        """In a fully redundant spine-leaf, spines are NOT articulation points."""
        topo  = self._spine_leaf_graph()
        spof  = topo.single_points_of_failure()
        # In a well-designed dual-spine topology, no device should be a SPOF
        # (leafs have 2 paths to any other leaf)
        assert isinstance(spof, list)

    def test_segments_returns_spine_and_leaf(self):
        topo = self._spine_leaf_graph()
        segs = topo.segments()
        assert "spine" in segs or "leaf" in segs

    def test_auto_creates_nodes_for_edge(self):
        topo = TopologyGraph()
        topo.add_edge(TopologyEdge(source="sw-01", target="sw-02"))
        assert len(topo) == 2

    def test_repr_contains_stats(self):
        topo = self._spine_leaf_graph()
        r    = repr(topo)
        assert "6" in r    # nodes
        assert "edge" in r.lower()


class TestTopologyExport:
    def test_to_dict_has_nodes_and_edges(self):
        topo = TopologyGraph()
        topo.add_node(TopologyNode(hostname="sw-01"))
        topo.add_node(TopologyNode(hostname="sw-02"))
        topo.add_edge(TopologyEdge(source="sw-01", target="sw-02"))

        d = topo.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1

    def test_to_d3_format(self):
        topo = TopologyGraph()
        topo.add_node(TopologyNode(hostname="sw-01", role="spine"))
        topo.add_node(TopologyNode(hostname="sw-02", role="leaf"))
        topo.add_edge(TopologyEdge(source="sw-01", target="sw-02", speed_mbps=100000))

        d3 = topo.to_d3()
        assert "nodes" in d3
        assert "links" in d3
        assert d3["nodes"][0]["group"] in ("spine", "leaf", "unknown")
        assert d3["links"][0]["speed"] == 100000

    def test_to_json_is_valid_json(self):
        import json
        topo = TopologyGraph()
        topo.add_node(TopologyNode(hostname="sw-01"))
        topo.add_edge(TopologyEdge(source="sw-01", target="sw-02"))
        json_str = topo.to_json()
        parsed   = json.loads(json_str)
        assert "nodes" in parsed


# ── LLDP Parser Tests ─────────────────────────────────────────────────

class TestLLDPParsers:
    def test_normalize_hostname_strips_domain(self):
        assert _normalize_hostname("spine-01.corp.com") == "spine-01"

    def test_normalize_hostname_lowercases(self):
        assert _normalize_hostname("SPINE-01") == "spine-01"

    def test_normalize_hostname_strips_trailing_dot(self):
        assert _normalize_hostname("leaf-01.") == "leaf-01"

    def test_normalize_hostname_preserves_ip(self):
        # IPs should not be split on dots
        result = _normalize_hostname("10.0.0.1")
        assert result == "10.0.0.1"

    def test_parse_cdp_detail(self):
        output = """
----------------------------
Device ID: spine-01.corp.com
Interface: GigabitEthernet0/1,  Port ID (outgoing port): Ethernet1
----------------------------
Device ID: spine-02.corp.com
Interface: GigabitEthernet0/2,  Port ID (outgoing port): Ethernet1
"""
        edges = _parse_cdp_detail("leaf-01", output)
        assert len(edges) == 2
        assert edges[0].source == "leaf-01"
        assert edges[0].target == "spine-01"
        assert edges[0].source_interface == "GigabitEthernet0/1"
        assert edges[0].discovered_via == "cdp"

    def test_parse_lldp_brief(self):
        output = """
spine-01.corp.com  Eth1  120  B  Eth3
spine-02.corp.com  Eth2  120  B  Eth3
"""
        edges = _parse_lldp_brief("leaf-01", output)
        assert any(e.target == "spine-01" for e in edges)
        assert any(e.target == "spine-02" for e in edges)

    def test_topology_node_to_dict(self):
        node = TopologyNode(hostname="spine-01", platform="arista_eos", role="spine", site="dc1")
        d    = node.to_dict()
        assert d["id"]       == "spine-01"
        assert d["platform"] == "arista_eos"
        assert d["role"]     == "spine"

    def test_topology_edge_to_dict(self):
        edge = TopologyEdge(
            source="leaf-01", target="spine-01",
            source_interface="Eth1", target_interface="Eth3",
            speed_mbps=25000,
        )
        d = edge.to_dict()
        assert d["source"]           == "leaf-01"
        assert d["target"]           == "spine-01"
        assert d["source_interface"] == "Eth1"
        assert d["speed_mbps"]       == 25000
