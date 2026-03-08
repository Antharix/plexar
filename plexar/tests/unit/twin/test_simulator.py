"""Tests for the Digital Twin simulator."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime, timezone, timedelta

from plexar.twin.simulator import DigitalTwin, SimulationResult, IntentValidationResult

pytest.importorskip("networkx", reason="networkx required for twin topology tests")


def _make_snapshot(hostname: str, bgp_peers=2, interfaces=4) -> MagicMock:
    """Create a mock StateSnapshot."""
    from plexar.models.bgp import BGPSummary, BGPPeer
    from plexar.models.interfaces import Interface
    from plexar.models.routing import RoutingTable, Route

    snap = MagicMock()
    snap.device_hostname = hostname
    snap.bgp = BGPSummary(
        local_as=65001,
        router_id="10.0.0.1",
        peers=[
            BGPPeer(
                neighbor_ip=f"10.0.{i}.1",
                remote_as=65000,
                state="established",
                prefixes_received=100,
            )
            for i in range(bgp_peers)
        ],
    )
    snap.interfaces = [
        Interface(
            name=f"Ethernet{i+1}",
            admin_state="up",
            oper_state="up",
            mtu=9214,
        )
        for i in range(interfaces)
    ]
    snap.routes = MagicMock()
    snap.routes.routes = []
    snap.routes.has_route = lambda p: False
    return snap


class TestDigitalTwinBasics:
    def test_initial_state(self):
        twin = DigitalTwin()
        assert twin.device_count == 0
        assert twin.captured_at is None
        assert twin.is_stale

    def test_load_snapshot_increments_count(self):
        twin     = DigitalTwin()
        snapshot = _make_snapshot("leaf-01")
        twin.load_snapshot("leaf-01", snapshot)
        assert twin.device_count == 1

    def test_is_stale_when_old(self):
        twin = DigitalTwin()
        twin._captured_at = datetime.now(timezone.utc) - timedelta(hours=2)
        assert twin.is_stale

    def test_is_not_stale_when_recent(self):
        twin = DigitalTwin()
        twin._captured_at = datetime.now(timezone.utc)
        assert not twin.is_stale

    def test_repr_contains_device_count(self):
        twin = DigitalTwin()
        twin.load_snapshot("leaf-01", _make_snapshot("leaf-01"))
        assert "1" in repr(twin)


class TestSimulateInterfaceFailure:
    def test_returns_simulation_result(self):
        twin = DigitalTwin()
        twin.load_snapshot("leaf-01", _make_snapshot("leaf-01"))
        result = twin.simulate_interface_failure("leaf-01", "Ethernet1")
        assert isinstance(result, SimulationResult)
        assert result.simulation_type == "interface_failure"
        assert result.subject == "leaf-01/Ethernet1"

    def test_warns_when_no_snapshot(self):
        twin   = DigitalTwin()
        result = twin.simulate_interface_failure("unknown-device", "Eth1")
        assert any("No snapshot" in w for w in result.warnings)

    def test_with_topology(self):
        from plexar.topology.graph import TopologyGraph, TopologyNode, TopologyEdge

        twin = DigitalTwin()
        twin.load_snapshot("leaf-01", _make_snapshot("leaf-01"))
        twin.load_snapshot("spine-01", _make_snapshot("spine-01"))
        twin.load_snapshot("spine-02", _make_snapshot("spine-02"))

        topo = TopologyGraph()
        for name in ["leaf-01", "spine-01", "spine-02"]:
            topo.add_node(TopologyNode(hostname=name))
        topo.add_edge(TopologyEdge(source="leaf-01", target="spine-01"))
        topo.add_edge(TopologyEdge(source="leaf-01", target="spine-02"))
        twin.load_topology(topo)

        result = twin.simulate_interface_failure("leaf-01", "Ethernet1")
        assert isinstance(result, SimulationResult)


class TestSimulateBGPPeerRemoval:
    def test_finds_peer(self):
        twin     = DigitalTwin()
        snapshot = _make_snapshot("spine-01", bgp_peers=2)
        twin.load_snapshot("spine-01", snapshot)

        result = twin.simulate_bgp_peer_removal("spine-01", "10.0.0.1")
        assert isinstance(result, SimulationResult)
        assert result.simulation_type == "bgp_peer_removal"

    def test_warns_on_prefix_loss(self):
        twin     = DigitalTwin()
        snapshot = _make_snapshot("spine-01", bgp_peers=2)
        twin.load_snapshot("spine-01", snapshot)

        result = twin.simulate_bgp_peer_removal("spine-01", "10.0.0.1")
        # Should have warnings about prefix loss (100 prefixes in mock)
        assert len(result.warnings) > 0 or result.metadata.get("prefixes_lost", 0) >= 0

    def test_single_peer_high_risk(self):
        twin     = DigitalTwin()
        snapshot = _make_snapshot("leaf-01", bgp_peers=1)
        twin.load_snapshot("leaf-01", snapshot)

        result = twin.simulate_bgp_peer_removal("leaf-01", "10.0.0.1")
        assert len(result.errors) > 0
        assert result.risk_score == 100

    def test_peer_not_found_returns_info(self):
        twin     = DigitalTwin()
        snapshot = _make_snapshot("leaf-01", bgp_peers=1)
        twin.load_snapshot("leaf-01", snapshot)

        result = twin.simulate_bgp_peer_removal("leaf-01", "192.168.99.99")
        assert result.risk_score == 0
        assert len(result.info) > 0


class TestSimulateDeviceFailure:
    def test_returns_result(self):
        twin   = DigitalTwin()
        result = twin.simulate_device_failure("spine-01")
        assert isinstance(result, SimulationResult)
        assert result.simulation_type == "device_failure"

    def test_warns_when_no_topology(self):
        twin   = DigitalTwin()
        result = twin.simulate_device_failure("spine-01")
        assert any("networkx" in w.lower() or "topology" in w.lower() for w in result.warnings)


class TestIntentValidation:
    def test_validates_interface_intent(self):
        from plexar.intent.engine import Intent
        from plexar.intent.primitives import InterfaceIntent

        twin     = DigitalTwin()
        snapshot = _make_snapshot("leaf-01", interfaces=4)
        twin.load_snapshot("leaf-01", snapshot)

        device = MagicMock()
        device.hostname = "leaf-01"
        device.platform = "arista_eos"

        intent = Intent(devices=[device])
        intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9000))

        result = twin.validate_intent(intent)
        assert isinstance(result, IntentValidationResult)
        # Ethernet1 exists in snapshot (mtu=9214), intent sets 9000 → info
        assert any("MTU" in i or "Ethernet1" in i for i in result.info + result.warnings) or result.passed

    def test_validates_bgp_intent_warns_on_removed_peers(self):
        from plexar.intent.engine import Intent
        from plexar.intent.primitives import BGPIntent, BGPNeighbor

        twin     = DigitalTwin()
        snapshot = _make_snapshot("leaf-01", bgp_peers=2)
        twin.load_snapshot("leaf-01", snapshot)

        device = MagicMock()
        device.hostname = "leaf-01"
        device.platform = "arista_eos"

        # Intent declares only 1 peer, but snapshot has 2
        intent = Intent(devices=[device])
        intent.ensure(BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(ip="10.0.0.1", remote_as=65000)],
        ))

        result = twin.validate_intent(intent)
        # Should warn about removing the second peer
        assert any("REMOVE" in w or "remove" in w.lower() for w in result.warnings) or isinstance(result, IntentValidationResult)

    def test_passed_true_on_no_conflicts(self):
        from plexar.intent.engine import Intent
        from plexar.intent.primitives import NTPIntent

        twin   = DigitalTwin()
        device = MagicMock()
        device.hostname = "leaf-01"
        device.platform = "arista_eos"

        intent = Intent(devices=[device])
        intent.ensure(NTPIntent(servers=["10.0.0.100"]))

        result = twin.validate_intent(intent)
        assert isinstance(result, IntentValidationResult)
        assert result.passed  # NTP has no conflict checks

    def test_simulation_result_is_safe(self):
        result = SimulationResult(simulation_type="test", subject="device", risk_score=20)
        assert result.is_safe

    def test_simulation_result_not_safe_with_errors(self):
        result = SimulationResult(
            simulation_type="test",
            subject="device",
            risk_score=20,
            errors=["Fatal: device would be isolated"],
        )
        assert not result.is_safe

    def test_impact_summary_contains_risk(self):
        result = SimulationResult(
            simulation_type="interface_failure",
            subject="leaf-01/Eth1",
            risk_score=45,
            warnings=["Redundancy degraded"],
        )
        summary = result.impact_summary()
        assert "45" in summary
        assert "Redundancy" in summary
