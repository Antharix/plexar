"""Tests for the Validation Engine."""

import pytest
from plexar.config.validator import (
    bgp_peers_up, interface_up, route_exists, default_route_exists,
    run_validators, ValidationResult, ValidationReport,
)
from plexar.core.device import Device
from plexar.core.credentials import Credentials
from plexar.drivers.mock import MockDriver
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.models.interfaces import Interface
from plexar.models.routing import RoutingTable, Route
from plexar.core.enums import BGPState, OperState, AdminState


def make_device_with_mock(**responses) -> Device:
    d = Device(
        hostname="test-sw",
        platform="arista_eos",
        credentials=Credentials(username="admin", password="test"),
    )
    mock = MockDriver.build(**responses)
    object.__setattr__(d, "_driver", mock)
    object.__setattr__(d, "_connected", True)
    return d


class TestBGPPeersUpValidator:
    @pytest.mark.asyncio
    async def test_passes_when_enough_peers(self):
        bgp = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.ESTABLISHED),
            BGPPeer(neighbor_ip="10.0.0.2", state=BGPState.ESTABLISHED),
        ])
        device = make_device_with_mock(get_bgp_summary=bgp)
        result = await bgp_peers_up(min_peers=2)(device)
        assert result.passed

    @pytest.mark.asyncio
    async def test_fails_when_too_few_peers(self):
        bgp = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.IDLE),
            BGPPeer(neighbor_ip="10.0.0.2", state=BGPState.ESTABLISHED),
        ])
        device = make_device_with_mock(get_bgp_summary=bgp)
        result = await bgp_peers_up(min_peers=2)(device)
        assert not result.passed

    @pytest.mark.asyncio
    async def test_result_has_name(self):
        device = make_device_with_mock()
        result = await bgp_peers_up(min_peers=1)(device)
        assert "BGPPeersUp" in result.name


class TestInterfaceUpValidator:
    @pytest.mark.asyncio
    async def test_passes_when_interface_up(self):
        ifaces = [Interface(name="Ethernet1", oper_state=OperState.UP, admin_state=AdminState.UP)]
        device = make_device_with_mock(get_interfaces=ifaces)
        result = await interface_up("Ethernet1")(device)
        assert result.passed

    @pytest.mark.asyncio
    async def test_fails_when_interface_down(self):
        ifaces = [Interface(name="Ethernet1", oper_state=OperState.DOWN, admin_state=AdminState.UP)]
        device = make_device_with_mock(get_interfaces=ifaces)
        result = await interface_up("Ethernet1")(device)
        assert not result.passed

    @pytest.mark.asyncio
    async def test_fails_when_interface_not_found(self):
        device = make_device_with_mock(get_interfaces=[])
        result = await interface_up("Ethernet99")(device)
        assert not result.passed
        assert "not found" in result.reason.lower()


class TestRouteExistsValidator:
    @pytest.mark.asyncio
    async def test_passes_when_route_exists(self):
        rt = RoutingTable(routes=[Route(prefix="10.0.0.0/8", next_hop="192.168.1.1")])
        device = make_device_with_mock(get_routing_table=rt)
        result = await route_exists("10.0.0.0/8")(device)
        assert result.passed

    @pytest.mark.asyncio
    async def test_fails_when_route_missing(self):
        rt = RoutingTable(routes=[])
        device = make_device_with_mock(get_routing_table=rt)
        result = await route_exists("10.0.0.0/8")(device)
        assert not result.passed

    @pytest.mark.asyncio
    async def test_default_route_validator(self):
        rt = RoutingTable(routes=[Route(prefix="0.0.0.0/0", next_hop="10.0.0.1")])
        device = make_device_with_mock(get_routing_table=rt)
        result = await default_route_exists()(device)
        assert result.passed


class TestRunValidators:
    @pytest.mark.asyncio
    async def test_all_pass(self):
        device = make_device_with_mock()  # default mock has 2 established peers
        report = await run_validators(device, [bgp_peers_up(min_peers=1)])
        assert report.passed
        assert len(report.results) == 1

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        device = make_device_with_mock()
        validators = [
            bgp_peers_up(min_peers=1),    # will pass
            bgp_peers_up(min_peers=100),  # will fail
        ]
        report = await run_validators(device, validators)
        assert not report.passed
        assert len(report.failed) == 1

    @pytest.mark.asyncio
    async def test_report_summary(self):
        device = make_device_with_mock()
        report = await run_validators(device, [bgp_peers_up(min_peers=1)])
        summary = report.summary()
        assert "1/1" in summary

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        import asyncio

        async def slow_validator(device):
            await asyncio.sleep(100)  # will timeout
            return ValidationResult(name="slow", passed=True)

        device = make_device_with_mock()
        report = await run_validators(device, [slow_validator], timeout=0)
        assert not report.passed
        assert "Timed out" in report.failed[0].reason
