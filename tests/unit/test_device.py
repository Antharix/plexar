"""Unit tests for the Device model."""

import pytest
from plexar.core.device import Device
from plexar.core.credentials import Credentials
from plexar.core.enums import Transport, BGPState
from plexar.core.exceptions import ConnectionError, DriverNotFoundError
from plexar.drivers.mock import MockDriver
from plexar.models.bgp import BGPSummary, BGPPeer


def make_device(platform: str = "arista_eos") -> Device:
    return Device(
        hostname="test-sw-01",
        management_ip="10.0.0.1",
        platform=platform,
        transport=Transport.SSH,
        credentials=Credentials(username="admin", password="test"),
    )


def inject_mock(device: Device, **responses) -> MockDriver:
    """Helper: inject a MockDriver directly into a device."""
    mock = MockDriver.build(**responses)
    object.__setattr__(device, "_driver", mock)
    object.__setattr__(device, "_connected", True)
    return mock


class TestDeviceModel:
    def test_creation(self):
        d = make_device()
        assert d.hostname == "test-sw-01"
        assert d.platform == "arista_eos"
        assert d.transport == Transport.SSH
        assert d.port == 22

    def test_default_port_ssh(self):
        d = make_device()
        assert d.port == 22

    def test_default_port_netconf(self):
        d = Device(
            hostname="r1",
            platform="juniper_junos",
            transport=Transport.NETCONF,
            credentials=Credentials(username="admin", password="test"),
        )
        assert d.port == 830

    def test_platform_normalised_to_lowercase(self):
        d = Device(
            hostname="r1",
            platform="ARISTA_EOS",
            credentials=Credentials(username="admin", password="test"),
        )
        assert d.platform == "arista_eos"

    def test_repr_disconnected(self):
        d = make_device()
        assert "disconnected" in repr(d)

    def test_str_returns_hostname(self):
        d = make_device()
        assert str(d) == "test-sw-01"


class TestDeviceConnectivity:
    @pytest.mark.asyncio
    async def test_connect_via_mock(self):
        d = make_device()
        mock = MockDriver(device=d)
        object.__setattr__(d, "_driver", mock)
        await d.connect()
        assert d.is_connected

    @pytest.mark.asyncio
    async def test_context_manager(self):
        d = make_device()
        mock = MockDriver(device=d)
        object.__setattr__(d, "_driver", mock)

        async with d:
            assert d.is_connected
        assert not d.is_connected

    @pytest.mark.asyncio
    async def test_run_requires_connection(self):
        d = make_device()
        with pytest.raises(ConnectionError, match="not connected"):
            await d.run("show version")

    @pytest.mark.asyncio
    async def test_connect_failure_propagates(self):
        d = make_device()
        mock = MockDriver(device=d)
        mock.connect_should_fail = True
        object.__setattr__(d, "_driver", mock)

        with pytest.raises(Exception):
            await d.connect()


class TestDeviceGetters:
    @pytest.mark.asyncio
    async def test_get_bgp_summary(self):
        d = make_device()
        inject_mock(d)
        bgp = await d.get_bgp_summary()
        assert isinstance(bgp, BGPSummary)
        assert len(bgp.peers) == 2
        assert bgp.peers_established == 2

    @pytest.mark.asyncio
    async def test_get_interfaces(self):
        d = make_device()
        inject_mock(d)
        ifaces = await d.get_interfaces()
        assert len(ifaces) > 0
        assert ifaces[0].name == "Ethernet1"
        assert ifaces[0].is_up is True

    @pytest.mark.asyncio
    async def test_get_routing_table(self):
        d = make_device()
        inject_mock(d)
        rt = await d.get_routing_table()
        assert rt.default_route is not None
        assert rt.has_route("0.0.0.0/0")

    @pytest.mark.asyncio
    async def test_custom_bgp_response(self):
        from plexar.core.enums import BGPState
        d = make_device()
        inject_mock(d, get_bgp_summary=BGPSummary(peers=[
            BGPPeer(neighbor_ip="1.2.3.4", state=BGPState.IDLE)
        ]))
        bgp = await d.get_bgp_summary()
        assert bgp.peers[0].state == BGPState.IDLE
        assert bgp.peers_established == 0
