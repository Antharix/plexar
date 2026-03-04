"""Unit tests for the MockDriver."""

import pytest
from plexar.drivers.mock import MockDriver
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.core.enums import BGPState
from plexar.core.exceptions import CommandError


class TestMockDriverDefaults:
    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        mock = MockDriver()
        assert not mock.is_connected
        await mock.connect()
        assert mock.is_connected
        await mock.disconnect()
        assert not mock.is_connected

    @pytest.mark.asyncio
    async def test_default_bgp_summary(self):
        mock = MockDriver()
        await mock.connect()
        bgp = await mock.get_bgp_summary()
        assert bgp.peers_established == 2

    @pytest.mark.asyncio
    async def test_default_interfaces(self):
        mock = MockDriver()
        await mock.connect()
        ifaces = await mock.get_interfaces()
        assert len(ifaces) == 2
        assert ifaces[0].is_up

    @pytest.mark.asyncio
    async def test_default_routing_table(self):
        mock = MockDriver()
        await mock.connect()
        rt = await mock.get_routing_table()
        assert rt.has_route("0.0.0.0/0")


class TestMockDriverCustomisation:
    @pytest.mark.asyncio
    async def test_set_response(self):
        mock = MockDriver()
        mock.set_response("get_bgp_summary", BGPSummary(peers=[
            BGPPeer(neighbor_ip="9.9.9.9", state=BGPState.IDLE)
        ]))
        bgp = await mock.get_bgp_summary()
        assert bgp.peers[0].neighbor_ip == "9.9.9.9"
        assert bgp.peers_established == 0

    @pytest.mark.asyncio
    async def test_set_run_response(self):
        mock = MockDriver()
        mock.set_run_response("show version", "EOS version 4.28.1F")
        out = await mock.run("show version")
        assert "4.28.1F" in out

    @pytest.mark.asyncio
    async def test_raise_on_exception_response(self):
        mock = MockDriver()
        mock.set_response("get_bgp_summary", CommandError("BGP not configured"))
        with pytest.raises(CommandError):
            await mock.get_bgp_summary()

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        mock = MockDriver()
        mock.connect_should_fail = True
        with pytest.raises(Exception):
            await mock.connect()


class TestMockDriverCallTracking:
    @pytest.mark.asyncio
    async def test_call_tracking(self):
        mock = MockDriver()
        await mock.connect()
        await mock.get_bgp_summary()
        await mock.get_interfaces()
        await mock.get_bgp_summary()

        assert mock.was_called("get_bgp_summary")
        assert mock.call_count("get_bgp_summary") == 2
        assert mock.call_count("get_interfaces") == 1
        assert not mock.was_called("get_routing_table")

    @pytest.mark.asyncio
    async def test_reset_calls(self):
        mock = MockDriver()
        await mock.get_bgp_summary()
        mock.reset_calls()
        assert not mock.was_called("get_bgp_summary")
