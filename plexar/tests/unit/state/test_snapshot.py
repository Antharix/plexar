"""Tests for the State Snapshot engine."""

import json
import pytest
import tempfile
from pathlib import Path

from plexar.state.snapshot import StateSnapshot, SnapshotDelta
from plexar.core.device import Device
from plexar.core.credentials import Credentials
from plexar.drivers.mock import MockDriver
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.models.interfaces import Interface
from plexar.core.enums import BGPState, OperState, AdminState


def make_device_with_mock(**responses) -> Device:
    d = Device(
        hostname="snap-test-sw",
        platform="arista_eos",
        credentials=Credentials(username="admin", password="test"),
    )
    mock = MockDriver.build(**responses)
    object.__setattr__(d, "_driver", mock)
    object.__setattr__(d, "_connected", True)
    return d


class TestStateSnapshotCapture:
    @pytest.mark.asyncio
    async def test_capture_populates_all_sections(self):
        device = make_device_with_mock()
        snap = await StateSnapshot.capture(device)
        assert snap.hostname == "snap-test-sw"
        assert len(snap.interfaces) > 0
        assert snap.bgp_summary.get("peers") is not None
        assert len(snap.routing_table) > 0

    @pytest.mark.asyncio
    async def test_capture_handles_partial_failures(self):
        """Snapshot should still succeed even if one getter fails."""
        from plexar.core.exceptions import CommandError
        device = make_device_with_mock(
            get_bgp_summary=CommandError("BGP not configured")
        )
        snap = await StateSnapshot.capture(device)
        # bgp_summary should be empty dict (failure handled gracefully)
        assert isinstance(snap.bgp_summary, dict)


class TestStateSnapshotPersistence:
    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        device = make_device_with_mock()
        snap = await StateSnapshot.capture(device)

        path = tmp_path / "test_snapshot.json"
        snap.save(str(path))

        assert path.exists()

        loaded = StateSnapshot.load(str(path))
        assert loaded.hostname == snap.hostname
        assert len(loaded.interfaces) == len(snap.interfaces)
        assert loaded.captured_at == snap.captured_at

    @pytest.mark.asyncio
    async def test_saved_json_is_valid(self, tmp_path):
        device = make_device_with_mock()
        snap = await StateSnapshot.capture(device)
        path = tmp_path / "snap.json"
        snap.save(str(path))

        with open(path) as f:
            data = json.load(f)
        assert "hostname" in data
        assert "captured_at" in data
        assert "interfaces" in data


class TestStateSnapshotComparison:
    @pytest.mark.asyncio
    async def test_compare_no_changes(self):
        device = make_device_with_mock()
        before = await StateSnapshot.capture(device)
        after  = await StateSnapshot.capture(device)
        delta  = before.compare(after)
        assert not delta.has_changes

    @pytest.mark.asyncio
    async def test_compare_detects_bgp_state_change(self):
        bgp_up = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.ESTABLISHED)
        ])
        bgp_down = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.IDLE)
        ])

        before_device = make_device_with_mock(get_bgp_summary=bgp_up)
        after_device  = make_device_with_mock(get_bgp_summary=bgp_down)

        before = await StateSnapshot.capture(before_device)
        after  = await StateSnapshot.capture(after_device)

        delta = before.compare(after)
        assert delta.has_changes
        assert "bgp" in delta.changes

    @pytest.mark.asyncio
    async def test_compare_detects_interface_down(self):
        ifaces_up   = [Interface(name="Eth1", oper_state=OperState.UP,   admin_state=AdminState.UP)]
        ifaces_down = [Interface(name="Eth1", oper_state=OperState.DOWN, admin_state=AdminState.UP)]

        before_device = make_device_with_mock(get_interfaces=ifaces_up)
        after_device  = make_device_with_mock(get_interfaces=ifaces_down)

        before = await StateSnapshot.capture(before_device)
        after  = await StateSnapshot.capture(after_device)

        delta = before.compare(after)
        assert "interfaces" in delta.changes

    def test_delta_summary_no_changes(self):
        from datetime import datetime, timezone
        delta = SnapshotDelta(
            device_hostname="sw01",
            captured_before=datetime.now(timezone.utc),
            captured_after=datetime.now(timezone.utc),
        )
        assert "No state changes" in delta.summary()
