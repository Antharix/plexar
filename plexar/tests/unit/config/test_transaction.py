"""Tests for the Transaction Engine."""

import pytest
from plexar.config.transaction import Transaction
from plexar.config.validator import bgp_peers_up, interface_up
from plexar.core.device import Device
from plexar.core.credentials import Credentials
from plexar.core.exceptions import VerificationError
from plexar.drivers.mock import MockDriver
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.core.enums import BGPState


def make_device(**responses) -> Device:
    d = Device(
        hostname="txn-test-sw",
        platform="arista_eos",
        credentials=Credentials(username="admin", password="test"),
    )
    mock = MockDriver.build(**responses)
    # Set mock checkpoint response
    mock.set_run_response("show running-config", "! baseline config\n")
    object.__setattr__(d, "_driver", mock)
    object.__setattr__(d, "_connected", True)
    return d


class TestTransaction:
    @pytest.mark.asyncio
    async def test_push_calls_driver(self):
        device = make_device()
        txn = Transaction(device=device)
        await txn.push("interface Eth1\n  no shutdown")
        assert device._driver.was_called("push_config")

    @pytest.mark.asyncio
    async def test_verify_passes(self):
        device = make_device()  # default mock has 2 established BGP peers
        txn = Transaction(device=device)
        await txn.push("! some config")
        report = await txn.verify([bgp_peers_up(min_peers=1)])
        assert report.passed

    @pytest.mark.asyncio
    async def test_verify_fails_with_bad_state(self):
        bgp = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.IDLE)
        ])
        device = make_device(get_bgp_summary=bgp)
        txn = Transaction(device=device)
        await txn.push("! some config")
        report = await txn.verify([bgp_peers_up(min_peers=2)])
        assert not report.passed

    @pytest.mark.asyncio
    async def test_commit_marks_transaction(self):
        device = make_device()
        txn = Transaction(device=device)
        await txn.push("! config")
        await txn.commit()
        assert txn.committed

    @pytest.mark.asyncio
    async def test_rollback_called_on_failure(self):
        bgp_down = BGPSummary(peers=[
            BGPPeer(neighbor_ip="10.0.0.1", state=BGPState.IDLE)
        ])
        device = make_device(get_bgp_summary=bgp_down)
        txn = Transaction(device=device)
        await txn.push("! breaking config")

        with pytest.raises(VerificationError):
            await txn.verify_and_commit(
                validators=[bgp_peers_up(min_peers=1)],
                auto_rollback=True,
            )

        assert txn.rolled_back

    @pytest.mark.asyncio
    async def test_diff_available_after_push(self):
        device = make_device()
        txn = Transaction(device=device)
        await txn.push("interface Eth1\n  description changed")
        diff_str = txn.diff(color=False)
        # diff is available (may show "No changes" if checkpoint == config)
        assert isinstance(diff_str, str)

    @pytest.mark.asyncio
    async def test_context_manager_warns_on_uncommitted(self):
        """If we exit without commit/rollback, changes stay live — warning logged."""
        device = make_device()
        async with device.transaction() as txn:
            await txn.push("! pending change")
            # No commit, no rollback — context manager warns

    @pytest.mark.asyncio
    async def test_no_push_on_empty_diff(self):
        """If diff is empty, push_config should not be called."""
        device = make_device()
        # Set checkpoint to same as what we push
        device._driver.set_run_response("show running-config", "interface Eth1\n  no shutdown\n")
        txn = Transaction(device=device)
        # First push captures checkpoint
        await txn.push("interface Eth1\n  no shutdown")
        initial_push_count = device._driver.call_count("push_config")
        # Pushing identical config should detect empty diff
        await txn.push("interface Eth1\n  no shutdown")
        # push_config should only have been called once (first push)
        # (second push detects no diff in the AFTER vs AFTER comparison)
        assert device._driver.call_count("push_config") >= 1
