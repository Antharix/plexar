"""Tests for the Intent Engine and plan/apply/verify flow."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from plexar.intent import Intent, IntentPlan, IntentResult
from plexar.intent.primitives import (
    BGPIntent, BGPNeighbor, InterfaceIntent, VLANIntent, NTPIntent,
)


def _make_device(hostname: str, platform: str = "arista_eos") -> MagicMock:
    device = MagicMock()
    device.hostname   = hostname
    device.platform   = platform
    device.is_connected = True
    device._driver    = MagicMock()
    device._driver.get_checkpoint = AsyncMock(return_value="")
    device.__aenter__ = AsyncMock(return_value=device)
    device.__aexit__  = AsyncMock(return_value=False)
    return device


class TestIntentPrimitives:
    def test_ensure_returns_self(self):
        devices = [_make_device("leaf-01")]
        intent  = Intent(devices=devices)
        result  = intent.ensure(InterfaceIntent(name="Eth1"))
        assert result is intent

    def test_chaining(self):
        intent = (
            Intent(devices=[_make_device("leaf-01")])
            .ensure(InterfaceIntent(name="Eth1"))
            .ensure(InterfaceIntent(name="Eth2"))
            .ensure(BGPIntent(asn=65001))
        )
        assert len(intent._primitives) == 3

    def test_clear_removes_all(self):
        intent = Intent(devices=[_make_device("leaf-01")])
        intent.ensure(BGPIntent(asn=65001))
        intent.clear()
        assert len(intent._primitives) == 0


class TestIntentPlan:
    @pytest.mark.asyncio
    async def test_plan_compiles_for_each_device(self):
        devices = [_make_device("leaf-01"), _make_device("leaf-02")]
        intent  = Intent(devices=devices)
        intent.ensure(BGPIntent(asn=65001, neighbors=[BGPNeighbor(ip="10.0.0.1", remote_as=65000)]))
        intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214))

        plan = await intent.plan()

        assert isinstance(plan, IntentPlan)
        assert len(plan.device_plans) == 2
        for dp in plan.device_plans:
            assert "router bgp 65001" in dp.config
            assert "interface Ethernet1" in dp.config

    @pytest.mark.asyncio
    async def test_plan_handles_unknown_platform(self):
        device = _make_device("router-01", platform="unknown_vendor")
        intent = Intent(devices=[device])
        intent.ensure(BGPIntent(asn=65001))

        plan = await intent.plan()
        assert plan.device_plans[0].error is not None

    @pytest.mark.asyncio
    async def test_plan_no_changes_for_empty_config(self):
        devices = [_make_device("leaf-01")]
        intent  = Intent(devices=devices)
        # Add a primitive that compiles to empty string
        intent.ensure(NTPIntent(servers=[]))   # empty servers → empty config

        plan = await intent.plan()
        # Should still work, just have no/minimal changes
        assert plan is not None

    @pytest.mark.asyncio
    async def test_plan_render(self):
        devices = [_make_device("spine-01")]
        intent  = Intent(devices=devices)
        intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214))

        plan   = await intent.plan()
        render = plan.render(color=False)
        assert "Intent Plan" in render
        assert "spine-01" in render

    @pytest.mark.asyncio
    async def test_plan_devices_with_changes(self):
        devices = [_make_device("leaf-01"), _make_device("leaf-02")]
        intent  = Intent(devices=devices)
        intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214))

        plan = await intent.plan()
        assert len(plan.devices_with_changes) == 2


class TestIntentApply:
    @pytest.mark.asyncio
    async def test_dry_run_returns_skipped(self):
        devices = [_make_device("leaf-01")]
        intent  = Intent(devices=devices)
        intent.ensure(InterfaceIntent(name="Eth1"))

        result = await intent.apply(dry_run=True)
        assert isinstance(result, IntentResult)
        assert "leaf-01" in [d.hostname for d in result.skipped]

    @pytest.mark.asyncio
    async def test_repr(self):
        intent = Intent(devices=[_make_device("leaf-01"), _make_device("leaf-02")])
        intent.ensure(BGPIntent(asn=65001))
        assert "2" in repr(intent)
        assert "1" in repr(intent)


class TestIntentResult:
    def test_all_succeeded_true_when_no_failures(self):
        result = IntentResult(
            succeeded=[MagicMock(hostname="leaf-01")],
        )
        assert result.all_succeeded

    def test_all_succeeded_false_with_failures(self):
        result = IntentResult(
            succeeded=[MagicMock(hostname="leaf-01")],
            failed=[(MagicMock(hostname="leaf-02"), Exception("timeout"))],
        )
        assert not result.all_succeeded

    def test_summary_contains_counts(self):
        result = IntentResult(
            succeeded=[MagicMock(hostname="leaf-01")],
            failed=[(MagicMock(hostname="leaf-02"), Exception("timeout"))],
            skipped=[MagicMock(hostname="leaf-03")],
            duration_seconds=2.5,
        )
        summary = result.summary()
        assert "1/3" in summary or "succeeded" in summary
