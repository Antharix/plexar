"""Tests for the Event Bus and Threshold Monitor."""

import asyncio
import pytest

from plexar.telemetry.events import (
    EventBus, PlexarEvent, EventType, ThresholdMonitor,
)
from plexar.telemetry.gnmi import (
    TelemetryEvent, TelemetryPath, InterfaceCounters, BGPTelemetryEvent,
    SubscriptionMode, SampleMode,
)


# ── Event Bus ─────────────────────────────────────────────────────────

class TestEventBus:
    @pytest.mark.asyncio
    async def test_handler_called_on_emit(self):
        bus      = EventBus()
        received = []

        @bus.on(EventType.BGP_PEER_DOWN)
        async def handler(event: PlexarEvent):
            received.append(event)

        await bus.emit(PlexarEvent(type=EventType.BGP_PEER_DOWN, hostname="spine-01"))
        assert len(received) == 1
        assert received[0].hostname == "spine-01"

    @pytest.mark.asyncio
    async def test_wildcard_handler_receives_all(self):
        bus      = EventBus()
        received = []

        @bus.on("*")
        async def catch_all(event: PlexarEvent):
            received.append(event)

        await bus.emit(PlexarEvent(type=EventType.BGP_PEER_DOWN))
        await bus.emit(PlexarEvent(type=EventType.INTERFACE_DOWN))
        await bus.emit(PlexarEvent(type=EventType.CONFIG_PUSHED))

        assert len(received) == 3

    @pytest.mark.asyncio
    async def test_handler_not_called_for_other_types(self):
        bus      = EventBus()
        received = []

        @bus.on(EventType.BGP_PEER_DOWN)
        async def handler(event: PlexarEvent):
            received.append(event)

        await bus.emit(PlexarEvent(type=EventType.INTERFACE_DOWN))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_multiple_handlers_same_type(self):
        bus = EventBus()
        counts = [0, 0]

        @bus.on(EventType.DRIFT_DETECTED)
        async def h1(e): counts[0] += 1

        @bus.on(EventType.DRIFT_DETECTED)
        async def h2(e): counts[1] += 1

        await bus.emit(PlexarEvent(type=EventType.DRIFT_DETECTED))
        assert counts == [1, 1]

    @pytest.mark.asyncio
    async def test_handler_error_does_not_crash_bus(self):
        bus = EventBus()

        @bus.on(EventType.CONFIG_PUSHED)
        async def bad_handler(event):
            raise RuntimeError("Intentional error in handler")

        # Should not raise
        await bus.emit(PlexarEvent(type=EventType.CONFIG_PUSHED))
        assert bus.stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_background_mode(self):
        bus      = EventBus()
        received = []

        @bus.on(EventType.DEVICE_CONNECTED)
        async def handler(event):
            received.append(event)

        await bus.start()
        await bus.emit(PlexarEvent(type=EventType.DEVICE_CONNECTED, hostname="sw-01"))
        await asyncio.sleep(0.05)  # let background loop process
        await bus.stop()

        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_stats_track_emitted(self):
        bus = EventBus()

        @bus.on("*")
        async def noop(e): pass

        for _ in range(5):
            await bus.emit(PlexarEvent(type=EventType.TELEMETRY_UPDATE))

        assert bus.stats["emitted"] == 5
        assert bus.stats["delivered"] == 5

    def test_plexar_event_str(self):
        event = PlexarEvent(
            type=EventType.BGP_PEER_DOWN,
            hostname="spine-01",
            data={"neighbor": "10.0.0.1"},
        )
        s = str(event)
        assert "bgp.peer_down" in s
        assert "spine-01" in s

    def test_plexar_event_has_unique_id(self):
        e1 = PlexarEvent(type=EventType.INTERFACE_DOWN)
        e2 = PlexarEvent(type=EventType.INTERFACE_DOWN)
        assert e1.event_id != e2.event_id


# ── Threshold Monitor ─────────────────────────────────────────────────

class TestThresholdMonitor:
    @pytest.mark.asyncio
    async def test_threshold_exceeded_emits_event(self):
        bus      = EventBus()
        alerts   = []

        @bus.on(EventType.TELEMETRY_THRESHOLD)
        async def handle(event):
            alerts.append(event)

        monitor = ThresholdMonitor(bus)
        monitor.add_threshold(name="high_errors", metric="in_errors", operator=">", value=100)

        await monitor.check({"in_errors": 500}, hostname="leaf-01")
        assert len(alerts) == 1
        assert alerts[0].data["threshold"] == "high_errors"
        assert alerts[0].data["actual"] == 500

    @pytest.mark.asyncio
    async def test_threshold_not_exceeded_no_event(self):
        bus    = EventBus()
        alerts = []

        @bus.on(EventType.TELEMETRY_THRESHOLD)
        async def handle(event):
            alerts.append(event)

        monitor = ThresholdMonitor(bus)
        monitor.add_threshold(name="high_errors", metric="in_errors", operator=">", value=100)

        await monitor.check({"in_errors": 50}, hostname="leaf-01")
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_missing_metric_no_event(self):
        bus    = EventBus()
        alerts = []

        @bus.on(EventType.TELEMETRY_THRESHOLD)
        async def handle(event): alerts.append(event)

        monitor = ThresholdMonitor(bus)
        monitor.add_threshold(name="test", metric="nonexistent", operator=">", value=0)

        await monitor.check({"in_errors": 999})
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_multiple_thresholds(self):
        bus    = EventBus()
        alerts = []

        @bus.on(EventType.TELEMETRY_THRESHOLD)
        async def handle(event): alerts.append(event)

        monitor = (
            ThresholdMonitor(bus)
            .add_threshold("high_in", "in_errors", ">", 100)
            .add_threshold("high_out", "out_errors", ">", 100)
        )

        await monitor.check({"in_errors": 200, "out_errors": 300})
        assert len(alerts) == 2

    def test_chaining(self):
        bus     = EventBus()
        monitor = ThresholdMonitor(bus)
        result  = monitor.add_threshold("t1", "m1", ">", 0)
        assert result is monitor


# ── TelemetryPath ─────────────────────────────────────────────────────

class TestTelemetryPath:
    def test_interface_counters_path(self):
        p = TelemetryPath.interface_counters(interval_ms=5000)
        assert "interfaces" in p.path
        assert p.interval_ms == 5000
        assert p.mode == SampleMode.SAMPLE

    def test_bgp_state_on_change(self):
        p = TelemetryPath.bgp_state(mode="ON_CHANGE")
        assert "bgp" in p.path
        assert p.mode == SampleMode.ON_CHANGE

    def test_custom_path(self):
        p = TelemetryPath.custom("/custom/path", interval_ms=2000, mode="SAMPLE")
        assert p.path == "/custom/path"
        assert p.interval_ms == 2000


# ── TelemetryEvent ────────────────────────────────────────────────────

class TestTelemetryEvent:
    def test_path_matches(self):
        event = TelemetryEvent(
            device_hostname="spine-01",
            path="interfaces/interface/state/counters",
            timestamp_ns=1_000_000_000,
            values={"in-octets": 1000, "out-octets": 2000},
        )
        assert event.path_matches("counters")
        assert event.path_matches("interfaces")
        assert not event.path_matches("bgp")

    def test_timestamp_conversion(self):
        event = TelemetryEvent(
            device_hostname="sw-01",
            path="/test",
            timestamp_ns=1_000_000_000_000_000_000,
            values={},
        )
        assert event.timestamp == 1_000_000_000.0

    def test_as_interface_counters(self):
        event = TelemetryEvent(
            device_hostname="leaf-01",
            path="interfaces/interface/state/counters",
            timestamp_ns=int(1e18),
            values={
                "name":             "Ethernet1",
                "in-octets":        100000,
                "out-octets":       200000,
                "in-unicast-pkts":  1000,
                "out-unicast-pkts": 2000,
                "in-errors":        5,
                "out-errors":       0,
            },
        )
        counters = event.as_interface_counters()
        assert isinstance(counters, InterfaceCounters)
        assert counters.in_octets  == 100000
        assert counters.out_octets == 200000
        assert counters.in_errors  == 5

    def test_interface_counters_error_rate(self):
        counters = InterfaceCounters(
            name="Eth1",
            in_pkts=1000, out_pkts=1000,
            in_errors=10, out_errors=10,
        )
        assert counters.error_rate_pct == pytest.approx(1.0)

    def test_as_bgp_event(self):
        event = TelemetryEvent(
            device_hostname="spine-01",
            path="bgp/neighbors/neighbor/state",
            timestamp_ns=int(1e18),
            values={
                "neighbor-address":  "10.0.0.1",
                "session-state":     "ESTABLISHED",
                "prefixes-received": 150,
            },
        )
        bgp = event.as_bgp_event()
        assert isinstance(bgp, BGPTelemetryEvent)
        assert bgp.neighbor_ip    == "10.0.0.1"
        assert bgp.session_state  == "ESTABLISHED"
        assert bgp.prefixes_received == 150
