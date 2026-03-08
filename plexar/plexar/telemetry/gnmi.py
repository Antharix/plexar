"""
gNMI Streaming Telemetry Engine.

Subscribes to real-time telemetry streams from network devices
using gNMI (gRPC Network Management Interface).

Supported subscription modes:
  STREAM    — continuous push from device (SAMPLE, ON_CHANGE, TARGET_DEFINED)
  ONCE      — single poll, device pushes and closes
  POLL      — client-driven polling over persistent channel

Normalized data models are emitted as typed TelemetryEvents,
making raw protobuf completely transparent to consumers.

Requires: pip install plexar[gnmi]  (installs grpcio, pygnmi)

Usage:
    from plexar.telemetry import TelemetrySubscriber, TelemetryPath

    subscriber = TelemetrySubscriber(device)

    @subscriber.on_update
    async def handle(event: TelemetryEvent):
        if event.path_matches("interfaces/interface/state/counters"):
            counters = event.as_interface_counters()
            print(f"{counters.name}: {counters.in_octets} in / {counters.out_octets} out")

    await subscriber.subscribe([
        TelemetryPath.interface_counters(interval_ms=5000),
        TelemetryPath.bgp_state(mode="ON_CHANGE"),
    ])
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Coroutine, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────

class SubscriptionMode(StrEnum):
    STREAM = "STREAM"
    ONCE   = "ONCE"
    POLL   = "POLL"


class SampleMode(StrEnum):
    SAMPLE          = "SAMPLE"
    ON_CHANGE       = "ON_CHANGE"
    TARGET_DEFINED  = "TARGET_DEFINED"


@dataclass
class TelemetryPath:
    """
    A gNMI subscription path with sampling configuration.

    Use the class methods for common paths:
        TelemetryPath.interface_counters(interval_ms=5000)
        TelemetryPath.bgp_state(mode="ON_CHANGE")
        TelemetryPath.cpu_memory(interval_ms=10000)
        TelemetryPath.custom("/openconfig-interfaces:interfaces/...", interval_ms=1000)
    """
    path:         str
    mode:         SampleMode = SampleMode.SAMPLE
    interval_ms:  int        = 10_000    # 10s default
    suppress_redundant: bool = True

    # ── Common OpenConfig paths ───────────────────────────────────────

    @classmethod
    def interface_counters(cls, interval_ms: int = 5000) -> "TelemetryPath":
        return cls(
            path="/interfaces/interface/state/counters",
            mode=SampleMode.SAMPLE,
            interval_ms=interval_ms,
        )

    @classmethod
    def interface_state(cls) -> "TelemetryPath":
        return cls(
            path="/interfaces/interface/state",
            mode=SampleMode.ON_CHANGE,
            interval_ms=0,
        )

    @classmethod
    def bgp_state(cls, mode: str = "ON_CHANGE") -> "TelemetryPath":
        return cls(
            path="/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state",
            mode=SampleMode(mode),
            interval_ms=0,
        )

    @classmethod
    def bgp_rib(cls, interval_ms: int = 30_000) -> "TelemetryPath":
        return cls(
            path="/network-instances/network-instance/protocols/protocol/bgp/rib",
            mode=SampleMode.SAMPLE,
            interval_ms=interval_ms,
        )

    @classmethod
    def cpu_memory(cls, interval_ms: int = 10_000) -> "TelemetryPath":
        return cls(
            path="/components/component/state",
            mode=SampleMode.SAMPLE,
            interval_ms=interval_ms,
        )

    @classmethod
    def platform_environment(cls, interval_ms: int = 30_000) -> "TelemetryPath":
        """Temperature, fans, power supply state."""
        return cls(
            path="/components/component/state/temperature",
            mode=SampleMode.SAMPLE,
            interval_ms=interval_ms,
        )

    @classmethod
    def lldp_neighbors(cls) -> "TelemetryPath":
        return cls(
            path="/lldp/interfaces/interface/neighbors/neighbor/state",
            mode=SampleMode.ON_CHANGE,
            interval_ms=0,
        )

    @classmethod
    def custom(cls, path: str, interval_ms: int = 10_000, mode: str = "SAMPLE") -> "TelemetryPath":
        return cls(path=path, mode=SampleMode(mode), interval_ms=interval_ms)


@dataclass
class InterfaceCounters:
    """Normalized interface counter data from a telemetry event."""
    name:               str
    in_octets:          int = 0
    out_octets:         int = 0
    in_pkts:            int = 0
    out_pkts:           int = 0
    in_errors:          int = 0
    out_errors:         int = 0
    in_discards:        int = 0
    out_discards:       int = 0
    timestamp:          float = field(default_factory=time.time)

    @property
    def error_rate_pct(self) -> float:
        total_pkts = self.in_pkts + self.out_pkts
        if total_pkts == 0:
            return 0.0
        return ((self.in_errors + self.out_errors) / total_pkts) * 100


@dataclass
class BGPTelemetryEvent:
    """Normalized BGP state change from telemetry."""
    neighbor_ip:  str
    session_state: str      # "ESTABLISHED" | "IDLE" | "ACTIVE" | etc.
    prefixes_received: int  = 0
    prefixes_sent:     int  = 0
    last_established:  int  = 0   # Unix timestamp
    timestamp:         float = field(default_factory=time.time)


@dataclass
class TelemetryEvent:
    """
    A single telemetry update from a device.

    Contains the raw gNMI notification data plus helpers for
    extracting normalized typed models.
    """
    device_hostname:  str
    path:             str
    timestamp_ns:     int
    values:           dict[str, Any]
    subscription_mode: str = "STREAM"

    @property
    def timestamp(self) -> float:
        return self.timestamp_ns / 1e9

    def path_matches(self, pattern: str) -> bool:
        """Check if this event's path contains the given pattern."""
        return pattern.lower() in self.path.lower()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the event by key."""
        return self.values.get(key, default)

    def as_interface_counters(self) -> InterfaceCounters:
        """Parse event as InterfaceCounters (for interface/state/counters paths)."""
        name = self.values.get("name", self.path.split("/")[-1])
        return InterfaceCounters(
            name=name,
            in_octets=int(self.values.get("in-octets", 0)),
            out_octets=int(self.values.get("out-octets", 0)),
            in_pkts=int(self.values.get("in-unicast-pkts", 0)),
            out_pkts=int(self.values.get("out-unicast-pkts", 0)),
            in_errors=int(self.values.get("in-errors", 0)),
            out_errors=int(self.values.get("out-errors", 0)),
            in_discards=int(self.values.get("in-discards", 0)),
            out_discards=int(self.values.get("out-discards", 0)),
            timestamp=self.timestamp,
        )

    def as_bgp_event(self) -> BGPTelemetryEvent:
        """Parse event as BGPTelemetryEvent (for bgp/neighbors paths)."""
        return BGPTelemetryEvent(
            neighbor_ip=self.values.get("neighbor-address", ""),
            session_state=self.values.get("session-state", "UNKNOWN"),
            prefixes_received=int(self.values.get("prefixes-received", 0)),
            prefixes_sent=int(self.values.get("prefixes-sent", 0)),
            last_established=int(self.values.get("last-established", 0)),
            timestamp=self.timestamp,
        )


# ── Subscriber ────────────────────────────────────────────────────────

HandlerFn = Callable[["TelemetryEvent"], Coroutine[Any, Any, None]]


class TelemetrySubscriber:
    """
    gNMI streaming telemetry subscriber for a single device.

    Usage:
        subscriber = TelemetrySubscriber(device, port=6030)

        @subscriber.on_update
        async def handle(event: TelemetryEvent):
            print(event.path, event.values)

        # Start subscribing
        await subscriber.subscribe([
            TelemetryPath.interface_counters(interval_ms=5000),
            TelemetryPath.bgp_state(),
        ])

        # Stop
        await subscriber.stop()
    """

    def __init__(
        self,
        device:       "Device",
        port:         int  = 6030,    # gNMI default port
        tls:          bool = True,
        insecure:     bool = False,   # set True for lab/self-signed
        username:     str  = "",
        password:     str  = "",
    ) -> None:
        self.device   = device
        self.port     = port
        self.tls      = tls
        self.insecure = insecure
        self.username = username
        self.password = password

        self._handlers:     list[HandlerFn]     = []
        self._subscriptions: list[TelemetryPath] = []
        self._running:      bool                 = False
        self._task:         asyncio.Task | None  = None
        self._stats = {"events_received": 0, "errors": 0, "uptime_seconds": 0.0}

    def on_update(self, fn: HandlerFn) -> HandlerFn:
        """Decorator to register a telemetry event handler."""
        self._handlers.append(fn)
        return fn

    def add_handler(self, fn: HandlerFn) -> "TelemetrySubscriber":
        """Add a telemetry event handler (non-decorator form)."""
        self._handlers.append(fn)
        return self

    async def subscribe(
        self,
        paths:          list[TelemetryPath],
        mode:           SubscriptionMode = SubscriptionMode.STREAM,
        reconnect:      bool = True,
        reconnect_delay: float = 5.0,
    ) -> None:
        """
        Start subscribing to telemetry paths.

        Runs in the background — non-blocking.
        Reconnects automatically on disconnect if reconnect=True.

        Args:
            paths:           List of TelemetryPath subscriptions
            mode:            Subscription mode (STREAM/ONCE/POLL)
            reconnect:       Auto-reconnect on disconnect
            reconnect_delay: Seconds to wait before reconnecting
        """
        self._subscriptions = paths
        self._running = True

        self._task = asyncio.create_task(
            self._subscription_loop(mode, reconnect, reconnect_delay),
            name=f"telemetry:{self.device.hostname}",
        )

    async def poll_once(self, paths: list[TelemetryPath]) -> list[TelemetryEvent]:
        """
        Perform a single gNMI GET/ONCE subscription.
        Returns all events synchronously (blocks until complete).
        """
        events: list[TelemetryEvent] = []

        async def collect(event: TelemetryEvent) -> None:
            events.append(event)

        self.add_handler(collect)
        await self.subscribe(paths, mode=SubscriptionMode.ONCE, reconnect=False)

        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=30.0)
            except asyncio.TimeoutError:
                logger.warning(f"gNMI ONCE subscription timed out on {self.device.hostname}")
        return events

    async def stop(self) -> None:
        """Stop the telemetry subscription."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(f"Telemetry stopped for {self.device.hostname}")

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    # ── Internal ──────────────────────────────────────────────────────

    async def _subscription_loop(
        self,
        mode:            SubscriptionMode,
        reconnect:       bool,
        reconnect_delay: float,
    ) -> None:
        """Main subscription loop with reconnect logic."""
        start = time.monotonic()
        while self._running:
            try:
                await self._run_gnmi_subscription(mode)
                if mode == SubscriptionMode.ONCE:
                    break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._stats["errors"] += 1
                logger.warning(
                    f"gNMI subscription error on {self.device.hostname}: {exc}. "
                    f"{'Reconnecting in' if reconnect else 'Stopping.'} "
                    f"{reconnect_delay if reconnect else ''}s"
                )
                if not reconnect or not self._running:
                    break
                await asyncio.sleep(reconnect_delay)

        self._stats["uptime_seconds"] = time.monotonic() - start

    async def _run_gnmi_subscription(self, mode: SubscriptionMode) -> None:
        """Attempt to connect and run gNMI subscription."""
        try:
            from pygnmi.client import gNMIclient
        except ImportError:
            raise ImportError(
                "gNMI telemetry requires: pip install plexar[gnmi]  (installs pygnmi + grpcio)"
            )

        host   = self.device.management_ip or self.device.hostname
        target = (host, self.port)

        # Resolve credentials
        username = self.username or (
            self.device.credentials.username if self.device.credentials else ""
        )
        password = self.password or (
            self.device.credentials.password if self.device.credentials else ""
        )

        async with gNMIclient(
            target=target,
            username=username,
            password=password,
            insecure=self.insecure,
            skip_verify=self.insecure,
        ) as client:
            logger.info(f"gNMI connected to {self.device.hostname}:{self.port}")

            subscription_list = [
                {
                    "path": p.path,
                    "mode": str(p.mode),
                    "sample_interval": p.interval_ms * 1_000_000,  # ns
                    "suppress_redundant": p.suppress_redundant,
                }
                for p in self._subscriptions
            ]

            async for notification in client.subscribe_async(
                subscription=subscription_list,
                mode=str(mode),
            ):
                if not self._running:
                    break
                events = self._parse_notification(notification)
                for event in events:
                    self._stats["events_received"] += 1
                    for handler in self._handlers:
                        try:
                            await handler(event)
                        except Exception as e:
                            logger.error(
                                f"Telemetry handler error on {self.device.hostname}: {e}"
                            )

    def _parse_notification(self, notification: Any) -> list[TelemetryEvent]:
        """Parse a raw gNMI notification into TelemetryEvent objects."""
        events = []
        try:
            path      = notification.get("update", {}).get("prefix", {}).get("elem", "")
            timestamp = notification.get("update", {}).get("timestamp", int(time.time() * 1e9))
            updates   = notification.get("update", {}).get("update", [])

            for update in updates:
                leaf_path = "/".join(
                    e.get("name", "") for e in update.get("path", {}).get("elem", [])
                )
                val = update.get("val", {})
                # Flatten scalar values
                if isinstance(val, dict) and len(val) == 1:
                    val = next(iter(val.values()))

                events.append(TelemetryEvent(
                    device_hostname=self.device.hostname,
                    path=f"{path}/{leaf_path}".strip("/"),
                    timestamp_ns=timestamp,
                    values={"value": val, "path": leaf_path},
                ))
        except Exception as e:
            logger.debug(f"Failed to parse gNMI notification: {e}")

        return events


# ── Fleet Telemetry ───────────────────────────────────────────────────

class FleetTelemetry:
    """
    Manage telemetry subscriptions across an entire fleet of devices.

    Usage:
        fleet = FleetTelemetry(devices=net.devices(role="spine"))

        @fleet.on_update
        async def handle(event: TelemetryEvent):
            print(f"{event.device_hostname}: {event.path}")

        await fleet.subscribe([
            TelemetryPath.interface_counters(interval_ms=5000),
            TelemetryPath.bgp_state(),
        ])

        await fleet.stop_all()
    """

    def __init__(self, devices: list["Device"], port: int = 6030, insecure: bool = False) -> None:
        self.devices    = devices
        self.port       = port
        self.insecure   = insecure
        self._handlers: list[HandlerFn]             = []
        self._subscribers: list[TelemetrySubscriber] = []

    def on_update(self, fn: HandlerFn) -> HandlerFn:
        """Register a handler for all devices."""
        self._handlers.append(fn)
        return fn

    async def subscribe(self, paths: list[TelemetryPath], **kwargs: Any) -> None:
        """Start subscriptions on all devices."""
        for device in self.devices:
            sub = TelemetrySubscriber(device, port=self.port, insecure=self.insecure)
            for handler in self._handlers:
                sub.add_handler(handler)
            await sub.subscribe(paths, **kwargs)
            self._subscribers.append(sub)

        logger.info(f"Fleet telemetry active on {len(self._subscribers)} devices")

    async def stop_all(self) -> None:
        """Stop all device subscriptions."""
        await asyncio.gather(*[s.stop() for s in self._subscribers])

    @property
    def stats(self) -> dict[str, Any]:
        total_events = sum(s.stats["events_received"] for s in self._subscribers)
        total_errors = sum(s.stats["errors"]          for s in self._subscribers)
        return {
            "devices":        len(self._subscribers),
            "events_total":   total_events,
            "errors_total":   total_errors,
        }
