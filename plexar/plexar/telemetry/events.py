"""
Plexar Event Bus.

A lightweight async pub/sub event bus that unifies events from
all Plexar subsystems into a single stream:

  - Telemetry events    (gNMI counters, BGP state changes)
  - Drift events        (running state diverged from snapshot)
  - Security events     (violations, auth failures)
  - Connection events   (connect/disconnect)
  - Config events       (push, rollback, commit)
  - Intent events       (apply started/completed, verify failed)

Consumers subscribe by event type or via wildcard.

Usage:
    from plexar.telemetry.events import event_bus, PlexarEvent, EventType

    # Subscribe to all BGP events
    @event_bus.on(EventType.BGP_STATE_CHANGE)
    async def handle_bgp(event: PlexarEvent):
        print(f"{event.hostname}: BGP {event.data['state']}")

    # Subscribe to all events
    @event_bus.on("*")
    async def log_all(event: PlexarEvent):
        logger.info(event)

    # Emit an event
    await event_bus.emit(PlexarEvent(
        type=EventType.BGP_STATE_CHANGE,
        hostname="spine-01",
        data={"neighbor": "10.0.0.1", "state": "ESTABLISHED"},
    ))
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Coroutine
from uuid import uuid4

logger = logging.getLogger(__name__)

HandlerFn = Callable[["PlexarEvent"], Coroutine[Any, Any, None]]


class EventType(StrEnum):
    # Connection
    DEVICE_CONNECTED    = "device.connected"
    DEVICE_DISCONNECTED = "device.disconnected"
    DEVICE_UNREACHABLE  = "device.unreachable"

    # Config
    CONFIG_PUSHED       = "config.pushed"
    CONFIG_ROLLED_BACK  = "config.rolled_back"
    CONFIG_COMMITTED    = "config.committed"

    # Intent
    INTENT_APPLIED      = "intent.applied"
    INTENT_FAILED       = "intent.failed"
    INTENT_VERIFIED     = "intent.verified"
    INTENT_VERIFY_FAILED = "intent.verify_failed"

    # BGP
    BGP_STATE_CHANGE    = "bgp.state_change"
    BGP_PEER_DOWN       = "bgp.peer_down"
    BGP_PEER_UP         = "bgp.peer_up"
    BGP_PREFIX_LIMIT    = "bgp.prefix_limit"

    # Interface
    INTERFACE_DOWN      = "interface.down"
    INTERFACE_UP        = "interface.up"
    INTERFACE_ERROR     = "interface.error"

    # Drift
    DRIFT_DETECTED      = "drift.detected"
    DRIFT_RESOLVED      = "drift.resolved"

    # Telemetry
    TELEMETRY_UPDATE    = "telemetry.update"
    TELEMETRY_THRESHOLD = "telemetry.threshold_exceeded"

    # Topology
    NEIGHBOR_ADDED      = "topology.neighbor_added"
    NEIGHBOR_REMOVED    = "topology.neighbor_removed"

    # Security
    SECURITY_VIOLATION  = "security.violation"
    AUTH_FAILURE        = "security.auth_failure"


@dataclass
class PlexarEvent:
    """
    A Plexar platform event.

    Emitted by all subsystems and delivered to registered handlers.
    """
    type:       EventType
    hostname:   str | None         = None
    data:       dict[str, Any]     = field(default_factory=dict)
    severity:   str                = "info"   # debug/info/warning/error/critical
    timestamp:  float              = field(default_factory=time.time)
    event_id:   str                = field(default_factory=lambda: str(uuid4())[:8])
    source:     str                = "plexar"

    def __str__(self) -> str:
        device = f"[{self.hostname}] " if self.hostname else ""
        return f"PlexarEvent({self.type} {device}{self.data})"


class EventBus:
    """
    Async pub/sub event bus.

    Handlers are async coroutines called for each matching event.
    Multiple handlers can be registered per event type.
    Wildcard "*" receives all events.

    Handler errors are caught and logged — never crash the bus.
    """

    def __init__(self, max_queue: int = 1000) -> None:
        self._handlers:  dict[str, list[HandlerFn]] = {"*": []}
        self._queue:     asyncio.Queue               = asyncio.Queue(maxsize=max_queue)
        self._running:   bool                        = False
        self._task:      asyncio.Task | None         = None
        self._stats = {
            "emitted":   0,
            "delivered": 0,
            "dropped":   0,
            "errors":    0,
        }

    def on(self, event_type: EventType | str) -> Callable:
        """
        Decorator to register a handler for an event type.

        event_type can be:
          - An EventType enum value
          - A string event type
          - "*" to receive all events

        Usage:
            @event_bus.on(EventType.BGP_PEER_DOWN)
            async def handle(event: PlexarEvent):
                alert(event.hostname)
        """
        def decorator(fn: HandlerFn) -> HandlerFn:
            key = str(event_type)
            if key not in self._handlers:
                self._handlers[key] = []
            self._handlers[key].append(fn)
            return fn
        return decorator

    def subscribe(self, event_type: EventType | str, handler: HandlerFn) -> None:
        """Register a handler (non-decorator form)."""
        key = str(event_type)
        if key not in self._handlers:
            self._handlers[key] = []
        self._handlers[key].append(fn)

    def unsubscribe(self, event_type: EventType | str, handler: HandlerFn) -> None:
        """Remove a handler."""
        key = str(event_type)
        if key in self._handlers:
            self._handlers[key] = [h for h in self._handlers[key] if h != handler]

    async def emit(self, event: PlexarEvent) -> None:
        """
        Emit an event to all registered handlers.

        If the bus is running in background mode, events are queued.
        Otherwise handlers are called directly (inline mode).
        """
        self._stats["emitted"] += 1
        if self._running:
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                self._stats["dropped"] += 1
                logger.warning(f"Event bus queue full — dropping event: {event.type}")
        else:
            await self._dispatch(event)

    def emit_sync(self, event: PlexarEvent) -> None:
        """Emit from synchronous context (schedules on event loop)."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.emit(event))
        except RuntimeError:
            pass   # No running loop — drop event

    async def start(self) -> None:
        """Start the event bus background processing loop."""
        if self._running:
            return
        self._running = True
        self._task    = asyncio.create_task(self._process_loop(), name="plexar-event-bus")
        logger.debug("Plexar event bus started")

    async def stop(self) -> None:
        """Stop the event bus."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.debug(f"Event bus stopped. Stats: {self._stats}")

    async def _process_loop(self) -> None:
        """Background loop that processes queued events."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _dispatch(self, event: PlexarEvent) -> None:
        """Call all registered handlers for an event."""
        handlers = list(self._handlers.get("*", []))
        handlers += list(self._handlers.get(str(event.type), []))

        for handler in handlers:
            try:
                await handler(event)
                self._stats["delivered"] += 1
            except Exception as e:
                self._stats["errors"] += 1
                logger.error(f"Event handler error for {event.type}: {e}")

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "queue_size": self._queue.qsize()}


# ── Threshold Monitor ─────────────────────────────────────────────────

class ThresholdMonitor:
    """
    Monitor telemetry values and emit events when thresholds are exceeded.

    Usage:
        monitor = ThresholdMonitor(event_bus)
        monitor.add_threshold(
            name="interface_error_rate",
            metric="in_errors",
            operator=">",
            value=100,
            severity="warning",
        )

        @event_bus.on(EventType.TELEMETRY_THRESHOLD)
        async def alert(event):
            print(f"Threshold exceeded: {event.data}")
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus        = bus
        self._thresholds: list[dict] = []

    def add_threshold(
        self,
        name:     str,
        metric:   str,
        operator: str,   # ">" | "<" | ">=" | "<=" | "==" | "!="
        value:    float,
        severity: str = "warning",
    ) -> "ThresholdMonitor":
        self._thresholds.append({
            "name":     name,
            "metric":   metric,
            "operator": operator,
            "value":    value,
            "severity": severity,
        })
        return self

    async def check(self, event_data: dict, hostname: str | None = None) -> None:
        """Check event data against all thresholds and emit if exceeded."""
        for threshold in self._thresholds:
            metric_val = event_data.get(threshold["metric"])
            if metric_val is None:
                continue
            exceeded = self._evaluate(float(metric_val), threshold["operator"], threshold["value"])
            if exceeded:
                await self._bus.emit(PlexarEvent(
                    type=EventType.TELEMETRY_THRESHOLD,
                    hostname=hostname,
                    severity=threshold["severity"],
                    data={
                        "threshold": threshold["name"],
                        "metric":    threshold["metric"],
                        "actual":    metric_val,
                        "limit":     threshold["value"],
                        "operator":  threshold["operator"],
                    },
                ))

    @staticmethod
    def _evaluate(actual: float, op: str, limit: float) -> bool:
        ops = {">": actual > limit, "<": actual < limit,
               ">=": actual >= limit, "<=": actual <= limit,
               "==": actual == limit, "!=": actual != limit}
        return ops.get(op, False)


# ── Module-level singleton ────────────────────────────────────────────

event_bus = EventBus()
