"""
Plexar Telemetry & Event Bus.

gNMI streaming telemetry + unified async event bus.

Usage:
    from plexar.telemetry import TelemetrySubscriber, FleetTelemetry, TelemetryPath
    from plexar.telemetry import event_bus, EventType, PlexarEvent
"""

from plexar.telemetry.gnmi import (
    TelemetrySubscriber, FleetTelemetry, TelemetryPath,
    TelemetryEvent, InterfaceCounters, BGPTelemetryEvent,
    SubscriptionMode, SampleMode,
)
from plexar.telemetry.events import (
    EventBus, PlexarEvent, EventType, ThresholdMonitor, event_bus,
)

__all__ = [
    "TelemetrySubscriber", "FleetTelemetry", "TelemetryPath",
    "TelemetryEvent", "InterfaceCounters", "BGPTelemetryEvent",
    "SubscriptionMode", "SampleMode",
    "EventBus", "PlexarEvent", "EventType", "ThresholdMonitor", "event_bus",
]
