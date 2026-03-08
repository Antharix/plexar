"""
OpenTelemetry Metrics Exporter.

Exports Plexar telemetry data as OpenTelemetry metrics for consumption
by Prometheus, Grafana, Datadog, Dynatrace, and any OTLP-compatible backend.

Metric categories:
  plexar.bgp.*          — BGP peer state, prefix counts
  plexar.interface.*    — Interface counters, error rates, operational state
  plexar.device.*       — Device reachability, connection pool stats
  plexar.intent.*       — Intent apply success/failure, verification results
  plexar.drift.*        — Drift events, risk scores
  plexar.security.*     — Security violations, auth failures

Usage:
    from plexar.integrations.opentelemetry import PlexarOTLPExporter

    exporter = PlexarOTLPExporter(
        endpoint="http://otel-collector:4317",
        service_name="plexar",
        resource_attributes={"deployment.environment": "production"},
    )
    exporter.start()

    # Wire to event bus — metrics emitted automatically
    from plexar.telemetry.events import event_bus
    exporter.attach(event_bus)

    # Or emit manually
    exporter.record_bgp_peer(hostname="spine-01", neighbor_ip="10.0.0.1", state="established")
    exporter.record_interface(hostname="leaf-01", interface="Eth1", oper_state="up", error_rate=0.01)
"""

from __future__ import annotations

import logging
import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.telemetry.events import EventBus, PlexarEvent

logger = logging.getLogger(__name__)


class PlexarOTLPExporter:
    """
    OpenTelemetry metrics exporter for Plexar.

    Wraps the OpenTelemetry SDK to emit Plexar-specific metrics.
    Falls back gracefully when OTLP endpoint is unavailable.

    Requires: pip install plexar[telemetry]
    """

    def __init__(
        self,
        endpoint:            str              = "http://localhost:4317",
        service_name:        str              = "plexar",
        resource_attributes: dict[str, str]   = None,
        export_interval_ms:  int              = 10_000,
        insecure:            bool             = True,
        headers:             dict[str, str]   = None,
    ) -> None:
        self.endpoint            = endpoint
        self.service_name        = service_name
        self.resource_attributes = resource_attributes or {}
        self.export_interval_ms  = export_interval_ms
        self.insecure            = insecure
        self.headers             = headers or {}
        self._meter: Any         = None
        self._metrics: dict[str, Any] = {}
        self._initialized        = False

    def start(self) -> "PlexarOTLPExporter":
        """Initialize the OTLP exporter and meter provider."""
        try:
            from opentelemetry import metrics
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            from opentelemetry.sdk.resources import Resource, SERVICE_NAME

            resource = Resource.create({
                SERVICE_NAME: self.service_name,
                **self.resource_attributes,
            })

            exporter = OTLPMetricExporter(
                endpoint=self.endpoint,
                insecure=self.insecure,
                headers=self.headers,
            )

            reader = PeriodicExportingMetricReader(
                exporter,
                export_interval_millis=self.export_interval_ms,
            )

            provider = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(provider)
            self._meter = metrics.get_meter("plexar", version="0.4.0")
            self._init_metrics()
            self._initialized = True
            logger.info(f"OTLP exporter started → {self.endpoint}")

        except ImportError:
            raise ImportError(
                "OpenTelemetry export requires: pip install plexar[telemetry]"
            )
        except Exception as exc:
            logger.warning(f"OTLP exporter init failed: {exc} — metrics disabled")

        return self

    def _init_metrics(self) -> None:
        """Initialize all metric instruments."""
        m = self._meter

        # BGP metrics
        self._metrics["bgp_peers_established"] = m.create_up_down_counter(
            "plexar.bgp.peers_established",
            description="Number of BGP peers in Established state",
            unit="peers",
        )
        self._metrics["bgp_peers_down"] = m.create_up_down_counter(
            "plexar.bgp.peers_down",
            description="Number of BGP peers not in Established state",
            unit="peers",
        )
        self._metrics["bgp_prefixes_received"] = m.create_up_down_counter(
            "plexar.bgp.prefixes_received",
            description="Total BGP prefixes received from all peers",
            unit="prefixes",
        )

        # Interface metrics
        self._metrics["interface_up"] = m.create_up_down_counter(
            "plexar.interface.up",
            description="Number of interfaces in operational up state",
            unit="interfaces",
        )
        self._metrics["interface_errors"] = m.create_counter(
            "plexar.interface.errors_total",
            description="Cumulative interface error counter",
            unit="errors",
        )
        self._metrics["interface_octets_in"] = m.create_counter(
            "plexar.interface.octets_in_total",
            description="Cumulative ingress octets",
            unit="By",
        )
        self._metrics["interface_octets_out"] = m.create_counter(
            "plexar.interface.octets_out_total",
            description="Cumulative egress octets",
            unit="By",
        )

        # Device metrics
        self._metrics["device_reachable"] = m.create_up_down_counter(
            "plexar.device.reachable",
            description="Device reachability (1=up, 0=down)",
        )

        # Intent metrics
        self._metrics["intent_apply_success"] = m.create_counter(
            "plexar.intent.apply_success_total",
            description="Number of successful intent apply operations",
        )
        self._metrics["intent_apply_failure"] = m.create_counter(
            "plexar.intent.apply_failure_total",
            description="Number of failed intent apply operations",
        )
        self._metrics["intent_verify_failures"] = m.create_counter(
            "plexar.intent.verify_failure_total",
            description="Number of intent verification failures",
        )

        # Drift metrics
        self._metrics["drift_events"] = m.create_counter(
            "plexar.drift.events_total",
            description="Total number of drift events detected",
        )
        self._metrics["drift_risk_score"] = m.create_up_down_counter(
            "plexar.drift.risk_score",
            description="Drift risk score (0-100)",
        )

        # Security metrics
        self._metrics["security_violations"] = m.create_counter(
            "plexar.security.violations_total",
            description="Total security violations detected",
        )

    def attach(self, bus: "EventBus") -> "PlexarOTLPExporter":
        """
        Attach to the Plexar event bus to emit metrics automatically.
        All relevant events are converted to OTLP metrics.
        """
        from plexar.telemetry.events import EventType

        @bus.on("*")
        async def handle_event(event: "PlexarEvent") -> None:
            self._handle_event(event)

        logger.info("OTLP exporter attached to event bus")
        return self

    def _handle_event(self, event: "PlexarEvent") -> None:
        """Convert a PlexarEvent into OTLP metrics."""
        if not self._initialized:
            return

        from plexar.telemetry.events import EventType
        attrs = {"hostname": event.hostname or "unknown"}

        try:
            if event.type == EventType.BGP_PEER_UP:
                self._metrics["bgp_peers_established"].add(1, attrs)
                self._metrics["bgp_peers_down"].add(-1, attrs)

            elif event.type == EventType.BGP_PEER_DOWN:
                self._metrics["bgp_peers_established"].add(-1, attrs)
                self._metrics["bgp_peers_down"].add(1, attrs)

            elif event.type == EventType.INTERFACE_UP:
                self._metrics["interface_up"].add(1, {**attrs, "interface": event.data.get("name", "")})

            elif event.type == EventType.INTERFACE_DOWN:
                self._metrics["interface_up"].add(-1, {**attrs, "interface": event.data.get("name", "")})

            elif event.type == EventType.DEVICE_CONNECTED:
                self._metrics["device_reachable"].add(1, attrs)

            elif event.type == EventType.DEVICE_UNREACHABLE:
                self._metrics["device_reachable"].add(-1, attrs)

            elif event.type == EventType.INTENT_APPLIED:
                self._metrics["intent_apply_success"].add(1, attrs)

            elif event.type == EventType.INTENT_FAILED:
                self._metrics["intent_apply_failure"].add(1, attrs)

            elif event.type == EventType.INTENT_VERIFY_FAILED:
                self._metrics["intent_verify_failures"].add(1, attrs)

            elif event.type == EventType.DRIFT_DETECTED:
                self._metrics["drift_events"].add(1, attrs)
                risk = event.data.get("risk_score", 0)
                self._metrics["drift_risk_score"].add(risk, attrs)

            elif event.type == EventType.SECURITY_VIOLATION:
                self._metrics["security_violations"].add(1, attrs)

        except Exception as exc:
            logger.debug(f"OTLP metric recording error: {exc}")

    def record_bgp_peer(
        self,
        hostname:    str,
        neighbor_ip: str,
        state:       str,
        prefixes:    int = 0,
    ) -> None:
        """Manually record a BGP peer state."""
        if not self._initialized:
            return
        attrs = {"hostname": hostname, "neighbor_ip": neighbor_ip, "state": state}
        is_up = 1 if state.lower() == "established" else 0
        self._metrics["bgp_peers_established"].add(is_up, attrs)
        if prefixes:
            self._metrics["bgp_prefixes_received"].add(prefixes, attrs)

    def record_interface(
        self,
        hostname:    str,
        interface:   str,
        oper_state:  str,
        in_octets:   int = 0,
        out_octets:  int = 0,
        in_errors:   int = 0,
        out_errors:  int = 0,
    ) -> None:
        """Manually record interface counters."""
        if not self._initialized:
            return
        attrs = {"hostname": hostname, "interface": interface}
        self._metrics["interface_up"].add(1 if oper_state == "up" else 0, attrs)
        if in_octets:
            self._metrics["interface_octets_in"].add(in_octets, attrs)
        if out_octets:
            self._metrics["interface_octets_out"].add(out_octets, attrs)
        if in_errors or out_errors:
            self._metrics["interface_errors"].add(in_errors + out_errors, attrs)

    def __repr__(self) -> str:
        status = "active" if self._initialized else "not started"
        return f"PlexarOTLPExporter(endpoint={self.endpoint}, status={status})"
