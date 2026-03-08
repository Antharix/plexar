"""
AI Root Cause Analysis (RCA) Engine.

When something goes wrong on the network, RCA takes:
  - The symptoms (alerts, events, state deltas)
  - The network context (topology, BGP state, interface stats)
  - Recent changes (config diffs, intent apply history)

...and produces a structured diagnosis with probable causes,
affected scope, and recommended remediation steps.

This is the feature that transforms Plexar from a tool into a platform.

Usage:
    from plexar.ai import RCAEngine
    from plexar.telemetry.events import PlexarEvent, EventType

    rca = RCAEngine(model="claude-3-5-sonnet-20241022")

    # Triggered by an event
    diagnosis = await rca.analyze(
        event=PlexarEvent(
            type=EventType.BGP_PEER_DOWN,
            hostname="leaf-01",
            data={"neighbor": "10.0.0.1", "state": "IDLE"},
        ),
        device=leaf01,
        topology=topo,
    )

    print(diagnosis.probable_cause)
    print(diagnosis.affected_devices)
    print(diagnosis.recommended_actions)

    # Approve and execute recommended remediation
    if diagnosis.has_auto_remediation:
        await rca.remediate(diagnosis, approver="alice")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from plexar.security.sanitizer import sanitize_for_llm, redact_credentials
from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType

if TYPE_CHECKING:
    from plexar.core.device import Device
    from plexar.topology.graph import TopologyGraph
    from plexar.telemetry.events import PlexarEvent
    from plexar.state.snapshot import SnapshotDelta

logger = logging.getLogger(__name__)


# ── RCA Models ────────────────────────────────────────────────────────

@dataclass
class RemediationAction:
    """A single recommended action to fix an issue."""
    description:    str
    command:        str | None  = None     # actual CLI command if applicable
    priority:       int         = 1        # 1=immediate, 2=soon, 3=monitor
    risk:           str         = "low"    # low/medium/high
    automated:      bool        = False    # can Plexar execute this automatically?
    requires_approval: bool     = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "description":        self.description,
            "command":            self.command,
            "priority":           self.priority,
            "risk":               self.risk,
            "automated":          self.automated,
            "requires_approval":  self.requires_approval,
        }


@dataclass
class RCADiagnosis:
    """
    The output of an RCA analysis.
    Contains structured diagnosis with actionable recommendations.
    """
    # Core diagnosis
    probable_cause:   str
    confidence:       float             # 0.0 - 1.0
    severity:         str               = "warning"   # info/warning/error/critical
    summary:          str               = ""

    # Scope
    primary_device:   str               = ""
    affected_devices: list[str]         = field(default_factory=list)
    affected_services: list[str]        = field(default_factory=list)

    # Evidence
    contributing_factors: list[str]     = field(default_factory=list)
    evidence:         list[str]         = field(default_factory=list)

    # Actions
    recommended_actions: list[RemediationAction] = field(default_factory=list)

    # Metadata
    model_used:       str               = ""
    analyzed_at:      datetime          = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    diagnosis_id:     str               = field(
        default_factory=lambda: __import__("uuid").uuid4().hex[:8]
    )

    @property
    def has_auto_remediation(self) -> bool:
        return any(a.automated for a in self.recommended_actions)

    @property
    def immediate_actions(self) -> list[RemediationAction]:
        return [a for a in self.recommended_actions if a.priority == 1]

    def render(self, color: bool = True) -> str:
        BOLD   = "\033[1m"  if color else ""
        RED    = "\033[31m" if color else ""
        YELLOW = "\033[33m" if color else ""
        GREEN  = "\033[32m" if color else ""
        RESET  = "\033[0m"  if color else ""

        sev_color = {"critical": RED, "error": RED, "warning": YELLOW, "info": GREEN}.get(
            self.severity, ""
        )
        lines = [
            f"{BOLD}RCA Diagnosis [{self.diagnosis_id}]{RESET}",
            f"  {sev_color}Severity:{RESET}       {self.severity.upper()}",
            f"  Confidence:      {int(self.confidence * 100)}%",
            f"  Primary device:  {self.primary_device}",
            "",
            f"  {BOLD}Probable Cause:{RESET}",
            f"  {self.probable_cause}",
        ]
        if self.contributing_factors:
            lines += ["", f"  {BOLD}Contributing Factors:{RESET}"]
            lines += [f"    • {f}" for f in self.contributing_factors]

        if self.affected_devices:
            lines += ["", f"  {BOLD}Affected Devices:{RESET}  {', '.join(self.affected_devices)}"]

        if self.recommended_actions:
            lines += ["", f"  {BOLD}Recommended Actions:{RESET}"]
            for i, action in enumerate(self.recommended_actions, 1):
                auto = " [AUTO]" if action.automated else ""
                lines.append(f"    {i}. [{action.risk.upper()}]{auto} {action.description}")
                if action.command:
                    lines.append(f"       $ {action.command}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnosis_id":         self.diagnosis_id,
            "probable_cause":       self.probable_cause,
            "confidence":           self.confidence,
            "severity":             self.severity,
            "summary":              self.summary,
            "primary_device":       self.primary_device,
            "affected_devices":     self.affected_devices,
            "contributing_factors": self.contributing_factors,
            "evidence":             self.evidence,
            "recommended_actions":  [a.to_dict() for a in self.recommended_actions],
            "model_used":           self.model_used,
            "analyzed_at":          self.analyzed_at.isoformat(),
        }


# ── RCA Engine ────────────────────────────────────────────────────────

_RCA_SYSTEM_PROMPT = """You are a senior network engineer performing root cause analysis.
You receive structured information about a network event and must diagnose the probable cause.

Rules:
- Return ONLY valid JSON matching the schema exactly
- Be specific about probable causes — avoid vague answers like "network issue"
- Confidence should reflect how certain you are (0.0-1.0)
- List evidence from the provided context that supports your diagnosis
- Recommended actions should be specific and actionable
- Mark actions as automated=true only if they are safe to execute without human review
- automated actions should only include show/display commands, never config changes
"""

_RCA_SCHEMA = {
    "probable_cause": "string — specific root cause",
    "confidence": "float 0.0-1.0",
    "severity": "info|warning|error|critical",
    "summary": "string — one sentence summary",
    "contributing_factors": ["string"],
    "affected_devices": ["string — hostnames"],
    "affected_services": ["string — bgp/ospf/vlan/etc"],
    "evidence": ["string — specific evidence from context"],
    "recommended_actions": [
        {
            "description": "string",
            "command": "string or null",
            "priority": "1=immediate|2=soon|3=monitor",
            "risk": "low|medium|high",
            "automated": "boolean",
            "requires_approval": "boolean",
        }
    ],
}


class RCAEngine:
    """
    AI-powered Root Cause Analysis engine.

    Analyzes network events, state deltas, and topology context
    to diagnose issues and recommend fixes.
    """

    def __init__(
        self,
        model:      str   = "gpt-4o-mini",
        max_tokens: int   = 3000,
        timeout:    float = 60.0,
    ) -> None:
        self.model      = model
        self.max_tokens = max_tokens
        self.timeout    = timeout
        self._history:  list[RCADiagnosis] = []

    async def analyze(
        self,
        event:          "PlexarEvent",
        device:         "Device | None"        = None,
        topology:       "TopologyGraph | None"  = None,
        delta:          "SnapshotDelta | None"  = None,
        extra_context:  dict[str, Any] | None   = None,
    ) -> RCADiagnosis:
        """
        Perform root cause analysis on a network event.

        Gathers context from the device and topology, then calls
        the LLM to produce a structured diagnosis.

        Args:
            event:         The triggering PlexarEvent
            device:        The primary affected device
            topology:      Network topology (for blast radius, path analysis)
            delta:         State snapshot delta (before/after comparison)
            extra_context: Any additional context to include

        Returns:
            RCADiagnosis with probable cause and recommendations
        """
        context = await self._gather_context(event, device, topology, delta, extra_context)
        prompt  = self._build_prompt(event, context)

        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.AI_QUERY,
            hostname=event.hostname,
            details={
                "rca_trigger":  str(event.type),
                "model":        self.model,
                "context_keys": list(context.keys()),
            },
        ))

        try:
            raw = await self._call_llm(prompt)
            data = json.loads(raw)
            diagnosis = self._build_diagnosis(data, event)
            self._history.append(diagnosis)

            logger.info(
                f"RCA complete for {event.hostname}: {diagnosis.probable_cause} "
                f"(confidence={int(diagnosis.confidence*100)}%)"
            )
            return diagnosis

        except Exception as exc:
            logger.error(f"RCA failed for {event.hostname}: {redact_credentials(str(exc))}")
            # Return a minimal diagnosis rather than raising
            return RCADiagnosis(
                probable_cause="RCA analysis failed — insufficient data or LLM unavailable",
                confidence=0.0,
                severity=event.severity,
                primary_device=event.hostname or "unknown",
                model_used=self.model,
            )

    async def analyze_drift(
        self,
        device:  "Device",
        delta:   "SnapshotDelta",
        topology: "TopologyGraph | None" = None,
    ) -> RCADiagnosis:
        """Analyze a state drift event."""
        from plexar.telemetry.events import PlexarEvent, EventType
        event = PlexarEvent(
            type=EventType.DRIFT_DETECTED,
            hostname=device.hostname,
            severity="warning",
            data={"changes": delta.summary()},
        )
        return await self.analyze(event=event, device=device, topology=topology, delta=delta)

    async def remediate(
        self,
        diagnosis:  RCADiagnosis,
        approver:   str,
        device:     "Device | None" = None,
        dry_run:    bool            = False,
    ) -> dict[str, Any]:
        """
        Execute automated remediation actions from a diagnosis.

        Only executes actions marked as automated=True.
        All executions are audit-logged with the approver's identity.

        Args:
            diagnosis: The RCA diagnosis to remediate
            approver:  Username approving the remediation
            device:    Target device (if not inferred from diagnosis)
            dry_run:   If True, show what would be done without doing it

        Returns:
            Dict with executed actions and their results
        """
        auto_actions = [a for a in diagnosis.recommended_actions if a.automated]

        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.AI_REMEDIATION,
            hostname=diagnosis.primary_device,
            severity="warning",
            details={
                "diagnosis_id":   diagnosis.diagnosis_id,
                "approver":       approver,
                "actions_count":  len(auto_actions),
                "dry_run":        dry_run,
            },
        ))

        results: dict[str, Any] = {
            "diagnosis_id": diagnosis.diagnosis_id,
            "approver":     approver,
            "dry_run":      dry_run,
            "executed":     [],
            "skipped":      [],
        }

        for action in auto_actions:
            if dry_run:
                results["skipped"].append({
                    "action":  action.description,
                    "command": action.command,
                    "reason":  "dry_run",
                })
                continue

            if action.command and device:
                try:
                    output = await device.run(action.command)
                    results["executed"].append({
                        "action":  action.description,
                        "command": action.command,
                        "output":  output[:500],
                        "status":  "success",
                    })
                    get_audit_logger().log(AuditEvent(
                        event_type=AuditEventType.AI_REMEDIATION_APPROVED,
                        hostname=diagnosis.primary_device,
                        details={
                            "approver": approver,
                            "command":  action.command,
                        },
                    ))
                except Exception as exc:
                    results["executed"].append({
                        "action":  action.description,
                        "command": action.command,
                        "status":  "failed",
                        "error":   str(exc),
                    })

        return results

    @property
    def history(self) -> list[RCADiagnosis]:
        """All diagnoses performed in this session."""
        return list(self._history)

    # ── Internal ──────────────────────────────────────────────────────

    async def _gather_context(
        self,
        event:         "PlexarEvent",
        device:        "Device | None",
        topology:      "TopologyGraph | None",
        delta:         "SnapshotDelta | None",
        extra_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Gather all available context for RCA."""
        context: dict[str, Any] = {
            "event_type":  str(event.type),
            "hostname":    event.hostname,
            "severity":    event.severity,
            "event_data":  event.data,
            "timestamp":   event.timestamp,
        }

        if device and device.is_connected:
            try:
                bgp     = await device.get_bgp_summary()
                context["bgp_state"] = {
                    "peers_established": bgp.peers_established,
                    "peers_down":        bgp.peers_down,
                    "total_prefixes":    bgp.total_prefixes_received,
                    "peers": [
                        {
                            "ip":    p.neighbor_ip,
                            "as":    p.remote_as,
                            "state": p.state,
                            "prefixes": p.prefixes_received,
                        }
                        for p in bgp.peers
                    ],
                }
            except Exception:
                pass

            try:
                interfaces  = await device.get_interfaces()
                down_ifaces = [i.name for i in interfaces if i.oper_state != "up"]
                context["interfaces"] = {
                    "total":    len(interfaces),
                    "down":     down_ifaces,
                    "up_count": len(interfaces) - len(down_ifaces),
                }
            except Exception:
                pass

            try:
                routes = await device.get_routing_table()
                context["routing"] = {
                    "total_routes":    len(routes.routes),
                    "has_default":     routes.default_route is not None,
                    "protocols":       list({r.protocol for r in routes.routes}),
                }
            except Exception:
                pass

        if topology and event.hostname:
            try:
                neighbors = list(topology._G.neighbors(event.hostname))
                context["topology"] = {
                    "neighbors":        neighbors,
                    "neighbor_count":   len(neighbors),
                    "is_spine":         topology._nodes.get(event.hostname, {}).role == "spine"
                    if hasattr(topology._nodes.get(event.hostname, object()), "role") else False,
                }
                # Blast radius
                blast = topology.blast_radius(event.hostname)
                context["blast_radius"] = {
                    "risk_score":      blast.risk_score,
                    "affected_count":  len(blast.affected_devices),
                    "isolated":        blast.isolated_devices,
                }
            except Exception:
                pass

        if delta:
            context["state_changes"] = delta.summary() if hasattr(delta, "summary") else str(delta)

        if extra_context:
            context.update(extra_context)

        return context

    def _build_prompt(self, event: "PlexarEvent", context: dict[str, Any]) -> str:
        schema_str = json.dumps(_RCA_SCHEMA, indent=2)
        context_str = json.dumps(context, indent=2, default=str)
        return (
            f"Network event requiring root cause analysis:\n\n"
            f"Context:\n{context_str}\n\n"
            f"Return a JSON object matching this schema:\n{schema_str}"
        )

    def _build_diagnosis(self, data: dict, event: "PlexarEvent") -> RCADiagnosis:
        actions = [
            RemediationAction(
                description=a.get("description", ""),
                command=a.get("command"),
                priority=int(a.get("priority", 2)),
                risk=a.get("risk", "low"),
                automated=bool(a.get("automated", False)),
                requires_approval=bool(a.get("requires_approval", True)),
            )
            for a in data.get("recommended_actions", [])
        ]
        return RCADiagnosis(
            probable_cause=data.get("probable_cause", "Unknown"),
            confidence=float(data.get("confidence", 0.5)),
            severity=data.get("severity", event.severity),
            summary=data.get("summary", ""),
            primary_device=event.hostname or "",
            affected_devices=data.get("affected_devices", [event.hostname] if event.hostname else []),
            affected_services=data.get("affected_services", []),
            contributing_factors=data.get("contributing_factors", []),
            evidence=data.get("evidence", []),
            recommended_actions=actions,
            model_used=self.model,
        )

    async def _call_llm(self, prompt: str) -> str:
        try:
            import litellm
        except ImportError:
            raise ImportError("AI features require: pip install plexar[ai]")

        response = await litellm.acompletion(
            model=self.model,
            messages=[
                {"role": "system", "content": _RCA_SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
        )
        content = response.choices[0].message.content or ""
        content = content.strip()
        if content.startswith("```"):
            lines   = content.splitlines()
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        return content
