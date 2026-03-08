"""
Plexar Reporting Engine.

Generates rich reports from network operations:
  ChangeReport        — What changed in an intent apply or config push
  ComplianceReport    — Is the network in the desired state?
  DriftReport         — What has drifted from baseline snapshots?
  InventoryReport     — Full device inventory with health status
  TopologyReport      — Network topology summary

Output formats:
  JSON    — Machine-readable, for downstream processing
  HTML    — Rich browser report with charts and tables
  Text    — Console-friendly plain text
  CSV     — Spreadsheet-compatible

Usage:
    from plexar.reporting import ReportEngine

    engine = ReportEngine()

    # After intent apply
    report = engine.change_report(intent_result, plan)
    report.save_html("./reports/change-2025-01-15.html")
    report.save_json("./reports/change-2025-01-15.json")

    # Compliance check
    report = await engine.compliance_report(network, intent)
    print(report.compliance_score)   # 0-100
    report.save_html("./reports/compliance.html")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.intent.engine import Intent, IntentPlan, IntentResult
    from plexar.core.network import Network
    from plexar.topology.graph import TopologyGraph
    from plexar.state.snapshot import SnapshotDelta

logger = logging.getLogger(__name__)


# ── Report Base ───────────────────────────────────────────────────────

@dataclass
class ReportMeta:
    title:      str
    report_type: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str      = "plexar"
    version:    str        = "0.5.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title":        self.title,
            "report_type":  self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "version":      self.version,
        }


class BaseReport:
    """Base class for all Plexar reports."""

    def __init__(self, meta: ReportMeta) -> None:
        self.meta = meta

    def to_dict(self) -> dict[str, Any]:
        return {"meta": self.meta.to_dict()}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self.to_json())
        logger.info(f"Report saved: {path}")

    def save_html(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self._render_html())
        logger.info(f"HTML report saved: {path}")

    def save_text(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self.to_text())
        logger.info(f"Text report saved: {path}")

    def to_text(self) -> str:
        return f"Report: {self.meta.title}\n{self.meta.generated_at.isoformat()}"

    def _render_html(self) -> str:
        """Generate HTML report. Override in subclasses for rich output."""
        data     = self.to_dict()
        json_str = json.dumps(data, indent=2, default=str)
        return _HTML_TEMPLATE.format(
            title=self.meta.title,
            generated_at=self.meta.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            body=self._render_html_body(),
            json_data=json_str,
        )

    def _render_html_body(self) -> str:
        return f"<pre>{self.to_json()}</pre>"


# ── Change Report ─────────────────────────────────────────────────────

@dataclass
class DeviceChange:
    hostname:      str
    status:        str           # succeeded | failed | skipped
    lines_changed: int           = 0
    error:         str | None    = None
    config_diff:   str | None    = None


@dataclass
class ChangeReport(BaseReport):
    """Report of a config change operation."""
    meta:           ReportMeta
    changes:        list[DeviceChange] = field(default_factory=list)
    primitives:     list[str]          = field(default_factory=list)
    duration_s:     float              = 0.0

    @property
    def succeeded_count(self) -> int:
        return sum(1 for c in self.changes if c.status == "succeeded")

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.changes if c.status == "failed")

    @property
    def skipped_count(self) -> int:
        return sum(1 for c in self.changes if c.status == "skipped")

    @property
    def success_rate(self) -> float:
        total = self.succeeded_count + self.failed_count
        return (self.succeeded_count / total * 100) if total > 0 else 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "summary": {
                "succeeded":   self.succeeded_count,
                "failed":      self.failed_count,
                "skipped":     self.skipped_count,
                "success_rate": f"{self.success_rate:.1f}%",
                "duration_s":  self.duration_s,
                "primitives":  self.primitives,
            },
            "changes": [
                {
                    "hostname":      c.hostname,
                    "status":        c.status,
                    "lines_changed": c.lines_changed,
                    "error":         c.error,
                }
                for c in self.changes
            ],
        }

    def to_text(self) -> str:
        lines = [
            f"Change Report — {self.meta.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Primitives: {', '.join(self.primitives)}",
            f"Duration:   {self.duration_s:.1f}s",
            f"Success:    {self.succeeded_count}/{self.succeeded_count + self.failed_count}",
            "",
        ]
        for c in self.changes:
            icon = {"succeeded": "✓", "failed": "✗", "skipped": "~"}.get(c.status, "?")
            line = f"  {icon} {c.hostname}: {c.status}"
            if c.error:
                line += f" — {c.error}"
            lines.append(line)
        return "\n".join(lines)

    def _render_html_body(self) -> str:
        rows = ""
        for c in self.changes:
            color = {"succeeded": "#22c55e", "failed": "#ef4444", "skipped": "#94a3b8"}.get(
                c.status, "#94a3b8"
            )
            rows += (
                f"<tr>"
                f"<td>{c.hostname}</td>"
                f"<td style='color:{color};font-weight:bold'>{c.status.upper()}</td>"
                f"<td>{c.lines_changed}</td>"
                f"<td>{c.error or '—'}</td>"
                f"</tr>"
            )
        return f"""
        <div class="summary-grid">
            <div class="metric"><span class="num green">{self.succeeded_count}</span><span>succeeded</span></div>
            <div class="metric"><span class="num red">{self.failed_count}</span><span>failed</span></div>
            <div class="metric"><span class="num gray">{self.skipped_count}</span><span>skipped</span></div>
            <div class="metric"><span class="num">{self.success_rate:.0f}%</span><span>success rate</span></div>
        </div>
        <table>
            <thead><tr><th>Device</th><th>Status</th><th>Lines Changed</th><th>Error</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """


# ── Compliance Report ─────────────────────────────────────────────────

@dataclass
class ComplianceItem:
    name:     str
    device:   str
    passed:   bool
    reason:   str
    severity: str = "error"   # error | warning | info


@dataclass
class ComplianceReport(BaseReport):
    """Report of intent verification / compliance check."""
    meta:             ReportMeta
    items:            list[ComplianceItem] = field(default_factory=list)
    devices_checked:  int                  = 0
    primitives:       list[str]            = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for i in self.items if i.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for i in self.items if not i.passed)

    @property
    def compliance_score(self) -> float:
        total = len(self.items)
        return (self.passed_count / total * 100) if total > 0 else 100.0

    @property
    def is_compliant(self) -> bool:
        return all(i.passed for i in self.items if i.severity == "error")

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "summary": {
                "compliance_score": f"{self.compliance_score:.1f}%",
                "is_compliant":     self.is_compliant,
                "passed":           self.passed_count,
                "failed":           self.failed_count,
                "devices_checked":  self.devices_checked,
            },
            "items": [
                {
                    "name":     i.name,
                    "device":   i.device,
                    "passed":   i.passed,
                    "reason":   i.reason,
                    "severity": i.severity,
                }
                for i in self.items
            ],
        }

    def to_text(self) -> str:
        lines = [
            f"Compliance Report — {self.meta.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Score:    {self.compliance_score:.1f}%",
            f"Status:   {'✓ COMPLIANT' if self.is_compliant else '✗ NON-COMPLIANT'}",
            f"Devices:  {self.devices_checked}",
            "",
        ]
        for item in self.items:
            icon = "✓" if item.passed else "✗"
            lines.append(f"  {icon} [{item.device}] {item.name}: {item.reason}")
        return "\n".join(lines)

    def _render_html_body(self) -> str:
        score_color = "#22c55e" if self.compliance_score >= 90 else (
            "#f59e0b" if self.compliance_score >= 70 else "#ef4444"
        )
        rows = ""
        for item in self.items:
            color = "#22c55e" if item.passed else "#ef4444"
            icon  = "✓" if item.passed else "✗"
            rows += (
                f"<tr>"
                f"<td>{item.device}</td>"
                f"<td>{item.name}</td>"
                f"<td style='color:{color};font-weight:bold'>{icon}</td>"
                f"<td>{item.reason}</td>"
                f"<td>{item.severity}</td>"
                f"</tr>"
            )
        return f"""
        <div class="summary-grid">
            <div class="metric"><span class="num" style="color:{score_color}">{self.compliance_score:.0f}%</span><span>compliance score</span></div>
            <div class="metric"><span class="num green">{self.passed_count}</span><span>checks passed</span></div>
            <div class="metric"><span class="num red">{self.failed_count}</span><span>checks failed</span></div>
            <div class="metric"><span class="num">{self.devices_checked}</span><span>devices checked</span></div>
        </div>
        <table>
            <thead><tr><th>Device</th><th>Check</th><th>Result</th><th>Reason</th><th>Severity</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """


# ── Inventory Report ──────────────────────────────────────────────────

@dataclass
class InventoryReport(BaseReport):
    """Full device inventory report with health status."""
    meta:      ReportMeta
    devices:   list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.devices)

    @property
    def reachable(self) -> int:
        return sum(1 for d in self.devices if d.get("reachable"))

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "summary": {"total": self.total, "reachable": self.reachable},
            "devices": self.devices,
        }

    def to_text(self) -> str:
        lines = [
            f"Inventory Report — {self.meta.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Total: {self.total}  Reachable: {self.reachable}",
            "",
        ]
        for d in self.devices:
            lines.append(
                f"  {d.get('hostname','?'):30s}  {d.get('platform','?'):20s}  "
                f"{d.get('role','?'):10s}  {d.get('site','?')}"
            )
        return "\n".join(lines)

    def _render_html_body(self) -> str:
        rows = ""
        for d in self.devices:
            reachable = d.get("reachable", None)
            color = "#22c55e" if reachable else ("#ef4444" if reachable is False else "#94a3b8")
            status = "✓" if reachable else ("✗" if reachable is False else "?")
            rows += (
                f"<tr>"
                f"<td><strong>{d.get('hostname','')}</strong></td>"
                f"<td>{d.get('platform','')}</td>"
                f"<td>{d.get('role','')}</td>"
                f"<td>{d.get('site','')}</td>"
                f"<td>{d.get('management_ip','')}</td>"
                f"<td style='color:{color}'>{status}</td>"
                f"</tr>"
            )
        return f"""
        <div class="summary-grid">
            <div class="metric"><span class="num">{self.total}</span><span>total devices</span></div>
            <div class="metric"><span class="num green">{self.reachable}</span><span>reachable</span></div>
        </div>
        <table>
            <thead><tr><th>Hostname</th><th>Platform</th><th>Role</th><th>Site</th><th>Mgmt IP</th><th>Status</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """


# ── Report Engine ─────────────────────────────────────────────────────

class ReportEngine:
    """
    Generates Plexar reports from operation results.

    Usage:
        engine = ReportEngine()

        # After intent apply
        change_report = engine.from_intent_result(result, plan)
        change_report.save_html("./reports/change.html")

        # Compliance
        compliance = await engine.compliance_report(network=net, intent=intent)
        print(f"Score: {compliance.compliance_score:.0f}%")
    """

    def from_intent_result(
        self,
        result:    "IntentResult",
        plan:      "IntentPlan",
    ) -> ChangeReport:
        """Create a ChangeReport from an IntentResult."""
        changes: list[DeviceChange] = []

        for device in result.succeeded:
            changes.append(DeviceChange(hostname=device.hostname, status="succeeded"))
        for device, exc in result.failed:
            changes.append(DeviceChange(hostname=device.hostname, status="failed", error=str(exc)))
        for device in result.skipped:
            changes.append(DeviceChange(hostname=device.hostname, status="skipped"))

        return ChangeReport(
            meta=ReportMeta(
                title="Intent Change Report",
                report_type="change",
            ),
            changes=changes,
            primitives=[p.intent_type() for p in plan.primitives],
            duration_s=result.duration_seconds,
        )

    async def compliance_report(
        self,
        network:  "Network | None"  = None,
        intent:   "Intent | None"   = None,
    ) -> ComplianceReport:
        """Run intent verification and generate a ComplianceReport."""
        items: list[ComplianceItem] = []
        devices_checked = 0

        if intent:
            report = await intent.verify()
            devices_checked = len(intent.devices)
            for r in report.results:
                parts = r.name.split(": ", 1)
                device  = parts[0] if len(parts) == 2 else "unknown"
                check   = parts[1] if len(parts) == 2 else r.name
                items.append(ComplianceItem(
                    name=check,
                    device=device,
                    passed=r.passed,
                    reason=r.reason,
                ))

        return ComplianceReport(
            meta=ReportMeta(title="Compliance Report", report_type="compliance"),
            items=items,
            devices_checked=devices_checked,
            primitives=[p.intent_type() for p in intent._primitives] if intent else [],
        )

    def inventory_report(self, network: "Network") -> InventoryReport:
        """Generate an inventory report from a Network object."""
        devices = [
            {
                "hostname":      d.hostname,
                "platform":      str(d.platform),
                "management_ip": d.management_ip or "",
                "role":          d.metadata.get("role", ""),
                "site":          d.metadata.get("site", ""),
                "tags":          list(d.tags),
            }
            for d in network.inventory.all()
        ]
        return InventoryReport(
            meta=ReportMeta(title="Inventory Report", report_type="inventory"),
            devices=devices,
        )


# ── HTML Template ─────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ color: #38bdf8; font-size: 1.5rem; margin-bottom: 0.5rem; }}
    .meta {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 2rem; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                    gap: 1rem; margin-bottom: 2rem; }}
    .metric {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }}
    .metric .num {{ display: block; font-size: 2rem; font-weight: 700; color: #38bdf8; }}
    .metric .num.green {{ color: #22c55e; }}
    .metric .num.red   {{ color: #ef4444; }}
    .metric .num.gray  {{ color: #94a3b8; }}
    .metric span:last-child {{ font-size: 0.8rem; color: #94a3b8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px;
             overflow: hidden; }}
    th {{ background: #0f172a; padding: 0.75rem 1rem; text-align: left; font-size: 0.85rem;
          color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 0.75rem 1rem; border-top: 1px solid #334155; font-size: 0.9rem; }}
    tr:hover td {{ background: #263549; }}
    .footer {{ margin-top: 2rem; color: #475569; font-size: 0.8rem; text-align: center; }}
    details {{ margin-top: 2rem; }}
    summary {{ cursor: pointer; color: #94a3b8; padding: 0.5rem; }}
    pre {{ background: #0f172a; padding: 1rem; border-radius: 6px; overflow-x: auto;
           font-size: 0.8rem; color: #94a3b8; }}
  </style>
</head>
<body>
  <h1>⚡ Plexar — {title}</h1>
  <div class="meta">Generated {generated_at} by Plexar v0.5.0</div>
  {body}
  <details>
    <summary>Raw JSON data</summary>
    <pre>{json_data}</pre>
  </details>
  <div class="footer">Generated by Plexar — the nervous system for your network</div>
</body>
</html>"""
