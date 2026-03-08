"""Tests for the Reporting Engine."""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime, timezone

from plexar.reporting.engine import (
    ReportEngine, ReportMeta, BaseReport,
    ChangeReport, DeviceChange,
    ComplianceReport, ComplianceItem,
    InventoryReport,
)


class TestReportMeta:
    def test_to_dict(self):
        meta = ReportMeta(title="Test", report_type="test")
        d    = meta.to_dict()
        assert d["title"]       == "Test"
        assert d["report_type"] == "test"
        assert "generated_at"   in d
        assert "generated_by"   in d

    def test_json_serializable(self):
        meta = ReportMeta(title="Test", report_type="test")
        json.dumps(meta.to_dict())


class TestChangeReport:
    def _report(self) -> ChangeReport:
        return ChangeReport(
            meta=ReportMeta(title="Test Change", report_type="change"),
            changes=[
                DeviceChange(hostname="leaf-01", status="succeeded", lines_changed=10),
                DeviceChange(hostname="leaf-02", status="succeeded", lines_changed=5),
                DeviceChange(hostname="leaf-03", status="failed", error="timeout"),
                DeviceChange(hostname="spine-01", status="skipped"),
            ],
            primitives=["BGPIntent", "InterfaceIntent"],
            duration_s=12.5,
        )

    def test_succeeded_count(self):
        r = self._report()
        assert r.succeeded_count == 2

    def test_failed_count(self):
        r = self._report()
        assert r.failed_count == 1

    def test_skipped_count(self):
        r = self._report()
        assert r.skipped_count == 1

    def test_success_rate(self):
        r = self._report()
        assert r.success_rate == pytest.approx(66.67, abs=0.1)

    def test_success_rate_all_pass(self):
        r = ChangeReport(
            meta=ReportMeta(title="T", report_type="change"),
            changes=[DeviceChange("sw-01", "succeeded")],
        )
        assert r.success_rate == 100.0

    def test_success_rate_no_changes(self):
        r = ChangeReport(meta=ReportMeta(title="T", report_type="change"))
        assert r.success_rate == 100.0

    def test_to_dict_structure(self):
        r = self._report()
        d = r.to_dict()
        assert "summary" in d
        assert "changes" in d
        assert d["summary"]["succeeded"]  == 2
        assert d["summary"]["failed"]     == 1
        assert d["summary"]["skipped"]    == 1
        assert d["summary"]["duration_s"] == 12.5

    def test_to_text_contains_key_info(self):
        r    = self._report()
        text = r.to_text()
        assert "leaf-01"     in text
        assert "succeeded"   in text
        assert "leaf-03"     in text
        assert "timeout"     in text

    def test_to_json_valid(self):
        r    = self._report()
        data = json.loads(r.to_json())
        assert "changes" in data

    def test_render_html_contains_table(self):
        r    = self._report()
        html = r._render_html()
        assert "<table>"     in html
        assert "leaf-01"     in html
        assert "SUCCEEDED"   in html
        assert "FAILED"      in html

    def test_save_json(self, tmp_path):
        r    = self._report()
        path = str(tmp_path / "report.json")
        r.save_json(path)
        data = json.loads(open(path).read())
        assert "changes" in data

    def test_save_html(self, tmp_path):
        r    = self._report()
        path = str(tmp_path / "report.html")
        r.save_html(path)
        html = open(path).read()
        assert "<!DOCTYPE html>" in html
        assert "Plexar" in html

    def test_save_text(self, tmp_path):
        r    = self._report()
        path = str(tmp_path / "report.txt")
        r.save_text(path)
        text = open(path).read()
        assert "leaf-01" in text


class TestComplianceReport:
    def _report(self) -> ComplianceReport:
        return ComplianceReport(
            meta=ReportMeta(title="Compliance", report_type="compliance"),
            items=[
                ComplianceItem("bgp_neighbor_10.0.0.1", "leaf-01", True,  "established"),
                ComplianceItem("bgp_neighbor_10.0.0.2", "leaf-01", True,  "established"),
                ComplianceItem("bgp_neighbor_10.0.0.3", "leaf-02", False, "peer not found"),
                ComplianceItem("interface_Eth1",        "leaf-01", True,  "up/up"),
            ],
            devices_checked=2,
            primitives=["BGPIntent"],
        )

    def test_passed_count(self):
        r = self._report()
        assert r.passed_count == 3

    def test_failed_count(self):
        r = self._report()
        assert r.failed_count == 1

    def test_compliance_score(self):
        r = self._report()
        assert r.compliance_score == pytest.approx(75.0)

    def test_is_compliant_false_with_failures(self):
        r = self._report()
        assert not r.is_compliant

    def test_is_compliant_true_when_all_pass(self):
        r = ComplianceReport(
            meta=ReportMeta(title="T", report_type="compliance"),
            items=[ComplianceItem("check", "sw-01", True, "ok")],
        )
        assert r.is_compliant

    def test_to_text_shows_status(self):
        r    = self._report()
        text = r.to_text()
        assert "75.0%" in text
        assert "NON-COMPLIANT" in text

    def test_render_html(self):
        r    = self._report()
        html = r._render_html()
        assert "leaf-01" in html
        assert "table"   in html

    def test_to_dict_json_serializable(self):
        r = self._report()
        json.dumps(r.to_dict())


class TestInventoryReport:
    def _report(self) -> InventoryReport:
        return InventoryReport(
            meta=ReportMeta(title="Inventory", report_type="inventory"),
            devices=[
                {"hostname": "leaf-01", "platform": "arista_eos",  "role": "leaf",  "site": "dc1", "reachable": True},
                {"hostname": "leaf-02", "platform": "arista_eos",  "role": "leaf",  "site": "dc1", "reachable": True},
                {"hostname": "spine-01","platform": "cisco_nxos",  "role": "spine", "site": "dc1", "reachable": False},
                {"hostname": "border-01","platform": "juniper_junos","role":"border","site": "dc1", "reachable": None},
            ],
        )

    def test_total(self):
        assert self._report().total == 4

    def test_reachable_count(self):
        assert self._report().reachable == 2

    def test_to_text(self):
        text = self._report().to_text()
        assert "leaf-01"  in text
        assert "spine-01" in text
        assert "Total: 4" in text

    def test_to_dict(self):
        d = self._report().to_dict()
        assert d["summary"]["total"]     == 4
        assert d["summary"]["reachable"] == 2


class TestReportEngine:
    def test_from_intent_result(self):
        from plexar.intent.engine import IntentResult, IntentPlan
        from plexar.intent.primitives import BGPIntent

        result = MagicMock(spec=IntentResult)
        result.succeeded = [MagicMock(hostname="leaf-01")]
        result.failed    = [(MagicMock(hostname="leaf-02"), Exception("fail"))]
        result.skipped   = [MagicMock(hostname="leaf-03")]
        result.duration_seconds = 5.0

        plan = MagicMock(spec=IntentPlan)
        plan.primitives = [BGPIntent(asn=65001)]

        engine = ReportEngine()
        report = engine.from_intent_result(result, plan)

        assert isinstance(report, ChangeReport)
        assert report.succeeded_count == 1
        assert report.failed_count    == 1
        assert report.skipped_count   == 1
        assert "BGPIntent" in report.primitives

    def test_inventory_report(self):
        net = MagicMock()
        d1  = MagicMock()
        d1.hostname       = "leaf-01"
        d1.platform       = "arista_eos"
        d1.management_ip  = "10.0.0.1"
        d1.metadata       = {"role": "leaf", "site": "dc1"}
        d1.tags           = ["prod"]

        net.inventory.all.return_value = [d1]

        engine = ReportEngine()
        report = engine.inventory_report(net)

        assert isinstance(report, InventoryReport)
        assert report.total == 1
        assert report.devices[0]["hostname"] == "leaf-01"

    @pytest.mark.asyncio
    async def test_compliance_report(self):
        from plexar.intent.engine import Intent
        from plexar.intent.primitives import InterfaceIntent
        from plexar.config.validator import ValidationReport, ValidationResult

        device = MagicMock()
        device.hostname = "leaf-01"
        device.platform = "arista_eos"

        intent = Intent(devices=[device])
        intent.ensure(InterfaceIntent(name="Eth1", admin_state="up"))
        intent.verify = AsyncMock(return_value=ValidationReport(results=[
            ValidationResult(name="leaf-01: interface_Eth1", passed=True, reason="up/up"),
        ]))

        engine = ReportEngine()
        report = await engine.compliance_report(intent=intent)

        assert isinstance(report, ComplianceReport)
        assert report.passed_count == 1
        assert report.compliance_score == 100.0
