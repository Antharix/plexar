"""Tests for the Config Diff Engine."""

import pytest
from plexar.config.diff import compute_diff, merge_configs, DiffType


BEFORE = """\
interface Ethernet1
  description uplink-to-spine-01
  mtu 9000
  no shutdown

router bgp 65001
  neighbor 10.0.0.1 remote-as 65000
  neighbor 10.0.0.1 description spine-01
"""

AFTER = """\
interface Ethernet1
  description uplink-to-spine-01
  mtu 9214
  no shutdown

router bgp 65001
  neighbor 10.0.0.1 remote-as 65000
  neighbor 10.0.0.1 description spine-01
  neighbor 10.0.0.2 remote-as 65000
"""


class TestComputeDiff:
    def test_no_changes(self):
        diff = compute_diff(BEFORE, BEFORE)
        assert diff.is_empty

    def test_detects_changed_line(self):
        diff = compute_diff(BEFORE, AFTER)
        assert not diff.is_empty

    def test_added_lines(self):
        diff = compute_diff(BEFORE, AFTER)
        added_content = [l.content for l in diff.added_lines]
        assert any("9214" in c for c in added_content)
        assert any("10.0.0.2" in c for c in added_content)

    def test_removed_lines(self):
        diff = compute_diff(BEFORE, AFTER)
        removed_content = [l.content for l in diff.removed_lines]
        assert any("9000" in c for c in removed_content)

    def test_change_count(self):
        diff = compute_diff(BEFORE, AFTER)
        # mtu line changed (+1 add, +1 remove) + new neighbor (+1 add)
        assert diff.change_count >= 3

    def test_render_no_color(self):
        diff = compute_diff(BEFORE, AFTER)
        rendered = diff.render(color=False)
        assert "+" in rendered
        assert "-" in rendered
        assert "9214" in rendered

    def test_render_empty_diff(self):
        diff = compute_diff(BEFORE, BEFORE)
        rendered = diff.render()
        assert "No changes" in rendered

    def test_summary_format(self):
        diff = compute_diff(BEFORE, AFTER)
        summary = diff.summary()
        assert "Diff:" in summary
        assert "+" in summary
        assert "-" in summary

    def test_repr(self):
        diff = compute_diff(BEFORE, AFTER)
        assert "ConfigDiff" in repr(diff)


class TestMergeConfigs:
    def test_merge_two_configs(self):
        a = "interface Gi0/0\n  no shutdown"
        b = "router bgp 65001\n  neighbor 10.0.0.1"
        merged = merge_configs(a, b)
        assert "interface Gi0/0" in merged
        assert "router bgp 65001" in merged

    def test_deduplicates_lines(self):
        a = "no shutdown\nip routing"
        b = "no shutdown\nhostname router1"
        merged = merge_configs(a, b)
        assert merged.count("no shutdown") == 1

    def test_empty_configs(self):
        merged = merge_configs("", "")
        assert merged == ""
