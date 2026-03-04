"""
Config Diff Engine.

Produces human-readable and machine-parseable diffs between
two configuration states. Supports:
  - Line-level diff (universal, works with any CLI config)
  - Semantic diff (understands config structure — future)

Used by the Transaction engine to show operators exactly
what will change before applying.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterator


class DiffType(StrEnum):
    ADD    = "add"
    REMOVE = "remove"
    EQUAL  = "equal"


@dataclass
class DiffLine:
    """A single line in a config diff."""
    line_type: DiffType
    content:   str
    line_num_before: int | None = None
    line_num_after:  int | None = None

    @property
    def prefix(self) -> str:
        return {
            DiffType.ADD:    "+",
            DiffType.REMOVE: "-",
            DiffType.EQUAL:  " ",
        }[self.line_type]

    def __str__(self) -> str:
        return f"{self.prefix} {self.content}"


@dataclass
class ConfigDiff:
    """
    The result of comparing two configurations.

    Provides formatted output and machine-readable change lists.
    """
    before:  str
    after:   str
    lines:   list[DiffLine] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True if there are no changes."""
        return not any(l.line_type != DiffType.EQUAL for l in self.lines)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == DiffType.ADD]

    @property
    def removed_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == DiffType.REMOVE]

    @property
    def change_count(self) -> int:
        return len(self.added_lines) + len(self.removed_lines)

    def summary(self) -> str:
        return (
            f"Diff: +{len(self.added_lines)} lines / -{len(self.removed_lines)} lines"
        )

    def render(self, context: int = 3, color: bool = True) -> str:
        """
        Render a human-readable unified diff.

        Args:
            context: Lines of context around changes
            color:   Use ANSI color codes (green=add, red=remove)
        """
        GREEN = "\033[32m" if color else ""
        RED   = "\033[31m" if color else ""
        RESET = "\033[0m"  if color else ""
        DIM   = "\033[2m"  if color else ""

        if self.is_empty:
            return f"{DIM}No changes.{RESET}"

        output_lines: list[str] = []

        # Group lines into hunks with context
        change_indices = [
            i for i, l in enumerate(self.lines) if l.line_type != DiffType.EQUAL
        ]

        shown: set[int] = set()
        hunks: list[tuple[int, int]] = []

        for idx in change_indices:
            start = max(0, idx - context)
            end   = min(len(self.lines), idx + context + 1)
            if hunks and start <= hunks[-1][1]:
                hunks[-1] = (hunks[-1][0], end)
            else:
                hunks.append((start, end))

        for hunk_start, hunk_end in hunks:
            # Hunk header
            added_in_hunk   = sum(1 for l in self.lines[hunk_start:hunk_end] if l.line_type == DiffType.ADD)
            removed_in_hunk = sum(1 for l in self.lines[hunk_start:hunk_end] if l.line_type == DiffType.REMOVE)
            output_lines.append(
                f"{DIM}@@ +{added_in_hunk} -{removed_in_hunk} @@{RESET}"
            )

            for line in self.lines[hunk_start:hunk_end]:
                if line.line_type == DiffType.ADD:
                    output_lines.append(f"{GREEN}+ {line.content}{RESET}")
                elif line.line_type == DiffType.REMOVE:
                    output_lines.append(f"{RED}- {line.content}{RESET}")
                else:
                    output_lines.append(f"  {line.content}")

        return "\n".join(output_lines)

    def __str__(self) -> str:
        return self.render(color=False)

    def __repr__(self) -> str:
        return f"ConfigDiff({self.summary()})"


def compute_diff(before: str, after: str) -> ConfigDiff:
    """
    Compute a line-level diff between two config strings.

    Args:
        before: Current/existing configuration
        after:  Desired/new configuration

    Returns:
        ConfigDiff object with full change information
    """
    before_lines = before.splitlines()
    after_lines  = after.splitlines()

    diff_lines: list[DiffLine] = []
    matcher = difflib.SequenceMatcher(
        isjunk=lambda x: x.strip() == "",
        a=before_lines,
        b=after_lines,
        autojunk=False,
    )

    line_num_before = 0
    line_num_after  = 0

    for opcode, a0, a1, b0, b1 in matcher.get_opcodes():
        if opcode == "equal":
            for i, line in enumerate(before_lines[a0:a1]):
                diff_lines.append(DiffLine(
                    line_type=DiffType.EQUAL,
                    content=line,
                    line_num_before=a0 + i + 1,
                    line_num_after=b0 + i + 1,
                ))
        elif opcode in ("replace", "delete"):
            for i, line in enumerate(before_lines[a0:a1]):
                diff_lines.append(DiffLine(
                    line_type=DiffType.REMOVE,
                    content=line,
                    line_num_before=a0 + i + 1,
                ))
        if opcode in ("replace", "insert"):
            for i, line in enumerate(after_lines[b0:b1]):
                diff_lines.append(DiffLine(
                    line_type=DiffType.ADD,
                    content=line,
                    line_num_after=b0 + i + 1,
                ))

    return ConfigDiff(before=before, after=after, lines=diff_lines)


def merge_configs(*configs: str, separator: str = "\n") -> str:
    """
    Merge multiple config blocks into one, removing duplicate lines.
    Order is preserved; duplicates are removed keeping first occurrence.
    """
    seen: set[str] = set()
    merged: list[str] = []
    for config in configs:
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                merged.append(line)
    return separator.join(merged)
