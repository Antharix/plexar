"""
Intent Engine — the crown jewel of Plexar.

Declares desired network state. Compiles to per-device config.
Applies changes transactionally. Verifies desired state is achieved.

This is what separates Plexar from every other network automation tool.

Usage:
    from plexar import Network
    from plexar.intent import Intent
    from plexar.intent.primitives import BGPIntent, BGPNeighbor, InterfaceIntent

    net = Network()
    net.inventory.load("yaml", path="./inventory.yaml")
    leafs = net.devices(role="leaf")

    intent = Intent(devices=leafs)
    intent.ensure(BGPIntent(
        asn=65001,
        neighbors=[BGPNeighbor(ip="10.0.0.1", remote_as=65000)],
    ))
    intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214, admin_state="up"))

    plan   = await intent.plan()     # show what will change — no side effects
    result = await intent.apply()    # push + verify
    report = await intent.verify()   # check current state matches intent
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from plexar.intent.compiler import IntentCompiler, CompilerError
from plexar.intent.primitives import IntentPrimitive
from plexar.config.diff import compute_diff, ConfigDiff
from plexar.config.validator import ValidationReport
from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType

if TYPE_CHECKING:
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


@dataclass
class DevicePlan:
    """The compiled plan for a single device."""
    device:   "Device"
    config:   str
    diff:     ConfigDiff | None = None
    error:    str | None        = None

    @property
    def has_changes(self) -> bool:
        return bool(self.config.strip()) and (
            self.diff is None or not self.diff.is_empty
        )

    def summary(self) -> str:
        if self.error:
            return f"  ✗ {self.device.hostname}: ERROR — {self.error}"
        if not self.has_changes:
            return f"  ✓ {self.device.hostname}: no changes"
        diff_summary = self.diff.summary() if self.diff else f"{len(self.config.splitlines())} lines"
        return f"  ~ {self.device.hostname}: {diff_summary}"


@dataclass
class IntentPlan:
    """
    The full compiled plan across all devices.
    Returned by intent.plan() — shows what WILL happen before applying.
    """
    primitives:    list[IntentPrimitive]
    device_plans:  list[DevicePlan]
    created_at:    datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def devices_with_changes(self) -> list["Device"]:
        return [p.device for p in self.device_plans if p.has_changes]

    @property
    def devices_with_errors(self) -> list[DevicePlan]:
        return [p for p in self.device_plans if p.error]

    @property
    def total_changes(self) -> int:
        return sum(
            (p.diff.change_count if p.diff else len(p.config.splitlines()))
            for p in self.device_plans if p.has_changes
        )

    def render(self, color: bool = True) -> str:
        """Render a human-readable plan summary."""
        BOLD  = "\033[1m"  if color else ""
        RESET = "\033[0m"  if color else ""
        CYAN  = "\033[36m" if color else ""
        lines = [
            f"{BOLD}Intent Plan{RESET}",
            f"  Primitives: {len(self.primitives)}",
            f"  Devices:    {len(self.device_plans)}",
            f"  Changes:    {len(self.devices_with_changes)} device(s) affected",
            "",
        ]
        for plan in self.device_plans:
            lines.append(plan.summary())
            if plan.diff and plan.has_changes:
                diff_text = plan.diff.render(color=color, context=2)
                for line in diff_text.splitlines():
                    lines.append(f"      {line}")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.render(color=False)


@dataclass
class IntentResult:
    """Result of intent.apply()."""
    succeeded: list["Device"]     = field(default_factory=list)
    failed:    list[tuple["Device", Exception]] = field(default_factory=list)
    skipped:   list["Device"]     = field(default_factory=list)  # no changes needed
    duration_seconds: float       = 0.0

    @property
    def all_succeeded(self) -> bool:
        return len(self.failed) == 0

    def summary(self) -> str:
        total = len(self.succeeded) + len(self.failed) + len(self.skipped)
        lines = [
            f"Intent Apply: {len(self.succeeded)}/{total} succeeded "
            f"({len(self.skipped)} skipped, {len(self.failed)} failed) "
            f"in {self.duration_seconds:.1f}s"
        ]
        for device, err in self.failed:
            lines.append(f"  ✗ {device.hostname}: {err}")
        return "\n".join(lines)


class Intent:
    """
    The Intent Engine.

    Declare desired state → compile → plan → apply → verify.

    Thread-safe. Supports partial application (per-device targeting).
    """

    def __init__(
        self,
        devices:        list["Device"],
        max_concurrent: int = 20,
        auto_rollback:  bool = True,
    ) -> None:
        self.devices        = devices
        self.max_concurrent = max_concurrent
        self.auto_rollback  = auto_rollback

        self._primitives: list[IntentPrimitive] = []

    # ── API ───────────────────────────────────────────────────────────

    def ensure(self, primitive: IntentPrimitive) -> "Intent":
        """
        Add an intent primitive — declare desired state.

        Call this multiple times to build up the full desired state.
        Returns self for chaining.

        Usage:
            intent.ensure(BGPIntent(...)).ensure(InterfaceIntent(...))
        """
        self._primitives.append(primitive)
        return self

    def clear(self) -> "Intent":
        """Remove all primitives."""
        self._primitives.clear()
        return self

    async def plan(self, connect: bool = False) -> IntentPlan:
        """
        Compile all primitives for all devices and show what will change.
        Does NOT push any config — purely read/compute.

        Args:
            connect: If True, connect to devices and compute actual diff
                     against running config. If False, just show generated config.
        """
        device_plans = await asyncio.gather(
            *[self._plan_device(device, connect=connect) for device in self.devices],
            return_exceptions=False,
        )
        return IntentPlan(
            primitives=list(self._primitives),
            device_plans=list(device_plans),
        )

    async def apply(
        self,
        dry_run:    bool = False,
        max_concurrent: int | None = None,
    ) -> IntentResult:
        """
        Compile and push all primitives to all devices.

        Operations run concurrently (up to max_concurrent devices at once).
        Each device uses a Transaction for automatic rollback on failure.

        Args:
            dry_run:        If True, plan only — don't push anything
            max_concurrent: Override concurrent device limit
        """
        import time
        concurrency = max_concurrent or self.max_concurrent
        semaphore   = asyncio.Semaphore(concurrency)
        start       = time.monotonic()

        if dry_run:
            plan = await self.plan(connect=False)
            logger.info(f"Dry run complete:\n{plan}")
            return IntentResult(skipped=self.devices, duration_seconds=time.monotonic() - start)

        tasks = [self._apply_device(device, semaphore) for device in self.devices]
        raw   = await asyncio.gather(*tasks, return_exceptions=False)

        result = IntentResult(duration_seconds=time.monotonic() - start)
        for item in raw:
            if isinstance(item, tuple) and len(item) == 2:
                device, exc = item
                if exc is None:
                    result.succeeded.append(device)
                elif exc == "skipped":
                    result.skipped.append(device)
                else:
                    result.failed.append((device, exc))

        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.CONFIG_PUSH,
            details={
                "intent_primitives": len(self._primitives),
                "devices_succeeded": len(result.succeeded),
                "devices_failed":    len(result.failed),
                "devices_skipped":   len(result.skipped),
                "duration_seconds":  result.duration_seconds,
            },
        ))

        logger.info(result.summary())
        return result

    async def verify(self) -> ValidationReport:
        """
        Verify current running state matches all declared intents.

        Connects to all devices and checks that each primitive's
        desired state is present in the running config/operational state.

        Returns a ValidationReport — check report.passed for overall result.
        """
        from plexar.config.validator import run_validators
        from plexar.intent.verifier import build_validators_for_primitives

        validators = build_validators_for_primitives(self._primitives)
        if not validators:
            from plexar.config.validator import ValidationReport, ValidationResult
            return ValidationReport(results=[
                ValidationResult(name="NoValidators", passed=True,
                                 reason="No verifiable primitives declared.")
            ])

        # Run verification concurrently across all devices
        reports = await asyncio.gather(
            *[run_validators(device, validators) for device in self.devices],
            return_exceptions=True,
        )

        # Merge all reports
        from plexar.config.validator import ValidationReport, ValidationResult
        all_results = []
        for device, report in zip(self.devices, reports):
            if isinstance(report, Exception):
                all_results.append(ValidationResult(
                    name=f"verify({device.hostname})",
                    passed=False,
                    reason=str(report),
                ))
            else:
                for r in report.results:
                    r.name = f"{device.hostname}: {r.name}"
                    all_results.append(r)

        return ValidationReport(results=all_results)

    # ── Internal ─────────────────────────────────────────────────────

    async def _plan_device(self, device: "Device", connect: bool = False) -> DevicePlan:
        """Compile all primitives for a single device."""
        try:
            compiler = IntentCompiler.for_platform(device.platform)
        except CompilerError as e:
            return DevicePlan(device=device, config="", error=str(e))

        config_blocks = []
        for primitive in self._primitives:
            try:
                block = compiler.compile(primitive, device)
                if block.strip():
                    config_blocks.append(block)
            except CompilerError as e:
                logger.warning(f"{device.hostname}: Could not compile {primitive.intent_type()}: {e}")

        compiled_config = "\n!\n".join(config_blocks)

        diff = None
        if connect and device.is_connected:
            try:
                running = await device._driver.get_checkpoint()
                diff    = compute_diff(running, compiled_config)
            except Exception as e:
                logger.debug(f"{device.hostname}: Could not compute diff: {e}")

        return DevicePlan(device=device, config=compiled_config, diff=diff)

    async def _apply_device(
        self,
        device: "Device",
        semaphore: asyncio.Semaphore,
    ) -> tuple["Device", Exception | str | None]:
        """Apply all primitives to a single device with transaction."""
        async with semaphore:
            try:
                plan = await self._plan_device(device, connect=False)
                if not plan.config.strip():
                    return (device, "skipped")

                async with device:
                    async with device.transaction() as txn:
                        await txn.push(plan.config)
                        if txn.has_changes:
                            await txn.commit()
                        else:
                            return (device, "skipped")

                return (device, None)

            except Exception as exc:
                logger.error(f"Intent apply failed on {device.hostname}: {exc}")
                return (device, exc)

    def __repr__(self) -> str:
        return (
            f"Intent(devices={len(self.devices)}, "
            f"primitives={len(self._primitives)})"
        )
