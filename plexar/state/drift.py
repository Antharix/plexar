"""
Drift Detection Engine.

Continuously compares running network state against desired state.
Fires registered callbacks when drift is detected.
Optionally auto-remediates low-risk drift.

Usage:
    monitor = DriftMonitor(inventory=net.inventory, interval_seconds=300)

    @monitor.on_drift
    async def alert(event: DriftEvent):
        await slack.send(f"Drift on {event.device.hostname}: {event.delta.summary()}")
        if event.risk_score < 20:
            await event.remediate()

    await monitor.start()   # runs forever
    await monitor.stop()    # clean shutdown
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from plexar.state.snapshot import StateSnapshot, SnapshotDelta

if TYPE_CHECKING:
    from plexar.core.device import Device
    from plexar.core.inventory import Inventory

logger = logging.getLogger(__name__)

DriftCallback = Callable[["DriftEvent"], Coroutine[Any, Any, None]]


@dataclass
class DriftEvent:
    """Emitted when drift is detected on a device."""
    device:      "Device"
    delta:       SnapshotDelta
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def risk_score(self) -> int:
        """
        Heuristic risk score 0-100.
        Higher = more impactful drift.
        Used to decide whether to auto-remediate.
        """
        score = 0
        changes = self.delta.changes

        # BGP state changes are high risk
        if "bgp" in changes:
            score += len(changes["bgp"]) * 20

        # Interface state changes
        if "interfaces" in changes:
            score += len(changes["interfaces"]) * 15

        # Route changes
        if "routing" in changes:
            score += min(len(changes["routing"]) * 5, 30)

        return min(score, 100)

    async def remediate(self) -> None:
        """
        Attempt to bring running state back to desired state.
        Currently a no-op placeholder — full implementation in Phase 3 (Intent Engine).
        """
        logger.info(f"Remediation requested for {self.device.hostname} — Phase 3 feature.")
        raise NotImplementedError(
            "Auto-remediation requires the Intent Engine (Phase 3). "
            "Define an Intent and call intent.apply() to remediate manually."
        )

    def summary(self) -> str:
        return self.delta.summary()


class DriftMonitor:
    """
    Polls devices on a schedule and fires callbacks on drift.

    Architecture:
      - One polling task per device (concurrent, rate-limited)
      - Callbacks fire in parallel for each drift event
      - Snapshots are compared per-device (no cross-device logic here)
    """

    def __init__(
        self,
        inventory: "Inventory",
        interval_seconds: int = 300,
        max_concurrent: int = 20,
    ) -> None:
        self.inventory         = inventory
        self.interval_seconds  = interval_seconds
        self.max_concurrent    = max_concurrent

        self._callbacks:  list[DriftCallback]         = []
        self._snapshots:  dict[str, StateSnapshot]    = {}
        self._running:    bool                        = False
        self._task:       asyncio.Task | None         = None
        self._semaphore:  asyncio.Semaphore | None    = None

    # ── Callback registration ─────────────────────────────────────────

    def on_drift(self, fn: DriftCallback) -> DriftCallback:
        """
        Decorator to register a drift callback.

        Usage:
            @monitor.on_drift
            async def handle(event: DriftEvent):
                await alert(event.summary())
        """
        self._callbacks.append(fn)
        return fn

    def add_callback(self, fn: DriftCallback) -> None:
        """Register a drift callback programmatically."""
        self._callbacks.append(fn)

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the drift monitor loop (runs until stop() is called)."""
        self._running   = True
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        logger.info(
            f"DriftMonitor started: {len(self.inventory)} devices, "
            f"interval={self.interval_seconds}s"
        )
        self._task = asyncio.create_task(self._poll_loop())
        await self._task

    async def stop(self) -> None:
        """Gracefully stop the monitor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("DriftMonitor stopped.")

    async def check_once(self) -> list[DriftEvent]:
        """
        Run one drift check across all devices immediately.
        Useful for on-demand checks or testing.

        Returns:
            List of DriftEvents for devices with detected drift.
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        devices = self.inventory.all()
        tasks   = [self._check_device(d) for d in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, DriftEvent)]

    # ── Internal ─────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                events = await self.check_once()
                for event in events:
                    await self._fire_callbacks(event)
            except Exception as e:
                logger.error(f"DriftMonitor poll error: {e}")

            await asyncio.sleep(self.interval_seconds)

    async def _check_device(self, device: "Device") -> DriftEvent | None:
        """Check a single device for drift."""
        assert self._semaphore is not None
        async with self._semaphore:
            try:
                async with device:
                    current = await StateSnapshot.capture(device)

                prev = self._snapshots.get(device.hostname)
                self._snapshots[device.hostname] = current

                if prev is None:
                    # First check — baseline established, no drift
                    logger.debug(f"{device.hostname}: baseline snapshot captured")
                    return None

                delta = prev.compare(current)
                if delta.has_changes:
                    logger.info(f"Drift detected on {device.hostname}: {delta.summary()}")
                    return DriftEvent(device=device, delta=delta)

                return None

            except Exception as e:
                logger.warning(f"Could not poll {device.hostname}: {e}")
                return None

    async def _fire_callbacks(self, event: DriftEvent) -> None:
        """Fire all registered callbacks for a drift event."""
        for callback in self._callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(
                    f"Drift callback '{getattr(callback, '__name__', callback)}' "
                    f"raised an exception: {e}"
                )

    # ── Status ───────────────────────────────────────────────────────

    @property
    def baseline_devices(self) -> list[str]:
        """Hostnames for which a baseline snapshot exists."""
        return list(self._snapshots.keys())

    def get_snapshot(self, hostname: str) -> StateSnapshot | None:
        """Return the most recent snapshot for a device."""
        return self._snapshots.get(hostname)

    def __repr__(self) -> str:
        return (
            f"DriftMonitor(devices={len(self.inventory)}, "
            f"interval={self.interval_seconds}s, "
            f"running={self._running})"
        )
