"""
Transaction Engine.

Provides transactional config push with guaranteed rollback.
Every config change through a Transaction is atomic — if
post-push verification fails, the previous state is restored.

Usage:
    async with device.transaction() as txn:
        await txn.push(config_block)
        report = await txn.verify([
            bgp_peers_up(min_peers=4),
            interface_up("Ethernet1"),
            route_exists("0.0.0.0/0"),
        ])
        if not report.passed:
            await txn.rollback()
            raise VerificationError(report.summary())
        # Implicit commit on clean exit

Design:
  1. On entry: capture a checkpoint (running config snapshot)
  2. push():   apply config to device
  3. verify(): run validators against running state
  4. On failure OR explicit rollback(): restore checkpoint
  5. On success: commit() — no-op for SSH (already live), explicit for NETCONF
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from plexar.config.diff import compute_diff, ConfigDiff
from plexar.config.validator import Validator, ValidationReport, run_validators
from plexar.core.exceptions import RollbackError, TransactionError, VerificationError

if TYPE_CHECKING:
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


class Transaction:
    """
    Atomic config transaction with rollback support.

    Never instantiate directly — use `async with device.transaction() as txn:`
    which is defined in device.py.
    """

    def __init__(self, device: "Device") -> None:
        self.device    = device
        self.committed = False
        self.rolled_back = False

        self._checkpoint:    str | None = None
        self._pushed_config: str        = ""
        self._diff:          ConfigDiff | None = None
        self._started_at:    datetime   = datetime.now(timezone.utc)
        self._push_count:    int        = 0

    # ── Public API ───────────────────────────────────────────────────

    async def push(self, config: str, *, diff: bool = True) -> "Transaction":
        """
        Push a config block to the device.

        Captures a checkpoint before the first push (for rollback).
        Subsequent push() calls within the same transaction are cumulative.

        Args:
            config: Config block in device-native format
            diff:   If True, compute and store a diff (for display)

        Returns:
            self (for chaining)
        """
        if self.committed:
            raise TransactionError("Cannot push to a committed transaction.")

        # Capture checkpoint before first change
        if self._checkpoint is None:
            await self._capture_checkpoint()

        # Compute diff for display
        if diff:
            current = self._checkpoint or ""
            self._diff = compute_diff(current, config)
            if self._diff.is_empty:
                logger.info(f"{self.device.hostname}: No changes in this push.")
                return self

        # Apply config
        logger.info(f"{self.device.hostname}: Pushing config ({self._push_count + 1})...")
        await self.device.push_config(config)
        self._pushed_config += "\n" + config
        self._push_count += 1

        return self

    async def verify(
        self,
        validators: list[Validator],
        timeout_per_check: int = 30,
    ) -> ValidationReport:
        """
        Run post-push validation checks against the device.

        Args:
            validators:         List of validator callables
            timeout_per_check:  Timeout in seconds per validator

        Returns:
            ValidationReport — check report.passed for overall result
        """
        logger.info(f"{self.device.hostname}: Running {len(validators)} post-push checks...")
        report = await run_validators(
            device=self.device,
            validators=validators,
            timeout=timeout_per_check,
        )

        if report.passed:
            logger.info(f"{self.device.hostname}: All checks passed.")
        else:
            logger.warning(
                f"{self.device.hostname}: {len(report.failed)} check(s) failed:\n"
                + "\n".join(f"  ✗ {r}" for r in report.failed)
            )

        return report

    async def rollback(self) -> None:
        """
        Roll back to the pre-transaction checkpoint.

        Raises RollbackError if rollback itself fails — this is a
        critical state and requires manual intervention.
        """
        if self.rolled_back:
            return
        if self._checkpoint is None:
            logger.warning(f"{self.device.hostname}: No checkpoint to roll back to.")
            return

        logger.warning(f"{self.device.hostname}: Rolling back transaction...")

        try:
            await self.device._driver.rollback_to_checkpoint(self._checkpoint)
            self.rolled_back = True
            logger.info(f"{self.device.hostname}: Rollback complete.")
        except NotImplementedError:
            # Driver doesn't support native rollback — re-apply checkpoint config
            logger.warning(
                f"{self.device.hostname}: Driver has no native rollback. "
                "Re-applying checkpoint config..."
            )
            try:
                await self.device.push_config(self._checkpoint)
                self.rolled_back = True
                logger.info(f"{self.device.hostname}: Config restore complete.")
            except Exception as e:
                raise RollbackError(
                    f"CRITICAL: Rollback failed on {self.device.hostname}: {e}\n"
                    "Device may be in inconsistent state. Manual intervention required."
                ) from e
        except Exception as e:
            raise RollbackError(
                f"CRITICAL: Rollback failed on {self.device.hostname}: {e}"
            ) from e

    async def commit(self) -> None:
        """
        Commit the transaction.

        For SSH drivers: config is already live — this is a no-op.
        For NETCONF drivers: sends the <commit> RPC.
        After commit, rollback is no longer possible.
        """
        if self.committed:
            return
        # For NETCONF drivers, send explicit commit
        if hasattr(self.device._driver, "netconf_commit"):
            await self.device._driver.netconf_commit()
        self.committed = True
        logger.info(f"{self.device.hostname}: Transaction committed.")

    async def verify_and_commit(
        self,
        validators: list[Validator],
        auto_rollback: bool = True,
    ) -> ValidationReport:
        """
        Convenience: verify then commit if passed, rollback if failed.

        Args:
            validators:     Validation checks to run
            auto_rollback:  If True (default), rollback automatically on failure

        Returns:
            ValidationReport

        Raises:
            VerificationError: If validation fails and auto_rollback=False
        """
        report = await self.verify(validators)

        if report.passed:
            await self.commit()
        else:
            if auto_rollback:
                await self.rollback()
            raise VerificationError(
                f"Transaction verification failed on {self.device.hostname}:\n"
                + report.summary()
            )

        return report

    # ── Display ──────────────────────────────────────────────────────

    def diff(self, color: bool = True) -> str:
        """
        Return a rendered diff of pending changes.
        Call after push() and before commit().
        """
        if self._diff is None:
            return "No diff available — call push() first."
        return self._diff.render(color=color)

    @property
    def has_changes(self) -> bool:
        return self._diff is not None and not self._diff.is_empty

    @property
    def duration_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self._started_at).total_seconds()

    # ── Internal ─────────────────────────────────────────────────────

    async def _capture_checkpoint(self) -> None:
        """Capture a point-in-time snapshot of the running config."""
        logger.debug(f"{self.device.hostname}: Capturing checkpoint...")
        self._checkpoint = await self.device._driver.get_checkpoint()

    async def cleanup(self) -> None:
        """Called by the context manager on exit."""
        if not self.committed and not self.rolled_back and self._push_count > 0:
            logger.warning(
                f"{self.device.hostname}: Transaction exited without commit or rollback. "
                "Changes remain live on device."
            )

    def __repr__(self) -> str:
        status = "committed" if self.committed else ("rolled_back" if self.rolled_back else "pending")
        return (
            f"Transaction(device={self.device.hostname!r}, "
            f"pushes={self._push_count}, status={status})"
        )
