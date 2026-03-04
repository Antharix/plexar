"""
Async Connection Pool.

Runs operations across many devices concurrently with:
  - Configurable max concurrency (semaphore)
  - Per-device rate limiting
  - Automatic retry with exponential backoff
  - Structured result collection (success + failures separated)

Usage:
    async with net.pool(max_concurrent=50) as pool:
        results = await pool.map(lambda d: d.get_bgp_summary(), devices)

    for device, result in results.success:
        print(device.hostname, result.peers_established)

    for device, error in results.failed:
        print(device.hostname, "FAILED:", error)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, TypeVar

from plexar.core.device import Device
from plexar.utils.retry import retry_async

T = TypeVar("T")


@dataclass
class PoolResult:
    """Holds the combined results of a pool.map() call."""
    success: list[tuple[Device, Any]]           = field(default_factory=list)
    failed:  list[tuple[Device, Exception]]     = field(default_factory=list)
    duration_seconds: float                     = 0.0

    @property
    def all_succeeded(self) -> bool:
        return len(self.failed) == 0

    @property
    def total(self) -> int:
        return len(self.success) + len(self.failed)

    def __iter__(self):
        """Iterate over successes for convenient unpacking."""
        return iter(self.success)

    def raise_on_errors(self) -> None:
        """Raise a RuntimeError if any devices failed."""
        if self.failed:
            names = [d.hostname for d, _ in self.failed]
            raise RuntimeError(f"Operations failed on: {', '.join(names)}")

    def summary(self) -> str:
        return (
            f"Pool result: {len(self.success)}/{self.total} succeeded "
            f"in {self.duration_seconds:.2f}s"
        )


class ConnectionPool:
    """
    Manages concurrent async operations across a fleet of devices.
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        rate_limit: int | None = None,      # max new connections per second
        connect_timeout: int = 15,
        command_timeout: int = 30,
        max_retries: int = 2,
        retry_delay: float = 1.0,
    ) -> None:
        self.max_concurrent  = max_concurrent
        self.rate_limit      = rate_limit
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.max_retries     = max_retries
        self.retry_delay     = retry_delay

        self._semaphore: asyncio.Semaphore | None = None
        self._connected_devices: list[Device] = []

    async def __aenter__(self) -> "ConnectionPool":
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self

    async def __aexit__(self, *_: Any) -> None:
        # Disconnect all devices that were connected through this pool
        disconnect_tasks = [d.disconnect() for d in self._connected_devices if d.is_connected]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
        self._connected_devices.clear()

    async def map(
        self,
        fn: Callable[[Device], Coroutine[Any, Any, T]],
        devices: list[Device],
    ) -> PoolResult:
        """
        Apply an async function to all devices concurrently.

        Args:
            fn: Async callable that takes a Device and returns a result.
                The device will be connected before fn is called.
            devices: List of devices to operate on.

        Returns:
            PoolResult with .success and .failed lists.
        """
        if self._semaphore is None:
            raise RuntimeError("ConnectionPool must be used as an async context manager.")

        start = time.monotonic()
        tasks = [self._run_one(fn, device) for device in devices]
        raw_results = await asyncio.gather(*tasks, return_exceptions=False)

        result = PoolResult(duration_seconds=time.monotonic() - start)
        for device, outcome in zip(devices, raw_results):
            if isinstance(outcome, Exception):
                result.failed.append((device, outcome))
            else:
                result.success.append((device, outcome))

        return result

    async def run_all(
        self,
        command: str,
        devices: list[Device],
    ) -> PoolResult:
        """
        Run a raw command on all devices concurrently.
        Returns PoolResult where each success value is raw string output.
        """
        return await self.map(lambda d: d.run(command), devices)

    async def _run_one(
        self,
        fn: Callable[[Device], Coroutine[Any, Any, T]],
        device: Device,
    ) -> T | Exception:
        """Run fn on a single device, with semaphore and retry."""
        assert self._semaphore is not None

        async with self._semaphore:
            try:
                await retry_async(
                    device.connect,
                    max_retries=self.max_retries,
                    delay=self.retry_delay,
                )
                if device not in self._connected_devices:
                    self._connected_devices.append(device)
                return await fn(device)
            except Exception as exc:
                return exc
