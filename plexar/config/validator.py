"""
Config Validation Engine.

Provides pre-push and post-push validation hooks.
Validators are callables that receive the device and return a
ValidationResult — pass/fail with a human-readable reason.

Built-in validators:
  - BGPPeersUp(min_peers=N)         — assert N BGP peers established
  - InterfaceUp(name)               — assert interface is operationally up
  - RouteExists(prefix)             — assert prefix exists in RIB
  - PingReachable(target)           — assert ICMP reachability
  - NoConfigDiff()                  — assert running matches startup (no unsaved diff)

Custom validators:
  Any async callable: (device) -> ValidationResult
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Coroutine, Any

if TYPE_CHECKING:
    from plexar.core.device import Device


@dataclass
class ValidationResult:
    """Result of a single validation check."""
    name:    str
    passed:  bool
    reason:  str  = ""
    details: Any  = None

    def __bool__(self) -> bool:
        return self.passed

    def __str__(self) -> str:
        icon = "✓" if self.passed else "✗"
        msg  = f"{icon} {self.name}"
        if self.reason:
            msg += f": {self.reason}"
        return msg


@dataclass
class ValidationReport:
    """Aggregated results from multiple validators."""
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failed(self) -> list[ValidationResult]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> str:
        total  = len(self.results)
        n_pass = sum(1 for r in self.results if r.passed)
        lines  = [f"Validation: {n_pass}/{total} checks passed"]
        for result in self.results:
            lines.append(f"  {result}")
        return "\n".join(lines)

    def __bool__(self) -> bool:
        return self.passed


# Type alias for a validator function
Validator = Callable[["Device"], Coroutine[Any, Any, ValidationResult]]


async def run_validators(
    device: "Device",
    validators: list[Validator],
    timeout: int = 30,
) -> ValidationReport:
    """
    Run all validators against a device concurrently.

    Args:
        device:     Device to validate against
        validators: List of async validator callables
        timeout:    Timeout per validator in seconds

    Returns:
        ValidationReport with all results
    """
    async def _run_one(validator: Validator) -> ValidationResult:
        try:
            return await asyncio.wait_for(validator(device), timeout=timeout)
        except asyncio.TimeoutError:
            name = getattr(validator, "__name__", str(validator))
            return ValidationResult(name=name, passed=False, reason=f"Timed out after {timeout}s")
        except Exception as e:
            name = getattr(validator, "__name__", str(validator))
            return ValidationResult(name=name, passed=False, reason=f"Exception: {e}")

    results = await asyncio.gather(*[_run_one(v) for v in validators])
    return ValidationReport(results=list(results))


# ── Built-in Validators ──────────────────────────────────────────────

def bgp_peers_up(min_peers: int = 1, vrf: str = "default") -> Validator:
    """Assert that at least min_peers BGP peers are established."""
    async def _validate(device: "Device") -> ValidationResult:
        bgp = await device.get_bgp_summary()
        established = bgp.peers_established
        passed = established >= min_peers
        return ValidationResult(
            name=f"BGPPeersUp(min={min_peers})",
            passed=passed,
            reason=(
                f"{established} of {len(bgp.peers)} peers established"
                + ("" if passed else f" (need {min_peers})")
            ),
            details=bgp,
        )
    _validate.__name__ = f"bgp_peers_up(min={min_peers})"
    return _validate


def interface_up(interface_name: str) -> Validator:
    """Assert that a specific interface is operationally up."""
    async def _validate(device: "Device") -> ValidationResult:
        interfaces = await device.get_interfaces()
        match = next((i for i in interfaces if i.name == interface_name), None)
        if match is None:
            return ValidationResult(
                name=f"InterfaceUp({interface_name})",
                passed=False,
                reason=f"Interface '{interface_name}' not found on device",
            )
        return ValidationResult(
            name=f"InterfaceUp({interface_name})",
            passed=match.is_up,
            reason=f"{interface_name} is {match.oper_state}",
            details=match,
        )
    _validate.__name__ = f"interface_up({interface_name})"
    return _validate


def route_exists(prefix: str) -> Validator:
    """Assert that a route for prefix exists in the routing table."""
    async def _validate(device: "Device") -> ValidationResult:
        rt = await device.get_routing_table()
        found = rt.has_route(prefix)
        return ValidationResult(
            name=f"RouteExists({prefix})",
            passed=found,
            reason=f"{'Found' if found else 'Missing'} route for {prefix}",
        )
    _validate.__name__ = f"route_exists({prefix})"
    return _validate


def default_route_exists() -> Validator:
    """Assert that a default route (0.0.0.0/0) exists."""
    async def _validate(device: "Device") -> ValidationResult:
        rt = await device.get_routing_table()
        found = rt.default_route is not None
        return ValidationResult(
            name="DefaultRouteExists",
            passed=found,
            reason="Default route 0.0.0.0/0 " + ("present" if found else "missing"),
        )
    _validate.__name__ = "default_route_exists"
    return _validate


def custom(name: str, fn: Callable[["Device"], Coroutine[Any, Any, bool]], reason: str = "") -> Validator:
    """
    Wrap a simple bool-returning async function as a validator.

    Usage:
        custom("CheckNTP", lambda d: d.run("show ntp status").then(...))
    """
    async def _validate(device: "Device") -> ValidationResult:
        result = await fn(device)
        return ValidationResult(name=name, passed=bool(result), reason=reason)
    _validate.__name__ = name
    return _validate
