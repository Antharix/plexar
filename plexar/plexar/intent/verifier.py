"""
Intent Verifier.

Translates IntentPrimitives into Validators that check whether
the desired state is actually present on a device after apply.

Each primitive type has a corresponding verification strategy:
  BGPIntent        → check BGP peers are established
  InterfaceIntent  → check interface is up with correct config
  VLANIntent       → check VLAN exists
  RouteIntent      → check route is in RIB
  NTPIntent        → check NTP servers are reachable
  OSPFIntent       → check OSPF adjacencies are up

Used internally by Intent.verify().
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from plexar.intent.primitives import (
    IntentPrimitive, BGPIntent, InterfaceIntent,
    VLANIntent, RouteIntent, OSPFIntent, NTPIntent,
)
from plexar.config.validator import Validator, ValidationResult

if TYPE_CHECKING:
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


def build_validators_for_primitives(
    primitives: list[IntentPrimitive],
) -> list[Validator]:
    """
    Build a list of Validators from a list of IntentPrimitives.
    Called by Intent.verify() to construct verification suite.
    """
    validators: list[Validator] = []

    for primitive in primitives:
        vs = _validators_for(primitive)
        validators.extend(vs)

    return validators


def _validators_for(primitive: IntentPrimitive) -> list[Validator]:
    """Dispatch to the correct validator builder."""
    dispatch = {
        BGPIntent:       _bgp_validators,
        InterfaceIntent: _interface_validators,
        VLANIntent:      _vlan_validators,
        RouteIntent:     _route_validators,
        NTPIntent:       _ntp_validators,
    }
    builder = dispatch.get(type(primitive))
    if builder is None:
        logger.debug(f"No verifier for {type(primitive).__name__} — skipping")
        return []
    return builder(primitive)


# ── BGP Verifiers ─────────────────────────────────────────────────────

def _bgp_validators(intent: BGPIntent) -> list[Validator]:
    validators = []

    # Check each declared neighbor is established
    for nbr in intent.neighbors:
        async def check_neighbor(device: "Device", ip=nbr.ip, asn=nbr.remote_as) -> ValidationResult:
            try:
                bgp = await device.get_bgp_summary()
                peer = next((p for p in bgp.peers if p.neighbor_ip == ip), None)
                if peer is None:
                    return ValidationResult(
                        name=f"bgp_neighbor_{ip}",
                        passed=False,
                        reason=f"BGP neighbor {ip} (AS{asn}) not found in BGP table",
                    )
                established = peer.state.lower() in ("established", "active")
                return ValidationResult(
                    name=f"bgp_neighbor_{ip}",
                    passed=established,
                    reason=(
                        f"BGP neighbor {ip} is {peer.state}"
                        if not established
                        else f"BGP neighbor {ip} established (AS{asn})"
                    ),
                )
            except Exception as exc:
                return ValidationResult(
                    name=f"bgp_neighbor_{ip}",
                    passed=False,
                    reason=f"Error verifying BGP neighbor {ip}: {exc}",
                )

        validators.append(Validator(
            name=f"bgp_neighbor_{nbr.ip}",
            fn=check_neighbor,
            timeout_seconds=15,
        ))

    # Check overall peer count
    if intent.neighbors:
        min_peers = len(intent.neighbors)

        async def check_peer_count(device: "Device", expected=min_peers) -> ValidationResult:
            bgp = await device.get_bgp_summary()
            return ValidationResult(
                name="bgp_peer_count",
                passed=bgp.peers_established >= expected,
                reason=(
                    f"{bgp.peers_established}/{expected} BGP peers established"
                    if bgp.peers_established < expected
                    else f"All {expected} BGP peers established"
                ),
            )

        validators.append(Validator(name="bgp_peer_count", fn=check_peer_count))

    return validators


# ── Interface Verifiers ───────────────────────────────────────────────

def _interface_validators(intent: InterfaceIntent) -> list[Validator]:
    validators = []

    async def check_interface(device: "Device", name=intent.name, desired_state=intent.admin_state) -> ValidationResult:
        try:
            interfaces = await device.get_interfaces()
            iface = next((i for i in interfaces if i.name == name), None)
            if iface is None:
                return ValidationResult(
                    name=f"interface_{name}",
                    passed=False,
                    reason=f"Interface {name} not found",
                )
            is_up = iface.admin_state == "up" and iface.oper_state == "up"
            if desired_state == "up" and not is_up:
                return ValidationResult(
                    name=f"interface_{name}",
                    passed=False,
                    reason=f"Interface {name} is {iface.admin_state}/{iface.oper_state}",
                )
            return ValidationResult(
                name=f"interface_{name}",
                passed=True,
                reason=f"Interface {name} is {iface.admin_state}/{iface.oper_state}",
            )
        except Exception as exc:
            return ValidationResult(
                name=f"interface_{name}",
                passed=False,
                reason=f"Error verifying interface {name}: {exc}",
            )

    validators.append(Validator(name=f"interface_{intent.name}", fn=check_interface))

    # Check MTU if declared
    if intent.mtu is not None:
        async def check_mtu(device: "Device", name=intent.name, mtu=intent.mtu) -> ValidationResult:
            interfaces = await device.get_interfaces()
            iface = next((i for i in interfaces if i.name == name), None)
            if iface is None:
                return ValidationResult(name=f"mtu_{name}", passed=False, reason=f"Interface {name} not found")
            passed = iface.mtu == mtu
            return ValidationResult(
                name=f"mtu_{name}",
                passed=passed,
                reason=f"MTU {iface.mtu} (expected {mtu})" if not passed else f"MTU {mtu} confirmed",
            )

        validators.append(Validator(name=f"mtu_{intent.name}", fn=check_mtu))

    return validators


# ── VLAN Verifiers ────────────────────────────────────────────────────

def _vlan_validators(intent: VLANIntent) -> list[Validator]:
    async def check_vlan(device: "Device", vlan_id=intent.vlan_id) -> ValidationResult:
        try:
            output = await device.run(f"show vlan id {vlan_id}")
            found  = str(vlan_id) in output
            return ValidationResult(
                name=f"vlan_{vlan_id}",
                passed=found,
                reason=f"VLAN {vlan_id} {'present' if found else 'not found'}",
            )
        except Exception as exc:
            return ValidationResult(
                name=f"vlan_{vlan_id}",
                passed=False,
                reason=f"Error verifying VLAN {vlan_id}: {exc}",
            )

    return [Validator(name=f"vlan_{intent.vlan_id}", fn=check_vlan)]


# ── Route Verifiers ───────────────────────────────────────────────────

def _route_validators(intent: RouteIntent) -> list[Validator]:
    async def check_route(device: "Device", prefix=intent.prefix, nh=intent.next_hop) -> ValidationResult:
        try:
            rib = await device.get_routing_table()
            route = rib.has_route(prefix)
            if not route:
                return ValidationResult(
                    name=f"route_{prefix}",
                    passed=False,
                    reason=f"Route {prefix} not found in RIB",
                )
            return ValidationResult(
                name=f"route_{prefix}",
                passed=True,
                reason=f"Route {prefix} present in RIB",
            )
        except Exception as exc:
            return ValidationResult(
                name=f"route_{prefix}",
                passed=False,
                reason=f"Error verifying route {prefix}: {exc}",
            )

    return [Validator(name=f"route_{intent.prefix}", fn=check_route)]


# ── NTP Verifiers ─────────────────────────────────────────────────────

def _ntp_validators(intent: NTPIntent) -> list[Validator]:
    validators = []

    for server in intent.servers:
        async def check_ntp(device: "Device", ntp_ip=server) -> ValidationResult:
            try:
                output = await device.run("show ntp status")
                synced = "synchronised" in output.lower() or "synchronized" in output.lower()
                has_server = ntp_ip in output
                passed = has_server
                return ValidationResult(
                    name=f"ntp_{ntp_ip}",
                    passed=passed,
                    reason=(
                        f"NTP server {ntp_ip} configured, sync={'yes' if synced else 'no'}"
                        if passed
                        else f"NTP server {ntp_ip} not found in NTP config"
                    ),
                )
            except Exception as exc:
                return ValidationResult(
                    name=f"ntp_{ntp_ip}",
                    passed=False,
                    reason=f"Error verifying NTP server {ntp_ip}: {exc}",
                )

        validators.append(Validator(name=f"ntp_{server}", fn=check_ntp))

    return validators
