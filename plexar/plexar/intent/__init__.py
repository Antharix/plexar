"""
Plexar Intent Engine.

Declare desired network state. Compile to vendor config. Apply. Verify.

Usage:
    from plexar.intent import Intent
    from plexar.intent.primitives import BGPIntent, BGPNeighbor, InterfaceIntent

    intent = Intent(devices=leafs)
    intent.ensure(BGPIntent(asn=65001, neighbors=[BGPNeighbor(ip="10.0.0.2", remote_as=65000)]))
    intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214))

    plan   = await intent.plan()
    result = await intent.apply()
    report = await intent.verify()
"""

from plexar.intent.primitives import (
    IntentPrimitive,
    BGPIntent, BGPNeighbor, BGPAddressFamily,
    InterfaceIntent,
    VLANIntent,
    RouteIntent,
    OSPFIntent,
    NTPIntent,
    SNMPIntent,
    BannerIntent,
    PrefixListIntent,
)
from plexar.intent.engine import Intent, IntentPlan, IntentResult, DevicePlan
from plexar.intent.compiler import IntentCompiler, CompilerError

__all__ = [
    "Intent", "IntentPlan", "IntentResult", "DevicePlan",
    "IntentCompiler", "CompilerError",
    "IntentPrimitive",
    "BGPIntent", "BGPNeighbor", "BGPAddressFamily",
    "InterfaceIntent", "VLANIntent", "RouteIntent",
    "OSPFIntent", "NTPIntent", "SNMPIntent", "BannerIntent",
    "PrefixListIntent",
]
