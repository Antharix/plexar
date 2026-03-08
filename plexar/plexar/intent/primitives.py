"""
Intent Primitives.

An Intent Primitive describes a desired network state in
vendor-neutral terms. The Intent Compiler translates each
primitive into device-specific configuration.

Design philosophy:
  - Declare WHAT you want, not HOW to configure it
  - One primitive = one logical network concern
  - All primitives are Pydantic models — fully typed, validated
  - Primitives are idempotent — applying twice = same result

Available primitives:
  BGPIntent          — BGP neighbor relationships
  InterfaceIntent    — Interface state, MTU, description, IP
  VLANIntent         — VLAN existence and naming
  IPAddressIntent    — IP address assignment on interface
  RouteIntent        — Static route declaration
  OSPFIntent         — OSPF process and area membership
  PrefixListIntent   — Prefix list for route filtering
  NTPIntent          — NTP server configuration
  SNMPIntent         — SNMP community/trap config
  BannerIntent       — Login/MOTD banner
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class IntentPrimitive(BaseModel):
    """Base class for all intent primitives."""
    model_config = {"arbitrary_types_allowed": True}

    #: Human-readable description of this intent (optional, for docs/audit)
    description: str = ""

    def intent_type(self) -> str:
        return self.__class__.__name__


# ── BGP ──────────────────────────────────────────────────────────────

class BGPAddressFamily(StrEnum):
    IPV4_UNICAST   = "ipv4 unicast"
    IPV6_UNICAST   = "ipv6 unicast"
    EVPN           = "l2vpn evpn"
    VPNv4          = "vpnv4 unicast"


class BGPNeighbor(BaseModel):
    """A single BGP neighbor declaration."""
    ip:              str
    remote_as:       int
    description:     str                     = ""
    update_source:   str | None              = None     # loopback for iBGP
    next_hop_self:   bool                    = False
    password:        str | None              = None
    send_community:  bool                    = True
    soft_reconfiguration: bool               = False
    route_map_in:    str | None              = None
    route_map_out:   str | None              = None
    address_families: list[BGPAddressFamily] = Field(
        default_factory=lambda: [BGPAddressFamily.IPV4_UNICAST]
    )
    bfd:             bool                    = False
    shutdown:        bool                    = False


class BGPIntent(IntentPrimitive):
    """
    Declare desired BGP configuration.

    Usage:
        BGPIntent(
            asn=65001,
            router_id="10.0.0.1",
            neighbors=[
                BGPNeighbor(ip="10.0.0.2", remote_as=65000),
                BGPNeighbor(ip="10.0.0.3", remote_as=65000),
            ],
        )
    """
    asn:               int
    router_id:         str | None              = None
    neighbors:         list[BGPNeighbor]       = Field(default_factory=list)
    address_families:  list[BGPAddressFamily]  = Field(
        default_factory=lambda: [BGPAddressFamily.IPV4_UNICAST]
    )
    graceful_restart:  bool                    = True
    log_neighbor_changes: bool                 = True
    max_paths:         int                     = 1


# ── Interface ─────────────────────────────────────────────────────────

class InterfaceIntent(IntentPrimitive):
    """
    Declare desired interface state.

    Usage:
        InterfaceIntent(
            name="Ethernet1",
            admin_state="up",
            description="uplink-to-spine-01",
            mtu=9214,
        )
    """
    name:         str
    admin_state:  str         = "up"       # "up" | "down"
    description:  str | None  = None
    mtu:          int | None  = None
    speed:        str | None  = None       # "1G" | "10G" | "25G" | "100G"
    duplex:       str | None  = None       # "full" | "half" | "auto"
    ip_address:   str | None  = None       # "10.0.0.1/30"
    switchport:   bool        = False
    access_vlan:  int | None  = None
    trunk_vlans:  str | None  = None       # "1-100,200"
    storm_control: bool       = False
    portfast:     bool        = False


# ── VLAN ─────────────────────────────────────────────────────────────

class VLANIntent(IntentPrimitive):
    """
    Declare VLAN existence and properties.

    Usage:
        VLANIntent(vlan_id=100, name="PROD_SERVERS", state="active")
    """
    vlan_id:  int
    name:     str | None  = None
    state:    str         = "active"   # "active" | "suspend"


# ── Routing ───────────────────────────────────────────────────────────

class RouteIntent(IntentPrimitive):
    """
    Declare a static route.

    Usage:
        RouteIntent(prefix="0.0.0.0/0", next_hop="10.0.0.1")
    """
    prefix:       str
    next_hop:     str | None  = None
    interface:    str | None  = None
    admin_distance: int       = 1
    tag:          int | None  = None
    description:  str         = ""


class OSPFIntent(IntentPrimitive):
    """
    Declare OSPF process and network membership.

    Usage:
        OSPFIntent(
            process_id=1,
            router_id="10.0.0.1",
            networks=[("10.0.0.0/24", "0.0.0.0"), ("10.0.1.0/24", "0.0.0.1")],
        )
    """
    process_id:        int
    router_id:         str | None          = None
    networks:          list[tuple[str, str]] = Field(default_factory=list)
    passive_interfaces: list[str]          = Field(default_factory=list)
    default_route:     bool                = False
    log_adjacency:     bool                = True
    bfd:               bool                = False


class PrefixListIntent(IntentPrimitive):
    """
    Declare a prefix list for route filtering.

    Usage:
        PrefixListIntent(
            name="ALLOWED_PREFIXES",
            entries=[
                PrefixListEntry(seq=10, action="permit", prefix="10.0.0.0/8"),
                PrefixListEntry(seq=20, action="deny",   prefix="0.0.0.0/0"),
            ]
        )
    """

    class PrefixListEntry(BaseModel):
        seq:    int
        action: str    # "permit" | "deny"
        prefix: str
        ge:     int | None = None
        le:     int | None = None

    name:    str
    entries: list[PrefixListEntry] = Field(default_factory=list)


# ── System ────────────────────────────────────────────────────────────

class NTPIntent(IntentPrimitive):
    """
    Declare NTP server configuration.

    Usage:
        NTPIntent(servers=["10.0.0.100", "10.0.0.101"], timezone="UTC")
    """
    servers:     list[str]   = Field(default_factory=list)
    timezone:    str         = "UTC"
    source_interface: str | None = None
    authenticate: bool       = False


class SNMPIntent(IntentPrimitive):
    """
    Declare SNMP configuration.

    Usage:
        SNMPIntent(
            community="public",
            version="v2c",
            location="DC1-Row-A",
            contact="netops@corp.com",
        )
    """
    community:   str         = "public"
    version:     str         = "v2c"
    location:    str | None  = None
    contact:     str | None  = None
    trap_hosts:  list[str]   = Field(default_factory=list)


class BannerIntent(IntentPrimitive):
    """
    Declare login/MOTD banner.

    Usage:
        BannerIntent(
            motd="AUTHORIZED ACCESS ONLY. All sessions are monitored.",
            login="Please authenticate with your corporate credentials.",
        )
    """
    motd:  str | None = None
    login: str | None = None


# ── Type registry ─────────────────────────────────────────────────────

PRIMITIVE_TYPES: dict[str, type[IntentPrimitive]] = {
    "BGPIntent":        BGPIntent,
    "InterfaceIntent":  InterfaceIntent,
    "VLANIntent":       VLANIntent,
    "RouteIntent":      RouteIntent,
    "OSPFIntent":       OSPFIntent,
    "PrefixListIntent": PrefixListIntent,
    "NTPIntent":        NTPIntent,
    "SNMPIntent":       SNMPIntent,
    "BannerIntent":     BannerIntent,
}
