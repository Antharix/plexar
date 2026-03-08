"""
Discovery data models.

All data produced by the discovery pipeline is represented here.
These models are intentionally separate from the core device models —
discovery produces *candidates* that become devices only after
correlation and export.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


# ── Enums ─────────────────────────────────────────────────────────────

class DiscoveryMethod(StrEnum):
    ICMP           = "icmp"
    SNMP           = "snmp"
    TCP_PORT       = "tcp_port"
    LLDP_WALK      = "lldp_walk"
    CDP_WALK       = "cdp_walk"
    SSH_BANNER     = "ssh_banner"
    HTTP           = "http"


class DeviceRole(StrEnum):
    SPINE          = "spine"
    LEAF           = "leaf"
    ACCESS         = "access"
    BORDER         = "border"
    FIREWALL       = "firewall"
    LOAD_BALANCER  = "load_balancer"
    UNKNOWN        = "unknown"


class AuthStatus(StrEnum):
    SUCCESS        = "success"
    FAILED         = "failed"
    NOT_ATTEMPTED  = "not_attempted"
    LOCKED_OUT     = "locked_out"


# ── SNMP Data ─────────────────────────────────────────────────────────

@dataclass
class SNMPData:
    """Raw SNMP data collected from a device."""
    sys_descr:      str        = ""     # OID 1.3.6.1.2.1.1.1.0
    sys_name:       str        = ""     # OID 1.3.6.1.2.1.1.5.0
    sys_uptime:     int        = 0      # OID 1.3.6.1.2.1.1.3.0 (hundredths of seconds)
    sys_location:   str        = ""     # OID 1.3.6.1.2.1.1.6.0
    sys_contact:    str        = ""     # OID 1.3.6.1.2.1.1.4.0
    sys_object_id:  str        = ""     # OID 1.3.6.1.2.1.1.2