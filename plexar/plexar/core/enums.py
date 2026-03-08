"""
Central enumerations for Plexar.
All transport protocols and vendor platform identifiers live here.
"""

from enum import StrEnum, auto


class Transport(StrEnum):
    """Supported transport protocols for device connectivity."""
    SSH       = "ssh"
    NETCONF   = "netconf"
    RESTCONF  = "restconf"
    GNMI      = "gnmi"
    SNMP      = "snmp"


class Platform(StrEnum):
    """
    Canonical vendor platform identifiers.
    These strings are used to auto-select the correct driver.
    """
    # Cisco
    CISCO_IOS   = "cisco_ios"
    CISCO_NXOS  = "cisco_nxos"
    CISCO_XR    = "cisco_xr"
    CISCO_ASA   = "cisco_asa"

    # Arista
    ARISTA_EOS  = "arista_eos"

    # Juniper
    JUNIPER_JUNOS = "juniper_junos"

    # Palo Alto
    PALOALTO_PANOS = "paloalto_panos"

    # Fortinet
    FORTINET_FORTIOS = "fortinet_fortios"

    # Nokia
    NOKIA_SROS = "nokia_sros"


class OperState(StrEnum):
    """Operational state of a network element."""
    UP      = "up"
    DOWN    = "down"
    UNKNOWN = "unknown"
    TESTING = "testing"
    DORMANT = "dormant"


class AdminState(StrEnum):
    """Administrative state of a network element."""
    UP   = "up"
    DOWN = "down"


class BGPState(StrEnum):
    """BGP finite state machine states."""
    IDLE        = "idle"
    CONNECT     = "connect"
    ACTIVE      = "active"
    OPENSENT    = "opensent"
    OPENCONFIRM = "openconfirm"
    ESTABLISHED = "established"
    UNKNOWN     = "unknown"
