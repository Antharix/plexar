"""Plexar normalized data models — vendor-neutral."""

from plexar.models.interfaces import Interface, InterfaceStats
from plexar.models.bgp import BGPSummary, BGPPeer
from plexar.models.routing import RoutingTable, Route
from plexar.models.platform import PlatformInfo

__all__ = [
    "Interface", "InterfaceStats",
    "BGPSummary", "BGPPeer",
    "RoutingTable", "Route",
    "PlatformInfo",
]
