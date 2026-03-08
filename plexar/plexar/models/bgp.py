"""Normalized BGP models — vendor-neutral."""

from __future__ import annotations
from pydantic import BaseModel, Field
from plexar.core.enums import BGPState


class BGPPeer(BaseModel):
    """A single BGP peer/neighbor."""
    neighbor_ip:        str
    remote_as:          int | None    = None
    state:              BGPState      = BGPState.UNKNOWN
    prefixes_received:  int           = 0
    prefixes_sent:      int           = 0
    uptime_seconds:     int           = 0
    description:        str           = ""
    address_family:     str           = "ipv4"
    bfd_enabled:        bool          = False
    hold_time:          int           = 90
    keepalive:          int           = 30

    @property
    def is_established(self) -> bool:
        return self.state == BGPState.ESTABLISHED


class BGPSummary(BaseModel):
    """BGP summary for a device."""
    local_as:           int | None    = None
    router_id:          str | None    = None
    peers:              list[BGPPeer] = Field(default_factory=list)

    @property
    def peers_established(self) -> int:
        return sum(1 for p in self.peers if p.is_established)

    @property
    def peers_down(self) -> int:
        return len(self.peers) - self.peers_established

    @property
    def total_prefixes_received(self) -> int:
        return sum(p.prefixes_received for p in self.peers if p.is_established)
