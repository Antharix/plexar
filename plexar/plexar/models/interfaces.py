"""Normalized Interface models — vendor-neutral."""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field
from plexar.core.enums import OperState, AdminState


class InterfaceStats(BaseModel):
    """Interface traffic counters."""
    input_bytes:    int = 0
    output_bytes:   int = 0
    input_packets:  int = 0
    output_packets: int = 0
    input_errors:   int = 0
    output_errors:  int = 0
    input_drops:    int = 0
    output_drops:   int = 0


class Interface(BaseModel):
    """
    Normalized interface model.

    Represents a single network interface regardless of vendor.
    All drivers return this model from get_interfaces().
    """
    name:          str
    oper_state:    OperState    = OperState.UNKNOWN
    admin_state:   AdminState   = AdminState.UP
    description:   str          = ""
    mtu:           int          = 1500
    speed_mbps:    int | None   = None
    mac_address:   str | None   = None
    ip_address:    str | None   = None
    prefix_length: int | None   = None
    is_physical:   bool         = True
    is_enabled:    bool         = True
    stats:         InterfaceStats = Field(default_factory=InterfaceStats)

    @property
    def is_up(self) -> bool:
        return self.oper_state == OperState.UP

    def __str__(self) -> str:
        return f"{self.name} ({self.oper_state})"
