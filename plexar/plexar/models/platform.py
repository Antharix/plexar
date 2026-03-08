"""Normalized platform/device info model."""

from __future__ import annotations
from pydantic import BaseModel


class PlatformInfo(BaseModel):
    """Device platform, version, and hardware info."""
    hostname:        str
    platform:        str
    os_version:      str           = ""
    serial:          str | None    = None
    model:           str | None    = None
    uptime_seconds:  int           = 0
    memory_total_mb: int | None    = None
    memory_used_mb:  int | None    = None
    cpu_percent:     float | None  = None
