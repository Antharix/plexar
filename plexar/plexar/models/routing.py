"""Normalized routing table models."""

from __future__ import annotations
from pydantic import BaseModel, Field


class Route(BaseModel):
    """A single route in the RIB."""
    prefix:    str
    next_hop:  str | None  = None
    protocol:  str         = "unknown"   # bgp, ospf, static, connected, etc.
    metric:    int         = 0
    distance:  int         = 0
    interface: str | None  = None
    age:       int         = 0           # seconds


class RoutingTable(BaseModel):
    """IPv4 routing information base."""
    routes: list[Route] = Field(default_factory=list)

    @property
    def default_route(self) -> Route | None:
        return next((r for r in self.routes if r.prefix == "0.0.0.0/0"), None)

    def has_route(self, prefix: str) -> bool:
        return any(r.prefix == prefix for r in self.routes)

    def by_protocol(self, protocol: str) -> list[Route]:
        return [r for r in self.routes if r.protocol.lower() == protocol.lower()]
