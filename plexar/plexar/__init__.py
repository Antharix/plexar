"""
Plexar — The nervous system for your network.

A unified, async-first Python SDK for network automation.
Transport · Parsing · Intent · Telemetry · Topology · AI

Quick start:
    from plexar import Network
    net = Network()
    net.inventory.load("yaml", path="./inventory.yaml")
    async with net.pool() as pool:
        results = await pool.map(lambda d: d.get_bgp_summary(), net.devices(role="leaf"))
"""

from importlib.metadata import version, PackageNotFoundError

from plexar.core.network import Network
from plexar.core.device import Device
from plexar.core.credentials import Credentials
from plexar.core.inventory import Inventory
from plexar.core.enums import Transport, Platform

try:
    __version__ = version("plexar")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

__all__ = [
    "Network",
    "Device",
    "Credentials",
    "Inventory",
    "Transport",
    "Platform",
    "__version__",
]
