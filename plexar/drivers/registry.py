"""
Driver Registry.

Auto-discovers vendor drivers registered via Python entry_points.
External packages can register drivers without modifying Plexar core.

Registration (in pyproject.toml of the driver package):
    [project.entry-points."plexar.drivers"]
    my_vendor_os = "my_package.driver:MyVendorDriver"

Discovery happens once on first access (lazy, thread-safe).
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from plexar.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


class DriverRegistry:
    """
    Singleton registry mapping (platform, transport) → driver class.

    Drivers are loaded from 'plexar.drivers' entry_points and from
    the built-in vendor drivers in plexar.vendors.
    """

    _registry: dict[tuple[str, str], Type["BaseDriver"]] | None = None

    @classmethod
    def _load(cls) -> None:
        """Load and register all available drivers."""
        cls._registry = {}

        # Load from entry_points (external + built-in registered drivers)
        eps = entry_points(group="plexar.drivers")
        for ep in eps:
            try:
                driver_cls = ep.load()
                cls._register_driver(driver_cls)
            except Exception as e:
                logger.warning(f"Failed to load driver '{ep.name}': {e}")

        # Fallback: directly import built-in drivers if entry_points not set up
        # (useful during development before the package is installed)
        cls._load_builtin_drivers()

        logger.debug(f"Loaded {len(cls._registry)} driver(s): {list(cls._registry.keys())}")

    @classmethod
    def _load_builtin_drivers(cls) -> None:
        """Import built-in vendor drivers directly."""
        builtin_modules = [
            "plexar.vendors.cisco.ios",
            "plexar.vendors.cisco.nxos",
            "plexar.vendors.arista.eos",
            "plexar.vendors.juniper.junos",
            "plexar.drivers.mock",
        ]
        for module_path in builtin_modules:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                # Find all BaseDriver subclasses in the module
                from plexar.drivers.base import BaseDriver
                for name in dir(mod):
                    obj = getattr(mod, name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseDriver)
                        and obj is not BaseDriver
                        and getattr(obj, "platform", None)
                    ):
                        cls._register_driver(obj)
            except ImportError:
                pass  # optional modules may not be installed
            except Exception as e:
                logger.debug(f"Could not load builtin driver from '{module_path}': {e}")

    @classmethod
    def _register_driver(cls, driver_cls: Type["BaseDriver"]) -> None:
        """Register a driver class for its platform(s)."""
        assert cls._registry is not None
        platforms = driver_cls.platform
        if isinstance(platforms, str):
            platforms = [platforms]

        transports = getattr(driver_cls, "supported_transports", ["ssh"])
        if isinstance(transports, str):
            transports = [transports]

        for platform in platforms:
            for transport in transports:
                key = (platform.lower(), transport.lower())
                if key not in cls._registry:
                    cls._registry[key] = driver_cls
                    logger.debug(f"Registered driver: {platform}/{transport} → {driver_cls.__name__}")

    @classmethod
    def get(
        cls,
        platform: str,
        transport: str = "ssh",
    ) -> Type["BaseDriver"] | None:
        """
        Look up a driver for the given platform and transport.

        Falls back to SSH driver if the requested transport isn't available.

        Returns None if no driver is found.
        """
        if cls._registry is None:
            cls._load()
        assert cls._registry is not None

        key = (platform.lower(), transport.lower())
        if key in cls._registry:
            return cls._registry[key]

        # Fallback: try SSH transport
        fallback = (platform.lower(), "ssh")
        if fallback in cls._registry:
            logger.debug(
                f"No driver for {platform}/{transport}, "
                f"falling back to {platform}/ssh"
            )
            return cls._registry[fallback]

        return None

    @classmethod
    def all(cls) -> dict[tuple[str, str], Type["BaseDriver"]]:
        """Return all registered drivers."""
        if cls._registry is None:
            cls._load()
        return dict(cls._registry)  # type: ignore[return-value]

    @classmethod
    def reset(cls) -> None:
        """Reset the registry (used in tests)."""
        cls._registry = None
