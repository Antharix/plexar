"""
Plexar Plugin SDK.

Plexar is designed to be extended. The Plugin SDK provides the
base classes and registration mechanisms for building:

  DriverPlugin         — Support for new vendor platforms
  InventoryPlugin      — New inventory sources (CMDB, spreadsheet, etc.)
  ParserPlugin         — New CLI/API output parsers
  ValidatorPlugin      — Custom post-apply verification checks
  ReporterPlugin       — Custom report formats and destinations
  IntentCompilerPlugin — Vendor compilers for new platforms
  HookPlugin           — Event hooks for side effects

Plugins are discovered via Python entry points:
    [project.entry-points."plexar.plugins"]
    my_vendor = "my_package.plexar_plugin:MyVendorPlugin"

Or registered programmatically:
    from plexar.plugins import plugin_registry
    plugin_registry.register(MyPlugin())

Example vendor driver plugin:
    from plexar.plugins import DriverPlugin
    from plexar.drivers.base import BaseDriver

    class MyVendorDriver(BaseDriver):
        ...

    class MyVendorPlugin(DriverPlugin):
        name     = "my_vendor"
        version  = "1.0.0"
        platform = "my_vendor_os"
        driver_class = MyVendorDriver

    plugin_registry.register(MyVendorPlugin())
"""

from __future__ import annotations

import importlib.metadata
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.drivers.base import BaseDriver
    from plexar.intent.compiler import BaseCompiler

logger = logging.getLogger(__name__)


# ── Plugin Base ───────────────────────────────────────────────────────

class PlexarPlugin(ABC):
    """Base class for all Plexar plugins."""

    #: Unique plugin name
    name:    str = ""
    #: Semver version string
    version: str = "0.1.0"
    #: Short description
    description: str = ""
    #: Plugin author
    author: str = ""

    def on_load(self) -> None:
        """Called when the plugin is loaded. Override for setup."""

    def on_unload(self) -> None:
        """Called when the plugin is unloaded. Override for cleanup."""

    def validate(self) -> list[str]:
        """
        Validate plugin configuration. Return list of error strings.
        Called before on_load(). Empty list = valid.
        """
        return []

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, version={self.version!r})"


# ── Plugin Types ──────────────────────────────────────────────────────

class DriverPlugin(PlexarPlugin):
    """
    Plugin that adds support for a new vendor platform.

    Usage:
        class ArubaCXPlugin(DriverPlugin):
            name         = "aruba_cx"
            version      = "1.0.0"
            platform     = "aruba_cx"
            driver_class = ArubaCXDriver

        plugin_registry.register(ArubaCXPlugin())
    """
    platform:      str  = ""
    driver_class:  type | None = None

    def on_load(self) -> None:
        if not self.platform:
            raise ValueError(f"DriverPlugin {self.name} must set platform")
        if self.driver_class is None:
            raise ValueError(f"DriverPlugin {self.name} must set driver_class")

        from plexar.drivers.registry import DriverRegistry
        DriverRegistry.register(self.platform, self.driver_class)
        logger.info(f"Plugin '{self.name}': registered driver for platform '{self.platform}'")


class IntentCompilerPlugin(PlexarPlugin):
    """
    Plugin that adds intent compilation for a new platform.

    Usage:
        class ArubaCXCompilerPlugin(IntentCompilerPlugin):
            name          = "aruba_cx_compiler"
            platform      = "aruba_cx"
            compiler_class = ArubaCXCompiler
    """
    platform:        str  = ""
    compiler_class:  type | None = None

    def on_load(self) -> None:
        if self.compiler_class is None:
            raise ValueError(f"IntentCompilerPlugin {self.name} must set compiler_class")

        from plexar.intent.compiler import IntentCompiler
        IntentCompiler.register(self.compiler_class())
        logger.info(f"Plugin '{self.name}': registered intent compiler for '{self.platform}'")


class InventoryPlugin(PlexarPlugin):
    """
    Plugin that adds a new inventory source.

    Usage:
        class ExcelInventoryPlugin(InventoryPlugin):
            name         = "excel_inventory"
            source_type  = "excel"

            async def load(self, inventory, **kwargs):
                # Load from Excel file
                path = kwargs["path"]
                ...
    """
    source_type: str = ""

    @abstractmethod
    async def load(self, inventory: Any, **kwargs: Any) -> int:
        """Load devices into inventory. Returns count loaded."""
        ...

    def on_load(self) -> None:
        from plexar.core.inventory import Inventory
        Inventory.register_loader(self.source_type, self)
        logger.info(f"Plugin '{self.name}': registered inventory loader '{self.source_type}'")


class ValidatorPlugin(PlexarPlugin):
    """
    Plugin that adds custom validators for intent verification.

    Usage:
        class MTRRouteValidator(ValidatorPlugin):
            name = "mtr_route_validator"

            def get_validators(self) -> list:
                return [
                    Validator(name="mtr_route", fn=self.check_mtr),
                ]

            async def check_mtr(self, device):
                ...
    """

    @abstractmethod
    def get_validators(self) -> list[Any]:
        """Return list of Validator objects."""
        ...


class ReporterPlugin(PlexarPlugin):
    """
    Plugin that adds custom report output formats or destinations.

    Usage:
        class SlackReporterPlugin(ReporterPlugin):
            name       = "slack_reporter"
            format     = "slack"

            async def send(self, report, **kwargs):
                webhook = kwargs["webhook_url"]
                await post_to_slack(webhook, report.to_slack_blocks())
    """
    format: str = ""

    @abstractmethod
    async def send(self, report: Any, **kwargs: Any) -> None:
        """Send a report using this plugin."""
        ...


class HookPlugin(PlexarPlugin):
    """
    Plugin that registers event hooks.

    Usage:
        class PagerDutyPlugin(HookPlugin):
            name = "pagerduty"

            def register_hooks(self, event_bus):
                @event_bus.on(EventType.BGP_PEER_DOWN)
                async def alert(event):
                    await trigger_pagerduty(event)
    """

    @abstractmethod
    def register_hooks(self, event_bus: Any) -> None:
        """Register event handlers on the event bus."""
        ...

    def on_load(self) -> None:
        from plexar.telemetry.events import event_bus
        self.register_hooks(event_bus)
        logger.info(f"Plugin '{self.name}': hooks registered")


# ── Plugin Registry ───────────────────────────────────────────────────

@dataclass
class PluginInfo:
    plugin:     PlexarPlugin
    loaded:     bool         = False
    errors:     list[str]    = field(default_factory=list)


class PluginRegistry:
    """
    Central registry for all Plexar plugins.

    Manages plugin lifecycle: discovery → validation → loading → unloading.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, PluginInfo] = {}

    def register(self, plugin: PlexarPlugin) -> bool:
        """
        Register and load a plugin.

        Returns True if loaded successfully.
        """
        if not plugin.name:
            raise ValueError(f"Plugin {plugin.__class__.__name__} must set name")

        if plugin.name in self._plugins:
            logger.warning(f"Plugin '{plugin.name}' already registered — replacing")

        errors = plugin.validate()
        if errors:
            logger.error(f"Plugin '{plugin.name}' validation failed: {errors}")
            self._plugins[plugin.name] = PluginInfo(plugin=plugin, errors=errors)
            return False

        try:
            plugin.on_load()
            self._plugins[plugin.name] = PluginInfo(plugin=plugin, loaded=True)
            logger.info(f"Plugin '{plugin.name}' v{plugin.version} loaded successfully")
            return True
        except Exception as exc:
            errors = [str(exc)]
            self._plugins[plugin.name] = PluginInfo(plugin=plugin, errors=errors)
            logger.error(f"Plugin '{plugin.name}' failed to load: {exc}")
            return False

    def unregister(self, name: str) -> None:
        """Unload and remove a plugin."""
        info = self._plugins.get(name)
        if not info:
            raise KeyError(f"Plugin '{name}' not registered")
        if info.loaded:
            info.plugin.on_unload()
        del self._plugins[name]
        logger.info(f"Plugin '{name}' unloaded")

    def get(self, name: str) -> PlexarPlugin | None:
        info = self._plugins.get(name)
        return info.plugin if info and info.loaded else None

    def all(self) -> list[PluginInfo]:
        return list(self._plugins.values())

    def loaded(self) -> list[PlexarPlugin]:
        return [i.plugin for i in self._plugins.values() if i.loaded]

    def discover_entry_points(self) -> int:
        """
        Auto-discover and load plugins from installed package entry points.

        Plugins must declare entry points under "plexar.plugins":
            [project.entry-points."plexar.plugins"]
            my_plugin = "my_package.plugin:MyPlugin"

        Returns number of plugins loaded.
        """
        loaded = 0
        try:
            eps = importlib.metadata.entry_points(group="plexar.plugins")
            for ep in eps:
                try:
                    plugin_class = ep.load()
                    plugin       = plugin_class()
                    if self.register(plugin):
                        loaded += 1
                except Exception as exc:
                    logger.error(f"Failed to load plugin from entry point '{ep.name}': {exc}")
        except Exception as exc:
            logger.warning(f"Entry point discovery failed: {exc}")

        if loaded:
            logger.info(f"Auto-discovered {loaded} plugin(s) via entry points")
        return loaded

    def status(self) -> dict[str, Any]:
        return {
            "total":  len(self._plugins),
            "loaded": len([i for i in self._plugins.values() if i.loaded]),
            "failed": len([i for i in self._plugins.values() if i.errors]),
            "plugins": [
                {
                    "name":    i.plugin.name,
                    "version": i.plugin.version,
                    "loaded":  i.loaded,
                    "errors":  i.errors,
                }
                for i in self._plugins.values()
            ],
        }

    def __len__(self) -> int:
        return len(self._plugins)

    def __repr__(self) -> str:
        return f"PluginRegistry({len(self.loaded())} loaded)"


# ── Module-level singleton ────────────────────────────────────────────

plugin_registry = PluginRegistry()
