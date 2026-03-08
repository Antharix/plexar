"""Tests for the Plexar Plugin SDK."""

import pytest
from unittest.mock import MagicMock, patch

from plexar.plugins.sdk import (
    PlexarPlugin, DriverPlugin, HookPlugin,
    PluginRegistry, PluginInfo,
)


# ── Test Plugin Implementations ───────────────────────────────────────

class GoodPlugin(PlexarPlugin):
    name        = "test_good"
    version     = "1.0.0"
    description = "A test plugin"

    def __init__(self):
        self.loaded   = False
        self.unloaded = False

    def on_load(self):
        self.loaded = True

    def on_unload(self):
        self.unloaded = True


class BadPlugin(PlexarPlugin):
    name = "test_bad"

    def on_load(self):
        raise RuntimeError("Load failure")


class InvalidPlugin(PlexarPlugin):
    name = ""   # missing name

    def validate(self) -> list[str]:
        return ["name is required"]


class ValidationFailPlugin(PlexarPlugin):
    name = "validation_fail"

    def validate(self) -> list[str]:
        return ["missing required config"]


class MockHookPlugin(HookPlugin):
    name = "mock_hooks"

    def __init__(self):
        self.hooks_registered = False

    def register_hooks(self, event_bus):
        self.hooks_registered = True


# ── Plugin Tests ──────────────────────────────────────────────────────

class TestPlexarPlugin:
    def test_repr(self):
        plugin = GoodPlugin()
        r      = repr(plugin)
        assert "GoodPlugin" in r
        assert "test_good"  in r

    def test_validate_returns_empty_by_default(self):
        plugin = GoodPlugin()
        assert plugin.validate() == []

    def test_on_load_called(self):
        plugin = GoodPlugin()
        plugin.on_load()
        assert plugin.loaded

    def test_on_unload_called(self):
        plugin = GoodPlugin()
        plugin.on_unload()
        assert plugin.unloaded


class TestPluginRegistry:
    def setup_method(self):
        self.registry = PluginRegistry()

    def test_register_good_plugin(self):
        plugin = GoodPlugin()
        result = self.registry.register(plugin)
        assert result is True
        assert plugin.loaded

    def test_register_loads_plugin(self):
        plugin = GoodPlugin()
        self.registry.register(plugin)
        loaded = self.registry.loaded()
        assert plugin in loaded

    def test_register_bad_plugin_logs_error(self):
        plugin = BadPlugin()
        result = self.registry.register(plugin)
        assert result is False
        info   = self.registry._plugins.get("test_bad")
        assert info is not None
        assert len(info.errors) > 0

    def test_register_missing_name_raises(self):
        plugin = GoodPlugin()
        plugin.name = ""
        with pytest.raises(ValueError, match="must set name"):
            self.registry.register(plugin)

    def test_register_validation_failure(self):
        plugin = ValidationFailPlugin()
        result = self.registry.register(plugin)
        assert result is False
        info = self.registry._plugins["validation_fail"]
        assert "missing required config" in info.errors

    def test_get_loaded_plugin(self):
        plugin = GoodPlugin()
        self.registry.register(plugin)
        found  = self.registry.get("test_good")
        assert found is plugin

    def test_get_unloaded_returns_none(self):
        plugin = BadPlugin()
        self.registry.register(plugin)
        assert self.registry.get("test_bad") is None

    def test_get_nonexistent_returns_none(self):
        assert self.registry.get("nonexistent") is None

    def test_unregister_calls_on_unload(self):
        plugin = GoodPlugin()
        self.registry.register(plugin)
        self.registry.unregister("test_good")
        assert plugin.unloaded

    def test_unregister_removes_from_registry(self):
        plugin = GoodPlugin()
        self.registry.register(plugin)
        self.registry.unregister("test_good")
        assert self.registry.get("test_good") is None

    def test_unregister_nonexistent_raises(self):
        with pytest.raises(KeyError):
            self.registry.unregister("nonexistent")

    def test_replacing_existing_plugin(self):
        p1 = GoodPlugin()
        p1.name = "replace_test"
        p2 = GoodPlugin()
        p2.name = "replace_test"
        self.registry.register(p1)
        self.registry.register(p2)  # replaces p1 — should not raise
        assert self.registry.get("replace_test") is p2

    def test_all_returns_all_infos(self):
        self.registry.register(GoodPlugin())
        infos = self.registry.all()
        assert len(infos) == 1
        assert isinstance(infos[0], PluginInfo)

    def test_loaded_returns_only_loaded(self):
        self.registry.register(GoodPlugin())
        self.registry.register(BadPlugin())
        loaded = self.registry.loaded()
        assert len(loaded) == 1
        assert loaded[0].name == "test_good"

    def test_len(self):
        self.registry.register(GoodPlugin())
        assert len(self.registry) == 1

    def test_repr(self):
        self.registry.register(GoodPlugin())
        assert "1" in repr(self.registry)

    def test_status(self):
        self.registry.register(GoodPlugin())
        self.registry.register(BadPlugin())
        status = self.registry.status()
        assert status["total"]  == 2
        assert status["loaded"] == 1
        assert status["failed"] == 1
        assert len(status["plugins"]) == 2

    def test_hook_plugin_registers_hooks(self):
        plugin = MockHookPlugin()
        with patch("plexar.telemetry.events.event_bus") as mock_bus:
            plugin.on_load()
        assert plugin.hooks_registered


class TestDriverPlugin:
    def test_driver_plugin_registers_on_load(self):
        from plexar.drivers.base import BaseDriver

        class MockDriver(BaseDriver):
            async def connect(self): pass
            async def disconnect(self): pass
            async def run(self, cmd): return ""
            async def push_config(self, config): pass
            async def get_interfaces(self): return []
            async def get_bgp_summary(self): pass
            async def get_routing_table(self): pass
            async def get_platform_info(self): pass

        class MockDriverPlugin(DriverPlugin):
            name         = "test_driver_plugin"
            platform     = "test_os"
            driver_class = MockDriver

        plugin   = MockDriverPlugin()
        registry = PluginRegistry()

        with patch("plexar.drivers.registry.DriverRegistry.register") as mock_reg:
            result = registry.register(plugin)
            if result:
                mock_reg.assert_called_once_with("test_os", MockDriver)

    def test_driver_plugin_requires_platform(self):
        class NoPlatformPlugin(DriverPlugin):
            name         = "no_platform"
            platform     = ""
            driver_class = MagicMock()

        plugin   = NoPlatformPlugin()
        registry = PluginRegistry()
        result   = registry.register(plugin)
        assert result is False

    def test_driver_plugin_requires_driver_class(self):
        class NoDriverPlugin(DriverPlugin):
            name         = "no_driver"
            platform     = "test_os"
            driver_class = None

        plugin   = NoDriverPlugin()
        registry = PluginRegistry()
        result   = registry.register(plugin)
        assert result is False
