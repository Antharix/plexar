"""
Inventory Engine.

Loads device inventories from multiple sources and provides
a query interface for filtering devices by role, tag, platform, etc.

Supported sources:
  - YAML file
  - NetBox (requires plexar[netbox])
  - Nautobot (requires plexar[netbox])
  - Plain dict / programmatic

Usage:
    inventory = Inventory()
    inventory.load("yaml", path="./devices.yaml")

    # Or from NetBox
    inventory.load("netbox", url="https://netbox.corp.com", token_env="NB_TOKEN")

    # Query
    leafs  = inventory.filter(role="leaf")
    spines = inventory.filter(tags=["spine", "dc1"])  # AND logic on tags
    cisco  = inventory.filter(platform="cisco_nxos")
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml

from plexar.core.credentials import Credentials
from plexar.core.device import Device
from plexar.core.enums import Transport, Platform
from plexar.core.exceptions import InventoryError, DeviceNotFoundError


class Inventory:
    """
    Device inventory store.

    Devices can be loaded from multiple sources simultaneously.
    The inventory is a flat list internally — sources are merged.
    """

    def __init__(self) -> None:
        self._devices: list[Device] = []
        self._default_credentials: Credentials | None = None

    # ── Loading ─────────────────────────────────────────────────────

    def load(self, source: str, **kwargs: Any) -> "Inventory":
        """
        Load devices from a source.

        Args:
            source: One of 'yaml', 'netbox', 'nautobot', 'dict'
            **kwargs: Source-specific arguments

        Returns:
            self (for method chaining)
        """
        loaders: dict[str, Callable[..., list[Device]]] = {
            "yaml":    self._load_yaml,
            "dict":    self._load_dict,
            "netbox":  self._load_netbox,
        }
        loader = loaders.get(source.lower())
        if loader is None:
            raise InventoryError(
                f"Unknown inventory source '{source}'. "
                f"Supported: {list(loaders.keys())}"
            )
        devices = loader(**kwargs)
        self._devices.extend(devices)
        return self

    def add(self, device: Device) -> "Inventory":
        """Add a single device programmatically."""
        self._devices.append(device)
        return self

    def set_default_credentials(self, credentials: Credentials) -> "Inventory":
        """
        Set credentials used for devices that don't specify their own.
        Useful when all devices share the same credentials.
        """
        self._default_credentials = credentials
        return self

    # ── Querying ─────────────────────────────────────────────────────

    def all(self) -> list[Device]:
        """Return all devices in inventory."""
        return list(self._devices)

    def filter(
        self,
        *,
        role:     str | None = None,
        site:     str | None = None,
        platform: str | None = None,
        tags:     list[str] | None = None,
        hostname: str | None = None,
        **metadata_filters: Any,
    ) -> list[Device]:
        """
        Filter devices by field values.

        Tags filtering uses AND logic — device must have ALL specified tags.
        Metadata filters match against device.metadata dict.

        Examples:
            inventory.filter(role="leaf")
            inventory.filter(tags=["spine", "dc1"])
            inventory.filter(platform="arista_eos", site="dc1")
        """
        results = self._devices

        if hostname is not None:
            results = [d for d in results if d.hostname == hostname]
        if platform is not None:
            results = [d for d in results if d.platform == platform.lower()]
        if role is not None:
            results = [d for d in results if d.metadata.get("role") == role]
        if site is not None:
            results = [d for d in results if d.metadata.get("site") == site]
        if tags is not None:
            results = [d for d in results if all(t in d.tags for t in tags)]
        for key, value in metadata_filters.items():
            results = [d for d in results if d.metadata.get(key) == value]

        return results

    def get(self, hostname: str) -> Device:
        """
        Get a single device by hostname. Raises DeviceNotFoundError if not found.
        """
        matches = self.filter(hostname=hostname)
        if not matches:
            raise DeviceNotFoundError(f"No device with hostname '{hostname}' in inventory.")
        return matches[0]

    def __len__(self) -> int:
        return len(self._devices)

    def __iter__(self) -> Iterator[Device]:
        return iter(self._devices)

    def __repr__(self) -> str:
        return f"Inventory(devices={len(self._devices)})"

    # ── Source Loaders ───────────────────────────────────────────────

    def _load_yaml(self, path: str | Path, **_: Any) -> list[Device]:
        """
        Load devices from a YAML file.

        Expected format:
            defaults:
              transport: ssh
              credentials:
                username: admin
                password_env: DEVICE_PASS

            devices:
              - hostname: spine-01
                management_ip: 10.0.0.1
                platform: arista_eos
                tags: [spine, dc1]
                metadata:
                  role: spine
                  site: dc1

              - hostname: leaf-01
                management_ip: 10.0.0.2
                platform: cisco_nxos
                tags: [leaf, dc1]
                metadata:
                  role: leaf
        """
        path = Path(path)
        if not path.exists():
            raise InventoryError(f"Inventory file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or "devices" not in data:
            raise InventoryError(f"Invalid YAML inventory: missing 'devices' key in {path}")

        defaults = data.get("defaults", {})
        devices: list[Device] = []

        for raw in data["devices"]:
            device = self._device_from_dict(raw, defaults)
            devices.append(device)

        return devices

    def _load_dict(self, devices: list[dict[str, Any]], **_: Any) -> list[Device]:
        """Load devices from a list of dicts (programmatic use)."""
        return [self._device_from_dict(d, {}) for d in devices]

    def _load_netbox(
        self,
        url: str,
        token: str | None = None,
        token_env: str = "NETBOX_TOKEN",
        **kwargs: Any,
    ) -> list[Device]:
        """
        Load devices from NetBox.
        Requires: pip install plexar[netbox]
        """
        try:
            import pynetbox
        except ImportError as e:
            raise InventoryError(
                "NetBox integration requires 'pynetbox'. "
                "Install with: pip install plexar[netbox]"
            ) from e

        resolved_token = token or os.environ.get(token_env)
        if not resolved_token:
            raise InventoryError(
                f"NetBox token not provided. Set token= or env var '{token_env}'."
            )

        nb = pynetbox.api(url, token=resolved_token)
        nb_devices = list(nb.dcim.devices.all())

        devices: list[Device] = []
        for nb_dev in nb_devices:
            if not nb_dev.primary_ip:
                continue  # skip devices without management IP

            platform_slug = (
                nb_dev.platform.slug.replace("-", "_") if nb_dev.platform else "unknown"
            )

            device = self._device_from_dict(
                {
                    "hostname":      nb_dev.name,
                    "management_ip": str(nb_dev.primary_ip.address).split("/")[0],
                    "platform":      platform_slug,
                    "tags":          [t.slug for t in nb_dev.tags],
                    "metadata": {
                        "role":   nb_dev.device_role.slug if nb_dev.device_role else None,
                        "site":   nb_dev.site.slug if nb_dev.site else None,
                        "tenant": nb_dev.tenant.slug if nb_dev.tenant else None,
                    },
                },
                {},
            )
            devices.append(device)

        return devices

    # ── Device construction ──────────────────────────────────────────

    def _device_from_dict(
        self,
        raw: dict[str, Any],
        defaults: dict[str, Any],
    ) -> Device:
        """Construct a Device from a raw dict, merging with defaults."""
        merged = {**defaults, **raw}

        # Resolve credentials
        creds_data = merged.pop("credentials", None)
        if creds_data:
            credentials = Credentials(**creds_data)
        elif self._default_credentials:
            credentials = self._default_credentials
        else:
            raise InventoryError(
                f"Device '{merged.get('hostname', '?')}' has no credentials. "
                f"Set per-device credentials or call inventory.set_default_credentials()."
            )

        return Device(credentials=credentials, **merged)
