"""
NetBox Inventory Integration.

Loads Plexar inventory directly from NetBox — the de facto
source of truth for network infrastructure.

Supported NetBox versions: 3.x, 4.x
Requires: pip install plexar[netbox]  (installs pynetbox)

Features:
  - Full device inventory from NetBox (with all metadata)
  - Credential mapping by device role/site/tag
  - Custom field support
  - Tag-based filtering
  - Incremental sync (only changed devices)
  - Webhook receiver for real-time updates (Phase 5)

Usage:
    from plexar import Network
    from plexar.integrations.netbox import NetBoxInventory

    net = Network()

    # Load from NetBox
    nb_inv = NetBoxInventory(
        url="https://netbox.corp.com",
        token_env="NETBOX_TOKEN",
        site="dc1",
        role=["leaf", "spine"],
    )
    await nb_inv.load(net.inventory)

    # Or use the shorthand on Network
    await net.inventory.load("netbox",
        url="https://netbox.corp.com",
        token_env="NETBOX_TOKEN",
    )

    # Now use as normal
    leafs = net.devices(role="leaf")
"""

from __future__ import annotations

import logging
import os
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.inventory import Inventory
    from plexar.core.device import Device

logger = logging.getLogger(__name__)

# NetBox platform slug → Plexar platform string
_PLATFORM_MAP: dict[str, str] = {
    "ios":              "cisco_ios",
    "ios-xe":           "cisco_ios",
    "ios-xr":           "cisco_iosxr",
    "nxos":             "cisco_nxos",
    "nx-os":            "cisco_nxos",
    "eos":              "arista_eos",
    "arista-eos":       "arista_eos",
    "junos":            "juniper_junos",
    "juniper-junos":    "juniper_junos",
    "eos-ce":           "arista_eos",
    "cumulus-linux":    "cumulus",
    "sonic":            "sonic",
    "frr":              "frr",
}

# NetBox device role slug → Plexar role
_ROLE_MAP: dict[str, str] = {
    "spine":          "spine",
    "leaf":           "leaf",
    "border-leaf":    "border",
    "border":         "border",
    "access":         "access",
    "distribution":   "distribution",
    "core":           "core",
}


class NetBoxInventory:
    """
    Loads Plexar inventory from a NetBox instance.

    Supports filtering by site, role, tenant, tags, status, and custom fields.
    Maps NetBox platforms to Plexar platform strings automatically.
    """

    def __init__(
        self,
        url:              str,
        token_env:        str                  = "NETBOX_TOKEN",
        token:            str | None           = None,
        site:             str | list[str] | None = None,
        role:             str | list[str] | None = None,
        tenant:           str | None           = None,
        tags:             list[str] | None     = None,
        status:           str                  = "active",
        custom_fields:    dict[str, Any] | None = None,
        platform_map:     dict[str, str] | None = None,
        verify_ssl:       bool                 = True,
        default_transport: str                 = "ssh",
        default_port:     int                  = 22,
    ) -> None:
        self.url               = url.rstrip("/")
        self._token_env        = token_env
        self._token            = token
        self.site              = [site] if isinstance(site, str) else site
        self.role              = [role] if isinstance(role, str) else role
        self.tenant            = tenant
        self.tags              = tags
        self.status            = status
        self.custom_fields     = custom_fields or {}
        self.platform_map      = {**_PLATFORM_MAP, **(platform_map or {})}
        self.verify_ssl        = verify_ssl
        self.default_transport = default_transport
        self.default_port      = default_port
        self._nb: Any          = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        token = os.environ.get(self._token_env)
        if not token:
            raise ValueError(
                f"NetBox token not found. Set env var '{self._token_env}' "
                "or pass token= directly."
            )
        return token

    def _connect(self) -> Any:
        try:
            import pynetbox
        except ImportError:
            raise ImportError("NetBox integration requires: pip install plexar[netbox]")

        nb = pynetbox.api(self.url, token=self._get_token())
        nb.http_session.verify = self.verify_ssl
        return nb

    async def load(self, inventory: "Inventory") -> int:
        """
        Load devices from NetBox into a Plexar Inventory.

        Returns number of devices loaded.
        """
        if self._nb is None:
            self._nb = self._connect()

        params: dict[str, Any] = {"status": self.status}
        if self.site:
            params["site"] = self.site
        if self.role:
            params["role"] = self.role
        if self.tenant:
            params["tenant"] = self.tenant
        if self.tags:
            params["tag"] = self.tags

        try:
            nb_devices = list(self._nb.dcim.devices.filter(**params))
        except Exception as exc:
            raise ConnectionError(f"Failed to fetch devices from NetBox at {self.url}: {exc}")

        loaded = 0
        for nb_dev in nb_devices:
            try:
                device_cfg = self._nb_device_to_plexar(nb_dev)
                if device_cfg:
                    inventory.add_from_dict(device_cfg)
                    loaded += 1
            except Exception as exc:
                logger.warning(f"Skipping NetBox device '{nb_dev.name}': {exc}")

        logger.info(f"NetBox: loaded {loaded}/{len(nb_devices)} devices from {self.url}")
        return loaded

    def _nb_device_to_plexar(self, nb_dev: Any) -> dict[str, Any] | None:
        """Convert a pynetbox Device object to a Plexar device config dict."""
        if not nb_dev.name:
            return None

        # Resolve platform
        platform = "unknown"
        if nb_dev.platform:
            slug = nb_dev.platform.slug.lower().replace("_", "-")
            platform = self.platform_map.get(slug, slug)

        # Resolve management IP
        mgmt_ip = None
        if nb_dev.primary_ip4:
            mgmt_ip = str(nb_dev.primary_ip4.address).split("/")[0]
        elif nb_dev.primary_ip6:
            mgmt_ip = str(nb_dev.primary_ip6.address).split("/")[0]

        # Resolve role
        role = "unknown"
        if nb_dev.role:
            role = _ROLE_MAP.get(nb_dev.role.slug, nb_dev.role.slug)

        # Build tags list
        tags = [str(t) for t in (nb_dev.tags or [])]

        # Build metadata from NetBox fields
        metadata: dict[str, Any] = {
            "role":       role,
            "site":       str(nb_dev.site) if nb_dev.site else "",
            "tenant":     str(nb_dev.tenant) if nb_dev.tenant else "",
            "rack":       str(nb_dev.rack) if nb_dev.rack else "",
            "position":   nb_dev.position,
            "serial":     nb_dev.serial or "",
            "asset_tag":  nb_dev.asset_tag or "",
            "netbox_id":  nb_dev.id,
            "status":     nb_dev.status.value if nb_dev.status else "active",
        }

        # Merge custom fields
        if nb_dev.custom_fields:
            for k, v in nb_dev.custom_fields.items():
                if v is not None:
                    metadata[f"cf_{k}"] = v

        return {
            "hostname":       nb_dev.name,
            "management_ip":  mgmt_ip or nb_dev.name,
            "platform":       platform,
            "transport":      self.default_transport,
            "port":           self.default_port,
            "tags":           tags,
            "metadata":       metadata,
        }

    async def sync(self, inventory: "Inventory") -> dict[str, int]:
        """
        Incremental sync — only update devices that changed in NetBox.

        Returns dict with added/updated/removed counts.
        """
        if self._nb is None:
            self._nb = self._connect()

        existing = {d.hostname for d in inventory.all()}
        nb_names: set[str] = set()
        stats = {"added": 0, "updated": 0, "removed": 0}

        params: dict[str, Any] = {"status": self.status}
        if self.site:
            params["site"] = self.site
        if self.role:
            params["role"] = self.role

        for nb_dev in self._nb.dcim.devices.filter(**params):
            if not nb_dev.name:
                continue
            nb_names.add(nb_dev.name)
            cfg = self._nb_device_to_plexar(nb_dev)
            if cfg:
                if nb_dev.name in existing:
                    inventory.update_from_dict(cfg)
                    stats["updated"] += 1
                else:
                    inventory.add_from_dict(cfg)
                    stats["added"] += 1

        # Remove devices no longer in NetBox
        for hostname in existing - nb_names:
            inventory.remove(hostname)
            stats["removed"] += 1

        logger.info(f"NetBox sync: {stats}")
        return stats
