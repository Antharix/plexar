"""
Nautobot Inventory Integration.

Loads Plexar inventory from Nautobot — the popular open-source
network automation platform built on NetBox's foundation.

Nautobot differences from NetBox:
  - GraphQL API (faster, flexible queries)
  - Device roles via relationship model
  - Git repositories for configuration
  - App framework for extensions

Requires: pip install plexar[nautobot]  (installs requests + pynautobot)

Usage:
    from plexar.integrations.nautobot import NautobotInventory

    nb_inv = NautobotInventory(
        url="https://nautobot.corp.com",
        token_env="NAUTOBOT_TOKEN",
        site="dc1",
    )
    await nb_inv.load(net.inventory)
"""

from __future__ import annotations

import logging
import os
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from plexar.core.inventory import Inventory

logger = logging.getLogger(__name__)

# Nautobot platform → Plexar platform
_PLATFORM_MAP: dict[str, str] = {
    "cisco_ios":      "cisco_ios",
    "cisco_iosxe":    "cisco_ios",
    "cisco_nxos":     "cisco_nxos",
    "cisco_iosxr":    "cisco_iosxr",
    "arista_eos":     "arista_eos",
    "juniper_junos":  "juniper_junos",
    "cumulus_linux":  "cumulus",
}

_GRAPHQL_DEVICES_QUERY = """
query PlexarDeviceQuery($site: [String], $role: [String], $status: [String]) {
  devices(site: $site, role: $role, status: $status) {
    id
    name
    status { value }
    role { slug }
    site { slug }
    tenant { name }
    platform { slug napalm_driver }
    primary_ip4 { address }
    primary_ip6 { address }
    serial
    asset_tag
    rack { name }
    position
    tags { name }
    custom_fields
  }
}
"""


class NautobotInventory:
    """
    Loads Plexar inventory from a Nautobot instance via GraphQL API.
    """

    def __init__(
        self,
        url:            str,
        token_env:      str                    = "NAUTOBOT_TOKEN",
        token:          str | None             = None,
        site:           str | list[str] | None = None,
        role:           str | list[str] | None = None,
        status:         str | list[str]        = "active",
        verify_ssl:     bool                   = True,
        platform_map:   dict[str, str] | None  = None,
        default_transport: str                 = "ssh",
        default_port:   int                    = 22,
    ) -> None:
        self.url               = url.rstrip("/")
        self._token_env        = token_env
        self._token            = token
        self.site              = [site]   if isinstance(site,   str) else (site   or [])
        self.role              = [role]   if isinstance(role,   str) else (role   or [])
        self.status            = [status] if isinstance(status, str) else (status or ["active"])
        self.verify_ssl        = verify_ssl
        self.platform_map      = {**_PLATFORM_MAP, **(platform_map or {})}
        self.default_transport = default_transport
        self.default_port      = default_port

    def _get_token(self) -> str:
        if self._token:
            return self._token
        token = os.environ.get(self._token_env)
        if not token:
            raise ValueError(
                f"Nautobot token not found. Set env var '{self._token_env}' "
                "or pass token= directly."
            )
        return token

    async def load(self, inventory: "Inventory") -> int:
        """Load devices from Nautobot into a Plexar Inventory."""
        try:
            import requests
        except ImportError:
            raise ImportError("Nautobot integration requires: pip install requests")

        token = self._get_token()
        headers = {
            "Authorization": f"Token {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

        variables: dict[str, Any] = {}
        if self.site:   variables["site"]   = self.site
        if self.role:   variables["role"]   = self.role
        if self.status: variables["status"] = self.status

        try:
            resp = requests.post(
                f"{self.url}/api/graphql/",
                json={"query": _GRAPHQL_DEVICES_QUERY, "variables": variables},
                headers=headers,
                verify=self.verify_ssl,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise ConnectionError(
                f"Failed to query Nautobot at {self.url}: {exc}"
            )

        if "errors" in data:
            raise ValueError(f"Nautobot GraphQL errors: {data['errors']}")

        nb_devices = data.get("data", {}).get("devices", [])
        loaded     = 0

        for nb_dev in nb_devices:
            try:
                cfg = self._nb_device_to_plexar(nb_dev)
                if cfg:
                    inventory.add_from_dict(cfg)
                    loaded += 1
            except Exception as exc:
                logger.warning(f"Skipping Nautobot device '{nb_dev.get('name')}': {exc}")

        logger.info(
            f"Nautobot: loaded {loaded}/{len(nb_devices)} devices from {self.url}"
        )
        return loaded

    def _nb_device_to_plexar(self, nb_dev: dict) -> dict[str, Any] | None:
        """Convert a Nautobot GraphQL device to a Plexar config dict."""
        name = nb_dev.get("name")
        if not name:
            return None

        # Platform resolution — prefer napalm_driver if set
        platform = "unknown"
        plat_obj = nb_dev.get("platform") or {}
        napalm_driver = plat_obj.get("napalm_driver", "")
        plat_slug     = plat_obj.get("slug", "").lower()

        if napalm_driver:
            platform = self.platform_map.get(napalm_driver, napalm_driver)
        elif plat_slug:
            platform = self.platform_map.get(plat_slug, plat_slug)

        # Management IP
        mgmt_ip = None
        ip4 = nb_dev.get("primary_ip4") or {}
        ip6 = nb_dev.get("primary_ip6") or {}
        if ip4.get("address"):
            mgmt_ip = ip4["address"].split("/")[0]
        elif ip6.get("address"):
            mgmt_ip = ip6["address"].split("/")[0]

        # Role and site
        role = (nb_dev.get("role") or {}).get("slug", "unknown")
        site = (nb_dev.get("site") or {}).get("slug", "")

        # Tags
        tags = [t.get("name", "") for t in (nb_dev.get("tags") or [])]

        metadata: dict[str, Any] = {
            "role":       role,
            "site":       site,
            "tenant":     (nb_dev.get("tenant") or {}).get("name", ""),
            "rack":       (nb_dev.get("rack")   or {}).get("name", ""),
            "position":   nb_dev.get("position"),
            "serial":     nb_dev.get("serial", ""),
            "asset_tag":  nb_dev.get("asset_tag", ""),
            "nautobot_id": nb_dev.get("id", ""),
            "status":     (nb_dev.get("status") or {}).get("value", "active"),
        }

        # Custom fields
        for k, v in (nb_dev.get("custom_fields") or {}).items():
            if v is not None:
                metadata[f"cf_{k}"] = v

        return {
            "hostname":       name,
            "management_ip":  mgmt_ip or name,
            "platform":       platform,
            "transport":      self.default_transport,
            "port":           self.default_port,
            "tags":           tags,
            "metadata":       metadata,
        }
