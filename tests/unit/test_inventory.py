"""Unit tests for the Inventory engine."""

import pytest
import yaml
import tempfile
from pathlib import Path

from plexar.core.inventory import Inventory
from plexar.core.credentials import Credentials
from plexar.core.exceptions import InventoryError, DeviceNotFoundError


SAMPLE_INVENTORY = {
    "defaults": {
        "transport": "ssh",
        "credentials": {"username": "admin", "password": "lab123"}
    },
    "devices": [
        {"hostname": "spine-01", "management_ip": "10.0.0.1", "platform": "arista_eos",
         "tags": ["spine", "dc1"], "metadata": {"role": "spine", "site": "dc1"}},
        {"hostname": "leaf-01",  "management_ip": "10.0.0.2", "platform": "cisco_nxos",
         "tags": ["leaf", "dc1"],  "metadata": {"role": "leaf",  "site": "dc1"}},
        {"hostname": "leaf-02",  "management_ip": "10.0.0.3", "platform": "cisco_nxos",
         "tags": ["leaf", "dc2"],  "metadata": {"role": "leaf",  "site": "dc2"}},
    ]
}


@pytest.fixture
def yaml_inventory_file(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(yaml.dump(SAMPLE_INVENTORY))
    return str(path)


@pytest.fixture
def inventory(yaml_inventory_file):
    inv = Inventory()
    inv.load("yaml", path=yaml_inventory_file)
    return inv


class TestInventoryLoading:
    def test_load_yaml(self, inventory):
        assert len(inventory) == 3

    def test_missing_file_raises(self):
        inv = Inventory()
        with pytest.raises(InventoryError, match="not found"):
            inv.load("yaml", path="/nonexistent/path.yaml")

    def test_unknown_source_raises(self):
        inv = Inventory()
        with pytest.raises(InventoryError, match="Unknown inventory source"):
            inv.load("mongodb")

    def test_add_device_programmatically(self, inventory):
        before = len(inventory)
        from plexar.core.device import Device
        d = Device(
            hostname="fw-01",
            platform="paloalto_panos",
            credentials=Credentials(username="admin", password="test"),
        )
        inventory.add(d)
        assert len(inventory) == before + 1


class TestInventoryFiltering:
    def test_filter_by_role(self, inventory):
        leafs = inventory.filter(role="leaf")
        assert len(leafs) == 2
        assert all(d.metadata["role"] == "leaf" for d in leafs)

    def test_filter_by_site(self, inventory):
        dc1 = inventory.filter(site="dc1")
        assert len(dc1) == 2

    def test_filter_by_platform(self, inventory):
        nxos = inventory.filter(platform="cisco_nxos")
        assert len(nxos) == 2

    def test_filter_by_tag(self, inventory):
        spines = inventory.filter(tags=["spine"])
        assert len(spines) == 1
        assert spines[0].hostname == "spine-01"

    def test_filter_multi_tag_and_logic(self, inventory):
        # Only dc1 leafs
        results = inventory.filter(tags=["leaf", "dc1"])
        assert len(results) == 1
        assert results[0].hostname == "leaf-01"

    def test_get_by_hostname(self, inventory):
        d = inventory.get("spine-01")
        assert d.hostname == "spine-01"

    def test_get_missing_raises(self, inventory):
        with pytest.raises(DeviceNotFoundError):
            inventory.get("does-not-exist")

    def test_filter_no_match_returns_empty(self, inventory):
        assert inventory.filter(role="firewall") == []

    def test_iter(self, inventory):
        hostnames = [d.hostname for d in inventory]
        assert "spine-01" in hostnames
        assert len(hostnames) == 3
