"""Tests for the Intent Compiler — all 4 vendor compilers."""

import pytest
from plexar.intent.compiler import IntentCompiler, CompilerError
from plexar.intent.primitives import (
    BGPIntent, BGPNeighbor, BGPAddressFamily,
    InterfaceIntent, VLANIntent, RouteIntent,
    OSPFIntent, NTPIntent, SNMPIntent, BannerIntent,
    PrefixListIntent,
)


# ── Arista EOS ────────────────────────────────────────────────────────

class TestAristaEOSCompiler:
    def setup_method(self):
        self.compiler = IntentCompiler.for_platform("arista_eos")

    def test_bgp_basic(self):
        intent = BGPIntent(asn=65001, router_id="10.0.0.1")
        config = self.compiler.compile(intent)
        assert "router bgp 65001" in config
        assert "router-id 10.0.0.1" in config

    def test_bgp_with_neighbor(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(ip="10.0.0.2", remote_as=65000, next_hop_self=True)]
        )
        config = self.compiler.compile(intent)
        assert "neighbor 10.0.0.2 remote-as 65000" in config
        assert "neighbor 10.0.0.2 next-hop-self" in config

    def test_bgp_evpn_af(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(
                ip="10.0.0.2",
                remote_as=65000,
                address_families=[BGPAddressFamily.EVPN],
            )]
        )
        config = self.compiler.compile(intent)
        assert "l2vpn evpn" in config

    def test_bgp_send_community(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(ip="10.0.0.2", remote_as=65000, send_community=True)]
        )
        config = self.compiler.compile(intent)
        assert "send-community" in config

    def test_bgp_route_maps(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(
                ip="10.0.0.2", remote_as=65000,
                route_map_in="RM-IN", route_map_out="RM-OUT",
            )]
        )
        config = self.compiler.compile(intent)
        assert "route-map RM-IN in" in config
        assert "route-map RM-OUT out" in config

    def test_interface_basic(self):
        intent = InterfaceIntent(name="Ethernet1", admin_state="up", mtu=9214)
        config = self.compiler.compile(intent)
        assert "interface Ethernet1" in config
        assert "mtu 9214" in config
        assert "no shutdown" in config

    def test_interface_shutdown(self):
        intent = InterfaceIntent(name="Ethernet2", admin_state="down")
        config = self.compiler.compile(intent)
        assert "shutdown" in config
        assert "no shutdown" not in config

    def test_interface_ip_address(self):
        intent = InterfaceIntent(name="Loopback0", ip_address="10.0.0.1/32")
        config = self.compiler.compile(intent)
        assert "ip address 10.0.0.1/32" in config

    def test_interface_switchport(self):
        intent = InterfaceIntent(name="Ethernet3", switchport=True, access_vlan=100)
        config = self.compiler.compile(intent)
        assert "switchport" in config
        assert "switchport access vlan 100" in config

    def test_vlan_basic(self):
        intent = VLANIntent(vlan_id=100, name="PROD_SERVERS")
        config = self.compiler.compile(intent)
        assert "vlan 100" in config
        assert "name PROD_SERVERS" in config

    def test_route_basic(self):
        intent = RouteIntent(prefix="0.0.0.0/0", next_hop="10.0.0.1")
        config = self.compiler.compile(intent)
        assert "ip route 0.0.0.0/0 10.0.0.1" in config

    def test_ntp_servers(self):
        intent = NTPIntent(servers=["10.0.0.100", "10.0.0.101"])
        config = self.compiler.compile(intent)
        assert "ntp server 10.0.0.100" in config
        assert "ntp server 10.0.0.101" in config

    def test_snmp_basic(self):
        intent = SNMPIntent(community="plexar_ro", location="DC1")
        config = self.compiler.compile(intent)
        assert "snmp-server community plexar_ro" in config
        assert "snmp-server location DC1" in config

    def test_banner(self):
        intent = BannerIntent(motd="AUTHORIZED ACCESS ONLY")
        config = self.compiler.compile(intent)
        assert "banner motd" in config
        assert "AUTHORIZED ACCESS ONLY" in config

    def test_prefix_list(self):
        intent = PrefixListIntent(
            name="ALLOWED",
            entries=[
                PrefixListIntent.PrefixListEntry(seq=10, action="permit", prefix="10.0.0.0/8"),
                PrefixListIntent.PrefixListEntry(seq=20, action="deny",   prefix="0.0.0.0/0"),
            ]
        )
        config = self.compiler.compile(intent)
        assert "ip prefix-list ALLOWED seq 10 permit 10.0.0.0/8" in config
        assert "ip prefix-list ALLOWED seq 20 deny 0.0.0.0/0" in config

    def test_prefix_list_ge_le(self):
        intent = PrefixListIntent(
            name="FILTER",
            entries=[
                PrefixListIntent.PrefixListEntry(seq=10, action="permit", prefix="10.0.0.0/8", ge=24, le=32),
            ]
        )
        config = self.compiler.compile(intent)
        assert "ge 24" in config
        assert "le 32" in config


# ── Cisco IOS Compiler ────────────────────────────────────────────────

class TestCiscoIOSCompiler:
    def setup_method(self):
        self.compiler = IntentCompiler.for_platform("cisco_ios")

    def test_bgp_basic(self):
        intent = BGPIntent(asn=65001, router_id="10.0.0.1")
        config = self.compiler.compile(intent)
        assert "router bgp 65001" in config
        assert "bgp router-id 10.0.0.1" in config

    def test_bgp_neighbor(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(ip="10.0.0.2", remote_as=65000)]
        )
        config = self.compiler.compile(intent)
        assert "neighbor 10.0.0.2 remote-as 65000" in config

    def test_interface_uses_dotted_mask(self):
        """IOS uses dotted-decimal subnet masks, not CIDR."""
        intent = InterfaceIntent(name="GigabitEthernet0/1", ip_address="192.168.1.1/24")
        config = self.compiler.compile(intent)
        assert "255.255.255.0" in config
        assert "/24" not in config

    def test_interface_loopback_mask(self):
        intent = InterfaceIntent(name="Loopback0", ip_address="10.0.0.1/32")
        config = self.compiler.compile(intent)
        assert "255.255.255.255" in config

    def test_route_uses_dotted_mask(self):
        intent = RouteIntent(prefix="10.0.0.0/8", next_hop="192.168.1.1")
        config = self.compiler.compile(intent)
        assert "255.0.0.0" in config

    def test_ospf_uses_wildcard(self):
        intent = OSPFIntent(
            process_id=1,
            router_id="10.0.0.1",
            networks=[("10.0.0.0/24", "0.0.0.0")],
        )
        config = self.compiler.compile(intent)
        assert "0.0.0.255" in config   # wildcard for /24

    def test_banner_uses_caret_c(self):
        intent = BannerIntent(motd="AUTHORIZED ONLY")
        config = self.compiler.compile(intent)
        assert "^C" in config

    def test_snmp_uppercase_ro(self):
        intent = SNMPIntent(community="public")
        config = self.compiler.compile(intent)
        assert "RO" in config


# ── Cisco NX-OS Compiler ──────────────────────────────────────────────

class TestCiscoNXOSCompiler:
    def setup_method(self):
        self.compiler = IntentCompiler.for_platform("cisco_nxos")

    def test_bgp_nested_neighbor(self):
        intent = BGPIntent(
            asn=65001,
            neighbors=[BGPNeighbor(ip="10.0.0.2", remote_as=65000)]
        )
        config = self.compiler.compile(intent)
        assert "neighbor 10.0.0.2" in config
        assert "remote-as 65000" in config

    def test_interface_no_switchport_for_routed(self):
        intent = InterfaceIntent(name="Ethernet1/1", ip_address="10.0.0.1/30")
        config = self.compiler.compile(intent)
        assert "no switchport" in config

    def test_ntp_uses_vrf_syntax(self):
        intent = NTPIntent(servers=["10.0.0.100"])
        config = self.compiler.compile(intent)
        assert "ntp server 10.0.0.100" in config

    def test_snmp_uses_network_operator(self):
        intent = SNMPIntent(community="public")
        config = self.compiler.compile(intent)
        assert "network-operator" in config


# ── Juniper JunOS Compiler ────────────────────────────────────────────

class TestJuniperJunOSCompiler:
    def setup_method(self):
        self.compiler = IntentCompiler.for_platform("juniper_junos")

    def test_bgp_uses_set_format(self):
        intent = BGPIntent(asn=65001, router_id="10.0.0.1")
        config = self.compiler.compile(intent)
        assert config.startswith("set ")
        assert "autonomous-system 65001" in config

    def test_interface_uses_set_format(self):
        intent = InterfaceIntent(name="ge-0/0/0", description="uplink", mtu=9000)
        config = self.compiler.compile(intent)
        assert "set interfaces ge-0/0/0" in config
        assert "mtu 9000" in config

    def test_route_uses_static_syntax(self):
        intent = RouteIntent(prefix="0.0.0.0/0", next_hop="10.0.0.1")
        config = self.compiler.compile(intent)
        assert "routing-options static route" in config
        assert "next-hop 10.0.0.1" in config

    def test_ntp_uses_system_ntp(self):
        intent = NTPIntent(servers=["10.0.0.100"])
        config = self.compiler.compile(intent)
        assert "set system ntp server 10.0.0.100" in config

    def test_banner_uses_login_message(self):
        intent = BannerIntent(motd="AUTHORIZED ONLY")
        config = self.compiler.compile(intent)
        assert "set system login message" in config


# ── Registry Tests ────────────────────────────────────────────────────

class TestIntentCompilerRegistry:
    def test_known_platforms_available(self):
        platforms = IntentCompiler.supported_platforms()
        assert "arista_eos"    in platforms
        assert "cisco_ios"     in platforms
        assert "cisco_nxos"    in platforms
        assert "juniper_junos" in platforms

    def test_unknown_platform_raises(self):
        with pytest.raises(CompilerError):
            IntentCompiler.for_platform("unknown_vendor")

    def test_custom_compiler_can_register(self):
        from plexar.intent.compiler import BaseCompiler
        from plexar.intent.primitives import (
            BGPIntent, InterfaceIntent, VLANIntent, RouteIntent,
            OSPFIntent, NTPIntent, SNMPIntent, BannerIntent, PrefixListIntent,
        )

        class DummyCompiler(BaseCompiler):
            platform = "dummy_os"
            def compile_bgp(self, i, d): return "dummy bgp"
            def compile_interface(self, i, d): return "dummy interface"
            def compile_vlan(self, i, d): return "dummy vlan"
            def compile_route(self, i, d): return "dummy route"
            def compile_ospf(self, i, d): return "dummy ospf"
            def compile_ntp(self, i, d): return "dummy ntp"
            def compile_snmp(self, i, d): return "dummy snmp"
            def compile_banner(self, i, d): return "dummy banner"
            def compile_prefix_list(self, i, d): return "dummy prefix"

        IntentCompiler.register(DummyCompiler())
        compiler = IntentCompiler.for_platform("dummy_os")
        assert compiler.compile(BGPIntent(asn=1)) == "dummy bgp"
