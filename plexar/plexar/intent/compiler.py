"""
Intent Compiler.

Translates vendor-neutral IntentPrimitives into device-specific
configuration blocks. Each vendor has a compiler subclass that
knows how to render each primitive type for that platform.

Compiler registry is auto-discovered — new vendors register themselves.

Usage (internal — called by Intent.compile()):
    compiler = IntentCompiler.for_platform("arista_eos")
    config   = compiler.compile(BGPIntent(asn=65001, neighbors=[...]))
    # Returns: "router bgp 65001\n   neighbor 10.0.0.1 remote-as 65000\n..."
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from plexar.intent.primitives import (
    IntentPrimitive, BGPIntent, InterfaceIntent, VLANIntent,
    RouteIntent, OSPFIntent, NTPIntent, SNMPIntent, BannerIntent,
    PrefixListIntent,
)

if TYPE_CHECKING:
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


class CompilerError(Exception):
    """Raised when a primitive cannot be compiled for a platform."""


class BaseCompiler(ABC):
    """
    Abstract intent compiler.
    One subclass per vendor platform.
    """

    #: Platform string(s) this compiler handles
    platform: str | list[str] = ""

    def compile(self, primitive: IntentPrimitive, device: "Device | None" = None) -> str:
        """
        Compile a primitive into a device config block.

        Dispatches to the appropriate method based on primitive type.
        """
        dispatch: dict[type, Any] = {
            BGPIntent:        self.compile_bgp,
            InterfaceIntent:  self.compile_interface,
            VLANIntent:       self.compile_vlan,
            RouteIntent:      self.compile_route,
            OSPFIntent:       self.compile_ospf,
            NTPIntent:        self.compile_ntp,
            SNMPIntent:       self.compile_snmp,
            BannerIntent:     self.compile_banner,
            PrefixListIntent: self.compile_prefix_list,
        }
        handler = dispatch.get(type(primitive))
        if handler is None:
            raise CompilerError(
                f"Compiler '{self.__class__.__name__}' does not support "
                f"primitive type '{type(primitive).__name__}'"
            )
        return handler(primitive, device)

    @abstractmethod
    def compile_bgp(self, intent: BGPIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_interface(self, intent: InterfaceIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_vlan(self, intent: VLANIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_route(self, intent: RouteIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_ospf(self, intent: OSPFIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_ntp(self, intent: NTPIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_snmp(self, intent: SNMPIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_banner(self, intent: BannerIntent, device: "Device | None") -> str: ...

    @abstractmethod
    def compile_prefix_list(self, intent: PrefixListIntent, device: "Device | None") -> str: ...


# ── Arista EOS Compiler ───────────────────────────────────────────────

class AristaEOSCompiler(BaseCompiler):
    """Compiles intent primitives to Arista EOS configuration."""

    platform = "arista_eos"

    def compile_bgp(self, intent: BGPIntent, device=None) -> str:
        lines = [f"router bgp {intent.asn}"]
        if intent.router_id:
            lines.append(f"   router-id {intent.router_id}")
        if intent.log_neighbor_changes:
            lines.append("   bgp log-neighbor-changes")
        if intent.graceful_restart:
            lines.append("   graceful-restart")

        for af in intent.address_families:
            lines.append(f"   address-family {af}")
            lines.append("   exit-address-family")

        for nbr in intent.neighbors:
            lines.append(f"   neighbor {nbr.ip} remote-as {nbr.remote_as}")
            if nbr.description:
                lines.append(f"   neighbor {nbr.ip} description {nbr.description}")
            if nbr.update_source:
                lines.append(f"   neighbor {nbr.ip} update-source {nbr.update_source}")
            if nbr.next_hop_self:
                lines.append(f"   neighbor {nbr.ip} next-hop-self")
            if nbr.send_community:
                lines.append(f"   neighbor {nbr.ip} send-community")
            if nbr.route_map_in:
                lines.append(f"   neighbor {nbr.ip} route-map {nbr.route_map_in} in")
            if nbr.route_map_out:
                lines.append(f"   neighbor {nbr.ip} route-map {nbr.route_map_out} out")
            if nbr.bfd:
                lines.append(f"   neighbor {nbr.ip} bfd")
            if nbr.shutdown:
                lines.append(f"   neighbor {nbr.ip} shutdown")
            for af in nbr.address_families:
                lines.append(f"   address-family {af}")
                lines.append(f"      neighbor {nbr.ip} activate")
                lines.append("   exit-address-family")

        if intent.max_paths > 1:
            lines.append(f"   maximum-paths {intent.max_paths}")

        return "\n".join(lines)

    def compile_interface(self, intent: InterfaceIntent, device=None) -> str:
        lines = [f"interface {intent.name}"]
        if intent.description is not None:
            lines.append(f"   description {intent.description}")
        if intent.mtu is not None:
            lines.append(f"   mtu {intent.mtu}")
        if intent.ip_address:
            lines.append(f"   ip address {intent.ip_address}")
        if intent.admin_state == "down":
            lines.append("   shutdown")
        else:
            lines.append("   no shutdown")
        if intent.switchport:
            lines.append("   switchport")
            if intent.access_vlan:
                lines.append("   switchport mode access")
                lines.append(f"   switchport access vlan {intent.access_vlan}")
            elif intent.trunk_vlans:
                lines.append("   switchport mode trunk")
                lines.append(f"   switchport trunk allowed vlan {intent.trunk_vlans}")
        return "\n".join(lines)

    def compile_vlan(self, intent: VLANIntent, device=None) -> str:
        lines = [f"vlan {intent.vlan_id}"]
        if intent.name:
            lines.append(f"   name {intent.name}")
        if intent.state == "suspend":
            lines.append("   state suspend")
        return "\n".join(lines)

    def compile_route(self, intent: RouteIntent, device=None) -> str:
        line = f"ip route {intent.prefix}"
        if intent.next_hop:
            line += f" {intent.next_hop}"
        if intent.interface:
            line += f" {intent.interface}"
        if intent.admin_distance != 1:
            line += f" {intent.admin_distance}"
        if intent.description:
            line += f" name {intent.description}"
        return line

    def compile_ospf(self, intent: OSPFIntent, device=None) -> str:
        lines = [f"router ospf {intent.process_id}"]
        if intent.router_id:
            lines.append(f"   router-id {intent.router_id}")
        if intent.log_adjacency:
            lines.append("   log-adjacency-changes detail")
        for network, area in intent.networks:
            lines.append(f"   network {network} area {area}")
        for iface in intent.passive_interfaces:
            lines.append(f"   passive-interface {iface}")
        if intent.default_route:
            lines.append("   default-information originate always")
        return "\n".join(lines)

    def compile_ntp(self, intent: NTPIntent, device=None) -> str:
        lines = []
        for server in intent.servers:
            line = f"ntp server {server}"
            if intent.source_interface:
                line += f" source {intent.source_interface}"
            lines.append(line)
        if intent.timezone != "UTC":
            lines.append(f"clock timezone {intent.timezone}")
        return "\n".join(lines)

    def compile_snmp(self, intent: SNMPIntent, device=None) -> str:
        lines = [f"snmp-server community {intent.community} ro"]
        if intent.location:
            lines.append(f"snmp-server location {intent.location}")
        if intent.contact:
            lines.append(f"snmp-server contact {intent.contact}")
        for host in intent.trap_hosts:
            lines.append(f"snmp-server host {host} traps version {intent.version} {intent.community}")
        return "\n".join(lines)

    def compile_banner(self, intent: BannerIntent, device=None) -> str:
        lines = []
        if intent.motd:
            lines.append(f"banner motd\n{intent.motd}\nEOF")
        if intent.login:
            lines.append(f"banner login\n{intent.login}\nEOF")
        return "\n".join(lines)

    def compile_prefix_list(self, intent: PrefixListIntent, device=None) -> str:
        lines = []
        for entry in sorted(intent.entries, key=lambda e: e.seq):
            line = f"ip prefix-list {intent.name} seq {entry.seq} {entry.action} {entry.prefix}"
            if entry.ge:
                line += f" ge {entry.ge}"
            if entry.le:
                line += f" le {entry.le}"
            lines.append(line)
        return "\n".join(lines)


# ── Cisco NX-OS Compiler ──────────────────────────────────────────────

class CiscoNXOSCompiler(BaseCompiler):
    """Compiles intent primitives to Cisco NX-OS configuration."""

    platform = "cisco_nxos"

    def compile_bgp(self, intent: BGPIntent, device=None) -> str:
        lines = [f"router bgp {intent.asn}"]
        if intent.router_id:
            lines.append(f"  router-id {intent.router_id}")
        if intent.log_neighbor_changes:
            lines.append("  log-neighbor-changes")

        for nbr in intent.neighbors:
            lines.append(f"  neighbor {nbr.ip}")
            lines.append(f"    remote-as {nbr.remote_as}")
            if nbr.description:
                lines.append(f"    description {nbr.description}")
            if nbr.update_source:
                lines.append(f"    update-source {nbr.update_source}")
            if nbr.bfd:
                lines.append("    bfd")
            if nbr.shutdown:
                lines.append("    shutdown")
            for af in nbr.address_families:
                lines.append(f"    address-family {af}")
                if nbr.next_hop_self:
                    lines.append("      next-hop-self")
                if nbr.send_community:
                    lines.append("      send-community")
                    lines.append("      send-community extended")
                if nbr.route_map_in:
                    lines.append(f"      route-map {nbr.route_map_in} in")
                if nbr.route_map_out:
                    lines.append(f"      route-map {nbr.route_map_out} out")

        return "\n".join(lines)

    def compile_interface(self, intent: InterfaceIntent, device=None) -> str:
        lines = [f"interface {intent.name}"]
        if intent.description is not None:
            lines.append(f"  description {intent.description}")
        if intent.mtu is not None:
            lines.append(f"  mtu {intent.mtu}")
        if intent.ip_address:
            lines.append("  no switchport")
            lines.append(f"  ip address {intent.ip_address}")
        if intent.admin_state == "down":
            lines.append("  shutdown")
        else:
            lines.append("  no shutdown")
        if intent.switchport:
            lines.append("  switchport")
            if intent.access_vlan:
                lines.append("  switchport mode access")
                lines.append(f"  switchport access vlan {intent.access_vlan}")
        return "\n".join(lines)

    def compile_vlan(self, intent: VLANIntent, device=None) -> str:
        lines = [f"vlan {intent.vlan_id}"]
        if intent.name:
            lines.append(f"  name {intent.name}")
        if intent.state == "suspend":
            lines.append("  state suspend")
        return "\n".join(lines)

    def compile_route(self, intent: RouteIntent, device=None) -> str:
        line = f"ip route {intent.prefix}"
        if intent.next_hop:
            line += f" {intent.next_hop}"
        if intent.admin_distance != 1:
            line += f" {intent.admin_distance}"
        if intent.description:
            line += f" name {intent.description}"
        return line

    def compile_ospf(self, intent: OSPFIntent, device=None) -> str:
        lines = [f"router ospf {intent.process_id}"]
        if intent.router_id:
            lines.append(f"  router-id {intent.router_id}")
        if intent.log_adjacency:
            lines.append("  log-adjacency-changes detail")
        for iface in intent.passive_interfaces:
            lines.append(f"  passive-interface {iface}")
        # NX-OS uses interface-level OSPF config for networks
        return "\n".join(lines)

    def compile_ntp(self, intent: NTPIntent, device=None) -> str:
        lines = []
        for server in intent.servers:
            line = f"ntp server {server}"
            if intent.source_interface:
                line += f" use-vrf default source-interface {intent.source_interface}"
            lines.append(line)
        return "\n".join(lines)

    def compile_snmp(self, intent: SNMPIntent, device=None) -> str:
        lines = [f"snmp-server community {intent.community} group network-operator"]
        if intent.location:
            lines.append(f"snmp-server location {intent.location}")
        if intent.contact:
            lines.append(f"snmp-server contact {intent.contact}")
        return "\n".join(lines)

    def compile_banner(self, intent: BannerIntent, device=None) -> str:
        lines = []
        if intent.motd:
            lines.append(f"banner motd #\n{intent.motd}\n#")
        return "\n".join(lines)

    def compile_prefix_list(self, intent: PrefixListIntent, device=None) -> str:
        lines = []
        for entry in sorted(intent.entries, key=lambda e: e.seq):
            line = f"ip prefix-list {intent.name} seq {entry.seq} {entry.action} {entry.prefix}"
            if entry.ge:
                line += f" ge {entry.ge}"
            if entry.le:
                line += f" le {entry.le}"
            lines.append(line)
        return "\n".join(lines)


# ── Cisco IOS Compiler ────────────────────────────────────────────────

class CiscoIOSCompiler(BaseCompiler):
    """Compiles intent primitives to Cisco IOS / IOS-XE configuration."""

    platform = ["cisco_ios", "cisco_iosxe"]

    def compile_bgp(self, intent: BGPIntent, device=None) -> str:
        lines = [f"router bgp {intent.asn}"]
        if intent.router_id:
            lines.append(f" bgp router-id {intent.router_id}")
        if intent.log_neighbor_changes:
            lines.append(" bgp log-neighbor-changes")
        if intent.max_paths > 1:
            lines.append(f" maximum-paths {intent.max_paths}")

        for nbr in intent.neighbors:
            lines.append(f" neighbor {nbr.ip} remote-as {nbr.remote_as}")
            if nbr.description:
                lines.append(f" neighbor {nbr.ip} description {nbr.description}")
            if nbr.update_source:
                lines.append(f" neighbor {nbr.ip} update-source {nbr.update_source}")
            if nbr.next_hop_self:
                lines.append(f" neighbor {nbr.ip} next-hop-self")
            if nbr.send_community:
                lines.append(f" neighbor {nbr.ip} send-community both")
            if nbr.route_map_in:
                lines.append(f" neighbor {nbr.ip} route-map {nbr.route_map_in} in")
            if nbr.route_map_out:
                lines.append(f" neighbor {nbr.ip} route-map {nbr.route_map_out} out")
            if nbr.soft_reconfiguration:
                lines.append(f" neighbor {nbr.ip} soft-reconfiguration inbound")
            if nbr.shutdown:
                lines.append(f" neighbor {nbr.ip} shutdown")

        lines.append("!")
        return "\n".join(lines)

    def compile_interface(self, intent: InterfaceIntent, device=None) -> str:
        lines = [f"interface {intent.name}"]
        if intent.description is not None:
            lines.append(f" description {intent.description}")
        if intent.mtu is not None:
            lines.append(f" mtu {intent.mtu}")
        if intent.ip_address:
            # IOS uses 'ip address x.x.x.x y.y.y.y' format
            addr, prefix = intent.ip_address.split("/")
            mask = self._prefix_to_mask(int(prefix))
            lines.append(f" ip address {addr} {mask}")
        if intent.admin_state == "down":
            lines.append(" shutdown")
        else:
            lines.append(" no shutdown")
        if intent.switchport and intent.access_vlan:
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {intent.access_vlan}")
        lines.append("!")
        return "\n".join(lines)

    def compile_vlan(self, intent: VLANIntent, device=None) -> str:
        lines = [f"vlan {intent.vlan_id}"]
        if intent.name:
            lines.append(f" name {intent.name}")
        return "\n".join(lines)

    def compile_route(self, intent: RouteIntent, device=None) -> str:
        parts = intent.prefix.split("/")
        if len(parts) == 2:
            prefix = parts[0]
            mask   = self._prefix_to_mask(int(parts[1]))
        else:
            prefix, mask = parts[0], "255.255.255.255"
        line = f"ip route {prefix} {mask}"
        if intent.next_hop:
            line += f" {intent.next_hop}"
        if intent.admin_distance != 1:
            line += f" {intent.admin_distance}"
        return line

    def compile_ospf(self, intent: OSPFIntent, device=None) -> str:
        lines = [f"router ospf {intent.process_id}"]
        if intent.router_id:
            lines.append(f" router-id {intent.router_id}")
        if intent.log_adjacency:
            lines.append(" log-adjacency-changes detail")
        for network, area in intent.networks:
            # Convert CIDR to wildcard
            parts = network.split("/")
            wildcard = self._prefix_to_wildcard(int(parts[1])) if len(parts) == 2 else "0.0.0.255"
            lines.append(f" network {parts[0]} {wildcard} area {area}")
        for iface in intent.passive_interfaces:
            lines.append(f" passive-interface {iface}")
        if intent.default_route:
            lines.append(" default-information originate always")
        lines.append("!")
        return "\n".join(lines)

    def compile_ntp(self, intent: NTPIntent, device=None) -> str:
        lines = []
        for server in intent.servers:
            lines.append(f"ntp server {server}")
        return "\n".join(lines)

    def compile_snmp(self, intent: SNMPIntent, device=None) -> str:
        lines = [f"snmp-server community {intent.community} RO"]
        if intent.location:
            lines.append(f"snmp-server location {intent.location}")
        if intent.contact:
            lines.append(f"snmp-server contact {intent.contact}")
        for host in intent.trap_hosts:
            lines.append(f"snmp-server host {host} {intent.community}")
        return "\n".join(lines)

    def compile_banner(self, intent: BannerIntent, device=None) -> str:
        lines = []
        if intent.motd:
            lines.append(f"banner motd ^C\n{intent.motd}\n^C")
        if intent.login:
            lines.append(f"banner login ^C\n{intent.login}\n^C")
        return "\n".join(lines)

    def compile_prefix_list(self, intent: PrefixListIntent, device=None) -> str:
        lines = []
        for entry in sorted(intent.entries, key=lambda e: e.seq):
            line = f"ip prefix-list {intent.name} seq {entry.seq} {entry.action} {entry.prefix}"
            if entry.ge:
                line += f" ge {entry.ge}"
            if entry.le:
                line += f" le {entry.le}"
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def _prefix_to_mask(prefix_len: int) -> str:
        mask = (0xFFFFFFFF >> (32 - prefix_len)) << (32 - prefix_len)
        return ".".join(str((mask >> (8 * i)) & 0xFF) for i in range(3, -1, -1))

    @staticmethod
    def _prefix_to_wildcard(prefix_len: int) -> str:
        mask = (0xFFFFFFFF >> (32 - prefix_len)) << (32 - prefix_len)
        wildcard = ~mask & 0xFFFFFFFF
        return ".".join(str((wildcard >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


# ── Juniper JunOS Compiler ────────────────────────────────────────────

class JuniperJunOSCompiler(BaseCompiler):
    """Compiles intent primitives to Juniper JunOS set-format configuration."""

    platform = "juniper_junos"

    def compile_bgp(self, intent: BGPIntent, device=None) -> str:
        lines = []
        if intent.router_id:
            lines.append(f"set routing-options router-id {intent.router_id}")
        lines.append(f"set routing-options autonomous-system {intent.asn}")

        for nbr in intent.neighbors:
            base = f"set protocols bgp group PLEXAR-{nbr.remote_as} neighbor {nbr.ip}"
            lines.append(f"{base}")
            lines.append(f"set protocols bgp group PLEXAR-{nbr.remote_as} peer-as {nbr.remote_as}")
            if nbr.description:
                lines.append(f"{base} description \"{nbr.description}\"")
            if nbr.update_source:
                lines.append(f"set protocols bgp group PLEXAR-{nbr.remote_as} local-address {nbr.update_source}")
            if nbr.bfd:
                lines.append(f"{base} bfd-liveness-detection minimum-interval 300")

        return "\n".join(lines)

    def compile_interface(self, intent: InterfaceIntent, device=None) -> str:
        lines = []
        base = f"set interfaces {intent.name}"
        if intent.description is not None:
            lines.append(f"{base} description \"{intent.description}\"")
        if intent.mtu is not None:
            lines.append(f"{base} mtu {intent.mtu}")
        if intent.ip_address:
            lines.append(f"{base} unit 0 family inet address {intent.ip_address}")
        if intent.admin_state == "down":
            lines.append(f"{base} disable")
        return "\n".join(lines)

    def compile_vlan(self, intent: VLANIntent, device=None) -> str:
        lines = [f"set vlans vlan{intent.vlan_id} vlan-id {intent.vlan_id}"]
        if intent.name:
            lines.append(f"set vlans {intent.name} vlan-id {intent.vlan_id}")
        return "\n".join(lines)

    def compile_route(self, intent: RouteIntent, device=None) -> str:
        line = f"set routing-options static route {intent.prefix}"
        if intent.next_hop:
            line += f" next-hop {intent.next_hop}"
        else:
            line += " discard"
        return line

    def compile_ospf(self, intent: OSPFIntent, device=None) -> str:
        lines = []
        if intent.router_id:
            lines.append(f"set routing-options router-id {intent.router_id}")
        for network, area in intent.networks:
            lines.append(f"set protocols ospf area {area} interface {network}")
        return "\n".join(lines)

    def compile_ntp(self, intent: NTPIntent, device=None) -> str:
        lines = []
        for server in intent.servers:
            lines.append(f"set system ntp server {server}")
        if intent.timezone != "UTC":
            lines.append(f"set system time-zone {intent.timezone}")
        return "\n".join(lines)

    def compile_snmp(self, intent: SNMPIntent, device=None) -> str:
        lines = [f"set snmp community {intent.community} authorization read-only"]
        if intent.location:
            lines.append(f"set snmp location \"{intent.location}\"")
        if intent.contact:
            lines.append(f"set snmp contact \"{intent.contact}\"")
        return "\n".join(lines)

    def compile_banner(self, intent: BannerIntent, device=None) -> str:
        lines = []
        if intent.motd:
            lines.append(f"set system login message \"{intent.motd}\"")
        return "\n".join(lines)

    def compile_prefix_list(self, intent: PrefixListIntent, device=None) -> str:
        lines = []
        for entry in sorted(intent.entries, key=lambda e: e.seq):
            if entry.action == "permit":
                lines.append(f"set policy-options prefix-list {intent.name} {entry.prefix}")
        return "\n".join(lines)


# ── Registry ──────────────────────────────────────────────────────────

_COMPILERS: dict[str, BaseCompiler] = {}


def _register_builtins() -> None:
    for cls in [AristaEOSCompiler, CiscoNXOSCompiler, CiscoIOSCompiler, JuniperJunOSCompiler]:
        inst = cls()
        platforms = [cls.platform] if isinstance(cls.platform, str) else cls.platform
        for p in platforms:
            _COMPILERS[p] = inst


_register_builtins()


class IntentCompiler:
    """Public API for the compiler registry."""

    @staticmethod
    def for_platform(platform: str) -> BaseCompiler:
        compiler = _COMPILERS.get(platform.lower())
        if compiler is None:
            raise CompilerError(
                f"No intent compiler for platform '{platform}'. "
                f"Available: {list(_COMPILERS.keys())}"
            )
        return compiler

    @staticmethod
    def supported_platforms() -> list[str]:
        return list(_COMPILERS.keys())

    @staticmethod
    def register(compiler: BaseCompiler) -> None:
        """Register a custom compiler."""
        platforms = [compiler.platform] if isinstance(compiler.platform, str) else compiler.platform
        for p in platforms:
            _COMPILERS[p] = compiler
