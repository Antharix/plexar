"""
Plexar CLI — plexar command line interface.

The CLI is the fastest way to use Plexar without writing Python.
It wraps the full Plexar SDK and exposes every major operation as
a command with rich terminal output.

Commands:
    plexar devices list              — list all devices in inventory
    plexar devices connect <host>    — test connectivity
    plexar devices show <host>       — show device details

    plexar bgp show <host>           — show BGP summary
    plexar bgp peers <host>          — show BGP peer details

    plexar interfaces show <host>    — show interface table
    plexar interfaces errors <host>  — show interfaces with errors

    plexar intent apply <file>       — apply intent from YAML file
    plexar intent plan <file>        — plan without applying
    plexar intent verify <file>      — verify current state vs intent

    plexar topology discover         — discover topology via LLDP
    plexar topology show             — print topology as ASCII or JSON
    plexar topology path <a> <b>     — show path between two devices
    plexar topology blast <host>     — show blast radius for a device

    plexar snapshot capture          — capture state snapshot of fleet
    plexar snapshot diff             — diff current state vs snapshot

    plexar rca analyze <host>        — run RCA on a device
    plexar ask "<question>"          — ask a natural language question

    plexar config push <host> <file> — push config to a device

Usage:
    plexar --inventory ./inventory.yaml devices list
    plexar --inventory ./inventory.yaml bgp show spine-01
    plexar ask "which leafs have BGP peers down?"
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("Plexar CLI requires: pip install plexar[cli]  (installs click, rich)")
    sys.exit(1)

console = Console()

# ── Global options ────────────────────────────────────────────────────

@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.option("--inventory", "-i", default="inventory.yaml",
              envvar="PLEXAR_INVENTORY", help="Path to inventory file")
@click.option("--model", default="gpt-4o-mini", envvar="PLEXAR_AI_MODEL",
              help="AI model for RCA/query features")
@click.option("--output", "-o", type=click.Choice(["table", "json", "yaml"]),
              default="table", help="Output format")
@click.option("--no-color", is_flag=True, help="Disable color output")
@click.version_option(version="0.5.0", prog_name="plexar")
@click.pass_context
def cli(ctx: click.Context, inventory: str, model: str, output: str, no_color: bool) -> None:
    """Plexar — the nervous system for your network."""
    ctx.ensure_object(dict)
    ctx.obj["inventory"] = inventory
    ctx.obj["model"]     = model
    ctx.obj["output"]    = output
    ctx.obj["no_color"]  = no_color

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def _run(coro: Any) -> Any:
    """Run an async coroutine from a sync CLI command."""
    return asyncio.run(coro)


def _load_network(ctx: click.Context) -> Any:
    """Load Network from inventory file."""
    from plexar import Network
    inventory_path = ctx.obj["inventory"]
    net = Network()
    if Path(inventory_path).exists():
        net.inventory.load("yaml", path=inventory_path)
    else:
        console.print(f"[yellow]Warning: inventory file '{inventory_path}' not found[/yellow]")
    return net


# ── devices group ─────────────────────────────────────────────────────

@cli.group()
def devices() -> None:
    """Device inventory and connectivity commands."""


@devices.command("list")
@click.option("--role",    help="Filter by role")
@click.option("--site",    help="Filter by site")
@click.option("--tag",     multiple=True, help="Filter by tag (repeatable)")
@click.option("--platform", help="Filter by platform")
@click.pass_context
def devices_list(ctx: click.Context, role: str, site: str, tag: tuple, platform: str) -> None:
    """List all devices in inventory."""
    net     = _load_network(ctx)
    filters = {}
    if role:     filters["role"]     = role
    if site:     filters["site"]     = site
    if tag:      filters["tags"]     = list(tag)
    if platform: filters["platform"] = platform

    devs = net.devices(**filters) if filters else net.inventory.all()

    if ctx.obj["output"] == "json":
        data = [
            {
                "hostname": d.hostname,
                "platform": str(d.platform),
                "management_ip": d.management_ip,
                "role": d.metadata.get("role", ""),
                "site": d.metadata.get("site", ""),
                "tags": list(d.tags),
            }
            for d in devs
        ]
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"Devices ({len(devs)} total)", show_header=True)
    table.add_column("Hostname",  style="cyan", no_wrap=True)
    table.add_column("Platform",  style="green")
    table.add_column("Mgmt IP",   style="yellow")
    table.add_column("Role")
    table.add_column("Site")
    table.add_column("Tags", style="dim")

    for d in devs:
        table.add_row(
            d.hostname,
            str(d.platform),
            d.management_ip or "—",
            d.metadata.get("role", "—"),
            d.metadata.get("site", "—"),
            ", ".join(d.tags) or "—",
        )
    console.print(table)


@devices.command("connect")
@click.argument("hostname")
@click.pass_context
def devices_connect(ctx: click.Context, hostname: str) -> None:
    """Test connectivity to a device."""
    net = _load_network(ctx)

    async def _test() -> None:
        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found in inventory[/red]")
            sys.exit(1)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
            p.add_task(f"Connecting to {hostname}...", total=None)
            try:
                async with device:
                    info = await device.get_platform_info()
                console.print(f"[green]✓[/green] {hostname} — {info.platform} {info.version}")
            except Exception as exc:
                console.print(f"[red]✗[/red] {hostname} — {exc}")
                sys.exit(1)

    _run(_test())


@devices.command("show")
@click.argument("hostname")
@click.pass_context
def devices_show(ctx: click.Context, hostname: str) -> None:
    """Show detailed info for a device."""
    net = _load_network(ctx)

    async def _show() -> None:
        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found[/red]")
            sys.exit(1)

        async with device:
            info       = await device.get_platform_info()
            interfaces = await device.get_interfaces()
            bgp        = await device.get_bgp_summary()

        up_ifaces   = sum(1 for i in interfaces if i.oper_state == "up")
        down_ifaces = sum(1 for i in interfaces if i.oper_state != "up")

        panel_text = (
            f"[bold]Platform:[/bold]      {info.platform}\n"
            f"[bold]Version:[/bold]       {info.version}\n"
            f"[bold]Model:[/bold]         {info.model}\n"
            f"[bold]Serial:[/bold]        {info.serial}\n"
            f"[bold]Uptime:[/bold]        {info.uptime}\n"
            f"\n"
            f"[bold]Interfaces:[/bold]    {up_ifaces} up / {down_ifaces} down\n"
            f"[bold]BGP Peers:[/bold]     {bgp.peers_established} established / "
            f"{bgp.peers_down} down\n"
            f"[bold]BGP Prefixes:[/bold]  {bgp.total_prefixes_received:,} received\n"
        )
        console.print(Panel(panel_text, title=f"[bold cyan]{hostname}[/bold cyan]",
                            border_style="cyan"))

    _run(_show())


# ── bgp group ─────────────────────────────────────────────────────────

@cli.group()
def bgp() -> None:
    """BGP operations and diagnostics."""


@bgp.command("show")
@click.argument("hostname")
@click.pass_context
def bgp_show(ctx: click.Context, hostname: str) -> None:
    """Show BGP summary for a device."""
    net = _load_network(ctx)

    async def _show() -> None:
        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found[/red]")
            sys.exit(1)

        async with device:
            summary = await device.get_bgp_summary()

        if ctx.obj["output"] == "json":
            click.echo(summary.model_dump_json(indent=2))
            return

        console.print(f"\n[bold]BGP Summary — {hostname}[/bold]")
        console.print(f"  Local AS:   {summary.local_as}")
        console.print(f"  Router ID:  {summary.router_id}")
        console.print(f"  Established: [green]{summary.peers_established}[/green]  "
                      f"Down: [red]{summary.peers_down}[/red]  "
                      f"Total prefixes: {summary.total_prefixes_received:,}\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Neighbor",   style="cyan", no_wrap=True)
        table.add_column("AS",         style="yellow")
        table.add_column("State",      style="green")
        table.add_column("Prefixes",   justify="right")
        table.add_column("Uptime/Age", style="dim")

        for peer in summary.peers:
            state_style = "green" if peer.state.lower() == "established" else "red"
            table.add_row(
                peer.neighbor_ip,
                str(peer.remote_as),
                Text(peer.state, style=state_style),
                str(peer.prefixes_received),
                peer.uptime or "—",
            )
        console.print(table)

    _run(_show())


@bgp.command("fleet")
@click.option("--role", default="all", help="Filter by role")
@click.pass_context
def bgp_fleet(ctx: click.Context, role: str) -> None:
    """Show BGP health across the fleet."""
    net = _load_network(ctx)

    async def _fleet() -> None:
        devs = net.devices(role=role) if role != "all" else net.inventory.all()
        if not devs:
            console.print("[yellow]No devices found[/yellow]")
            return

        import asyncio
        semaphore = asyncio.Semaphore(20)

        async def get_bgp(device: Any) -> dict:
            async with semaphore:
                try:
                    async with device:
                        bgp = await device.get_bgp_summary()
                    return {"hostname": device.hostname, "bgp": bgp, "error": None}
                except Exception as exc:
                    return {"hostname": device.hostname, "bgp": None, "error": str(exc)}

        results = await asyncio.gather(*[get_bgp(d) for d in devs])

        table = Table(title=f"BGP Fleet Status ({len(devs)} devices)", show_header=True)
        table.add_column("Device",      style="cyan", no_wrap=True)
        table.add_column("Local AS",    style="yellow")
        table.add_column("Established", style="green", justify="right")
        table.add_column("Down",        style="red",   justify="right")
        table.add_column("Prefixes",    justify="right")
        table.add_column("Status")

        for r in results:
            if r["error"]:
                table.add_row(r["hostname"], "—", "—", "—", "—",
                              Text("UNREACHABLE", style="red"))
            else:
                bgp = r["bgp"]
                status = Text("✓ OK", style="green") if bgp.peers_down == 0 else \
                         Text(f"⚠ {bgp.peers_down} down", style="yellow")
                table.add_row(
                    r["hostname"],
                    str(bgp.local_as),
                    str(bgp.peers_established),
                    str(bgp.peers_down),
                    f"{bgp.total_prefixes_received:,}",
                    status,
                )
        console.print(table)

    _run(_fleet())


# ── interfaces group ──────────────────────────────────────────────────

@cli.group()
def interfaces() -> None:
    """Interface inspection commands."""


@interfaces.command("show")
@click.argument("hostname")
@click.option("--down-only", is_flag=True, help="Show only down interfaces")
@click.pass_context
def interfaces_show(ctx: click.Context, hostname: str, down_only: bool) -> None:
    """Show interfaces for a device."""
    net = _load_network(ctx)

    async def _show() -> None:
        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found[/red]")
            sys.exit(1)

        async with device:
            ifaces = await device.get_interfaces()

        if down_only:
            ifaces = [i for i in ifaces if i.oper_state != "up"]

        if ctx.obj["output"] == "json":
            click.echo(json.dumps([i.model_dump() for i in ifaces], indent=2, default=str))
            return

        table = Table(title=f"Interfaces — {hostname}", show_header=True)
        table.add_column("Name",       style="cyan", no_wrap=True)
        table.add_column("Admin",      justify="center")
        table.add_column("Oper",       justify="center")
        table.add_column("MTU",        justify="right")
        table.add_column("Speed",      justify="right")
        table.add_column("Description", style="dim")

        for i in ifaces:
            admin_style = "green" if i.admin_state == "up" else "red"
            oper_style  = "green" if i.oper_state  == "up" else "red"
            table.add_row(
                i.name,
                Text(i.admin_state, style=admin_style),
                Text(i.oper_state,  style=oper_style),
                str(i.mtu or "—"),
                f"{i.speed_mbps:,}" if i.speed_mbps else "—",
                i.description or "—",
            )
        console.print(table)

    _run(_show())


# ── intent group ──────────────────────────────────────────────────────

@cli.group()
def intent() -> None:
    """Intent-based configuration management."""


@intent.command("plan")
@click.argument("intent_file", type=click.Path(exists=True))
@click.pass_context
def intent_plan(ctx: click.Context, intent_file: str) -> None:
    """Show what would change without applying."""
    net = _load_network(ctx)

    async def _plan() -> None:
        loaded_intent = _load_intent_file(intent_file, net)
        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task("Planning...", total=None)
            plan = await loaded_intent.plan()
        console.print(plan.render(color=not ctx.obj["no_color"]))

    _run(_plan())


@intent.command("apply")
@click.argument("intent_file", type=click.Path(exists=True))
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def intent_apply(ctx: click.Context, intent_file: str, yes: bool) -> None:
    """Apply intent to network devices."""
    net = _load_network(ctx)

    async def _apply() -> None:
        loaded_intent = _load_intent_file(intent_file, net)

        # Show plan first
        console.print("[dim]Computing plan...[/dim]")
        plan = await loaded_intent.plan()
        console.print(plan.render(color=not ctx.obj["no_color"]))

        if not plan.devices_with_changes:
            console.print("[green]✓ Network already matches intent — nothing to do[/green]")
            return

        if not yes:
            click.confirm(
                f"\nApply to {len(plan.devices_with_changes)} device(s)?",
                abort=True,
            )

        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task(f"Applying to {len(plan.devices_with_changes)} devices...", total=None)
            result = await loaded_intent.apply()

        console.print(f"\n{result.summary()}")
        if not result.all_succeeded:
            sys.exit(1)

    _run(_apply())


@intent.command("verify")
@click.argument("intent_file", type=click.Path(exists=True))
@click.pass_context
def intent_verify(ctx: click.Context, intent_file: str) -> None:
    """Verify running state matches intent."""
    net = _load_network(ctx)

    async def _verify() -> None:
        loaded_intent = _load_intent_file(intent_file, net)
        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task("Verifying...", total=None)
            report = await loaded_intent.verify()

        passed = sum(1 for r in report.results if r.passed)
        failed = sum(1 for r in report.results if not r.passed)

        console.print(f"\n[bold]Verification Report[/bold]  "
                      f"[green]{passed} passed[/green]  [red]{failed} failed[/red]\n")

        for r in report.results:
            icon = "[green]✓[/green]" if r.passed else "[red]✗[/red]"
            console.print(f"  {icon}  {r.name}: {r.reason}")

        if not report.passed:
            sys.exit(1)

    _run(_verify())


def _load_intent_file(intent_file: str, net: Any) -> Any:
    """Load and parse an intent YAML file."""
    import yaml
    from plexar.intent import (
        Intent, BGPIntent, BGPNeighbor, InterfaceIntent, VLANIntent,
        RouteIntent, NTPIntent, SNMPIntent, BannerIntent,
    )

    with open(intent_file) as f:
        data = yaml.safe_load(f)

    # Resolve devices
    filters    = data.get("devices", {})
    role       = filters.get("role")
    site       = filters.get("site")
    hostnames  = filters.get("hostnames", [])

    if hostnames:
        devs = [net.inventory.get(h) for h in hostnames if net.inventory.get(h)]
    elif role or site:
        kw = {}
        if role: kw["role"] = role
        if site: kw["site"] = site
        devs = net.devices(**kw)
    else:
        devs = net.inventory.all()

    loaded_intent = Intent(devices=devs)

    _PRIMITIVE_MAP = {
        "bgp":        BGPIntent,
        "interface":  InterfaceIntent,
        "vlan":       VLANIntent,
        "route":      RouteIntent,
        "ntp":        NTPIntent,
        "snmp":       SNMPIntent,
        "banner":     BannerIntent,
    }

    for primitive_data in data.get("ensure", []):
        ptype = primitive_data.pop("type", None)
        if ptype and ptype in _PRIMITIVE_MAP:
            loaded_intent.ensure(_PRIMITIVE_MAP[ptype](**primitive_data))

    return loaded_intent


# ── topology group ────────────────────────────────────────────────────

@cli.group()
def topology() -> None:
    """Network topology discovery and analysis."""


@topology.command("discover")
@click.option("--protocol", type=click.Choice(["lldp", "cdp"]), default="lldp")
@click.pass_context
def topology_discover(ctx: click.Context, protocol: str) -> None:
    """Discover network topology via LLDP/CDP."""
    net = _load_network(ctx)

    async def _discover() -> None:
        from plexar.topology import TopologyGraph
        topo = TopologyGraph()
        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task(f"Discovering via {protocol.upper()}...", total=None)
            await topo.discover(net.inventory, protocol=protocol)

        console.print(f"\n[green]✓[/green] Discovered: {repr(topo)}\n")
        segs = topo.segments()
        for role, hosts in segs.items():
            console.print(f"  [bold]{role}[/bold]: {', '.join(hosts)}")

        spof = topo.single_points_of_failure()
        if spof:
            console.print(f"\n[yellow]⚠  Single points of failure: {', '.join(spof)}[/yellow]")

    _run(_discover())


@topology.command("path")
@click.argument("source")
@click.argument("target")
@click.pass_context
def topology_path(ctx: click.Context, source: str, target: str) -> None:
    """Show the shortest path between two devices."""
    net = _load_network(ctx)

    async def _path() -> None:
        from plexar.topology import TopologyGraph
        topo = TopologyGraph()
        topo.add_from_inventory(net.inventory)

        try:
            path    = topo.shortest_path(source, target)
            all_p   = topo.all_paths(source, target)
            console.print(f"\n[bold]Path: {source} → {target}[/bold]")
            console.print(f"  Hops: {len(path) - 1}")
            console.print(f"  Path: {' → '.join(path)}")
            console.print(f"  Redundant paths: {len(all_p)}")
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

    _run(_path())


@topology.command("blast")
@click.argument("hostname")
@click.pass_context
def topology_blast(ctx: click.Context, hostname: str) -> None:
    """Show blast radius if a device is removed."""
    net = _load_network(ctx)

    async def _blast() -> None:
        from plexar.topology import TopologyGraph
        topo = TopologyGraph()
        topo.add_from_inventory(net.inventory)

        try:
            blast = topo.blast_radius(hostname)
            console.print(f"\n{blast.summary()}")
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

    _run(_blast())


# ── snapshot group ────────────────────────────────────────────────────

@cli.group()
def snapshot() -> None:
    """Network state snapshot and drift detection."""


@snapshot.command("capture")
@click.option("--output-dir", default="./snapshots", help="Where to save snapshots")
@click.option("--role", help="Filter by role")
@click.pass_context
def snapshot_capture(ctx: click.Context, output_dir: str, role: str) -> None:
    """Capture state snapshots of all devices."""
    net = _load_network(ctx)

    async def _capture() -> None:
        from plexar.state.snapshot import StateSnapshot
        import asyncio, os

        devs = net.devices(role=role) if role else net.inventory.all()
        os.makedirs(output_dir, exist_ok=True)
        semaphore = asyncio.Semaphore(20)
        captured, failed = 0, 0

        async def cap(device: Any) -> None:
            nonlocal captured, failed
            async with semaphore:
                try:
                    async with device:
                        snap = await StateSnapshot.capture(device)
                    path = os.path.join(output_dir, f"{device.hostname}.json")
                    snap.save(path)
                    captured += 1
                except Exception as exc:
                    console.print(f"[yellow]  ✗ {device.hostname}: {exc}[/yellow]")
                    failed += 1

        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task(f"Capturing {len(devs)} devices...", total=None)
            await asyncio.gather(*[cap(d) for d in devs])

        console.print(f"\n[green]✓[/green] Captured {captured} / {len(devs)} devices → {output_dir}")
        if failed:
            console.print(f"[yellow]  {failed} device(s) failed[/yellow]")

    _run(_capture())


# ── rca command ───────────────────────────────────────────────────────

@cli.command("rca")
@click.argument("hostname")
@click.option("--event-type", default="bgp.peer_down", help="Event type to analyze")
@click.pass_context
def rca_command(ctx: click.Context, hostname: str, event_type: str) -> None:
    """Run AI root cause analysis on a device."""
    net = _load_network(ctx)

    async def _rca() -> None:
        from plexar.ai import RCAEngine
        from plexar.telemetry.events import PlexarEvent, EventType

        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found[/red]")
            sys.exit(1)

        engine = RCAEngine(model=ctx.obj["model"])
        event  = PlexarEvent(
            type=EventType.BGP_PEER_DOWN,
            hostname=hostname,
            data={},
        )

        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task(f"Running RCA on {hostname}...", total=None)
            try:
                async with device:
                    diagnosis = await engine.analyze(event=event, device=device)
            except Exception:
                diagnosis = await engine.analyze(event=event)

        console.print(f"\n{diagnosis.render(color=not ctx.obj['no_color'])}")

    _run(_rca())


# ── ask command ───────────────────────────────────────────────────────

@cli.command("ask")
@click.argument("question")
@click.pass_context
def ask_command(ctx: click.Context, question: str) -> None:
    """Ask a natural language question about your network."""
    net = _load_network(ctx)

    async def _ask() -> None:
        from plexar.ai import NetworkQuery
        nq = NetworkQuery(network=net, model=ctx.obj["model"])

        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as p:
            p.add_task("Thinking...", total=None)
            result = await nq.ask(question)

        console.print(f"\n[bold cyan]Q:[/bold cyan] {question}")
        console.print(f"[bold green]A:[/bold green] {result.answer}\n")

        if result.followups:
            console.print("[dim]You might also ask:[/dim]")
            for q in result.followups:
                console.print(f"  [dim]• {q}[/dim]")

    _run(_ask())


# ── config group ──────────────────────────────────────────────────────

@cli.group("config")
def config_group() -> None:
    """Configuration push and management."""


@config_group.command("push")
@click.argument("hostname")
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def config_push(ctx: click.Context, hostname: str, config_file: str, yes: bool) -> None:
    """Push a config file to a device."""
    net = _load_network(ctx)

    async def _push() -> None:
        device = net.inventory.get(hostname)
        if not device:
            console.print(f"[red]Device '{hostname}' not found[/red]")
            sys.exit(1)

        config = Path(config_file).read_text()
        console.print(f"\n[dim]Config to push ({len(config.splitlines())} lines):[/dim]")
        console.print(f"[dim]{config[:500]}{'...' if len(config) > 500 else ''}[/dim]\n")

        if not yes:
            click.confirm(f"Push to {hostname}?", abort=True)

        async with device:
            async with device.transaction() as txn:
                await txn.push(config)
                await txn.commit()

        console.print(f"[green]✓[/green] Config pushed to {hostname}")

    _run(_push())


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
