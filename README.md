<div align="center">
<br/>
<pre>
██████╗ ██╗     ███████╗██╗  ██╗ █████╗ ██████╗
██╔══██╗██║     ██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗
██████╔╝██║     █████╗   ╚███╔╝ ███████║██████╔╝
██╔═══╝ ██║     ██╔══╝   ██╔██╗ ██╔══██║██╔══██╗
██║     ███████╗███████╗██╔╝ ██╗██║  ██║██║  ██║
╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
</pre>
    
**The nervous system for your network.**

*A unified, async-first Python SDK for network automation — transport, parsing, intent, telemetry, topology, and AI in one platform.*

<br/>

{![PyPI](https://img.shields.io/pypi/v/plexar?color=00D4FF&labelColor=0A0F1E&style=for-the-badge)]
[![Python](https://img.shields.io/badge/python-3.11%2B-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-00D4FF?labelColor=0A0F1E&style=for-the-badge)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-plexar.dev-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://antharix.github.io/plexar/)
[![Discord](https://img.shields.io/badge/discord-join-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://discord.gg/plexar)

</div>

Plexar is a production-grade Python SDK and CLI for network automation. It unifies vendor-specific APIs behind a clean, async-first interface and layers in security, AI, intent-based management, topology analysis, and change simulation — all out of the box.
```bash
pip install plexar
```

---

## What Plexar Does

```python
import asyncio
from plexar import Network

async def main():
    net = Network()
    net.inventory.load("yaml", path="inventory.yaml")

    # Query every device in the fleet concurrently
    async with net.pool() as pool:
        results = await pool.run_on_all("show bgp summary")

    # Ask a natural language question
    from plexar.ai import NetworkQuery
    nq     = NetworkQuery(network=net)
    result = await nq.ask("which leafs have BGP peers down?")
    print(result.answer)

asyncio.run(main())
```

```bash
# Or use the CLI
plexar --inventory inventory.yaml bgp fleet --role leaf
plexar ask "which devices have BGP peers down?"
plexar intent apply ./intent/bgp.yaml
```

---

## Features

### 🔌 Multi-Vendor Support
Arista EOS, Cisco IOS/IOS-XE, Cisco NX-OS, Juniper JunOS — with a clean driver abstraction for adding more. Every driver implements the same interface.

### 🎯 Intent Engine
Declare what you want. Plexar figures out the commands.

```python
from plexar.intent import Intent, BGPIntent

intent = Intent(devices=leafs)
intent.ensure(BGPIntent(asn=65001, neighbors=[
    BGPNeighbor(ip="10.0.0.1", remote_as=65000, description="spine-01"),
]))
await intent.apply()
```

### 🧠 AI Features
- **AI Parser**: LLM-powered fallback for unknown vendors or unparseable output
- **RCA Engine**: Root cause analysis with automated remediation suggestions
- **Natural Language Query**: Ask questions in plain English, get fleet-wide answers

### 🔐 Security-First
Every operation is sanitized, audited, and access-controlled. The security layer is automatic — no opt-in required.

- Input sanitization: command injection, prompt injection, SSTI, path traversal
- Append-only audit trail with SIEM/Splunk export
- RBAC: VIEWER → OPERATOR → ENGINEER → ADMIN → SUPERADMIN
- Multi-backend secrets: HashiCorp Vault, OS keyring, environment variables
- TLS/SSH policy enforcement

### 🗺️ Topology Engine
Discover your network topology via LLDP/CDP. Find paths, calculate blast radius, detect single points of failure.

```python
from plexar.topology import TopologyGraph

topo  = TopologyGraph()
await topo.discover(inventory)
blast = topo.blast_radius("spine-01")
path  = topo.shortest_path("server-01", "firewall-01")
```

### 👯 Digital Twin
Simulate changes before you push them to production.

```python
from plexar.twin import DigitalTwin

twin   = DigitalTwin()
await twin.capture(network=net)
result = twin.simulate_interface_failure("leaf-01", "Ethernet1")
print(f"Risk score: {result.risk_score}/100")
print(result.impact_summary())
```

### 📡 Streaming Telemetry
Subscribe to gNMI streams and react to events with an async pub/sub event bus.

### 📊 Reporting
HTML, JSON, and text reports for compliance checks, change operations, and inventory.

### 🔌 Plugin SDK
Extend Plexar with custom drivers, inventory sources, validators, and more — published as ordinary Python packages.

### 🔗 Integrations
- **NetBox** — use as inventory source or sync device changes
- **Nautobot** — GraphQL-native integration
- **OpenTelemetry** — export all Plexar metrics to your observability stack
- **HashiCorp Vault** — secrets backend

---

## Installation

```bash
# Core
pip install plexar

# With AI features (requires OPENAI_API_KEY or ANTHROPIC_API_KEY)
pip install plexar[ai]

# With gNMI streaming
pip install plexar[gnmi]

# With NETCONF
pip install plexar[netconf]

# With NetBox integration
pip install plexar[netbox]

# With Nautobot integration
pip install plexar[nautobot]

# With OpenTelemetry export
pip install plexar[telemetry]

# With HashiCorp Vault
pip install plexar[vault]

# Everything
pip install plexar[all]
```

---

## Quick Start

**1. Create your inventory:**

```yaml
# inventory.yaml
devices:
  - hostname: spine-01
    management_ip: 192.168.1.1
    platform: arista_eos
    credentials:
      username: admin
      password_env: NET_PASSWORD
    metadata:
      role: spine
      site: dc1

  - hostname: leaf-01
    management_ip: 192.168.1.10
    platform: arista_eos
    credentials:
      username: admin
      password_env: NET_PASSWORD
    metadata:
      role: leaf
      site: dc1
```

**2. Connect and query:**

```python
import asyncio
from plexar import Network

async def main():
    net = Network()
    net.inventory.load("yaml", path="inventory.yaml")

    device = net.inventory.get("spine-01")
    async with device:
        bgp        = await device.get_bgp_summary()
        interfaces = await device.get_interfaces()

    print(f"BGP peers established: {bgp.peers_established}")
    print(f"Interfaces up: {sum(1 for i in interfaces if i.oper_state == 'up')}")

asyncio.run(main())
```

**3. Or use the CLI:**

```bash
export NET_PASSWORD=secret
plexar --inventory inventory.yaml devices list
plexar --inventory inventory.yaml bgp show spine-01
plexar --inventory inventory.yaml bgp fleet
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     USER API / CLI                      │
├───────────────────┬─────────────────────────────────────┤
│   AI ENGINE       │   INTENT ENGINE                     │
│   • AI Parser     │   • Primitives (BGP, VLAN, Route…)  │
│   • RCA Engine    │   • 4-vendor compiler               │
│   • NL Query      │   • Plan / Apply / Verify           │
├───────────────────┴──────────────┬──────────────────────┤
│   STATE MANAGER                  │   TOPOLOGY ENGINE    │
│   • Snapshots                    │   • LLDP/CDP         │
│   • Drift Monitor                │   • Graph analysis   │
│   • Digital Twin                 │   • Blast radius     │
├──────────────────────────────────┴──────────────────────┤
│               DEVICE ABSTRACTION LAYER                  │
│   • Config diff / transaction                           │
│   • Parsers (Regex/TTP/TextFSM/JSON/XML)               │
│   • Security (sanitize / audit / RBAC)                  │
│   • Connection Pool                                     │
├─────────────────────────────────────────────────────────┤
│            TRANSPORT + VENDOR DRIVERS                   │
│   Arista EOS │ Cisco IOS │ Cisco NX-OS │ Juniper JunOS  │
│   SSH/Scrapli │ NETCONF/ncclient │ gNMI/grpc            │
└─────────────────────────────────────────────────────────┘
```

---

## Documentation

Full documentation is available at [plexar.dev](https://plexar.dev) (coming soon) or in the `docs/` directory.

| Guide | Description |
|---|---|
| [Installation](docs/installation.md) | All installation options and extras |
| [Quick Start](docs/quickstart.md) | Up and running in 5 minutes |
| [Core Concepts](docs/concepts.md) | Architecture and mental model |
| [Inventory Guide](docs/guides/inventory.md) | YAML, NetBox, Nautobot, programmatic |
| [Device Operations](docs/guides/devices.md) | Connect, query, push config |
| [Intent Engine](docs/guides/intent.md) | Declare-and-apply configuration management |
| [Security](docs/guides/security.md) | Audit, RBAC, secrets, TLS |
| [Topology](docs/guides/topology.md) | Discovery, path analysis, blast radius |
| [AI Features](docs/guides/ai.md) | Parser, RCA, natural language query |
| [Digital Twin](docs/guides/twin.md) | Change simulation |
| [Telemetry](docs/guides/telemetry.md) | gNMI streaming and events |
| [Reporting](docs/guides/reporting.md) | HTML/JSON/text reports |
| [CLI Reference](docs/cli.md) | All commands and options |
| [Plugin Development](docs/plugins.md) | Build and publish extensions |
| [CI/CD Guide](docs/cicd.md) | Network-as-code pipeline |
| [Integrations](docs/integrations.md) | NetBox, Nautobot, OpenTelemetry, Vault |

---

## License

Apache 2.0 — free for commercial and open-source use.

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/yourorg/plexar
cd plexar
pip install -e ".[all,dev]"
pytest
```
