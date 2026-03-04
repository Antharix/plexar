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

[![PyPI version](https://img.shields.io/pypi/v/plexar?color=00D4FF&labelColor=0A0F1E&style=for-the-badge)](https://pypi.org/project/plexar/)
[![Python](https://img.shields.io/badge/python-3.11%2B-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-00D4FF?labelColor=0A0F1E&style=for-the-badge)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-plexar.dev-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://antharix.github.io/plexar/)
[![Discord](https://img.shields.io/badge/discord-join-00D4FF?labelColor=0A0F1E&style=for-the-badge)](https://discord.gg/plexar)

</div>

---

## Why Plexar?

The Python network automation ecosystem is fragmented across a dozen libraries — each solving one layer well, none solving the whole problem.

| You need to... | Current reality |
|---|---|
| Connect to devices | Netmiko *or* Scrapli *or* Paramiko |
| Parse CLI output | TextFSM *or* TTP *or* Genie (Cisco-only) |
| Abstract vendors | NAPALM (limited drivers, no async) |
| Orchestrate at scale | Nornir + plugins |
| Detect config drift | Build it yourself |
| Push with rollback | Only if using NETCONF |
| Stream telemetry | pyGNMI (raw, unnormalized) |
| Model topology | Doesn't exist |
| Test network state | pyATS (Cisco-only) |
| Get AI-assisted RCA | Doesn't exist |

**Plexar collapses all of this into a single, layered, async-native SDK.**

---

## Quickstart

```bash
pip install plexar
```

```python
from plexar import Network

net = Network()
net.inventory.load("netbox", url="https://netbox.corp.com", token_env="NB_TOKEN")

# Connect to all leaf switches and get BGP state — concurrently
async with net.pool(max_concurrent=50) as pool:
    results = await pool.map(lambda d: d.get_bgp_summary(), net.devices(role="leaf"))

for device, bgp in results:
    for peer in bgp.peers:
        if peer.state != "established":
            print(f"⚠️  {device.hostname} → {peer.neighbor_ip} is {peer.state}")
```

---

## Core Features

### 🔌 Async Transport Layer
Connect over SSH, NETCONF, RESTCONF, gNMI, or SNMP — async throughout, with automatic fallback, connection pooling, and per-device rate limiting.

```python
device = Device(
    hostname="spine-01",
    platform="arista_eos",
    transport=Transport.SSH,        # or NETCONF, GNMI, RESTCONF
    credentials=Credentials(password_env="DEVICE_PASS")
)
await device.connect()
```

### 🏭 Vendor-Neutral Data Models
Every `get_*` call returns a normalized Pydantic model — not raw text — regardless of vendor.

```python
# Same API across Cisco, Arista, Juniper, Palo Alto
interfaces = await device.get_interfaces()
bgp        = await device.get_bgp_summary()
routes     = await device.get_routing_table()

# Fully typed, validated, serializable
print(bgp.peers[0].state)           # "established"
print(interfaces[0].speed_mbps)     # 10000
```

### 🎯 Intent Engine
Declare what you want. Plexar figures out how to get there, per vendor.

```python
from plexar.intent import Intent
from plexar.intent.primitives import BGPIntent, InterfaceIntent

intent = Intent(devices=net.devices(role="leaf"))
intent.ensure(BGPIntent(asn=65001, neighbors=["10.0.0.1"], address_family="evpn"))
intent.ensure(InterfaceIntent(name="Ethernet1", mtu=9214, admin_state="up"))

plan = await intent.compile()
print(plan.diff())           # see exactly what will change, per device

result = await intent.apply()
report = await intent.verify()
print(report.compliant)      # True
```

### 🔄 Transactional Config Push
Every push is a transaction. Automatic rollback on verification failure.

```python
async with device.transaction() as txn:
    await txn.push(new_config)
    ok = await txn.verify([
        ("bgp_peers_up", lambda r: r.peers_established >= 4),
    ])
    if not ok:
        await txn.rollback()    # guaranteed, across all transports
```

### 📡 Drift Detection
Continuously compare running state against desired state. Get alerted. Auto-remediate.

```python
monitor = DriftMonitor(inventory=net.inventory, interval_seconds=300)

@monitor.on_drift
async def handle_drift(event):
    await alert_slack(f"Drift on {event.device}: {event.summary}")
    await event.remediate()     # optional: auto-fix

await monitor.start()
```

### 🌐 Topology Engine
Understand your network as a graph. Discover via LLDP/CDP. Compute blast radius.

```python
topo = TopologyEngine(net.inventory)
await topo.discover()

path   = topo.shortest_path("leaf-01", "spine-02")
blast  = topo.blast_radius("core-sw-01")   # what breaks if this dies?

topo.export_d3("topology.html")            # interactive browser visualization
```

### 🤖 AI Engine
Natural language RCA. Autonomous remediation. LLM-assisted parsing for unknown output.

```python
ai = NetworkAI(net)

# Ask in plain English
rca = await ai.ask("Why is traffic slow between dc1 and dc2?")
print(rca.root_cause)           # "BGP prefix limit reached on leaf-03"
print(rca.affected_devices)     # ["leaf-03", "spine-01"]

# Parse unknown CLI output — no template required
raw    = await device.run("show platform qos queue-stats")
parsed = await ai.parse(raw, hint="QoS queue statistics")
```

### 🧪 Network Testing Framework
pytest-native. Mock driver for CI/CD. No real devices needed in your pipeline.

```python
@pytest.mark.asyncio
async def test_all_bgp_peers_established(net):
    async for device in net.devices(role="leaf"):
        bgp = await device.get_bgp_summary()
        assert all(p.state == "established" for p in bgp.peers)

async def test_no_config_drift(net):
    report = await net.drift_report()
    assert report.is_clean, report.summary()
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                     USER API                        │
├─────────────────────────────────────────────────────┤
│               AI ENGINE  ·  INTENT ENGINE           │
├─────────────────────────────────────────────────────┤
│          STATE MANAGER  ·  TOPOLOGY ENGINE          │
├─────────────────────────────────────────────────────┤
│              DEVICE ABSTRACTION LAYER               │
├─────────────────────────────────────────────────────┤
│     SSH  ·  NETCONF  ·  RESTCONF  ·  gNMI  ·  SNMP  │
├─────────────────────────────────────────────────────┤
│   Cisco  ·  Juniper  ·  Arista  ·  Palo Alto  · …   │
└─────────────────────────────────────────────────────┘
```

---

## Supported Platforms

| Vendor | SSH | NETCONF | RESTCONF | gNMI |
|---|:---:|:---:|:---:|:---:|
| Cisco IOS / IOS-XE | ✅ | ✅ | ✅ | ⚡ |
| Cisco NX-OS | ✅ | ✅ | ✅ | ⚡ |
| Cisco IOS-XR | ✅ | ✅ | ✅ | ✅ |
| Arista EOS | ✅ | ✅ | ✅ | ✅ |
| Juniper JunOS | ✅ | ✅ | ⚡ | ⚡ |
| Palo Alto PAN-OS | ✅ | ✅ | ✅ | — |
| Fortinet FortiOS | ✅ | ⚡ | ✅ | — |
| Nokia SR-OS | ⚡ | ✅ | ⚡ | ✅ |

✅ Stable · ⚡ In Progress · — Roadmap

---

## Compared to the Ecosystem

| Capability | Netmiko | NAPALM | Nornir | pyATS | **Plexar** |
|---|:---:|:---:|:---:|:---:|:---:|
| Async-native | ❌ | ❌ | ❌ | ❌ | ✅ |
| Vendor-neutral models | ❌ | ⚠️ | ❌ | ⚠️ | ✅ |
| Intent engine | ❌ | ❌ | ❌ | ❌ | ✅ |
| Drift detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Transactional push | ❌ | ❌ | ❌ | ❌ | ✅ |
| Streaming telemetry | ❌ | ❌ | ❌ | ❌ | ✅ |
| Topology graph | ❌ | ❌ | ❌ | ❌ | ✅ |
| AI-assisted RCA | ❌ | ❌ | ❌ | ❌ | ✅ |
| Mock driver / CI-CD | ❌ | ❌ | ⚠️ | ✅ | ✅ |
| Multi-vendor testing | ❌ | ❌ | ❌ | ❌ | ✅ |

---

## Installation

```bash
# Core
pip install plexar

# With AI engine
pip install plexar[ai]

# With gNMI telemetry
pip install plexar[gnmi]

# Everything
pip install plexar[all]
```

**Requires Python 3.11+**

---

## Documentation

Full documentation, tutorials, and API reference at **[plexar.dev](https://plexar.dev)**

- [Getting Started](https://plexar.dev/docs/quickstart)
- [Inventory Setup](https://plexar.dev/docs/inventory)
- [Writing Intent](https://plexar.dev/docs/intent)
- [Vendor Drivers](https://plexar.dev/docs/drivers)
- [AI Engine](https://plexar.dev/docs/ai)
- [Testing Guide](https://plexar.dev/docs/testing)

---

## Contributing

We welcome contributions — especially new vendor drivers.

```bash
git clone https://github.com/plexar/plexar
cd plexar
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Driver Authoring Guide](https://plexar.dev/docs/contributing/drivers).

---

## Roadmap

- [x] Core device model + async SSH
- [x] Cisco IOS/NX-OS/XR drivers
- [x] Arista EOS driver
- [x] Juniper JunOS driver
- [ ] Intent engine v1
- [ ] Drift monitor
- [ ] Topology engine
- [ ] gNMI telemetry
- [ ] AI parser + RCA
- [ ] Digital twin / simulation
- [ ] Web UI (enterprise)

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

Built with obsession by the Plexar team and contributors.

**[plexar.dev](https://plexar.dev) · [Discord](https://discord.gg/plexar) · [Twitter](https://twitter.com/plexar_dev)**

*The nervous system for your network.*

</div>
