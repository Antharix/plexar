"""
Natural Language Query Engine.

Ask your network questions in plain English. Get structured answers.

This translates natural language questions into Plexar API calls,
executes them across the fleet, and returns human-readable answers.

Examples:
    net.ask("which leaf switches have BGP peers down?")
    net.ask("what's the MTU on all spine uplinks?")
    net.ask("show me interfaces with errors above 100 in the last hour")
    net.ask("which devices are running EOS version older than 4.28?")
    net.ask("is there a path from leaf-01 to leaf-08?")
    net.ask("what changed on spine-01 in the last snapshot?")

Architecture:
    1. LLM translates question → structured query plan
    2. Plexar executes the plan (connects, runs getters)
    3. LLM synthesizes results → natural language answer
    4. Structured data is also returned for programmatic use

Usage:
    from plexar.ai import NetworkQuery

    nq = NetworkQuery(network=net, model="gpt-4o-mini")

    result = await nq.ask("which leafs have BGP peers down?")
    print(result.answer)
    print(result.data)      # structured data behind the answer
    print(result.devices)   # devices that were queried
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from plexar.security.sanitizer import sanitize_for_llm, redact_credentials
from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType

if TYPE_CHECKING:
    from plexar.core.network import Network
    from plexar.core.device import Device

logger = logging.getLogger(__name__)


# ── Query Models ──────────────────────────────────────────────────────

@dataclass
class QueryResult:
    """Result of a natural language network query."""
    question:   str
    answer:     str
    data:       list[dict[str, Any]]    = field(default_factory=list)
    devices:    list[str]               = field(default_factory=list)
    confidence: float                   = 1.0
    followups:  list[str]               = field(default_factory=list)

    def __str__(self) -> str:
        return self.answer


@dataclass
class QueryPlan:
    """
    Structured plan generated from a natural language question.
    Describes which devices to query and what data to collect.
    """
    question:    str
    operation:   str          # get_bgp_summary | get_interfaces | get_routing_table | run | topology
    filters:     dict[str, Any] = field(default_factory=dict)   # role, site, tags
    command:     str | None   = None                             # for 'run' operation
    explanation: str          = ""


# ── Query Planner ─────────────────────────────────────────────────────

_PLAN_SYSTEM = """You are a network automation assistant.
Convert natural language questions about a network into structured query plans.

Return ONLY valid JSON matching the schema. No markdown, no explanation.
"""

_PLAN_SCHEMA = {
    "operation": "get_bgp_summary|get_interfaces|get_routing_table|get_platform_info|run|topology",
    "filters": {
        "role":   "string or null — spine|leaf|border|access",
        "site":   "string or null",
        "tags":   "list of strings or null",
        "hostname": "specific hostname or null",
    },
    "command":     "string or null — only for operation=run",
    "explanation": "string — why this plan answers the question",
}

_SYNTHESIZE_SYSTEM = """You are a network engineer summarizing query results.
Given a question and structured data from network devices, provide a clear, concise answer.
Be specific — include device names, numbers, and states.
End with 1-3 followup questions the user might want to ask.
Return JSON with: answer (string), followups (list of strings), confidence (float 0-1).
"""


# ── Query Engine ──────────────────────────────────────────────────────

class NetworkQuery:
    """
    Natural language query engine for a Plexar Network.

    Usage:
        nq = NetworkQuery(network=net)
        result = await nq.ask("which leafs have BGP peers down?")
        print(result.answer)
    """

    def __init__(
        self,
        network:    "Network",
        model:      str   = "gpt-4o-mini",
        max_tokens: int   = 2000,
        timeout:    float = 30.0,
    ) -> None:
        self.network    = network
        self.model      = model
        self.max_tokens = max_tokens
        self.timeout    = timeout
        self._history:  list[QueryResult] = []

    async def ask(self, question: str) -> QueryResult:
        """
        Ask a natural language question about the network.

        Translates the question into API calls, executes them,
        and returns a human-readable answer plus structured data.

        Args:
            question: Natural language question about the network

        Returns:
            QueryResult with answer, data, and follow-up suggestions
        """
        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.AI_QUERY,
            details={"question_length": len(question), "model": self.model},
        ))

        # Step 1: Plan
        try:
            plan = await self._plan(question)
        except Exception as exc:
            logger.error(f"Query planning failed: {exc}")
            return QueryResult(
                question=question,
                answer="I couldn't understand that question. Try asking about BGP peers, interfaces, routes, or device versions.",
            )

        # Step 2: Execute
        try:
            raw_data, devices = await self._execute(plan)
        except Exception as exc:
            logger.error(f"Query execution failed: {exc}")
            return QueryResult(
                question=question,
                answer=f"I understood your question but couldn't retrieve the data: {exc}",
                devices=[],
            )

        # Step 3: Synthesize
        try:
            result = await self._synthesize(question, plan, raw_data, devices)
            self._history.append(result)
            return result
        except Exception as exc:
            logger.error(f"Query synthesis failed: {exc}")
            return QueryResult(
                question=question,
                answer=f"Retrieved data from {len(devices)} devices but couldn't summarize it.",
                data=raw_data,
                devices=devices,
            )

    @property
    def history(self) -> list[QueryResult]:
        return list(self._history)

    # ── Internal ──────────────────────────────────────────────────────

    async def _plan(self, question: str) -> QueryPlan:
        """Translate a question into a structured query plan."""
        schema_str = json.dumps(_PLAN_SCHEMA, indent=2)

        # Include inventory context
        try:
            device_list    = [d.hostname for d in self.network.inventory.all()]
            roles_sites    = list({
                (d.metadata.get("role"), d.metadata.get("site"))
                for d in self.network.inventory.all()
            })
            inventory_ctx  = f"Available devices: {device_list[:20]}\nRoles/sites: {roles_sites[:10]}"
        except Exception:
            inventory_ctx  = "Inventory context unavailable"

        prompt = (
            f"Network inventory context:\n{inventory_ctx}\n\n"
            f"Question: {question}\n\n"
            f"Return a JSON query plan matching:\n{schema_str}"
        )

        raw  = await self._call_llm(_PLAN_SYSTEM, prompt)
        data = json.loads(raw)

        return QueryPlan(
            question=question,
            operation=data.get("operation", "get_bgp_summary"),
            filters=data.get("filters", {}),
            command=data.get("command"),
            explanation=data.get("explanation", ""),
        )

    async def _execute(self, plan: QueryPlan) -> tuple[list[dict], list[str]]:
        """Execute a query plan and return raw results."""
        import asyncio

        # Apply device filters
        filters = {k: v for k, v in (plan.filters or {}).items() if v is not None}
        hostname = filters.pop("hostname", None)

        if hostname:
            devices = [self.network.inventory.get(hostname)]
            devices = [d for d in devices if d is not None]
        elif filters:
            devices = self.network.devices(**filters)
        else:
            devices = self.network.inventory.all()

        if not devices:
            return [], []

        # Cap at 50 devices for query performance
        devices = devices[:50]

        results: list[dict] = []
        semaphore = asyncio.Semaphore(20)

        async def query_device(device: "Device") -> dict | None:
            async with semaphore:
                try:
                    async with device:
                        return await self._run_operation(device, plan)
                except Exception as exc:
                    logger.debug(f"Query failed on {device.hostname}: {exc}")
                    return None

        raw = await asyncio.gather(*[query_device(d) for d in devices])
        results = [r for r in raw if r is not None]
        device_names = [d.hostname for d in devices]

        return results, device_names

    async def _run_operation(self, device: "Device", plan: QueryPlan) -> dict:
        """Run the specific operation on a device."""
        op  = plan.operation
        row: dict[str, Any] = {"hostname": device.hostname}

        if op == "get_bgp_summary":
            bgp = await device.get_bgp_summary()
            row.update({
                "peers_established": bgp.peers_established,
                "peers_down":        bgp.peers_down,
                "total_prefixes":    bgp.total_prefixes_received,
                "peers": [
                    {"ip": p.neighbor_ip, "as": p.remote_as, "state": p.state}
                    for p in bgp.peers
                ],
            })

        elif op == "get_interfaces":
            ifaces = await device.get_interfaces()
            row["interfaces"] = [
                {
                    "name":        i.name,
                    "admin_state": i.admin_state,
                    "oper_state":  i.oper_state,
                    "mtu":         i.mtu,
                    "speed_mbps":  i.speed_mbps,
                }
                for i in ifaces
            ]
            row["interfaces_down"] = [i.name for i in ifaces if i.oper_state != "up"]

        elif op == "get_routing_table":
            routes = await device.get_routing_table()
            row.update({
                "total_routes":  len(routes.routes),
                "has_default":   routes.default_route is not None,
                "protocols":     list({r.protocol for r in routes.routes}),
            })

        elif op == "get_platform_info":
            info = await device.get_platform_info()
            row.update({
                "platform": info.platform,
                "version":  info.version,
                "model":    info.model,
                "serial":   info.serial,
                "uptime":   info.uptime,
            })

        elif op == "run" and plan.command:
            output = await device.run(plan.command)
            row["output"] = output[:1000]  # truncate

        elif op == "topology":
            # Return topology neighbors if topology is available
            row["note"] = "Use topo.shortest_path() for path queries"

        return row

    async def _synthesize(
        self,
        question:    str,
        plan:        QueryPlan,
        data:        list[dict],
        device_names: list[str],
    ) -> QueryResult:
        """Synthesize raw data into a human-readable answer."""
        data_str = json.dumps(data[:30], indent=2, default=str)  # cap for token budget

        prompt = (
            f"Question: {question}\n\n"
            f"Data from {len(device_names)} devices:\n{data_str}\n\n"
            f"Return JSON: {{\"answer\": \"...\", \"followups\": [...], \"confidence\": 0.0-1.0}}"
        )

        raw     = await self._call_llm(_SYNTHESIZE_SYSTEM, prompt)
        parsed  = json.loads(raw)

        return QueryResult(
            question=question,
            answer=parsed.get("answer", "No answer generated"),
            data=data,
            devices=device_names,
            confidence=float(parsed.get("confidence", 0.8)),
            followups=parsed.get("followups", []),
        )

    async def _call_llm(self, system: str, prompt: str) -> str:
        try:
            import litellm
        except ImportError:
            raise ImportError("AI features require: pip install plexar[ai]")

        response = await litellm.acompletion(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
        )
        content = response.choices[0].message.content or ""
        content = content.strip()
        if content.startswith("```"):
            lines   = content.splitlines()
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        return content
