"""
AI Parser — LLM-powered CLI output parsing.

When regex/TextFSM/TTP parsers fail or a device platform is unknown,
the AI Parser sends raw CLI output to an LLM and asks it to return
structured JSON matching Plexar's normalized models.

This is the killer fallback that makes Plexar work with ANY vendor,
ANY OS version, ANY command — even ones nobody has written a template for.

Architecture:
  1. Try structured parsers first (fast, zero cost, no latency)
  2. If parsing fails or returns empty, fall back to LLM
  3. LLM output is validated against Pydantic models before returning
  4. Parsed results are cached — same output never sent to LLM twice
  5. All LLM interactions are audit-logged (never log the raw output)

Supported backends (via litellm):
  - OpenAI GPT-4o / GPT-4o-mini
  - Anthropic Claude
  - Azure OpenAI
  - Ollama (local, air-gapped environments)
  - Any litellm-compatible model

Usage:
    from plexar.ai import AIParser

    parser = AIParser(model="gpt-4o-mini")

    # Parse unknown BGP output
    bgp = await parser.parse_bgp_summary(raw_output, hostname="router-01")

    # Parse any command with a custom schema
    result = await parser.parse(
        output=raw_output,
        command="show ip bgp summary",
        schema=BGPSummary,
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Type, TypeVar

from pydantic import BaseModel, ValidationError

from plexar.security.sanitizer import sanitize_for_llm, redact_credentials
from plexar.security.audit import get_audit_logger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# ── Prompts ───────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a network automation assistant specialized in parsing
CLI output from network devices into structured JSON.

Rules:
- Return ONLY valid JSON. No markdown, no explanation, no code fences.
- Match the exact schema provided. Use null for missing fields.
- Normalize vendor-specific terminology (e.g. "Estab" → "established").
- If a value cannot be determined, use null, not a guess.
- Numbers should be integers or floats, not strings.
- Interface names should be preserved exactly as shown.
"""

_PARSE_PROMPT = """Parse the following network device output into JSON matching this schema:

Schema:
{schema}

Device output:
{device_output}

Return only the JSON object. No explanation."""


# ── Cache ─────────────────────────────────────────────────────────────

class _ParseCache:
    """Simple in-memory LRU cache for parsed results."""

    def __init__(self, max_size: int = 500) -> None:
        self._cache: dict[str, Any] = {}
        self._max   = max_size

    def key(self, output: str, schema_name: str) -> str:
        h = hashlib.sha256(f"{schema_name}:{output}".encode()).hexdigest()[:16]
        return h

    def get(self, output: str, schema_name: str) -> Any | None:
        return self._cache.get(self.key(output, schema_name))

    def set(self, output: str, schema_name: str, value: Any) -> None:
        if len(self._cache) >= self._max:
            # Evict oldest entry
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[self.key(output, schema_name)] = value

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# ── AI Parser ─────────────────────────────────────────────────────────

class AIParser:
    """
    LLM-powered network CLI parser.

    Converts raw device output into typed Pydantic models using an LLM.
    Caches results to avoid redundant API calls.
    Falls back gracefully when LLM is unavailable.

    Usage:
        parser = AIParser(model="gpt-4o-mini")
        bgp    = await parser.parse_bgp_summary(raw_output)
        ifaces = await parser.parse_interfaces(raw_output)
    """

    def __init__(
        self,
        model:       str   = "gpt-4o-mini",
        temperature: float = 0.0,
        max_tokens:  int   = 2000,
        cache:       bool  = True,
        timeout:     float = 30.0,
    ) -> None:
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.timeout     = timeout
        self._cache      = _ParseCache() if cache else None
        self._stats      = {"calls": 0, "cache_hits": 0, "errors": 0, "tokens_used": 0}

    async def parse(
        self,
        output:   str,
        command:  str,
        schema:   Type[T],
        hostname: str = "unknown",
    ) -> T | None:
        """
        Parse raw device output into a typed Pydantic model.

        Args:
            output:   Raw CLI/API output from device
            command:  The command that produced this output (for context)
            schema:   Target Pydantic model class
            hostname: Device hostname (for audit logging)

        Returns:
            Populated model instance, or None if parsing failed
        """
        schema_name = schema.__name__

        # Cache check
        if self._cache:
            cached = self._cache.get(output, schema_name)
            if cached is not None:
                self._stats["cache_hits"] += 1
                logger.debug(f"AI Parser cache hit for {schema_name}")
                return cached

        # Sanitize before sending to LLM
        try:
            safe_output = sanitize_for_llm(output, context=command)
        except Exception as e:
            logger.warning(f"Sanitizer rejected output from {hostname}: {e}")
            get_audit_logger().log(AuditEvent(
                event_type=AuditEventType.SECURITY_VIOLATION,
                hostname=hostname,
                severity="warning",
                details={"description": f"AI parser sanitizer rejected output: {e}"},
            ))
            return None

        # Build schema description
        schema_json = json.dumps(schema.model_json_schema(), indent=2)

        prompt = _PARSE_PROMPT.format(
            schema=schema_json,
            device_output=safe_output,
        )

        # Audit log the query (never log the actual output)
        get_audit_logger().log(AuditEvent(
            event_type=AuditEventType.AI_QUERY,
            hostname=hostname,
            details={
                "command":     command,
                "schema":      schema_name,
                "model":       self.model,
                "output_len":  len(output),
            },
        ))

        # Call LLM
        try:
            raw_json = await self._call_llm(prompt)
            self._stats["calls"] += 1
        except Exception as exc:
            self._stats["errors"] += 1
            logger.error(f"AI Parser LLM call failed for {hostname}: {redact_credentials(str(exc))}")
            return None

        # Parse and validate
        try:
            data   = json.loads(raw_json)
            result = schema.model_validate(data)

            if self._cache:
                self._cache.set(output, schema_name, result)

            logger.debug(f"AI Parser: {schema_name} parsed successfully for {hostname}")
            return result

        except (json.JSONDecodeError, ValidationError) as exc:
            self._stats["errors"] += 1
            logger.warning(f"AI Parser: {schema_name} validation failed for {hostname}: {exc}")
            return None

    async def parse_bgp_summary(
        self,
        output:   str,
        hostname: str = "unknown",
    ) -> "BGPSummary | None":
        """Parse BGP summary output into a BGPSummary model."""
        from plexar.models.bgp import BGPSummary
        return await self.parse(output, "show bgp summary", BGPSummary, hostname)

    async def parse_interfaces(
        self,
        output:   str,
        hostname: str = "unknown",
    ) -> list["Interface"] | None:
        """Parse interface output. Returns list of Interface models."""
        from plexar.models.interfaces import Interface
        from pydantic import RootModel

        class InterfaceList(RootModel[list[Interface]]):
            pass

        result = await self.parse(output, "show interfaces", InterfaceList, hostname)
        return result.root if result else None

    async def parse_routing_table(
        self,
        output:   str,
        hostname: str = "unknown",
    ) -> "RoutingTable | None":
        """Parse routing table output."""
        from plexar.models.routing import RoutingTable
        return await self.parse(output, "show ip route", RoutingTable, hostname)

    async def parse_platform_info(
        self,
        output:   str,
        hostname: str = "unknown",
    ) -> "PlatformInfo | None":
        """Parse platform/version output."""
        from plexar.models.platform import PlatformInfo
        return await self.parse(output, "show version", PlatformInfo, hostname)

    async def parse_custom(
        self,
        output:        str,
        command:       str,
        instructions:  str,
        hostname:      str = "unknown",
    ) -> dict[str, Any] | None:
        """
        Parse output with custom instructions — returns raw dict.

        Use when you need to extract data that doesn't map to an existing model.

        Args:
            output:       Raw device output
            command:      Command that produced it
            instructions: What to extract and how
            hostname:     Device hostname

        Returns:
            Dict of extracted data, or None on failure
        """
        try:
            safe_output = sanitize_for_llm(output, context=command)
        except Exception:
            return None

        prompt = (
            f"Extract the following from this network device output:\n\n"
            f"{instructions}\n\n"
            f"Device output:\n{safe_output}\n\n"
            f"Return only a JSON object with the extracted data."
        )

        try:
            raw_json = await self._call_llm(prompt)
            return json.loads(raw_json)
        except Exception as exc:
            logger.warning(f"Custom AI parse failed for {hostname}: {exc}")
            return None

    @property
    def stats(self) -> dict[str, Any]:
        return {
            **self._stats,
            "cache_size": self._cache.size if self._cache else 0,
        }

    # ── LLM Backend ───────────────────────────────────────────────────

    async def _call_llm(self, prompt: str) -> str:
        """
        Call the configured LLM and return the text response.
        Uses litellm for model-agnostic routing.
        """
        try:
            import litellm
        except ImportError:
            raise ImportError(
                "AI features require: pip install plexar[ai]  "
                "(installs litellm, openai)"
            )

        response = await litellm.acompletion(
            model=self.model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
        )

        usage = response.get("usage", {})
        self._stats["tokens_used"] += usage.get("total_tokens", 0)

        content = response.choices[0].message.content or ""

        # Strip markdown fences if LLM added them despite instructions
        content = content.strip()
        if content.startswith("```"):
            lines   = content.splitlines()
            content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return content
