"""
Parser Engine.

Plexar uses a layered parsing strategy:
  1. TTP (Template Text Parser)  — primary, flexible templates
  2. TextFSM                     — legacy, wide template library (ntc-templates)
  3. Regex                       — simple one-off patterns
  4. JSON                        — native structured output (EOS, NXOS API)
  5. XML / NETCONF               — structured API output
  6. AI (Phase 3)                — LLM fallback for unknown output

Parsers are registered per (platform, command) and selected automatically.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract parser. All parsers implement parse()."""

    @abstractmethod
    def parse(self, raw: str, **kwargs: Any) -> Any:
        """Parse raw device output and return structured data."""
        ...

    def parse_safe(self, raw: str, **kwargs: Any) -> Any | None:
        """Parse without raising — returns None on failure."""
        try:
            return self.parse(raw, **kwargs)
        except Exception:
            return None


class RegexParser(BaseParser):
    """
    Simple regex-based parser.
    Useful for single-value extractions.

    Usage:
        parser = RegexParser(r"Version\\s+([\\d.]+)", group=1)
        version = parser.parse("Cisco IOS Version 15.6.3")  # "15.6.3"
    """

    def __init__(self, pattern: str, group: int = 1, flags: int = re.IGNORECASE) -> None:
        self._pattern = re.compile(pattern, flags)
        self._group = group

    def parse(self, raw: str, **kwargs: Any) -> str | None:
        match = self._pattern.search(raw)
        return match.group(self._group) if match else None


class TTPParser(BaseParser):
    """
    TTP (Template Text Parser) backend.

    TTP is more flexible than TextFSM — supports variables, groups,
    repeating sections, and output transformation.

    Templates are stored as strings or loaded from files.
    """

    def __init__(self, template: str) -> None:
        self._template = template

    def parse(self, raw: str, **kwargs: Any) -> list[dict[str, Any]]:
        try:
            from ttp import ttp
        except ImportError as e:
            raise ImportError("TTP is required: pip install ttp") from e

        parser = ttp(data=raw, template=self._template)
        parser.parse()
        results = parser.result(format="raw")[0]
        # TTP wraps results in a list of groups — flatten one level
        return results[0] if results else []


class TextFSMParser(BaseParser):
    """
    TextFSM parser backend.

    Useful as a fallback when ntc-templates covers a command.
    Primary use is legacy platform support.
    """

    def __init__(self, template_path: str) -> None:
        self._template_path = template_path

    def parse(self, raw: str, **kwargs: Any) -> list[dict[str, Any]]:
        try:
            import textfsm
        except ImportError as e:
            raise ImportError("textfsm is required: pip install textfsm") from e

        with open(self._template_path) as f:
            fsm = textfsm.TextFSM(f)

        rows = fsm.ParseTextToDicts(raw)
        return rows


class NTCTemplatesParser(BaseParser):
    """
    Parser using the ntc-templates library.

    Automatically selects the correct TextFSM template based on
    platform and command string.

    Requires: pip install ntc-templates
    """

    def __init__(self, platform: str, command: str) -> None:
        self._platform = platform
        self._command = command

    def parse(self, raw: str, **kwargs: Any) -> list[dict[str, Any]]:
        try:
            from ntc_templates.parse import parse_output
        except ImportError as e:
            raise ImportError(
                "ntc-templates is required: pip install ntc-templates"
            ) from e

        return parse_output(
            platform=self._platform,
            command=self._command,
            data=raw,
        )


class JSONParser(BaseParser):
    """
    JSON parser — for platforms that return structured JSON natively.
    Used by Arista EOS (| json), Cisco NXOS (| json), etc.
    """

    def parse(self, raw: str, **kwargs: Any) -> dict[str, Any]:
        import json
        return json.loads(raw)


class XMLParser(BaseParser):
    """
    XML parser — for NETCONF RPC replies.
    Returns an ElementTree Element.
    """

    def __init__(self, namespace_map: dict[str, str] | None = None) -> None:
        self._nsmap = namespace_map or {}

    def parse(self, raw: str, **kwargs: Any) -> Any:
        import xml.etree.ElementTree as ET
        return ET.fromstring(raw)

    def find(self, raw: str, xpath: str) -> str | None:
        """Parse XML and extract a value by XPath."""
        root = self.parse(raw)
        element = root.find(xpath, self._nsmap)
        return element.text if element is not None else None

    def findall(self, raw: str, xpath: str) -> list[Any]:
        """Parse XML and extract all matching elements by XPath."""
        root = self.parse(raw)
        return root.findall(xpath, self._nsmap)
