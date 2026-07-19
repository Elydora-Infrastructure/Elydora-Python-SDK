"""Read-only parser for the dotenv grammar used by Qwen Code."""

from __future__ import annotations

import re
from typing import Dict


_LINE = re.compile(
    r"^\s*(?:export\s+)?([\w.-]+)"
    r"(?:\s*=\s*?|:\s+?)"
    r"(\s*'(?:\\'|[^'])*'|\s*\"(?:\\\"|[^\"])*\"|"
    r"\s*`(?:\\`|[^`])*`|[^#\r\n]+)?"
    r"\s*(?:#.*)?$",
    re.ASCII | re.MULTILINE,
)


def parse_dotenv(source: str) -> Dict[str, str]:
    """Parse values with the same read-only rules as Node dotenv 17."""
    values: Dict[str, str] = {}
    normalized = source.replace("\r\n", "\n").replace("\r", "\n")
    for match in _LINE.finditer(normalized):
        key = match.group(1)
        value = (match.group(2) or "").strip()
        quote = value[0] if value else ""
        if len(value) >= 2 and quote in {"'", '"', "`"} and value[-1] == quote:
            value = value[1:-1]
        if quote == '"':
            value = value.replace(r"\n", "\n").replace(r"\r", "\r")
        values[key] = value
    return values
