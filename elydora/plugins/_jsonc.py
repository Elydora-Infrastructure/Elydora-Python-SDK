"""Strict JSON-with-comments parsing and source-preserving edits."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


JsonObject = Dict[str, Any]
JsonPathPart = Union[str, int]
_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


@dataclass(frozen=True)
class JsoncItem:
    node: "JsoncNode"
    comma: Optional[int]


@dataclass(frozen=True)
class JsoncMember:
    key: str
    start: int
    end: int
    value_node: "JsoncNode"
    comma: Optional[int]


@dataclass(frozen=True)
class JsoncNode:
    kind: str
    start: int
    end: int
    value: Any
    members: Tuple[JsoncMember, ...] = ()
    items: Tuple[JsoncItem, ...] = ()


class _Parser:
    def __init__(
        self,
        raw: str,
        label: str,
        allow_trailing_commas: bool,
    ) -> None:
        self.raw = raw
        self.label = label
        self.allow_trailing_commas = allow_trailing_commas
        self.position = 0

    def _error(self, message: str, position: Optional[int] = None) -> ValueError:
        offset = self.position if position is None else position
        return ValueError(f"Failed to parse {self.label}: {message} at offset {offset}")

    def _skip_trivia(self) -> None:
        while self.position < len(self.raw):
            if self.position == 0 and self.raw.startswith("\ufeff"):
                self.position += 1
                continue
            character = self.raw[self.position]
            if character in " \t\r\n":
                self.position += 1
                continue
            if self.raw.startswith("//", self.position):
                newline = self.raw.find("\n", self.position + 2)
                self.position = len(self.raw) if newline < 0 else newline + 1
                continue
            if self.raw.startswith("/*", self.position):
                end = self.raw.find("*/", self.position + 2)
                if end < 0:
                    raise self._error("unterminated block comment")
                self.position = end + 2
                continue
            return

    def _expect(self, character: str) -> None:
        if self.position >= len(self.raw) or self.raw[self.position] != character:
            raise self._error(f'expected "{character}"')
        self.position += 1

    def _parse_string(self) -> Tuple[str, int, int]:
        start = self.position
        self._expect('"')
        escaped = False
        while self.position < len(self.raw):
            character = self.raw[self.position]
            self.position += 1
            if escaped:
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if character == '"':
                token = self.raw[start:self.position]
                try:
                    value = json.loads(token)
                except json.JSONDecodeError as error:
                    raise self._error(error.msg, start + error.pos) from error
                return value, start, self.position
            if ord(character) < 0x20:
                raise self._error("unescaped control character", self.position - 1)
        raise self._error("unterminated string", start)

    def _parse_object(self) -> JsoncNode:
        start = self.position
        self.position += 1
        members: List[JsoncMember] = []
        value: JsonObject = {}
        seen = set()
        self._skip_trivia()
        if self.position < len(self.raw) and self.raw[self.position] == "}":
            self.position += 1
            return JsoncNode("object", start, self.position, value)
        while True:
            self._skip_trivia()
            if self.position >= len(self.raw) or self.raw[self.position] != '"':
                raise self._error("object key must be a string")
            key, member_start, _ = self._parse_string()
            if key in seen:
                raise self._error(f'duplicate field "{key}"', member_start)
            seen.add(key)
            self._skip_trivia()
            self._expect(":")
            node = self._parse_value()
            value[key] = node.value
            member_end = node.end
            self._skip_trivia()
            comma: Optional[int] = None
            if self.position < len(self.raw) and self.raw[self.position] == ",":
                comma = self.position
                self.position += 1
                self._skip_trivia()
                members.append(JsoncMember(
                    key, member_start, member_end, node, comma
                ))
                if self.position < len(self.raw) and self.raw[self.position] == "}":
                    if not self.allow_trailing_commas:
                        raise self._error("trailing commas are not allowed", comma)
                    self.position += 1
                    return JsoncNode(
                        "object", start, self.position, value, tuple(members)
                    )
                continue
            members.append(JsoncMember(key, member_start, member_end, node, None))
            if self.position >= len(self.raw) or self.raw[self.position] != "}":
                raise self._error('expected "," or "}"')
            self.position += 1
            return JsoncNode("object", start, self.position, value, tuple(members))

    def _parse_array(self) -> JsoncNode:
        start = self.position
        self.position += 1
        items: List[JsoncItem] = []
        values: List[Any] = []
        self._skip_trivia()
        if self.position < len(self.raw) and self.raw[self.position] == "]":
            self.position += 1
            return JsoncNode("array", start, self.position, values)
        while True:
            node = self._parse_value()
            values.append(node.value)
            self._skip_trivia()
            comma: Optional[int] = None
            if self.position < len(self.raw) and self.raw[self.position] == ",":
                comma = self.position
                self.position += 1
                self._skip_trivia()
                items.append(JsoncItem(node, comma))
                if self.position < len(self.raw) and self.raw[self.position] == "]":
                    if not self.allow_trailing_commas:
                        raise self._error("trailing commas are not allowed", comma)
                    self.position += 1
                    return JsoncNode(
                        "array", start, self.position, values, items=tuple(items)
                    )
                continue
            items.append(JsoncItem(node, None))
            if self.position >= len(self.raw) or self.raw[self.position] != "]":
                raise self._error('expected "," or "]"')
            self.position += 1
            return JsoncNode(
                "array", start, self.position, values, items=tuple(items)
            )

    def _parse_value(self) -> JsoncNode:
        self._skip_trivia()
        if self.position >= len(self.raw):
            raise self._error("expected a value")
        start = self.position
        character = self.raw[self.position]
        if character == "{":
            return self._parse_object()
        if character == "[":
            return self._parse_array()
        if character == '"':
            value, _, end = self._parse_string()
            return JsoncNode("string", start, end, value)
        for token, literal in (("true", True), ("false", False), ("null", None)):
            if self.raw.startswith(token, self.position):
                self.position += len(token)
                return JsoncNode("scalar", start, self.position, literal)
        match = _NUMBER.match(self.raw, self.position)
        if match:
            self.position = match.end()
            token = match.group(0)
            number = float(token) if any(marker in token for marker in ".eE") else int(token)
            return JsoncNode("number", start, self.position, number)
        raise self._error("invalid value")

    def parse(self) -> JsoncNode:
        node = self._parse_value()
        self._skip_trivia()
        if self.position != len(self.raw):
            raise self._error("unexpected content")
        return node


def parse_jsonc(
    raw: str,
    label: str,
    *,
    allow_trailing_commas: bool = True,
) -> Any:
    """Parse JSON with comments and an explicit trailing-comma policy."""
    return _Parser(raw, label, allow_trailing_commas).parse().value


class JsoncEditor:
    """Apply narrow path edits while retaining untouched source bytes."""

    def __init__(
        self,
        raw: str,
        label: str,
        *,
        allow_trailing_commas: bool = True,
    ) -> None:
        self.raw = raw
        self.label = label
        self.allow_trailing_commas = allow_trailing_commas
        self._refresh()

    @property
    def value(self) -> Any:
        return self.root.value

    def _refresh(self) -> None:
        self.root = _Parser(
            self.raw,
            self.label,
            self.allow_trailing_commas,
        ).parse()

    def _resolve(self, path: Sequence[JsonPathPart]) -> JsoncNode:
        node = self.root
        for part in path:
            if isinstance(part, str) and node.kind == "object":
                member = next((item for item in node.members if item.key == part), None)
                if member is None:
                    raise KeyError(f"Missing JSONC path: {list(path)}")
                node = member.value_node
                continue
            if isinstance(part, int) and node.kind == "array":
                if part < 0 or part >= len(node.items):
                    raise IndexError(f"Invalid JSONC path: {list(path)}")
                node = node.items[part].node
                continue
            raise TypeError(f"Invalid JSONC path: {list(path)}")
        return node

    def _apply(self, ranges: Sequence[Tuple[int, int, str]]) -> None:
        next_raw = self.raw
        for start, end, replacement in sorted(ranges, reverse=True):
            next_raw = next_raw[:start] + replacement + next_raw[end:]
        self.raw = next_raw
        self._refresh()

    def delete(self, path: Sequence[JsonPathPart]) -> None:
        if not path:
            raise ValueError("Cannot delete the JSONC root")
        parent = self._resolve(path[:-1])
        part = path[-1]
        ranges: List[Tuple[int, int, str]] = []
        if isinstance(part, str) and parent.kind == "object":
            index = next(
                (position for position, item in enumerate(parent.members) if item.key == part),
                -1,
            )
            if index < 0:
                raise KeyError(f"Missing JSONC path: {list(path)}")
            member = parent.members[index]
            ranges.append((member.start, member.end, ""))
            if member.comma is not None:
                ranges.append((member.comma, member.comma + 1, ""))
            elif index > 0 and parent.members[index - 1].comma is not None:
                comma = parent.members[index - 1].comma
                if comma is None:
                    raise RuntimeError("JSONC object separator metadata is missing")
                ranges.append((comma, comma + 1, ""))
        elif isinstance(part, int) and parent.kind == "array":
            if part < 0 or part >= len(parent.items):
                raise IndexError(f"Invalid JSONC path: {list(path)}")
            item = parent.items[part]
            ranges.append((item.node.start, item.node.end, ""))
            if item.comma is not None:
                ranges.append((item.comma, item.comma + 1, ""))
            elif part > 0 and parent.items[part - 1].comma is not None:
                comma = parent.items[part - 1].comma
                if comma is None:
                    raise RuntimeError("JSONC array separator metadata is missing")
                ranges.append((comma, comma + 1, ""))
        else:
            raise TypeError(f"Invalid JSONC path: {list(path)}")
        self._apply(ranges)

    def _eol(self) -> str:
        return "\r\n" if "\r\n" in self.raw else "\n"

    def _indent_unit(self) -> str:
        match = re.search(r"\r?\n([ \t]+)\S", self.raw)
        if match is None:
            return "  "
        indentation = match.group(1)
        return "\t" if "\t" in indentation else " " * len(indentation)

    def _line_indent(self, position: int) -> str:
        line_start = self.raw.rfind("\n", 0, position) + 1
        prefix = self.raw[line_start:position]
        match = re.match(r"[ \t]*", prefix)
        if match is None:
            raise RuntimeError("JSONC indentation parser failed")
        return match.group(0)

    def _json_lines(self, value: Any) -> List[str]:
        unit = self._indent_unit()
        lines = json.dumps(value, ensure_ascii=False, indent=1).splitlines()
        converted = []
        for line in lines:
            depth = len(line) - len(line.lstrip(" "))
            converted.append(unit * depth + line[depth:])
        return converted

    def _insert(
        self,
        parent: JsoncNode,
        lines: List[str],
        had_trailing_comma: bool,
    ) -> None:
        close = parent.end - 1
        eol = self._eol()
        unit = self._indent_unit()
        pretty = "\n" in self.raw or "\r" in self.raw
        ranges: List[Tuple[int, int, str]] = []
        has_existing = bool(parent.members if parent.kind == "object" else parent.items)
        previous_end: Optional[int] = None
        if has_existing and not had_trailing_comma:
            if parent.kind == "object":
                previous_end = parent.members[-1].end
            else:
                previous_end = parent.items[-1].node.end
        if pretty:
            close_line_start = self.raw.rfind("\n", 0, close) + 1
            close_prefix = self.raw[close_line_start:close]
            if close_line_start > parent.start and not close_prefix.strip():
                insertion_at = close_line_start
                parent_indent = close_prefix
                prefix = ""
                suffix = eol
            else:
                insertion_at = close
                parent_indent = self._line_indent(parent.start)
                prefix = eol
                suffix = eol + parent_indent
            child_indent = parent_indent + unit
            content = eol.join(child_indent + line for line in lines)
            if had_trailing_comma:
                content += ","
            insertion = prefix + content + suffix
        else:
            insertion_at = close
            content = " ".join(lines)
            if had_trailing_comma:
                content += ","
            insertion = (" " if has_existing else "") + content
        if previous_end == insertion_at:
            insertion = "," + insertion
        elif previous_end is not None:
            ranges.append((previous_end, previous_end, ","))
        ranges.append((insertion_at, insertion_at, insertion))
        self._apply(ranges)

    def add_property(
        self,
        path: Sequence[JsonPathPart],
        key: str,
        value: Any,
    ) -> None:
        parent = self._resolve(path)
        if parent.kind != "object":
            raise TypeError(f"JSONC path must be an object: {list(path)}")
        if any(member.key == key for member in parent.members):
            raise KeyError(f'JSONC field "{key}" already exists')
        value_lines = self._json_lines(value)
        key_text = json.dumps(key, ensure_ascii=False) + ": "
        lines = [key_text + value_lines[0], *value_lines[1:]]
        trailing = bool(parent.members and parent.members[-1].comma is not None)
        self._insert(parent, lines, trailing)

    def append(self, path: Sequence[JsonPathPart], value: Any) -> None:
        parent = self._resolve(path)
        if parent.kind != "array":
            raise TypeError(f"JSONC path must be an array: {list(path)}")
        trailing = bool(parent.items and parent.items[-1].comma is not None)
        self._insert(parent, self._json_lines(value), trailing)
