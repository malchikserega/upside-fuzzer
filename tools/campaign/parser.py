#!/usr/bin/env python3
"""parser.py — a bounded, stdlib-only YAML SUBSET parser.

Split out of campaign.py (Phase 5 #124) during the tools/ packaging pass so
its two consumers (campaign.py's own campaign.yaml, scenarios.py's
security_scenarios.yaml) share one implementation without either importing
the other's CLI/orchestration code. No behavior changed by the split — every
function below is moved verbatim from campaign.py.

Stdlib-only, matching this repo's own established convention for
grammarc/fuzzprep ("stdlib-only, no pip install needed"): PyYAML is not a
dependency of this project, so campaign.yaml/security_scenarios.yaml are
parsed by parse_simple_yaml below, a deliberately bounded block-style YAML
SUBSET parser — see its own docstring for exactly what it supports and what
it explicitly rejects rather than silently misparsing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


class CampaignYAMLError(Exception):
    """Raised for a campaign.yaml/security_scenarios.yaml file this
    deliberately minimal parser can't handle (flow style, anchors/aliases,
    multi-document streams, block scalars, tab indentation, ...), or for a
    document that's structurally valid YAML but missing/misshaped fields its
    caller's contract requires."""


# ---------------------------------------------------------------------------
# parse_simple_yaml: a bounded, stdlib-only YAML SUBSET parser
# ---------------------------------------------------------------------------

_LIST_ITEM_RE = re.compile(r"^-\s?(.*)$")
_KEY_VALUE_RE = re.compile(r"^([^:\s][^:]*):\s?(.*)$")


def _strip_comment(line: str) -> str:
    """Strips a trailing # comment, respecting simple '...' / "..." quoting
    (a # inside a quoted scalar is not a comment). Not a full YAML/shell
    quote-aware tokenizer -- sufficient for the plain scalars campaign.yaml
    actually uses."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def _parse_inline_list(s: str) -> List[Any]:
    """Parses a bounded flow-style value 'key: [a, b, c]' (s is the bracketed
    text including the brackets) into a list of coerced scalars, splitting
    on top-level commas while respecting simple quoting. The caller
    (parse_simple_yaml's line-rejection pass) has already guaranteed no
    nested '[' is present."""
    inner = s[1:-1].strip()
    if inner == "":
        return []
    items: List[Any] = []
    buf = ""
    in_single = in_double = False
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf += ch
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf += ch
        elif ch == "," and not in_single and not in_double:
            items.append(_coerce_scalar(buf))
            buf = ""
        else:
            buf += ch
    items.append(_coerce_scalar(buf))
    return items


def _coerce_scalar(raw: str) -> Any:
    """Converts a raw YAML scalar token to a Python value: quoted strings
    (both ' and "), true/false/null (case-insensitive, YAML 1.1-ish), ints,
    floats, a bounded inline flow list ('[a, b, c]', scalars only), else a
    plain string."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == "[" and s[-1] == "]":
        return _parse_inline_list(s)
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def parse_simple_yaml(text: str) -> Any:
    """Parses the bounded YAML subset this project's campaign.yaml uses:
    block-style nested mappings (`key: value`, 2-space-indented children),
    block-style sequences (`- item`, including a sequence of scalars OR a
    sequence of mappings), scalar strings/ints/floats/bools/null, a single
    bounded flow-style form -- `key: [a, b, c]`, an inline list of scalars
    ONLY, added for security_scenarios.yaml's `status_in: [200, 201, 204]`
    style fields -- and `#` comments. Explicitly NOT supported -- raises
    CampaignYAMLError rather than silently misparsing: flow MAPPINGS
    (`{a: b}`), a flow list containing anything but scalars (`[{a: 1}]` /
    `[[1, 2]]`), a bare flow-style value at the top of a line with no `key:`
    prefix, anchors/aliases (`&`/`*`), multi-document streams (`---`), block
    scalars (`|`/`>`), tag directives (`!!type`), and tab-indented lines
    (YAML itself forbids tabs for indentation; this parser enforces the same
    rule explicitly rather than producing a confusing downstream error).
    """
    raw_lines = text.splitlines()
    lines: List[tuple] = []  # (indent, content)
    for lineno, raw in enumerate(raw_lines, start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
            raise CampaignYAMLError(f"line {lineno}: tab indentation is not supported")
        stripped = _strip_comment(raw).rstrip()
        if stripped.strip() == "":
            continue
        if stripped.strip() == "---":
            raise CampaignYAMLError(f"line {lineno}: multi-document streams ('---') are not supported")
        if re.search(r"&\w|\*\w", stripped):
            raise CampaignYAMLError(f"line {lineno}: anchors/aliases are not supported")
        if "{" in stripped:
            raise CampaignYAMLError(f"line {lineno}: flow mappings ('{{a: b}}') are not supported")
        if re.match(r"^\s*\[", stripped):
            raise CampaignYAMLError(f"line {lineno}: a bare flow-style value needs a 'key: ' prefix")
        inline_list_match = re.search(r":\s*(\[.*\])\s*$", stripped)
        if inline_list_match:
            inner = inline_list_match.group(1)[1:-1]
            if "[" in inner:
                raise CampaignYAMLError(f"line {lineno}: a flow list containing another list is not supported")
        elif "[" in stripped:
            raise CampaignYAMLError(f"line {lineno}: flow style ('[a, b]') is only supported as a full 'key: [a, b]' value")
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip(), lineno))

    if not lines:
        return {}

    value, consumed = _parse_block(lines, 0, lines[0][0])
    if consumed != len(lines):
        ln = lines[consumed][2]
        raise CampaignYAMLError(f"line {ln}: unexpected indentation/structure this parser can't follow")
    return value


def _parse_block(lines: List[tuple], start: int, indent: int) -> tuple:
    """Parses one indentation block starting at lines[start], all at exactly
    `indent`, returning (value, next_index). Dispatches to a mapping or a
    sequence parser based on the first line's shape."""
    first_indent, first_content, first_lineno = lines[start]
    if first_indent != indent:
        raise CampaignYAMLError(f"line {first_lineno}: inconsistent indentation")
    if _LIST_ITEM_RE.match(first_content):
        return _parse_sequence(lines, start, indent)
    return _parse_mapping(lines, start, indent)


def _parse_sequence(lines: List[tuple], start: int, indent: int) -> tuple:
    out: List[Any] = []
    i = start
    while i < len(lines):
        cur_indent, content, lineno = lines[i]
        if cur_indent != indent:
            break
        m = _LIST_ITEM_RE.match(content)
        if not m:
            break
        item_text = m.group(1)
        if item_text == "":
            # "- \n  key: value" style (item is itself a nested block) --
            # not needed by this project's own campaign.yaml shape, kept
            # unsupported rather than half-implemented.
            raise CampaignYAMLError(f"line {lineno}: a sequence item with a nested block value is not supported")
        kv = _KEY_VALUE_RE.match(item_text)
        if kv:
            # "- key: value" (first key of a mapping-shaped list item) --
            # also not needed by campaign.yaml's own fields (scenarios/
            # readiness/required_roles are all plain scalar lists).
            raise CampaignYAMLError(f"line {lineno}: a sequence of mappings is not supported")
        out.append(_coerce_scalar(item_text))
        i += 1
    return out, i


def _parse_mapping(lines: List[tuple], start: int, indent: int) -> tuple:
    out: Dict[str, Any] = {}
    i = start
    while i < len(lines):
        cur_indent, content, lineno = lines[i]
        if cur_indent != indent:
            break
        m = _KEY_VALUE_RE.match(content)
        if not m:
            raise CampaignYAMLError(f"line {lineno}: expected 'key: value', got {content!r}")
        key, rest = m.group(1).strip(), m.group(2).strip()
        i += 1
        if rest == "":
            # Value is a nested block on following, more-indented lines.
            if i < len(lines) and lines[i][0] > cur_indent:
                child_indent = lines[i][0]
                child_value, i = _parse_block(lines, i, child_indent)
                out[key] = child_value
            else:
                out[key] = None
        else:
            out[key] = _coerce_scalar(rest)
    return out, i
