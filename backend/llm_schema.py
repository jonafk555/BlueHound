"""Declarative schema validation for LLM JSON output (CR-2).

Generalizes the hand-written `_parse_analyze_response` / `_parse_summary_response`
pattern in llm_analyzer.py into one reusable `validate_against_schema()`. Model
output is *never* trusted: every field is coerced to a declared type, bounded by
length/range/enum, and on any failure falls back to a declared default (the safe
value) while the failure is recorded.

Schema spec (dict of field_name -> rule):
    {"type": "str",        "max_len": 4096, "default": ""}
    {"type": "int",        "min": 1, "max": 10, "default": 1}
    {"type": "float",      "min": 0.0, "max": 1.0, "default": 0.0}
    {"type": "bool",       "default": False}
    {"type": "enum",       "values": {"a", "b"}, "default": "a"}
    {"type": "list[str]",  "max_items": 20, "max_len": 512, "pattern": re.Pattern, "default": []}
    {"type": "dict",       "schema": {...}, "default": {}}
    {"type": "list[dict]", "schema": {...}, "max_items": 20, "default": []}

`validate_against_schema(raw, schema)` returns (validated_dict, errors). Unknown
keys in the input are dropped (allowlist by schema).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

_MAX_STR = 16_384


def _coerce_str(v: Any, max_len: int) -> str:
    return str(v).replace("\x00", "")[:max_len]


def _validate_field(value: Any, rule: dict, errors: List[str], path: str) -> Any:
    t = rule.get("type", "str")
    try:
        if t == "str":
            return _coerce_str(value, rule.get("max_len", 4096))

        if t == "int":
            iv = int(value)
            lo, hi = rule.get("min"), rule.get("max")
            if lo is not None:
                iv = max(lo, iv)
            if hi is not None:
                iv = min(hi, iv)
            return iv

        if t == "float":
            fv = float(value)
            lo, hi = rule.get("min"), rule.get("max")
            if lo is not None:
                fv = max(lo, fv)
            if hi is not None:
                fv = min(hi, fv)
            return fv

        if t == "bool":
            return value is True

        if t == "enum":
            sv = _coerce_str(value, 128)
            values = rule.get("values", set())
            if sv not in values:
                errors.append(f"{path}: '{sv[:40]}' not in enum")
                return rule.get("default")
            return sv

        if t == "list[str]":
            if not isinstance(value, list):
                errors.append(f"{path}: expected list")
                return list(rule.get("default", []))
            out, pat = [], rule.get("pattern")
            for item in value[: rule.get("max_items", 50)]:
                s = _coerce_str(item, rule.get("max_len", 512))
                if pat is not None and not pat.fullmatch(s):
                    errors.append(f"{path}: item failed pattern")
                    continue
                out.append(s)
            return out

        if t == "dict":
            if not isinstance(value, dict):
                errors.append(f"{path}: expected object")
                return dict(rule.get("default", {}))
            sub, _ = validate_against_schema(value, rule.get("schema", {}), path=path)
            return sub

        if t == "list[dict]":
            if not isinstance(value, list):
                errors.append(f"{path}: expected list")
                return list(rule.get("default", []))
            out = []
            for i, item in enumerate(value[: rule.get("max_items", 50)]):
                if not isinstance(item, dict):
                    errors.append(f"{path}[{i}]: expected object")
                    continue
                sub, sub_errs = validate_against_schema(item, rule.get("schema", {}), path=f"{path}[{i}]")
                # Drop items that lost a required (no-default) field — caller can
                # mark fields required by omitting "default".
                if rule.get("drop_invalid_items") and sub_errs:
                    continue
                out.append(sub)
            return out

    except (TypeError, ValueError):
        errors.append(f"{path}: type coercion failed for '{t}'")
        return rule.get("default")

    errors.append(f"{path}: unknown rule type '{t}'")
    return rule.get("default")


def validate_against_schema(raw: Any, schema: Dict[str, dict],
                            path: str = "") -> Tuple[Dict[str, Any], List[str]]:
    """Validate `raw` (dict or JSON string) against `schema`.

    Returns (validated, errors). Missing fields take their declared default;
    unknown fields are dropped. Never raises on bad model output.
    """
    errors: List[str] = []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return ({k: r.get("default") for k, r in schema.items()},
                    ["root: invalid JSON"])
    if not isinstance(raw, dict):
        return ({k: r.get("default") for k, r in schema.items()}, ["root: not an object"])

    out: Dict[str, Any] = {}
    for field, rule in schema.items():
        fpath = f"{path}.{field}" if path else field
        if field not in raw or raw[field] is None:
            if "default" in rule:
                out[field] = rule["default"]
            else:
                errors.append(f"{fpath}: missing required field")
            continue
        out[field] = _validate_field(raw[field], rule, errors, fpath)
    return out, errors


# Shared patterns reused across FR schemas.
MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
