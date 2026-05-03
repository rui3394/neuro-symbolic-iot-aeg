from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ns_aeg.config import TargetConfig, load_target_config
from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.ghidra.sink_catalog import get_sink_definition, normalize_symbol_name
from ns_aeg.source_model import SourceSpec, build_source_model

DEFAULT_ORACLE = "source_reaches_sink"
DEFAULT_BENIGN_MARKER = "__NS_AEG_MARKER__"

TOP_LEVEL_REQUIRED = {
    "task_id",
    "binary",
    "entry",
    "sources",
    "sinks",
    "sanitizers",
    "evidence",
    "expected",
    "provenance",
}


class DangerousPathTaskError(ValueError):
    """Raised for clear user-facing task construction failures."""


def build_dangerous_path_task(
    facts_path: str,
    target_path: str,
    *,
    output_path: str | None = None,
) -> dict[str, Any]:
    facts_file = Path(facts_path)
    target_file = Path(target_path)
    if not facts_file.exists():
        raise DangerousPathTaskError(f"facts JSON does not exist: {facts_path}")
    if not target_file.exists():
        raise DangerousPathTaskError(f"target YAML does not exist: {target_path}")

    try:
        facts = load_json(str(facts_file))
    except Exception as exc:
        raise DangerousPathTaskError(f"failed to load facts JSON: {facts_path}: {exc}") from exc

    try:
        target = load_target_config(str(target_file))
    except Exception as exc:
        raise DangerousPathTaskError(f"failed to load target YAML: {target_path}: {exc}") from exc

    sources = _build_sources(target)
    if not sources:
        raise DangerousPathTaskError(
            f"target YAML has no HTTP source parameters: {target_path}"
        )

    sinks = _build_sinks(facts)
    if not sinks:
        raise DangerousPathTaskError(
            f"facts JSON has no dangerous sinks: {facts_path}"
        )

    task = {
        "task_id": _task_id(target, facts),
        "binary": _build_binary(facts, target),
        "entry": _build_entry(facts),
        "sources": sources,
        "sinks": sinks,
        "sanitizers": _build_sanitizers(target),
        "evidence": _build_evidence(facts),
        "expected": {
            "oracle": DEFAULT_ORACLE,
            "benign_marker": DEFAULT_BENIGN_MARKER,
        },
        "provenance": {
            "facts_path": str(facts_file),
            "target_path": str(target_file),
        },
    }

    errors = basic_validate_dangerous_path_task(task)
    if errors:
        raise DangerousPathTaskError(
            "generated dangerous path task failed local validation: "
            + "; ".join(errors)
        )

    if output_path is not None:
        write_json(task, output_path)
    return task


def write_json(data: dict[str, Any], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def basic_validate_dangerous_path_task(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in sorted(TOP_LEVEL_REQUIRED - set(data)):
        errors.append(f"missing required key: {key}")
    for key in sorted(set(data) - TOP_LEVEL_REQUIRED):
        errors.append(f"unexpected key: $.{key}")

    _require_object(data, "binary", errors)
    _require_object(data, "entry", errors)
    _require_object(data, "evidence", errors)
    _require_object(data, "expected", errors)
    _require_object(data, "provenance", errors)

    _validate_object_keys(
        data.get("binary"),
        "binary",
        {"path", "name", "arch"},
        errors,
    )
    _validate_object_keys(
        data.get("entry"),
        "entry",
        {"function", "address"},
        errors,
    )
    _validate_object_keys(
        data.get("evidence"),
        "evidence",
        {"strings", "decompiled_snippets"},
        errors,
    )
    _validate_object_keys(
        data.get("expected"),
        "expected",
        {"oracle", "benign_marker"},
        errors,
    )
    _validate_object_keys(
        data.get("provenance"),
        "provenance",
        {"facts_path", "target_path"},
        errors,
    )

    _validate_array(data, "sources", errors)
    _validate_array(data, "sinks", errors)
    _validate_array(data, "sanitizers", errors)

    _validate_items(
        data.get("sources"),
        "sources",
        {"source_id", "type", "name", "carrier", "max_len", "symbolic"},
        errors,
    )
    _validate_items(
        data.get("sinks"),
        "sinks",
        {"sink_id", "type", "function", "address", "arg_index", "callers"},
        errors,
        optional={"external_address", "callsites"},
    )
    _validate_items(
        data.get("sanitizers"),
        "sanitizers",
        {"sanitizer_id", "type"},
        errors,
        optional={"source", "chars", "max_prefix_len", "requires_nul_within", "description"},
    )

    if isinstance(data.get("sources"), list) and not data["sources"]:
        errors.append("sources must contain at least one source")
    if isinstance(data.get("sinks"), list) and not data["sinks"]:
        errors.append("sinks must contain at least one sink")
    if isinstance(data.get("expected"), dict):
        if data["expected"].get("oracle") != DEFAULT_ORACLE:
            errors.append(f"expected.oracle must be {DEFAULT_ORACLE}")
        if not isinstance(data["expected"].get("benign_marker"), str):
            errors.append("expected.benign_marker must be a string")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a dangerous_path_task JSON from Ghidra facts and YAML target config.",
    )
    parser.add_argument("--facts", required=True, help="Ghidra facts JSON path.")
    parser.add_argument("--target", required=True, help="Target YAML path.")
    parser.add_argument("--out", required=True, help="Output dangerous path task JSON path.")
    args = parser.parse_args(argv)

    try:
        task = build_dangerous_path_task(args.facts, args.target, output_path=args.out)
    except DangerousPathTaskError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        "built dangerous path task "
        f"{task['task_id']} with {len(task['sources'])} source(s) "
        f"and {len(task['sinks'])} sink(s): {args.out}"
    )
    return 0


def _build_sources(target: TargetConfig) -> list[dict[str, Any]]:
    source_model = build_source_model(target)
    return [_source_to_task_source(index, source) for index, source in enumerate(source_model.sources)]


def _source_to_task_source(index: int, source: SourceSpec) -> dict[str, Any]:
    return {
        "source_id": f"source_{index + 1}:{source.name}",
        "type": source.source_type,
        "name": source.name,
        "carrier": source.runtime_binding,
        "max_len": source.max_len,
        "symbolic": source.symbolic_name,
    }


def _build_sinks(facts: dict[str, Any]) -> list[dict[str, Any]]:
    raw_sinks = facts.get("dangerous_sinks")
    if raw_sinks is None:
        raw_sinks = facts.get("sinks")
    if not isinstance(raw_sinks, list):
        return []

    sinks: list[dict[str, Any]] = []
    for index, sink in enumerate(raw_sinks):
        if not isinstance(sink, dict):
            continue
        function = normalize_symbol_name(str(sink.get("name") or sink.get("function") or ""))
        if not function:
            continue
        category = str(sink.get("category") or sink.get("type") or "unknown")
        task_sink = {
            "sink_id": f"sink_{index + 1}:{function}",
            "type": category,
            "function": function,
            "address": _sink_address(sink),
            "arg_index": _default_arg_index(function),
            "callers": _sink_callers(sink),
        }
        if sink.get("external_address") is not None:
            task_sink["external_address"] = sink.get("external_address")
        if isinstance(sink.get("callsites"), list):
            task_sink["callsites"] = [
                {
                    "address": item.get("address"),
                    "caller": item.get("caller"),
                    "caller_entry": item.get("caller_entry"),
                }
                for item in sink["callsites"]
                if isinstance(item, dict)
            ]
        sinks.append(task_sink)
    return sinks


def _build_sanitizers(target: TargetConfig) -> list[dict[str, Any]]:
    sanitizers: list[dict[str, Any]] = []
    for index, sanitizer in enumerate(target.sanitizers):
        sanitizer_type = str(sanitizer.get("type") or "")
        if not sanitizer_type:
            continue
        task_sanitizer: dict[str, Any] = {
            "sanitizer_id": str(sanitizer.get("sanitizer_id") or f"sanitizer_{index + 1}:{sanitizer_type}"),
            "type": sanitizer_type,
        }
        for key in ("source", "chars", "max_prefix_len", "requires_nul_within", "description"):
            if key in sanitizer:
                task_sanitizer[key] = sanitizer[key]
        sanitizers.append(task_sanitizer)
    return sanitizers


def _build_binary(facts: dict[str, Any], target: TargetConfig) -> dict[str, Any]:
    binary = facts.get("binary") if isinstance(facts.get("binary"), dict) else {}
    path = _first_string(binary.get("path"), target.binary)
    return {
        "path": path,
        "name": _first_string(binary.get("name"), Path(path).name),
        "arch": _first_string(
            binary.get("architecture"),
            binary.get("language_id"),
            target.arch,
        ),
    }


def _build_entry(facts: dict[str, Any]) -> dict[str, Any]:
    functions = facts.get("functions")
    if not isinstance(functions, list):
        return {"function": None, "address": None}

    for preferred in ("main", "_start"):
        for function in functions:
            if isinstance(function, dict) and function.get("name") == preferred:
                return {
                    "function": preferred,
                    "address": function.get("entry"),
                }

    for function in functions:
        if isinstance(function, dict):
            return {
                "function": function.get("name"),
                "address": function.get("entry"),
            }
    return {"function": None, "address": None}


def _build_evidence(facts: dict[str, Any]) -> dict[str, Any]:
    return {
        "strings": [
            {
                "address": item.get("address"),
                "value": str(item.get("value", "")),
            }
            for item in _dict_items(facts.get("strings"))
        ],
        "decompiled_snippets": [
            {
                "function": str(item.get("function", "")),
                "entry": item.get("entry"),
                "text": str(item.get("text", "")),
            }
            for item in _dict_items(facts.get("decompiled_snippets"))
        ],
    }


def _task_id(target: TargetConfig, facts: dict[str, Any]) -> str:
    binary = facts.get("binary") if isinstance(facts.get("binary"), dict) else {}
    binary_name = _first_string(binary.get("name"), Path(target.binary).name, "unknown_binary")
    return f"dangerous_path:{target.name}:{binary_name}"


def _default_arg_index(function: str) -> int | None:
    definition = get_sink_definition(function)
    if definition is None:
        return None
    for role in ("command", "format", "source", "path"):
        if role in definition.argument_roles:
            return definition.argument_roles.index(role)
    return None


def _sink_address(sink: dict[str, Any]) -> Any:
    callsites = sink.get("callsites")
    if isinstance(callsites, list):
        for callsite in callsites:
            if isinstance(callsite, dict) and callsite.get("address"):
                return callsite["address"]
    return sink.get("address")


def _sink_callers(sink: dict[str, Any]) -> list[str]:
    callers: list[str] = []
    raw_callers = sink.get("callers")
    if isinstance(raw_callers, list):
        callers.extend(str(caller) for caller in raw_callers if caller)
    callsites = sink.get("callsites")
    if isinstance(callsites, list):
        for callsite in callsites:
            if not isinstance(callsite, dict) or not callsite.get("caller"):
                continue
            caller = str(callsite["caller"])
            if caller not in callers:
                callers.append(caller)
    return callers


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _first_string(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value:
            return value
    return ""


def _require_object(data: dict[str, Any], key: str, errors: list[str]) -> None:
    if key in data and not isinstance(data[key], dict):
        errors.append(f"{key} must be an object")


def _validate_object_keys(
    value: Any,
    path: str,
    required: set[str],
    errors: list[str],
    *,
    allowed: set[str] | None = None,
) -> None:
    if not isinstance(value, dict):
        return
    allowed_keys = allowed or required
    for key in sorted(required - set(value)):
        errors.append(f"missing required key: {path}.{key}")
    for key in sorted(set(value) - allowed_keys):
        errors.append(f"unexpected key: {path}.{key}")


def _validate_array(data: dict[str, Any], key: str, errors: list[str]) -> None:
    if key in data and not isinstance(data[key], list):
        errors.append(f"{key} must be an array")


def _validate_items(
    value: Any,
    path: str,
    required: set[str],
    errors: list[str],
    *,
    optional: set[str] | None = None,
) -> None:
    if not isinstance(value, list):
        return
    allowed = required | (optional or set())
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{path}[{index}] must be an object")
            continue
        _validate_object_keys(item, f"{path}[{index}]", required, errors, allowed=allowed)


if __name__ == "__main__":
    raise SystemExit(main())
