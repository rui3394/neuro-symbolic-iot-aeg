from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from ns_aeg.tasks.loader import TaskLoadError, load_dangerous_path_task

PLANNER_NAME = "rule_based_planner"
PLANNER_VERSION = "0.1"
PLANNER_MODE = "benign_baseline"
DEFAULT_BENIGN_MARKER = "__NS_AEG_MARKER__"
DANGEROUS_CHARS = set(";&|`$()><")


class RulePlannerError(ValueError):
    """Raised when the rule planner cannot build benign candidates."""


def generate_candidate_set_for_task_path(task_path: str) -> dict[str, Any]:
    task = load_dangerous_path_task(task_path)
    return generate_candidate_set(task)


def generate_candidate_set(task: dict[str, Any]) -> dict[str, Any]:
    sources = task.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RulePlannerError("dangerous path task has no sources")

    expected = task.get("expected") if isinstance(task.get("expected"), dict) else {}
    marker = str(expected.get("benign_marker") or DEFAULT_BENIGN_MARKER)
    prefix = _candidate_prefix(task)
    sanitizers = _sanitizers(task)
    diagnostics = _planning_diagnostics(sanitizers, marker)
    candidates: list[dict[str, Any]] = []
    rejected_candidates: list[dict[str, Any]] = []

    sequence = 1
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_name = str(source.get("name") or "")
        if not source_name:
            raise RulePlannerError("task source is missing required name")
        max_len = _source_max_len(source)
        for strategy, value in _strategy_values(marker, max_len):
            reject_reason = _candidate_reject_reason(
                value=value,
                marker=marker,
                max_len=max_len,
                source_name=source_name,
                sanitizers=sanitizers,
            )
            if reject_reason is not None:
                rejected_candidates.append(
                    {
                        "strategy": strategy,
                        "source": source_name,
                        "reason": reject_reason["reason"],
                        "sanitizer": reject_reason.get("sanitizer"),
                        "details": reject_reason.get("details", {}),
                    }
                )
                continue
            candidates.append(
                {
                    "candidate_id": f"{prefix}_rule_{sequence:03d}",
                    "strategy": strategy,
                    "inputs": {source_name: value},
                    "assumptions": [
                        "source is argv/http parameter",
                        "benign marker is used for source-to-sink evidence",
                    ],
                    "safety": {
                        "benign": True,
                        "weaponized": False,
                    },
                }
            )
            sequence += 1

    diagnostics["rejected_count"] = len(rejected_candidates)
    if not candidates and rejected_candidates:
        diagnostics["notes"].append(
            "no valid candidates generated because sanitizer constraints are incompatible with the benign marker strategy"
        )
    elif not candidates:
        raise RulePlannerError(
            "rule planner generated no safe candidates; check source max_len and benign marker"
        )

    return {
        "planner": {
            "name": PLANNER_NAME,
            "version": PLANNER_VERSION,
            "mode": "sanitizer_aware_benign_baseline" if sanitizers else PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
        "planning_diagnostics": diagnostics,
        "rejected_candidates": rejected_candidates,
    }


def write_candidate_set(candidate_set: dict[str, Any], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(candidate_set, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate benign rule-based candidates for a dangerous path task.",
    )
    parser.add_argument("--task", required=True, help="dangerous_path_task JSON path.")
    parser.add_argument("--out", required=True, help="output candidate set JSON path.")
    args = parser.parse_args(argv)

    try:
        candidate_set = generate_candidate_set_for_task_path(args.task)
        write_candidate_set(candidate_set, args.out)
    except (TaskLoadError, RulePlannerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"generated {len(candidate_set['candidates'])} benign candidates "
        f"for task_id={candidate_set['task_id']} out={args.out}"
    )
    return 0


def _strategy_values(marker: str, max_len: int) -> list[tuple[str, str]]:
    values = [
        ("benign_marker_direct", f"127.0.0.1{marker}"),
        ("marker_only", marker),
        ("prefix_with_marker", f"SAFE{marker}"),
    ]
    boundary = _length_boundary_value(marker, max_len)
    if boundary is not None:
        values.append(("length_boundary_safe", boundary))
    return values


def _length_boundary_value(marker: str, max_len: int) -> str | None:
    if max_len <= 0 or len(marker) > max_len:
        return None
    fill_len = max_len - len(marker)
    return ("A" * fill_len) + marker


def _is_safe_candidate_value(value: str, max_len: int) -> bool:
    if "\n" in value or "\r" in value:
        return False
    if any(char in value for char in DANGEROUS_CHARS):
        return False
    return len(value) <= max_len


def _candidate_reject_reason(
    *,
    value: str,
    marker: str,
    max_len: int,
    source_name: str,
    sanitizers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if "\n" in value or "\r" in value:
        return {"reason": "candidate_contains_newline"}
    if any(char in value for char in DANGEROUS_CHARS):
        return {"reason": "candidate_contains_disallowed_shell_character"}
    if len(value) > max_len:
        return {"reason": "candidate_exceeds_source_max_len", "details": {"max_len": max_len}}

    for sanitizer in sanitizers:
        if _sanitizer_source(sanitizer) not in {None, source_name}:
            continue
        sanitizer_type = sanitizer.get("type")
        if sanitizer_type == "blacklist":
            forbidden = [str(char) for char in sanitizer.get("chars", [])]
            hit = [char for char in forbidden if char and char in value]
            if hit:
                return {
                    "reason": "candidate_contains_blacklisted_character",
                    "sanitizer": "blacklist",
                    "details": {"chars": hit},
                }
        elif sanitizer_type == "length_window":
            window = _requires_nul_within(sanitizer)
            if window is not None and marker and len(marker) >= window:
                return {
                    "reason": "marker_length_exceeds_required_window",
                    "sanitizer": "length_window",
                    "details": {
                        "marker_len": len(marker),
                        "requires_nul_within": window,
                    },
                }
            if window is not None and len(value) >= window:
                return {
                    "reason": "candidate_length_exceeds_required_window",
                    "sanitizer": "length_window",
                    "details": {
                        "candidate_len": len(value),
                        "requires_nul_within": window,
                    },
                }
    return None


def _sanitizers(task: dict[str, Any]) -> list[dict[str, Any]]:
    value = task.get("sanitizers")
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _planning_diagnostics(sanitizers: list[dict[str, Any]], marker: str) -> dict[str, Any]:
    sanitizer_types = sorted({str(item.get("type")) for item in sanitizers if item.get("type")})
    notes: list[str] = []
    for sanitizer in sanitizers:
        if sanitizer.get("type") == "length_window":
            window = _requires_nul_within(sanitizer)
            if window is not None and marker and len(marker) >= window:
                notes.append(
                    "benign marker length is incompatible with length_window sanitizer "
                    f"(marker_len={len(marker)}, requires_nul_within={window})"
                )
    return {
        "sanitizer_count": len(sanitizers),
        "sanitizer_types": sanitizer_types,
        "marker_len": len(marker),
        "rejected_count": 0,
        "notes": notes,
    }


def _sanitizer_source(sanitizer: dict[str, Any]) -> str | None:
    source = sanitizer.get("source")
    return str(source) if source else None


def _requires_nul_within(sanitizer: dict[str, Any]) -> int | None:
    try:
        return int(sanitizer.get("requires_nul_within"))
    except (TypeError, ValueError):
        return None


def _source_max_len(source: dict[str, Any]) -> int:
    try:
        return int(source.get("max_len"))
    except (TypeError, ValueError):
        return 64


def _candidate_prefix(task: dict[str, Any]) -> str:
    binary = task.get("binary") if isinstance(task.get("binary"), dict) else {}
    raw = str(binary.get("name") or task.get("task_id") or "task")
    prefix = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")
    return prefix or "task"


if __name__ == "__main__":
    raise SystemExit(main())
