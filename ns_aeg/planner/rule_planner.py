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
    candidates: list[dict[str, Any]] = []

    sequence = 1
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_name = str(source.get("name") or "")
        if not source_name:
            raise RulePlannerError("task source is missing required name")
        max_len = _source_max_len(source)
        for strategy, value in _strategy_values(marker, max_len):
            if not _is_safe_candidate_value(value, max_len):
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

    if not candidates:
        raise RulePlannerError(
            "rule planner generated no safe candidates; check source max_len and benign marker"
        )

    return {
        "planner": {
            "name": PLANNER_NAME,
            "version": PLANNER_VERSION,
            "mode": PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
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

