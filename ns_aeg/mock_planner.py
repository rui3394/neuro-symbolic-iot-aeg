from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.planner_schema import (
    basic_validate_planner_input,
    basic_validate_planner_output,
    load_json,
)

DEFAULT_PLANNER_DIR = Path("examples") / "planner"


def run_mock_planner(
    planner_input_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    planner_input = load_json(planner_input_path)
    input_errors = basic_validate_planner_input(planner_input)
    if input_errors:
        raise ValueError("; ".join(input_errors))

    output = _build_output(planner_input)
    output_errors = basic_validate_planner_output(output)
    if output_errors:
        raise ValueError("; ".join(output_errors))

    path = (
        Path(output_path)
        if output_path is not None
        else default_planner_output_path(output["target_name"])
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def run_mock_planner_dir(
    planner_input_dir: str,
    output_dir: str = str(DEFAULT_PLANNER_DIR),
) -> dict[str, Any]:
    input_dir = Path(planner_input_dir)
    targets: list[dict[str, Any]] = []
    built = 0
    errors = 0

    for input_path in sorted(input_dir.glob("*_planner_input.json")):
        try:
            planner_input = load_json(str(input_path))
            target_name = str(planner_input.get("target_name") or input_path.stem)
            output_path = Path(output_dir) / f"{target_name}_planner_output.json"
            output = run_mock_planner(str(input_path), str(output_path))
            built += 1
            targets.append(
                {
                    "input_path": str(input_path),
                    "target_name": output["target_name"],
                    "decision": output["decision"],
                    "output_path": str(output_path),
                    "valid": True,
                    "error": None,
                }
            )
        except Exception as exc:
            errors += 1
            targets.append(
                {
                    "input_path": str(input_path),
                    "target_name": input_path.stem.removesuffix("_planner_input"),
                    "decision": None,
                    "output_path": None,
                    "valid": False,
                    "error": str(exc),
                }
            )

    return {
        "inputs": len(targets),
        "output_dir": output_dir,
        "built": built,
        "errors": errors,
        "targets": targets,
    }


def default_planner_output_path(target_name: str) -> Path:
    return DEFAULT_PLANNER_DIR / f"{target_name}_planner_output.json"


def _build_output(planner_input: dict[str, Any]) -> dict[str, Any]:
    target_name = str(planner_input["target_name"])
    observations = planner_input["observations"]
    source = planner_input["source"]

    if not observations["source_to_sink_confirmed"]:
        return {
            "planner_version": "0.1",
            "target_name": target_name,
            "decision": "no_source_to_sink",
            "rationale_summary": (
                "No source-to-sink flow was confirmed in the analysis report."
            ),
            "candidate_plans": [],
            "safety": _safety_section(),
        }

    return {
        "planner_version": "0.1",
        "target_name": target_name,
        "decision": "candidate_plan_available",
        "rationale_summary": (
            "Source-to-sink flow was confirmed; this mock planner emits only an "
            "abstract candidate shape for later symbolic verification."
        ),
        "candidate_plans": [_candidate_plan(source, planner_input["constraint_summaries"])],
        "safety": _safety_section(),
    }


def _candidate_plan(
    source: dict[str, Any],
    constraint_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    kinds = {
        summary.get("kind")
        for summary in constraint_summaries
        if isinstance(summary, dict)
    }

    constraints_considered: list[str] = []
    forbidden_byte_classes: list[str] = []
    required_prefix: str | None = None

    if "sanitizer_candidate" in kinds:
        constraints_considered.append("sanitizer_candidate_constraints")
        forbidden_byte_classes.append("observed_fixed_test_byte_or_class")
    if "branch_condition" in kinds:
        constraints_considered.append("branch_condition_constraints")
        required_prefix = "observed_branch_prefix"
    if "input_modeling" in kinds:
        constraints_considered.append("input_modeling_constraints")
    if not constraints_considered:
        constraints_considered.append("source_to_sink_confirmed")

    return {
        "candidate_id": "cand_001",
        "target_source": source["name"],
        "intent": "reach_sink_under_observed_constraints",
        "constraints_considered": constraints_considered,
        "abstract_input_shape": {
            "max_len": source["max_len"],
            "required_prefix": required_prefix,
            "forbidden_byte_classes": forbidden_byte_classes,
            "notes": "abstract only; no concrete input generated",
        },
        "requires_symbolic_verification": True,
    }


def _safety_section() -> dict[str, bool]:
    return {
        "contains_concrete_payload": False,
        "contains_executable_code": False,
        "requires_human_review": True,
    }
