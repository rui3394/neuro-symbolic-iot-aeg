from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.planner_schema import basic_validate_planner_input

DEFAULT_PLANNER_INPUT_DIR = Path("examples") / "planner"
DISALLOWED_ACTIONS = [
    "no_execution",
    "no_network",
    "no_real_device",
    "no_poc_generation",
]


def build_planner_input_from_report(
    report_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    report = _load_report(report_path)
    planner_input = _planner_input_from_report(report)

    output = (
        Path(output_path)
        if output_path is not None
        else default_planner_input_path(planner_input["target_name"])
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(planner_input, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return planner_input


def build_planner_inputs_from_reports(
    reports_path: str,
    output_dir: str = str(DEFAULT_PLANNER_INPUT_DIR),
) -> dict[str, Any]:
    paths = _expand_report_paths(reports_path)
    targets: list[dict[str, Any]] = []
    built = 0
    errors = 0

    for path in paths:
        try:
            report = _load_report(str(path))
            planner_input = _planner_input_from_report(report)
            output_path = Path(output_dir) / f"{planner_input['target_name']}_planner_input.json"
            build_planner_input_from_report(str(path), str(output_path))
            validation_errors = basic_validate_planner_input(planner_input)
            built += 1
            targets.append(
                {
                    "report_path": str(path),
                    "target_name": planner_input["target_name"],
                    "output_path": str(output_path),
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                }
            )
        except Exception as exc:
            errors += 1
            targets.append(
                {
                    "report_path": str(path),
                    "target_name": path.stem.removesuffix("_analysis"),
                    "output_path": None,
                    "valid": False,
                    "validation_errors": [str(exc)],
                }
            )

    return {
        "reports": len(paths),
        "output_dir": output_dir,
        "built": built,
        "errors": errors,
        "targets": targets,
    }


def default_planner_input_path(target_name: str) -> Path:
    return DEFAULT_PLANNER_INPUT_DIR / f"{target_name}_planner_input.json"


def _load_report(report_path: str) -> dict[str, Any]:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("analysis report must be a JSON object")
    return data


def _planner_input_from_report(report: dict[str, Any]) -> dict[str, Any]:
    target = report.get("target", {})
    source_model = report.get("source_model", {})
    reachability = report.get("symbolic_reachability", {})
    observation = report.get("constraint_observation", {})
    summary = report.get("summary", {})

    source = _first_source(source_model)
    target_name = str(target.get("name") or "unknown_target")

    return {
        "target_name": target_name,
        "source": source,
        "sink": {
            "name": str(reachability.get("target_sink") or "system"),
            "address": reachability.get("target_addr"),
            "source_reaches_sink_arg": bool(reachability.get("source_var_in_sink_arg", False)),
        },
        "observations": {
            "source_to_sink_confirmed": bool(
                summary.get("source_to_sink_confirmed", False)
            ),
            "sanitizer_like_observed": bool(
                summary.get("sanitizer_like_observed", False)
            ),
            "sanitizer_candidate_count": int(
                observation.get("sanitizer_candidate_count", 0)
            ),
            "branch_condition_count": int(observation.get("branch_condition_count", 0)),
            "input_modeling_count": int(observation.get("input_modeling_count", 0)),
            "string_modeling_count": int(observation.get("string_modeling_count", 0)),
            "unknown_source_count": int(observation.get("unknown_source_count", 0)),
        },
        "constraint_summaries": _constraint_summaries(observation),
        "scope": {
            "environment": "local_toy_binary",
            "allowed_action": "structured_candidate_planning_only",
            "disallowed_actions": list(DISALLOWED_ACTIONS),
        },
    }


def _first_source(source_model: dict[str, Any]) -> dict[str, Any]:
    sources = source_model.get("sources", [])
    if isinstance(sources, list) and sources and isinstance(sources[0], dict):
        source = sources[0]
    else:
        source = {}
    return {
        "name": str(source.get("name") or "unknown_source"),
        "source_type": str(source.get("source_type") or "http_param"),
        "symbolic_name": str(source.get("symbolic_name") or "sym_unknown_source"),
        "runtime_binding": str(source.get("runtime_binding") or "argv[1]"),
        "max_len": int(source.get("max_len") or 1),
    }


def _constraint_summaries(observation: dict[str, Any]) -> list[dict[str, str]]:
    specs = [
        (
            "sanitizer_candidate_constraints",
            "sanitizer_candidate",
            "observed sanitizer candidate constraint",
        ),
        (
            "branch_condition_constraints",
            "branch_condition",
            "observed branch condition constraint",
        ),
        (
            "input_modeling_constraints",
            "input_modeling",
            "input modeling constraint used for stable symbolic observation",
        ),
        (
            "string_modeling_constraints",
            "string_modeling",
            "C string modeling constraint",
        ),
        (
            "unknown_source_constraints",
            "unknown",
            "source-related constraint not classified",
        ),
    ]
    summaries: list[dict[str, str]] = []
    for field_name, kind, description in specs:
        constraints = observation.get(field_name, [])
        if not isinstance(constraints, list):
            continue
        for raw in constraints[:3]:
            summaries.append(
                {
                    "kind": kind,
                    "description": description,
                    "raw": str(raw),
                }
            )
    return summaries


def _expand_report_paths(reports_path: str) -> list[Path]:
    path = Path(reports_path)
    if path.is_dir():
        return sorted(path.glob("*_analysis.json"))
    return [path]
