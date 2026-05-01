from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.angr_loader import load_with_angr
from ns_aeg.config import TargetConfig
from ns_aeg.constraint_observer import observe_constraints_to_sink
from ns_aeg.reachability import symbolic_reach_sink
from ns_aeg.source_model import build_source_model


def generate_analysis_report(
    config: TargetConfig,
    output_path: str | None = None,
) -> dict[str, Any]:
    report_path = Path(output_path) if output_path is not None else _default_report_path(config)

    source_model = None
    source_model_error = None
    try:
        source_model = build_source_model(config)
    except Exception as exc:
        source_model_error = f"failed to build source model: {exc}"

    angr_loader = _safe_call(
        lambda: load_with_angr(config.binary, config.sinks),
        "failed to load binary with angr",
    )

    symbolic_reachability = None
    constraint_observation = None
    if source_model is not None:
        symbolic_reachability = _safe_call(
            lambda: symbolic_reach_sink(config.binary, config.sinks, source_model),
            "failed to run symbolic reachability",
        )
        constraint_observation = _safe_call(
            lambda: observe_constraints_to_sink(config.binary, config.sinks, source_model),
            "failed to observe constraints",
        )

    report = {
        "report_path": str(report_path),
        "target": _target_section(config),
        "source_model": _source_model_section(source_model, source_model_error),
        "angr_loader": _angr_loader_section(angr_loader),
        "symbolic_reachability": _symbolic_reachability_section(symbolic_reachability),
        "constraint_observation": _constraint_observation_section(constraint_observation),
    }
    report["summary"] = _summary_section(report)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _default_report_path(config: TargetConfig) -> Path:
    return Path("reports") / f"{config.name}_analysis.json"


def _safe_call(func, prefix: str) -> Any:
    try:
        return func()
    except Exception as exc:
        return {"error": f"{prefix}: {exc}"}


def _target_section(config: TargetConfig) -> dict[str, Any]:
    return {
        "name": config.name,
        "binary": config.binary,
        "arch": config.arch,
        "http_method": config.http_method,
        "http_path": config.http_path,
        "vulnerability_type": config.vulnerability_type,
        "configured_sinks": list(config.sinks),
    }


def _source_model_section(source_model: Any, error: str | None) -> dict[str, Any]:
    sources = []
    if source_model is not None:
        sources = [
            {
                "name": source.name,
                "source_type": source.source_type,
                "max_len": source.max_len,
                "symbolic_name": source.symbolic_name,
                "runtime_binding": source.runtime_binding,
            }
            for source in getattr(source_model, "sources", [])
        ]
    return {"sources": sources, "error": error}


def _angr_loader_section(info: Any) -> dict[str, Any]:
    if isinstance(info, dict):
        return {
            "loaded": False,
            "arch": None,
            "bits": None,
            "entry": None,
            "base_addr": None,
            "plt": {},
            "missing_plt": [],
            "error": info.get("error"),
        }

    return {
        "loaded": bool(getattr(info, "loaded", False)),
        "arch": getattr(info, "arch", None),
        "bits": getattr(info, "bits", None),
        "entry": getattr(info, "entry", None),
        "base_addr": getattr(info, "base_addr", None),
        "main_object": getattr(info, "main_object", None),
        "plt": dict(getattr(info, "plt", {})),
        "missing_plt": list(getattr(info, "missing_plt", [])),
        "error": getattr(info, "error", None),
    }


def _symbolic_reachability_section(result: Any) -> dict[str, Any]:
    if result is None:
        return _empty_symbolic_reachability("source model is unavailable")
    if isinstance(result, dict):
        return _empty_symbolic_reachability(result.get("error"))

    return {
        "created": bool(getattr(result, "created", False)),
        "reachable": bool(getattr(result, "reachable", False)),
        "source_name": getattr(result, "source_name", None),
        "symbolic_var": getattr(result, "symbolic_var", None),
        "runtime_binding": getattr(result, "runtime_binding", None),
        "input_constraints": list(getattr(result, "input_constraints", [])),
        "target_sink": getattr(result, "target_sink", None),
        "target_addr": getattr(result, "target_addr", None),
        "sink_arg_symbolic": bool(getattr(result, "sink_arg_symbolic", False)),
        "source_var_in_sink_arg": bool(getattr(result, "source_var_in_sink_arg", False)),
        "sink_arg_variables": list(getattr(result, "sink_arg_variables", [])),
        "error": getattr(result, "error", None),
    }


def _empty_symbolic_reachability(error: str | None) -> dict[str, Any]:
    return {
        "created": False,
        "reachable": False,
        "source_name": None,
        "symbolic_var": None,
        "runtime_binding": None,
        "input_constraints": [],
        "target_sink": None,
        "target_addr": None,
        "sink_arg_symbolic": False,
        "source_var_in_sink_arg": False,
        "sink_arg_variables": [],
        "error": error,
    }


def _constraint_observation_section(result: Any) -> dict[str, Any]:
    if result is None:
        return _empty_constraint_observation("source model is unavailable")
    if isinstance(result, dict):
        return _empty_constraint_observation(result.get("error"))

    sanitizer_candidates = list(getattr(result, "sanitizer_candidate_constraints", []))
    string_modeling_constraints = list(
        getattr(result, "string_modeling_constraints", [])
    )
    input_modeling_constraints = list(
        getattr(result, "input_modeling_constraints", [])
    )
    branch_condition_constraints = list(
        getattr(result, "branch_condition_constraints", [])
    )
    unknown_source_constraints = list(
        getattr(result, "unknown_source_constraints", [])
    )
    return {
        "created": bool(getattr(result, "created", False)),
        "reachable": bool(getattr(result, "reachable", False)),
        "source_name": getattr(result, "source_name", None),
        "symbolic_var": getattr(result, "symbolic_var", None),
        "runtime_binding": getattr(result, "runtime_binding", None),
        "target_sink": getattr(result, "target_sink", None),
        "target_addr": getattr(result, "target_addr", None),
        "total_constraints": int(getattr(result, "total_constraints", 0)),
        "source_related_count": int(getattr(result, "source_related_count", 0)),
        "string_modeling_count": int(getattr(result, "string_modeling_count", 0)),
        "input_modeling_count": int(getattr(result, "input_modeling_count", 0)),
        "branch_condition_count": int(getattr(result, "branch_condition_count", 0)),
        "sanitizer_candidate_count": int(
            getattr(result, "sanitizer_candidate_count", 0)
        ),
        "unknown_source_count": int(getattr(result, "unknown_source_count", 0)),
        "sanitizer_like_observed": bool(
            getattr(result, "sanitizer_like_observed", False)
        ),
        "input_constraints": list(getattr(result, "input_constraints", [])),
        "string_modeling_constraints": string_modeling_constraints[:3],
        "input_modeling_constraints": input_modeling_constraints[:3],
        "branch_condition_constraints": branch_condition_constraints[:3],
        "sanitizer_candidate_constraints": sanitizer_candidates[:3],
        "unknown_source_constraints": unknown_source_constraints[:3],
        "error": getattr(result, "error", None),
    }


def _empty_constraint_observation(error: str | None) -> dict[str, Any]:
    return {
        "created": False,
        "reachable": False,
        "source_name": None,
        "symbolic_var": None,
        "runtime_binding": None,
        "target_sink": None,
        "target_addr": None,
        "total_constraints": 0,
        "source_related_count": 0,
        "string_modeling_count": 0,
        "input_modeling_count": 0,
        "branch_condition_count": 0,
        "sanitizer_candidate_count": 0,
        "unknown_source_count": 0,
        "sanitizer_like_observed": False,
        "input_constraints": [],
        "string_modeling_constraints": [],
        "input_modeling_constraints": [],
        "branch_condition_constraints": [],
        "sanitizer_candidate_constraints": [],
        "unknown_source_constraints": [],
        "error": error,
    }


def _summary_section(report: dict[str, Any]) -> dict[str, Any]:
    reachability = report["symbolic_reachability"]
    observation = report["constraint_observation"]
    source_to_sink_confirmed = bool(
        reachability["reachable"] and reachability["source_var_in_sink_arg"]
    )
    sanitizer_like_observed = bool(observation["sanitizer_like_observed"])

    errors = [
        report["source_model"].get("error"),
        report["angr_loader"].get("error"),
        reachability.get("error"),
        observation.get("error"),
    ]
    if source_to_sink_confirmed:
        status = "ok"
    elif reachability["reachable"] and not reachability["source_var_in_sink_arg"]:
        status = "not_source_to_sink"
    elif not reachability["reachable"] and reachability.get("error") == "target sink was not reached":
        status = "not_reachable"
    elif any(error for error in errors):
        status = "error"
    else:
        status = "not_reachable"

    return {
        "source_to_sink_confirmed": source_to_sink_confirmed,
        "sanitizer_like_observed": sanitizer_like_observed,
        "status": status,
    }
