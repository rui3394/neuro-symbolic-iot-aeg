from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.planner_schema import basic_validate_planner_output, load_json

DEFAULT_VERIFIER_DIR = Path("examples") / "verifier"


def build_verification_request(
    planner_output_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    planner_output = load_json(planner_output_path)
    errors = basic_validate_planner_output(planner_output)
    if errors:
        raise ValueError("; ".join(errors))

    request = _request_from_planner_output(planner_output)
    path = (
        Path(output_path)
        if output_path is not None
        else default_verification_request_path(request["target_name"])
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return request


def run_symbolic_verifier_skeleton(
    verification_request_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    request = _load_json_object(verification_request_path)
    result = _result_from_request(request)
    path = (
        Path(output_path)
        if output_path is not None
        else default_verification_result_path(result["target_name"])
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def build_verification_requests_from_dir(
    planner_output_dir: str,
    output_dir: str = str(DEFAULT_VERIFIER_DIR),
) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    built = 0
    errors = 0

    for planner_output_path in sorted(Path(planner_output_dir).glob("*_planner_output.json")):
        try:
            planner_output = load_json(str(planner_output_path))
            target_name = str(planner_output.get("target_name") or planner_output_path.stem)
            output_path = Path(output_dir) / f"{target_name}_verification_request.json"
            request = build_verification_request(str(planner_output_path), str(output_path))
            built += 1
            targets.append(
                {
                    "input_path": str(planner_output_path),
                    "target_name": request["target_name"],
                    "requests": len(request["requests"]),
                    "output_path": str(output_path),
                    "error": None,
                }
            )
        except Exception as exc:
            errors += 1
            targets.append(
                {
                    "input_path": str(planner_output_path),
                    "target_name": planner_output_path.stem.removesuffix("_planner_output"),
                    "requests": 0,
                    "output_path": None,
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


def run_symbolic_verifier_skeleton_dir(
    verification_request_dir: str,
    output_dir: str = str(DEFAULT_VERIFIER_DIR),
) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    built = 0
    errors = 0

    for request_path in sorted(Path(verification_request_dir).glob("*_verification_request.json")):
        try:
            request = _load_json_object(str(request_path))
            target_name = str(request.get("target_name") or request_path.stem)
            output_path = Path(output_dir) / f"{target_name}_verification_result.json"
            result = run_symbolic_verifier_skeleton(str(request_path), str(output_path))
            built += 1
            targets.append(
                {
                    "input_path": str(request_path),
                    "target_name": result["target_name"],
                    "deferred_requests": result["summary"]["deferred_requests"],
                    "output_path": str(output_path),
                    "error": None,
                }
            )
        except Exception as exc:
            errors += 1
            targets.append(
                {
                    "input_path": str(request_path),
                    "target_name": request_path.stem.removesuffix("_verification_request"),
                    "deferred_requests": 0,
                    "output_path": None,
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


def default_verification_request_path(target_name: str) -> Path:
    return DEFAULT_VERIFIER_DIR / f"{target_name}_verification_request.json"


def default_verification_result_path(target_name: str) -> Path:
    return DEFAULT_VERIFIER_DIR / f"{target_name}_verification_result.json"


def _request_from_planner_output(planner_output: dict[str, Any]) -> dict[str, Any]:
    target_name = str(planner_output["target_name"])
    requests = []
    if planner_output["decision"] != "no_source_to_sink":
        requests = [
            {
                "candidate_id": plan["candidate_id"],
                "target_source": plan["target_source"],
                "verification_mode": "abstract_plan_only",
                "requires_symbolic_verification": bool(
                    plan["requires_symbolic_verification"]
                ),
                "abstract_input_shape": dict(plan["abstract_input_shape"]),
            }
            for plan in planner_output["candidate_plans"]
        ]

    return {
        "target_name": target_name,
        "planner_version": planner_output["planner_version"],
        "decision": planner_output["decision"],
        "requests": requests,
        "safety": {
            "contains_concrete_payload": False,
            "contains_executable_code": False,
            "verification_executes_input": False,
        },
    }


def _result_from_request(request: dict[str, Any]) -> dict[str, Any]:
    requests = request.get("requests", [])
    if not isinstance(requests, list):
        raise ValueError("verification request field 'requests' must be an array")

    results = [
        {
            "candidate_id": item.get("candidate_id"),
            "status": "not_executed",
            "reason": "abstract plan only; no concrete candidate input is available",
            "requires_future_symbolic_verification": True,
        }
        for item in requests
    ]
    deferred = len(results)
    status = "skeleton_ready" if deferred else "no_verification_needed"

    return {
        "target_name": str(request.get("target_name") or "unknown_target"),
        "executed": False,
        "mode": "skeleton_only",
        "results": results,
        "summary": {
            "total_requests": len(requests),
            "executed_requests": 0,
            "deferred_requests": deferred,
            "status": status,
        },
        "safety": {
            "executed_input": False,
            "generated_payload": False,
            "generated_poc": False,
        },
    }


def _load_json_object(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    return data
