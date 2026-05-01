from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_VERIFIER_DIR = Path("examples") / "verifier"

CANDIDATE_REQUIRED = {
    "candidate_id",
    "target_name",
    "target_source",
    "candidate_kind",
    "candidate_value",
    "encoding",
    "max_len",
    "constraints_claimed",
    "safety",
    "requires_symbolic_verification",
}
CANDIDATE_ALLOWED = CANDIDATE_REQUIRED
CONSTRAINTS_REQUIRED = {
    "respects_max_len",
    "avoids_observed_sanitizer_candidates",
    "satisfies_branch_conditions",
}
SAFETY_REQUIRED = {
    "local_toy_only",
    "contains_shell_metacharacters",
    "contains_network_target",
    "contains_file_operation",
    "contains_executable_code",
}
CANDIDATE_KINDS = {
    "benign_local_test_value",
    "abstract_placeholder",
    "human_supplied_test_value",
}
ENCODINGS = {"plain", "hex", "escaped"}
DANGEROUS_TOKENS = (";", "&", "|", "`", "$(")
DANGEROUS_KEYWORDS = ("rm ", "curl ", "wget ", "nc ", "bash ", "sh ")

REQUEST_REQUIRED = {
    "target_name",
    "binary",
    "source",
    "sink",
    "verification_mode",
    "candidates",
    "safety",
}
REQUEST_ALLOWED = REQUEST_REQUIRED
REQUEST_SOURCE_REQUIRED = {"name", "runtime_binding", "max_len"}
REQUEST_SINK_REQUIRED = {"name", "address"}
REQUEST_SAFETY_REQUIRED = {
    "local_toy_only",
    "executes_candidate",
    "generates_payload",
    "generates_poc",
}
VERIFICATION_MODES = {"local_toy_candidate_check", "abstract_contract_only"}

RESULT_REQUIRED = {
    "target_name",
    "verification_mode",
    "executed",
    "results",
    "summary",
    "safety",
}
RESULT_STATUSES = {
    "contract_ready",
    "deferred",
    "rejected_by_contract",
    "no_candidates",
    "error",
}


def load_json(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    return data


def validate_candidate_contract(candidate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    _check_required(candidate, CANDIDATE_REQUIRED, "$", errors)
    _check_allowed(candidate, CANDIDATE_ALLOWED, "$", errors)

    if candidate.get("candidate_kind") not in CANDIDATE_KINDS:
        errors.append("candidate_kind is invalid")
    if candidate.get("encoding") not in ENCODINGS:
        errors.append("encoding is invalid")
    if not isinstance(candidate.get("candidate_value"), str):
        errors.append("candidate_value must be a string")
    else:
        errors.extend(_dangerous_value_errors(candidate["candidate_value"]))
    if not isinstance(candidate.get("max_len"), int) or candidate.get("max_len", 0) <= 0:
        errors.append("max_len must be a positive integer")
    if candidate.get("requires_symbolic_verification") is not True:
        errors.append("requires_symbolic_verification must be true")

    constraints = candidate.get("constraints_claimed")
    if not isinstance(constraints, dict):
        errors.append("constraints_claimed must be an object")
    else:
        _check_required(constraints, CONSTRAINTS_REQUIRED, "constraints_claimed", errors)
        _check_allowed(constraints, CONSTRAINTS_REQUIRED, "constraints_claimed", errors)
        for key in CONSTRAINTS_REQUIRED:
            if key in constraints and not isinstance(constraints[key], bool):
                errors.append(f"constraints_claimed.{key} must be a boolean")

    safety = candidate.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety must be an object")
    else:
        _check_required(safety, SAFETY_REQUIRED, "safety", errors)
        _check_allowed(safety, SAFETY_REQUIRED, "safety", errors)
        if safety.get("local_toy_only") is not True:
            errors.append("safety.local_toy_only must be true")
        for key in (
            "contains_shell_metacharacters",
            "contains_network_target",
            "contains_file_operation",
            "contains_executable_code",
        ):
            if safety.get(key) is not False:
                errors.append(f"safety.{key} must be false")

    return errors


def validate_verifier_request_contract(request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    _check_required(request, REQUEST_REQUIRED, "$", errors)
    _check_allowed(request, REQUEST_ALLOWED, "$", errors)

    if request.get("verification_mode") not in VERIFICATION_MODES:
        errors.append("verification_mode is invalid")

    source = request.get("source")
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        _check_required(source, REQUEST_SOURCE_REQUIRED, "source", errors)
        _check_allowed(source, REQUEST_SOURCE_REQUIRED, "source", errors)
        if not isinstance(source.get("max_len"), int) or source.get("max_len", 0) <= 0:
            errors.append("source.max_len must be a positive integer")

    sink = request.get("sink")
    if not isinstance(sink, dict):
        errors.append("sink must be an object")
    else:
        _check_required(sink, REQUEST_SINK_REQUIRED, "sink", errors)
        _check_allowed(sink, REQUEST_SINK_REQUIRED, "sink", errors)

    safety = request.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety must be an object")
    else:
        _check_required(safety, REQUEST_SAFETY_REQUIRED, "safety", errors)
        _check_allowed(safety, REQUEST_SAFETY_REQUIRED, "safety", errors)
        if safety.get("local_toy_only") is not True:
            errors.append("safety.local_toy_only must be true")
        if safety.get("executes_candidate") is not False:
            errors.append("safety.executes_candidate must be false")
        if safety.get("generates_payload") is not False:
            errors.append("safety.generates_payload must be false")
        if safety.get("generates_poc") is not False:
            errors.append("safety.generates_poc must be false")

    candidates = request.get("candidates")
    if not isinstance(candidates, list):
        errors.append("candidates must be an array")
    else:
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                errors.append(f"candidates[{index}] must be an object")
                continue
            for error in validate_candidate_contract(candidate):
                errors.append(f"candidates[{index}]: {error}")

    return errors


def validate_verifier_result_contract(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    _check_required(result, RESULT_REQUIRED, "$", errors)

    if result.get("verification_mode") not in VERIFICATION_MODES:
        errors.append("verification_mode is invalid")
    if result.get("executed") is not False:
        errors.append("executed must be false")

    results = result.get("results")
    if not isinstance(results, list):
        errors.append("results must be an array")
    else:
        for index, item in enumerate(results):
            if not isinstance(item, dict):
                errors.append(f"results[{index}] must be an object")
                continue
            if item.get("verified") is not False:
                errors.append(f"results[{index}].verified must be false")
            if item.get("status") not in {"deferred", "rejected_by_contract"}:
                errors.append(f"results[{index}].status is invalid")

    summary = result.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
    elif summary.get("status") not in RESULT_STATUSES:
        errors.append("summary.status is invalid")

    safety = result.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety must be an object")
    else:
        if safety.get("executed_input") is not False:
            errors.append("safety.executed_input must be false")
        if safety.get("generated_payload") is not False:
            errors.append("safety.generated_payload must be false")
        if safety.get("generated_poc") is not False:
            errors.append("safety.generated_poc must be false")

    return errors


def build_verifier_request_from_candidates(
    analysis_report_path: str,
    candidates_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    report = load_json(analysis_report_path)
    candidates = _load_candidates(candidates_path)
    target = report.get("target", {})
    source = _first_source(report)
    reachability = report.get("symbolic_reachability", {})

    target_name = str(target.get("name") or "unknown_target")
    request = {
        "target_name": target_name,
        "binary": str(target.get("binary") or ""),
        "source": {
            "name": source["name"],
            "runtime_binding": source["runtime_binding"],
            "max_len": source["max_len"],
        },
        "sink": {
            "name": str(reachability.get("target_sink") or "system"),
            "address": reachability.get("target_addr"),
        },
        "verification_mode": (
            "local_toy_candidate_check" if candidates else "abstract_contract_only"
        ),
        "candidates": candidates,
        "safety": {
            "local_toy_only": True,
            "executes_candidate": False,
            "generates_payload": False,
            "generates_poc": False,
        },
    }

    output = (
        Path(output_path)
        if output_path is not None
        else DEFAULT_VERIFIER_DIR / f"{target_name}_candidate_verifier_request.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return request


def run_contract_only_verifier(
    verifier_request_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    request = load_json(verifier_request_path)
    candidates = request.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []

    results = []
    accepted_count = 0
    rejected_count = 0
    for candidate in candidates:
        candidate_id = candidate.get("candidate_id", "unknown_candidate")
        errors = validate_candidate_contract(candidate) if isinstance(candidate, dict) else [
            "candidate must be an object"
        ]
        if errors:
            rejected_count += 1
            results.append(
                {
                    "candidate_id": str(candidate_id),
                    "accepted_by_contract": False,
                    "verified": False,
                    "status": "rejected_by_contract",
                    "reason": "; ".join(errors),
                }
            )
        else:
            accepted_count += 1
            results.append(
                {
                    "candidate_id": str(candidate_id),
                    "accepted_by_contract": True,
                    "verified": False,
                    "status": "deferred",
                    "reason": "candidate execution is disabled in current skeleton",
                }
            )

    if not candidates:
        status = "no_candidates"
    elif rejected_count:
        status = "rejected_by_contract"
    else:
        status = "contract_ready"

    result = {
        "target_name": str(request.get("target_name") or "unknown_target"),
        "verification_mode": str(request.get("verification_mode") or "abstract_contract_only"),
        "executed": False,
        "results": results,
        "summary": {
            "total_candidates": len(candidates),
            "accepted_by_contract": accepted_count,
            "verified_count": 0,
            "deferred_count": accepted_count,
            "rejected_count": rejected_count,
            "status": status,
        },
        "safety": {
            "executed_input": False,
            "generated_payload": False,
            "generated_poc": False,
        },
    }

    output = (
        Path(output_path)
        if output_path is not None
        else DEFAULT_VERIFIER_DIR
        / f"{result['target_name']}_candidate_verifier_result.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _load_candidates(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        candidates = data.get("candidates", [])
    else:
        raise ValueError("candidate file must be an object or array")
    if not isinstance(candidates, list):
        raise ValueError("candidates must be an array")
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _first_source(report: dict[str, Any]) -> dict[str, Any]:
    sources = report.get("source_model", {}).get("sources", [])
    source = sources[0] if isinstance(sources, list) and sources else {}
    return {
        "name": str(source.get("name") or "unknown_source"),
        "runtime_binding": str(source.get("runtime_binding") or "argv[1]"),
        "max_len": int(source.get("max_len") or 1),
    }


def _dangerous_value_errors(value: str) -> list[str]:
    lowered = value.lower()
    errors = []
    for token in DANGEROUS_TOKENS:
        if token in value:
            errors.append(f"candidate_value contains disallowed token: {token}")
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in lowered:
            errors.append(f"candidate_value contains disallowed keyword: {keyword.strip()}")
    return errors


def _check_required(
    data: dict[str, Any],
    required: set[str],
    prefix: str,
    errors: list[str],
) -> None:
    for key in sorted(required - set(data)):
        errors.append(f"missing required key: {prefix}.{key}")


def _check_allowed(
    data: dict[str, Any],
    allowed: set[str],
    prefix: str,
    errors: list[str],
) -> None:
    for key in sorted(set(data) - allowed):
        errors.append(f"unexpected key: {prefix}.{key}")
