from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

CONSTRAINT_KINDS = {
    "sanitizer_candidate",
    "branch_condition",
    "input_modeling",
    "string_modeling",
    "unknown",
}
DECISIONS = {
    "candidate_plan_available",
    "no_source_to_sink",
    "insufficient_information",
}
INPUT_REQUIRED = {
    "target_name",
    "source",
    "sink",
    "observations",
    "constraint_summaries",
    "scope",
}
OUTPUT_REQUIRED = {
    "planner_version",
    "target_name",
    "decision",
    "rationale_summary",
    "candidate_plans",
    "safety",
}
FORBIDDEN_OUTPUT_KEYS = {
    "concrete_payload",
    "payload",
    "command",
    "shell_command",
    "script",
    "code",
    "executable",
}
ALLOWED_SAFETY_KEYS = {
    "contains_concrete_payload",
    "contains_executable_code",
    "requires_human_review",
}
INPUT_ALLOWED = INPUT_REQUIRED
SOURCE_ALLOWED = {"name", "source_type", "symbolic_name", "runtime_binding", "max_len"}
SINK_ALLOWED = {"name", "address", "source_reaches_sink_arg"}
OBSERVATIONS_ALLOWED = {
    "source_to_sink_confirmed",
    "sanitizer_like_observed",
    "sanitizer_candidate_count",
    "branch_condition_count",
    "input_modeling_count",
    "string_modeling_count",
    "unknown_source_count",
}
CONSTRAINT_SUMMARY_ALLOWED = {"kind", "description", "raw"}
SCOPE_ALLOWED = {"environment", "allowed_action", "disallowed_actions"}
OUTPUT_ALLOWED = OUTPUT_REQUIRED
PLAN_ALLOWED = {
    "candidate_id",
    "target_source",
    "intent",
    "constraints_considered",
    "abstract_input_shape",
    "requires_symbolic_verification",
}
ABSTRACT_SHAPE_ALLOWED = {
    "max_len",
    "required_prefix",
    "forbidden_byte_classes",
    "notes",
}


def load_json(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    return data


def validate_required_keys(data: dict[str, Any], schema_kind: str) -> list[str]:
    if schema_kind == "input":
        required = INPUT_REQUIRED
    elif schema_kind == "output":
        required = OUTPUT_REQUIRED
    else:
        return [f"unknown schema kind: {schema_kind}"]

    return [f"missing required key: {key}" for key in sorted(required - set(data))]


def basic_validate_planner_input(data: dict[str, Any]) -> list[str]:
    errors = validate_required_keys(data, "input")
    _check_allowed_keys(data, "$", INPUT_ALLOWED, errors)

    source = _require_object(data, "source", errors)
    if source is not None:
        _check_allowed_keys(source, "source", SOURCE_ALLOWED, errors)
        _check_required_nested(
            source,
            "source",
            {"name", "source_type", "symbolic_name", "runtime_binding", "max_len"},
            errors,
        )
        if source.get("source_type") != "http_param":
            errors.append("source.source_type must be http_param")
        if not isinstance(source.get("runtime_binding"), str) or not re.fullmatch(
            r"argv\[[0-9]+\]",
            source.get("runtime_binding", ""),
        ):
            errors.append("source.runtime_binding must have form argv[n]")
        if not isinstance(source.get("max_len"), int) or source.get("max_len", 0) <= 0:
            errors.append("source.max_len must be a positive integer")

    sink = _require_object(data, "sink", errors)
    if sink is not None:
        _check_allowed_keys(sink, "sink", SINK_ALLOWED, errors)
        _check_required_nested(
            sink,
            "sink",
            {"name", "address", "source_reaches_sink_arg"},
            errors,
        )
        if sink.get("name") not in {"system", "popen", "snprintf"}:
            errors.append("sink.name must be system, popen, or snprintf")
        if not isinstance(sink.get("source_reaches_sink_arg"), bool):
            errors.append("sink.source_reaches_sink_arg must be a boolean")

    observations = _require_object(data, "observations", errors)
    if observations is not None:
        _check_allowed_keys(observations, "observations", OBSERVATIONS_ALLOWED, errors)
        _check_required_nested(
            observations,
            "observations",
            {
                "source_to_sink_confirmed",
                "sanitizer_like_observed",
                "sanitizer_candidate_count",
                "branch_condition_count",
                "input_modeling_count",
                "string_modeling_count",
                "unknown_source_count",
            },
            errors,
        )
        for key in ("source_to_sink_confirmed", "sanitizer_like_observed"):
            if key in observations and not isinstance(observations[key], bool):
                errors.append(f"observations.{key} must be a boolean")
        for key in (
            "sanitizer_candidate_count",
            "branch_condition_count",
            "input_modeling_count",
            "string_modeling_count",
            "unknown_source_count",
        ):
            if key in observations and (
                not isinstance(observations[key], int) or observations[key] < 0
            ):
                errors.append(f"observations.{key} must be a non-negative integer")

    summaries = data.get("constraint_summaries")
    if not isinstance(summaries, list):
        errors.append("constraint_summaries must be an array")
    else:
        for index, summary in enumerate(summaries):
            if not isinstance(summary, dict):
                errors.append(f"constraint_summaries[{index}] must be an object")
                continue
            _check_allowed_keys(
                summary,
                f"constraint_summaries[{index}]",
                CONSTRAINT_SUMMARY_ALLOWED,
                errors,
            )
            _check_required_nested(
                summary,
                f"constraint_summaries[{index}]",
                {"kind", "description", "raw"},
                errors,
            )
            if summary.get("kind") not in CONSTRAINT_KINDS:
                errors.append(f"constraint_summaries[{index}].kind is invalid")

    scope = _require_object(data, "scope", errors)
    if scope is not None:
        _check_allowed_keys(scope, "scope", SCOPE_ALLOWED, errors)
        _check_required_nested(
            scope,
            "scope",
            {"environment", "allowed_action", "disallowed_actions"},
            errors,
        )
        if scope.get("environment") != "local_toy_binary":
            errors.append("scope.environment must be local_toy_binary")
        if scope.get("allowed_action") != "structured_candidate_planning_only":
            errors.append("scope.allowed_action must be structured_candidate_planning_only")
        if not isinstance(scope.get("disallowed_actions"), list):
            errors.append("scope.disallowed_actions must be an array")
        else:
            allowed_disallowed = {
                "no_execution",
                "no_network",
                "no_real_device",
                "no_poc_generation",
            }
            for action in scope["disallowed_actions"]:
                if action not in allowed_disallowed:
                    errors.append(f"scope.disallowed_actions contains invalid value: {action}")

    return errors


def basic_validate_planner_output(data: dict[str, Any]) -> list[str]:
    errors = validate_required_keys(data, "output")
    _check_allowed_keys(data, "$", OUTPUT_ALLOWED, errors)
    errors.extend(_find_forbidden_output_keys(data))

    if data.get("decision") not in DECISIONS:
        errors.append("decision is invalid")

    plans = data.get("candidate_plans")
    if not isinstance(plans, list):
        errors.append("candidate_plans must be an array")
    else:
        for index, plan in enumerate(plans):
            if not isinstance(plan, dict):
                errors.append(f"candidate_plans[{index}] must be an object")
                continue
            _check_allowed_keys(plan, f"candidate_plans[{index}]", PLAN_ALLOWED, errors)
            _check_required_nested(
                plan,
                f"candidate_plans[{index}]",
                {
                    "candidate_id",
                    "target_source",
                    "intent",
                    "constraints_considered",
                    "abstract_input_shape",
                    "requires_symbolic_verification",
                },
                errors,
            )
            if plan.get("intent") != "reach_sink_under_observed_constraints":
                errors.append(f"candidate_plans[{index}].intent is invalid")
            if plan.get("requires_symbolic_verification") is not True:
                errors.append(
                    f"candidate_plans[{index}].requires_symbolic_verification must be true"
                )
            if not isinstance(plan.get("constraints_considered"), list):
                errors.append(f"candidate_plans[{index}].constraints_considered must be an array")
            shape = plan.get("abstract_input_shape")
            if not isinstance(shape, dict):
                errors.append(f"candidate_plans[{index}].abstract_input_shape must be an object")
            else:
                _check_allowed_keys(
                    shape,
                    f"candidate_plans[{index}].abstract_input_shape",
                    ABSTRACT_SHAPE_ALLOWED,
                    errors,
                )
                _check_required_nested(
                    shape,
                    f"candidate_plans[{index}].abstract_input_shape",
                    {"max_len", "required_prefix", "forbidden_byte_classes", "notes"},
                    errors,
                )
                if not isinstance(shape.get("max_len"), int) or shape.get("max_len", 0) <= 0:
                    errors.append(
                        f"candidate_plans[{index}].abstract_input_shape.max_len "
                        "must be a positive integer"
                    )
                if not isinstance(shape.get("forbidden_byte_classes"), list):
                    errors.append(
                        f"candidate_plans[{index}].abstract_input_shape."
                        "forbidden_byte_classes must be an array"
                    )

    safety = _require_object(data, "safety", errors)
    if safety is not None:
        _check_allowed_keys(safety, "safety", ALLOWED_SAFETY_KEYS, errors)
        _check_required_nested(
            safety,
            "safety",
            {
                "contains_concrete_payload",
                "contains_executable_code",
                "requires_human_review",
            },
            errors,
        )
        if safety.get("contains_concrete_payload") is not False:
            errors.append("safety.contains_concrete_payload must be false")
        if safety.get("contains_executable_code") is not False:
            errors.append("safety.contains_executable_code must be false")
        if safety.get("requires_human_review") is not True:
            errors.append("safety.requires_human_review must be true")

    return errors


def _require_object(
    data: dict[str, Any],
    key: str,
    errors: list[str],
) -> dict[str, Any] | None:
    if key not in data:
        return None
    value = data[key]
    if not isinstance(value, dict):
        errors.append(f"{key} must be an object")
        return None
    return value


def _check_required_nested(
    data: dict[str, Any],
    prefix: str,
    required: set[str],
    errors: list[str],
) -> None:
    for key in sorted(required - set(data)):
        errors.append(f"missing required key: {prefix}.{key}")


def _check_allowed_keys(
    data: dict[str, Any],
    prefix: str,
    allowed: set[str],
    errors: list[str],
) -> None:
    for key in sorted(set(data) - allowed):
        errors.append(f"unexpected key: {prefix}.{key}")


def _find_forbidden_output_keys(data: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            lowered = key.lower()
            if key not in ALLOWED_SAFETY_KEYS and _is_forbidden_output_key(lowered):
                errors.append(f"forbidden planner output key: {path}.{key}")
            errors.extend(_find_forbidden_output_keys(value, f"{path}.{key}"))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            errors.extend(_find_forbidden_output_keys(value, f"{path}[{index}]"))
    return errors


def _is_forbidden_output_key(key: str) -> bool:
    if key in FORBIDDEN_OUTPUT_KEYS:
        return True
    return any(token in key for token in ("payload", "command", "script", "code"))
