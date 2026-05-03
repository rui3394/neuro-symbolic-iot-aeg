from __future__ import annotations

from typing import Any


UNKNOWN = "unknown"


def evaluate_sink_policy(
    sink: dict[str, Any],
    sink_argument: dict[str, Any],
    task: dict[str, Any] | None = None,
    candidate: dict[str, Any] | None = None,
    state: Any | None = None,
) -> dict[str, Any]:
    """Evaluate sink-specific source-to-sink evidence without executing the sink."""

    del task, candidate, state
    sink_type = str(sink.get("type") or "unknown")
    sink_function = str(sink.get("function") or sink.get("name") or "unknown")
    if sink_type == "command_execution" and sink_function == "system":
        return _evaluate_system_arg0_policy(sink, sink_argument)
    if sink_type in {"string_format", "string_formatting"} and sink_function in {"snprintf", "sprintf"}:
        return _evaluate_format_policy(sink, sink_argument)
    if sink_function in {"snprintf", "sprintf"}:
        return _evaluate_format_policy(sink, sink_argument)
    if sink_function == "memcpy":
        return _evaluate_memcpy_policy(sink, sink_argument)
    return _unsupported_policy(
        sink_type=sink_type,
        sink_function=sink_function,
        reason=f"no sink-specific policy implemented for {sink_type}/{sink_function}",
        limitation="sink-specific policy is currently implemented for command_execution/system and snprintf/sprintf format-flow evidence",
    )


def _unsupported_policy(
    *,
    sink_type: str,
    sink_function: str,
    reason: str,
    limitation: str,
) -> dict[str, Any]:
    return {
        "sink_type": sink_type,
        "sink_function": sink_function,
        "policy_name": "unsupported_sink_policy",
        "policy_status": "unsupported",
        "reason": reason,
        "source_reaches_sink": UNKNOWN,
        "marker_reaches_sink": UNKNOWN,
        "fixed_safe_argument": UNKNOWN,
        "limitations": [limitation],
    }


def _evaluate_system_arg0_policy(
    sink: dict[str, Any],
    sink_argument: dict[str, Any],
) -> dict[str, Any]:
    source_reaches = _tri_state(sink_argument.get("contains_source"))
    marker_reaches = _tri_state(sink_argument.get("contains_marker"))
    base = {
        "sink_type": str(sink.get("type") or "command_execution"),
        "sink_function": str(sink.get("function") or "system"),
        "policy_name": "command_execution_system_arg0",
        "source_reaches_sink": source_reaches,
        "marker_reaches_sink": marker_reaches,
        "limitations": [],
    }

    if source_reaches is True and marker_reaches is True:
        return {
            **base,
            "policy_status": "positive_evidence",
            "reason": "source_and_marker_observed_in_system_argument",
            "fixed_safe_argument": False,
        }

    if sink_argument.get("error"):
        return {
            **base,
            "policy_status": "inconclusive",
            "reason": "sink_argument_unreadable",
            "fixed_safe_argument": UNKNOWN,
            "limitations": [str(sink_argument["error"])],
        }

    if source_reaches is False and marker_reaches is False:
        return {
            **base,
            "policy_status": "negative_evidence",
            "reason": "safe_fixed_sink_argument_without_source",
            "fixed_safe_argument": _fixed_safe_argument(sink_argument),
            "limitations": [
                "negative evidence means this candidate did not place source/marker into system(arg0)",
            ],
        }

    return {
        **base,
        "policy_status": "inconclusive",
        "reason": "system_argument_evidence_incomplete",
        "fixed_safe_argument": UNKNOWN,
        "limitations": [
            "sink reached, but policy could not prove positive or negative source-to-sink evidence",
        ],
    }


def _evaluate_format_policy(
    sink: dict[str, Any],
    sink_argument: dict[str, Any],
) -> dict[str, Any]:
    source_reaches = _tri_state(sink_argument.get("contains_source"))
    marker_reaches = _tri_state(sink_argument.get("contains_marker"))
    function = str(sink.get("function") or "unknown")
    return {
        "sink_type": str(sink.get("type") or "string_formatting"),
        "sink_function": function,
        "policy_name": f"string_format_{function}",
        "policy_status": "inconclusive",
        "reason": "format_sink_evidence_is_auxiliary_not_command_execution_evidence",
        "source_reaches_sink": source_reaches,
        "marker_reaches_sink": marker_reaches,
        "fixed_safe_argument": UNKNOWN,
        "limitations": [
            "source/marker reaching snprintf/sprintf is not sufficient for command execution evidence",
            "final positive evidence must be observed at command_execution/system(arg0)",
        ],
    }


def _evaluate_memcpy_policy(
    sink: dict[str, Any],
    sink_argument: dict[str, Any],
) -> dict[str, Any]:
    source_reaches = _tri_state(sink_argument.get("contains_source"))
    marker_reaches = _tri_state(sink_argument.get("contains_marker"))
    return {
        "sink_type": str(sink.get("type") or "memory_copy"),
        "sink_function": str(sink.get("function") or "memcpy"),
        "policy_name": "memory_copy_memcpy",
        "policy_status": "inconclusive",
        "reason": "memcpy_evidence_is_auxiliary_not_command_execution_evidence",
        "source_reaches_sink": source_reaches,
        "marker_reaches_sink": marker_reaches,
        "fixed_safe_argument": UNKNOWN,
        "limitations": [
            "memcpy propagation is tracked as auxiliary memory-flow evidence in toy tasks",
            "final positive evidence must still be observed at command_execution/system(arg0)",
        ],
    }


def _tri_state(value: Any) -> bool | str:
    if isinstance(value, bool):
        return value
    return UNKNOWN


def _fixed_safe_argument(sink_argument: dict[str, Any]) -> bool | str:
    if sink_argument.get("contains_source") is False and sink_argument.get("contains_marker") is False:
        return True
    return UNKNOWN
