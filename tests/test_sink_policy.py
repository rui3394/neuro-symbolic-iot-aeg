from __future__ import annotations

from ns_aeg.verifier.sink_policy import evaluate_sink_policy


def test_system_policy_positive_when_source_and_marker_reach_arg0() -> None:
    result = evaluate_sink_policy(
        {"type": "command_execution", "function": "system"},
        {"contains_source": True, "contains_marker": True, "error": None},
    )

    assert result["policy_name"] == "command_execution_system_arg0"
    assert result["policy_status"] == "positive_evidence"
    assert result["source_reaches_sink"] is True
    assert result["marker_reaches_sink"] is True
    assert result["fixed_safe_argument"] is False


def test_system_policy_negative_when_sink_argument_has_no_source_or_marker() -> None:
    result = evaluate_sink_policy(
        {"type": "command_execution", "function": "system"},
        {"contains_source": False, "contains_marker": False, "error": None, "value_repr": "echo fixed"},
    )

    assert result["policy_status"] == "negative_evidence"
    assert result["reason"] == "safe_fixed_sink_argument_without_source"
    assert result["source_reaches_sink"] is False
    assert result["marker_reaches_sink"] is False
    assert result["fixed_safe_argument"] is True


def test_system_policy_inconclusive_when_argument_unreadable() -> None:
    result = evaluate_sink_policy(
        {"type": "command_execution", "function": "system"},
        {"contains_source": "unknown", "contains_marker": "unknown", "error": "read failed"},
    )

    assert result["policy_status"] == "inconclusive"
    assert result["reason"] == "sink_argument_unreadable"


def test_format_policy_is_auxiliary_not_command_positive() -> None:
    result = evaluate_sink_policy(
        {"type": "string_format", "function": "snprintf"},
        {"contains_source": True, "contains_marker": True},
    )

    assert result["policy_status"] == "inconclusive"
    assert result["policy_name"] == "string_format_snprintf"
    assert result["reason"] == "format_sink_evidence_is_auxiliary_not_command_execution_evidence"
    assert result["source_reaches_sink"] is True


def test_memcpy_policy_is_auxiliary_not_command_positive() -> None:
    result = evaluate_sink_policy(
        {"type": "memory_copy", "function": "memcpy"},
        {"contains_source": True, "contains_marker": True},
    )

    assert result["policy_status"] == "inconclusive"
    assert result["policy_name"] == "memory_copy_memcpy"
    assert result["reason"] == "memcpy_evidence_is_auxiliary_not_command_execution_evidence"
    assert result["source_reaches_sink"] is True
