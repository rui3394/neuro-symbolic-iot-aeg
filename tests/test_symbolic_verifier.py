from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.symbolic_verifier import (
    build_verification_request,
    build_verification_requests_from_dir,
    run_symbolic_verifier_skeleton,
    run_symbolic_verifier_skeleton_dir,
)


def test_candidate_plan_available_generates_one_verification_request(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(tmp_path, "toy_planner_output.json", _planner_output())

    request = build_verification_request(str(planner_output_path))

    assert request["target_name"] == "toy_verifier"
    assert request["decision"] == "candidate_plan_available"
    assert len(request["requests"]) == 1
    assert request["requests"][0]["verification_mode"] == "abstract_plan_only"


def test_no_source_to_sink_generates_empty_requests(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(
        tmp_path,
        "toy_safe_planner_output.json",
        _planner_output(decision="no_source_to_sink", candidate_plans=[]),
    )

    request = build_verification_request(str(planner_output_path))

    assert request["decision"] == "no_source_to_sink"
    assert request["requests"] == []


def test_request_safety_fields_are_fixed(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(tmp_path, "toy_planner_output.json", _planner_output())

    request = build_verification_request(str(planner_output_path))

    assert request["safety"] == {
        "contains_concrete_payload": False,
        "contains_executable_code": False,
        "verification_executes_input": False,
    }


def test_request_has_no_forbidden_fields_outside_safety(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(tmp_path, "toy_planner_output.json", _planner_output())

    request = build_verification_request(str(planner_output_path))

    assert _forbidden_keys_outside_safety(request) == []
    serialized = json.dumps(request).lower()
    assert "solver.eval" not in serialized
    assert "exploit" not in serialized
    assert "poc" not in serialized


def test_verifier_skeleton_does_not_execute_input(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "toy_verification_request.json", _request())

    result = run_symbolic_verifier_skeleton(str(request_path))

    assert result["executed"] is False
    assert result["safety"] == {
        "executed_input": False,
        "generated_payload": False,
        "generated_poc": False,
    }


def test_abstract_request_result_status_is_not_executed(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "toy_verification_request.json", _request())

    result = run_symbolic_verifier_skeleton(str(request_path))

    assert result["results"][0]["status"] == "not_executed"
    assert result["results"][0]["requires_future_symbolic_verification"] is True
    assert result["summary"] == {
        "total_requests": 1,
        "executed_requests": 0,
        "deferred_requests": 1,
        "status": "skeleton_ready",
    }


def test_empty_requests_summary_is_no_verification_needed(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "toy_verification_request.json", _request(requests=[]))

    result = run_symbolic_verifier_skeleton(str(request_path))

    assert result["results"] == []
    assert result["summary"] == {
        "total_requests": 0,
        "executed_requests": 0,
        "deferred_requests": 0,
        "status": "no_verification_needed",
    }


def test_default_request_output_path_uses_target_name(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(tmp_path, "toy_planner_output.json", _planner_output())

    build_verification_request(str(planner_output_path))

    assert (
        tmp_path
        / "examples"
        / "verifier"
        / "toy_verifier_verification_request.json"
    ).exists()


def test_default_result_output_path_uses_target_name(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "toy_verification_request.json", _request())

    run_symbolic_verifier_skeleton(str(request_path))

    assert (
        tmp_path
        / "examples"
        / "verifier"
        / "toy_verifier_verification_result.json"
    ).exists()


def test_custom_output_paths_are_used(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    planner_output_path = _write_json(tmp_path, "toy_planner_output.json", _planner_output())
    request_output = tmp_path / "custom" / "request.json"
    result_output = tmp_path / "custom" / "result.json"

    build_verification_request(str(planner_output_path), str(request_output))
    run_symbolic_verifier_skeleton(str(request_output), str(result_output))

    assert request_output.exists()
    assert result_output.exists()


def test_batch_build_requests_handles_multiple_planner_outputs(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    planner_dir = tmp_path / "examples" / "planner"
    planner_dir.mkdir(parents=True)
    _write_json(planner_dir, "toy_a_planner_output.json", _planner_output("toy_a"))
    _write_json(
        planner_dir,
        "toy_b_planner_output.json",
        _planner_output("toy_b", decision="no_source_to_sink", candidate_plans=[]),
    )
    _write_json(planner_dir, "toy_a_planner_input.json", {"ignored": True})

    summary = build_verification_requests_from_dir(str(planner_dir))

    assert summary["inputs"] == 2
    assert summary["built"] == 2
    assert summary["errors"] == 0
    assert (tmp_path / "examples" / "verifier" / "toy_a_verification_request.json").exists()
    assert (tmp_path / "examples" / "verifier" / "toy_b_verification_request.json").exists()


def test_batch_run_verifier_skeleton_handles_multiple_requests(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    verifier_dir = tmp_path / "examples" / "verifier"
    verifier_dir.mkdir(parents=True)
    _write_json(verifier_dir, "toy_a_verification_request.json", _request("toy_a"))
    _write_json(verifier_dir, "toy_b_verification_request.json", _request("toy_b", []))

    summary = run_symbolic_verifier_skeleton_dir(str(verifier_dir))

    assert summary["inputs"] == 2
    assert summary["built"] == 2
    assert summary["errors"] == 0
    assert (verifier_dir / "toy_a_verification_result.json").exists()
    assert (verifier_dir / "toy_b_verification_result.json").exists()


def _planner_output(
    target_name: str = "toy_verifier",
    *,
    decision: str = "candidate_plan_available",
    candidate_plans: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if candidate_plans is None:
        candidate_plans = [
            {
                "candidate_id": "cand_001",
                "target_source": "ip",
                "intent": "reach_sink_under_observed_constraints",
                "constraints_considered": ["sanitizer_candidate_constraints"],
                "abstract_input_shape": {
                    "max_len": 32,
                    "required_prefix": None,
                    "forbidden_byte_classes": ["observed_fixed_test_byte_or_class"],
                    "notes": "abstract only; no concrete input generated",
                },
                "requires_symbolic_verification": True,
            }
        ]
    return {
        "planner_version": "0.1",
        "target_name": target_name,
        "decision": decision,
        "rationale_summary": "abstract mock planner output",
        "candidate_plans": candidate_plans,
        "safety": {
            "contains_concrete_payload": False,
            "contains_executable_code": False,
            "requires_human_review": True,
        },
    }


def _request(
    target_name: str = "toy_verifier",
    requests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if requests is None:
        requests = [
            {
                "candidate_id": "cand_001",
                "target_source": "ip",
                "verification_mode": "abstract_plan_only",
                "requires_symbolic_verification": True,
                "abstract_input_shape": {
                    "max_len": 32,
                    "required_prefix": None,
                    "forbidden_byte_classes": ["observed_fixed_test_byte_or_class"],
                    "notes": "abstract only; no concrete input generated",
                },
            }
        ]
    return {
        "target_name": target_name,
        "planner_version": "0.1",
        "decision": "candidate_plan_available",
        "requests": requests,
        "safety": {
            "contains_concrete_payload": False,
            "contains_executable_code": False,
            "verification_executes_input": False,
        },
    }


def _write_json(directory: Path, filename: str, data: dict[str, Any]) -> Path:
    path = directory / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _forbidden_keys_outside_safety(data: Any, in_safety: bool = False) -> list[str]:
    forbidden = {"concrete_payload", "payload", "command", "script", "code"}
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            next_in_safety = in_safety or key == "safety"
            if not next_in_safety and key in forbidden:
                found.append(key)
            found.extend(_forbidden_keys_outside_safety(value, next_in_safety))
    elif isinstance(data, list):
        for value in data:
            found.extend(_forbidden_keys_outside_safety(value, in_safety))
    return found
