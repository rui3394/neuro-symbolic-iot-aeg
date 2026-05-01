from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.mock_planner import run_mock_planner, run_mock_planner_dir
from ns_aeg.planner_schema import basic_validate_planner_output


def test_no_source_to_sink_decision_has_no_candidate_plans(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(source_to_sink=False))

    output = run_mock_planner(str(input_path))

    assert output["decision"] == "no_source_to_sink"
    assert output["candidate_plans"] == []
    assert basic_validate_planner_output(output) == []


def test_source_to_sink_decision_has_candidate_plan(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(source_to_sink=True))

    output = run_mock_planner(str(input_path))

    assert output["decision"] == "candidate_plan_available"
    assert len(output["candidate_plans"]) == 1
    assert basic_validate_planner_output(output) == []


def test_toy_05_style_input_does_not_generate_candidate_plans(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(
        tmp_path,
        _planner_input(target_name="toy_05_safe_case", source_to_sink=False),
    )

    output = run_mock_planner(str(input_path))

    assert output["target_name"] == "toy_05_safe_case"
    assert output["decision"] == "no_source_to_sink"
    assert output["candidate_plans"] == []


def test_sanitizer_candidate_adds_abstract_forbidden_byte_class(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(
        tmp_path,
        _planner_input(kinds=["sanitizer_candidate"]),
    )

    output = run_mock_planner(str(input_path))
    shape = output["candidate_plans"][0]["abstract_input_shape"]

    assert "sanitizer_candidate_constraints" in output["candidate_plans"][0][
        "constraints_considered"
    ]
    assert shape["forbidden_byte_classes"] == ["observed_fixed_test_byte_or_class"]


def test_branch_condition_sets_abstract_required_prefix(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(kinds=["branch_condition"]))

    output = run_mock_planner(str(input_path))
    shape = output["candidate_plans"][0]["abstract_input_shape"]

    assert "branch_condition_constraints" in output["candidate_plans"][0][
        "constraints_considered"
    ]
    assert shape["required_prefix"] == "observed_branch_prefix"
    assert "AB" not in json.dumps(output)


def test_input_modeling_is_recorded_as_constraint_considered(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(kinds=["input_modeling"]))

    output = run_mock_planner(str(input_path))

    assert "input_modeling_constraints" in output["candidate_plans"][0][
        "constraints_considered"
    ]


def test_no_sanitizer_or_branch_uses_source_to_sink_confirmed(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(kinds=[]))

    output = run_mock_planner(str(input_path))

    assert output["candidate_plans"][0]["constraints_considered"] == [
        "source_to_sink_confirmed"
    ]


def test_output_safety_fields_are_fixed(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input())

    output = run_mock_planner(str(input_path))

    assert output["safety"] == {
        "contains_concrete_payload": False,
        "contains_executable_code": False,
        "requires_human_review": True,
    }


def test_output_has_no_forbidden_planning_keys_outside_safety(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(kinds=["sanitizer_candidate"]))

    output = run_mock_planner(str(input_path))

    assert _forbidden_keys_outside_safety(output) == []
    assert "solver.eval" not in json.dumps(output)
    assert "exploit" not in json.dumps(output).lower()
    assert "poc" not in json.dumps(output).lower()


def test_default_output_path_uses_target_name(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input(target_name="toy_default"))

    run_mock_planner(str(input_path))

    assert (tmp_path / "examples" / "planner" / "toy_default_planner_output.json").exists()


def test_custom_output_path_is_used(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = _write_input(tmp_path, _planner_input())
    output_path = tmp_path / "custom" / "planner_output.json"

    run_mock_planner(str(input_path), str(output_path))

    assert output_path.exists()
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["target_name"] == "toy_mock"


def test_mock_plan_dir_processes_multiple_inputs(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "examples" / "planner"
    input_dir.mkdir(parents=True)
    _write_input(input_dir, _planner_input(target_name="toy_a"), "toy_a_planner_input.json")
    _write_input(
        input_dir,
        _planner_input(target_name="toy_b", source_to_sink=False),
        "toy_b_planner_input.json",
    )
    (input_dir / "toy_a_planner_output.json").write_text("{}", encoding="utf-8")

    summary = run_mock_planner_dir(str(input_dir))

    assert summary["inputs"] == 2
    assert summary["built"] == 2
    assert summary["errors"] == 0
    assert (input_dir / "toy_a_planner_output.json").exists()
    assert (input_dir / "toy_b_planner_output.json").exists()


def _write_input(
    directory: Path,
    data: dict[str, Any],
    filename: str = "toy_mock_planner_input.json",
) -> Path:
    path = directory / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _planner_input(
    *,
    target_name: str = "toy_mock",
    source_to_sink: bool = True,
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    kinds = ["sanitizer_candidate"] if kinds is None else kinds
    return {
        "target_name": target_name,
        "source": {
            "name": "ip",
            "source_type": "http_param",
            "symbolic_name": "sym_ip",
            "runtime_binding": "argv[1]",
            "max_len": 32,
        },
        "sink": {
            "name": "system",
            "address": "0x401090",
            "source_reaches_sink_arg": source_to_sink,
        },
        "observations": {
            "source_to_sink_confirmed": source_to_sink,
            "sanitizer_like_observed": "sanitizer_candidate" in kinds,
            "sanitizer_candidate_count": 1 if "sanitizer_candidate" in kinds else 0,
            "branch_condition_count": 1 if "branch_condition" in kinds else 0,
            "input_modeling_count": 1 if "input_modeling" in kinds else 0,
            "string_modeling_count": 0,
            "unknown_source_count": 0,
        },
        "constraint_summaries": [
            {
                "kind": kind,
                "description": f"observed {kind} constraint",
                "raw": "<truncated constraint text>",
            }
            for kind in kinds
        ],
        "scope": {
            "environment": "local_toy_binary",
            "allowed_action": "structured_candidate_planning_only",
            "disallowed_actions": [
                "no_execution",
                "no_network",
                "no_real_device",
                "no_poc_generation",
            ],
        },
    }


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
