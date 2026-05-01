from __future__ import annotations

from ns_aeg.planner_schema import (
    basic_validate_planner_input,
    basic_validate_planner_output,
    load_json,
)


def test_toy_02_planner_input_example_is_valid() -> None:
    data = load_json("examples/planner/toy_02_planner_input.json")

    assert basic_validate_planner_input(data) == []


def test_toy_02_planner_output_example_is_valid() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")

    assert basic_validate_planner_output(data) == []


def test_toy_05_planner_output_is_no_source_to_sink_and_valid() -> None:
    data = load_json("examples/planner/toy_05_planner_output.json")

    assert data["decision"] == "no_source_to_sink"
    assert basic_validate_planner_output(data) == []


def test_missing_required_key_returns_error() -> None:
    data = load_json("examples/planner/toy_02_planner_input.json")
    data.pop("target_name")

    errors = basic_validate_planner_input(data)

    assert "missing required key: target_name" in errors


def test_output_rejects_concrete_payload_field() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["concrete_payload"] = "not allowed"

    errors = basic_validate_planner_output(data)

    assert any("forbidden planner output key: $.concrete_payload" == error for error in errors)


def test_output_rejects_nested_command_field() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["candidate_plans"][0]["abstract_input_shape"]["command"] = "not allowed"

    errors = basic_validate_planner_output(data)

    assert any("command" in error for error in errors)


def test_output_requires_contains_concrete_payload_false() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["safety"]["contains_concrete_payload"] = True

    errors = basic_validate_planner_output(data)

    assert "safety.contains_concrete_payload must be false" in errors


def test_output_requires_contains_executable_code_false() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["safety"]["contains_executable_code"] = True

    errors = basic_validate_planner_output(data)

    assert "safety.contains_executable_code must be false" in errors


def test_output_rejects_illegal_decision() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["decision"] = "generate_input"

    errors = basic_validate_planner_output(data)

    assert "decision is invalid" in errors


def test_output_requires_symbolic_verification_for_candidate_plans() -> None:
    data = load_json("examples/planner/toy_02_planner_output.json")
    data["candidate_plans"][0]["requires_symbolic_verification"] = False

    errors = basic_validate_planner_output(data)

    assert any("requires_symbolic_verification must be true" in error for error in errors)


def test_examples_do_not_contain_solver_or_exploit_terms() -> None:
    examples = [
        load_json("examples/planner/toy_02_planner_input.json"),
        load_json("examples/planner/toy_02_planner_output.json"),
        load_json("examples/planner/toy_05_planner_input.json"),
        load_json("examples/planner/toy_05_planner_output.json"),
    ]

    serialized = repr(examples).lower()

    assert "solver.eval" not in serialized
    assert "exploit" not in serialized
