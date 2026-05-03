from __future__ import annotations

import json
from pathlib import Path

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.planner.rule_planner import (
    DANGEROUS_CHARS,
    RulePlannerError,
    generate_candidate_set,
    generate_candidate_set_for_task_path,
    write_candidate_set,
)


def test_rule_planner_generates_benign_candidates_from_example_task() -> None:
    candidate_set = generate_candidate_set_for_task_path(
        "examples/dangerous_tasks/toy_01_task.example.json"
    )

    assert candidate_set["planner"]["name"] == "rule_based_planner"
    assert candidate_set["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert len(candidate_set["candidates"]) >= 4
    assert {candidate["strategy"] for candidate in candidate_set["candidates"]} >= {
        "benign_marker_direct",
        "marker_only",
        "prefix_with_marker",
        "length_boundary_safe",
    }


def test_rule_planner_candidates_are_safe_and_within_source_max_len() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    max_len = int(task["sources"][0]["max_len"])

    candidate_set = generate_candidate_set(task)

    for candidate in candidate_set["candidates"]:
        value = candidate["inputs"]["ip"]
        assert len(value) <= max_len
        assert "\n" not in value
        assert "\r" not in value
        assert not any(char in value for char in DANGEROUS_CHARS)
        assert candidate["safety"] == {"benign": True, "weaponized": False}


def test_rule_planner_uses_default_marker_when_task_marker_missing() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    task["expected"].pop("benign_marker")

    candidate_set = generate_candidate_set(task)

    assert any("__NS_AEG_MARKER__" in candidate["inputs"]["ip"] for candidate in candidate_set["candidates"])


def test_rule_planner_errors_without_sources() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    task["sources"] = []

    with pytest.raises(RulePlannerError, match="no sources"):
        generate_candidate_set(task)


def test_rule_planner_write_candidate_set(tmp_path: Path) -> None:
    candidate_set = generate_candidate_set_for_task_path(
        "examples/dangerous_tasks/toy_01_task.example.json"
    )
    output = tmp_path / "candidates.json"

    write_candidate_set(candidate_set, str(output))

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["planner"]["version"] == "0.1"
    assert data["candidates"][0]["inputs"]["ip"]


def test_rule_planner_records_blacklist_sanitizer_diagnostics() -> None:
    task = load_json("examples/dangerous_tasks/toy_02_task.real.json")

    candidate_set = generate_candidate_set(task)

    assert candidate_set["planner"]["mode"] == "sanitizer_aware_benign_baseline"
    assert candidate_set["planning_diagnostics"]["sanitizer_count"] == 1
    assert candidate_set["planning_diagnostics"]["sanitizer_types"] == ["blacklist"]
    assert len(candidate_set["candidates"]) >= 1
    assert candidate_set["rejected_candidates"] == []


def test_rule_planner_rejects_marker_incompatible_length_window() -> None:
    task = load_json("examples/dangerous_tasks/toy_03_task.real.json")

    candidate_set = generate_candidate_set(task)

    assert candidate_set["planner"]["mode"] == "sanitizer_aware_benign_baseline"
    assert candidate_set["candidates"] == []
    assert candidate_set["planning_diagnostics"]["sanitizer_types"] == ["length_window"]
    assert candidate_set["planning_diagnostics"]["rejected_count"] >= 1
    assert {
        rejected["reason"]
        for rejected in candidate_set["rejected_candidates"]
    } == {"marker_length_exceeds_required_window"}
