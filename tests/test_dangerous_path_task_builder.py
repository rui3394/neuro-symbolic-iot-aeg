from __future__ import annotations

import json
from pathlib import Path

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.tasks.builder import (
    DangerousPathTaskError,
    basic_validate_dangerous_path_task,
    build_dangerous_path_task,
)


def test_example_facts_and_toy_target_generate_task(tmp_path: Path) -> None:
    output = tmp_path / "task.json"

    task = build_dangerous_path_task(
        "examples/ghidra_exports/toy_01_facts.example.json",
        "configs/toy_01.yaml",
        output_path=str(output),
    )

    assert output.exists()
    assert task["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert task["binary"] == {
        "path": "datasets/toy_cgi/build/toy_01",
        "name": "toy_01",
        "arch": "x86",
    }
    assert len(task["sources"]) >= 1
    assert len(task["sinks"]) >= 1
    assert task["sources"][0]["name"] == "ip"
    assert {sink["function"] for sink in task["sinks"]} == {"system", "snprintf"}
    assert task["expected"]["oracle"] == "source_reaches_sink"
    assert basic_validate_dangerous_path_task(task) == []


def test_example_task_is_valid() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")

    assert basic_validate_dangerous_path_task(task) == []
    assert task["sources"]
    assert task["sinks"]


def test_json_schema_validates_task_example_when_available() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    schema = load_json("schemas/dangerous_path_task.schema.json")

    jsonschema.Draft202012Validator(schema).validate(task)


def test_missing_source_fails_clearly(tmp_path: Path) -> None:
    target = tmp_path / "no_source.yaml"
    target.write_text(
        "\n".join(
            [
                "name: no_source",
                "binary: datasets/toy_cgi/build/toy_01",
                "arch: auto",
                "http:",
                "  method: GET",
                "  path: /cgi-bin/ping",
                "  params:",
                "    ip:",
                "      source: false",
                "analysis:",
                "  vulnerability_type: command_injection",
                "  sinks:",
                "    - system",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(DangerousPathTaskError, match="no HTTP source parameters"):
        build_dangerous_path_task(
            "examples/ghidra_exports/toy_01_facts.example.json",
            str(target),
        )


def test_missing_sink_fails_clearly(tmp_path: Path) -> None:
    facts = load_json("examples/ghidra_exports/toy_01_facts.example.json")
    facts["dangerous_sinks"] = []
    facts_path = tmp_path / "no_sinks.json"
    facts_path.write_text(json.dumps(facts), encoding="utf-8")

    with pytest.raises(DangerousPathTaskError, match="no dangerous sinks"):
        build_dangerous_path_task(str(facts_path), "configs/toy_01.yaml")


def test_task_builder_prefers_sink_callsite_address(tmp_path: Path) -> None:
    facts = load_json("examples/ghidra_exports/toy_01_facts.example.json")
    facts["dangerous_sinks"] = [
        {
            "name": "system",
            "category": "command_execution",
            "address": "0x3",
            "external_address": "0x3",
            "imported": True,
            "source": "import",
            "description": "Executes a shell command string supplied by the caller.",
            "callers": [],
            "callsites": [
                {
                    "address": "0x4011f9",
                    "caller": "main",
                    "caller_entry": "0x401176",
                }
            ],
        }
    ]
    facts_path = tmp_path / "facts_with_callsites.json"
    facts_path.write_text(json.dumps(facts), encoding="utf-8")

    task = build_dangerous_path_task(str(facts_path), "configs/toy_01.yaml")

    assert task["sinks"] == [
        {
            "sink_id": "sink_1:system",
            "type": "command_execution",
            "function": "system",
            "address": "0x4011f9",
            "arg_index": 0,
            "callers": ["main"],
            "external_address": "0x3",
        }
    ]
    assert basic_validate_dangerous_path_task(task) == []


def test_missing_target_path_fails_clearly() -> None:
    with pytest.raises(DangerousPathTaskError, match="target YAML does not exist"):
        build_dangerous_path_task(
            "examples/ghidra_exports/toy_01_facts.example.json",
            "configs/missing.yaml",
        )
