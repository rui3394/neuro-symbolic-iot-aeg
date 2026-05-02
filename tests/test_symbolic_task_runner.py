from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.verifier.symbolic_task_runner import run_symbolic_task_verification
from ns_aeg.verifier.task_adapter import load_candidate, task_to_verifier_config


def test_symbolic_task_runner_reaches_toy_01_system_callsite() -> None:
    _require_angr()
    if not Path("datasets/toy_cgi/build/toy_01").exists():
        pytest.skip("toy_01 binary is not built")

    task = _toy_01_symbolic_task()
    candidate = load_candidate("examples/candidates/toy_01_candidate.example.json")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate)

    assert result["mode"] == "symbolic_task"
    assert result["executed"] is False
    assert result["backend"] == "angr"
    assert result["selected_sink"]["function"] == "system"
    assert result["selected_sink"]["address"] == "0x4011f9"
    assert result["sink_reached"] is True
    assert result["path_status"] in {"sat", "unknown"}
    assert result["source_bound"] in {True, False, "unknown"}
    assert result["marker_observed"] in {True, False, "unknown"}
    assert "weapon" not in json.dumps(result).lower()


def test_symbolic_task_runner_missing_candidate_input_is_unsupported() -> None:
    _require_angr()
    task = _toy_01_symbolic_task()
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(
        config,
        {"candidate_id": "missing", "inputs": {"other": "value"}},
    )

    assert result["status"] == "unsupported"
    assert result["sink_reached"] == "unknown"
    assert "missing_candidate_input: ip" in result["reason"]


def _toy_01_symbolic_task() -> dict:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    task["sinks"] = [
        {
            "sink_id": "sink_1:snprintf",
            "type": "string_formatting",
            "function": "snprintf",
            "address": "0x4011ea",
            "arg_index": 2,
            "callers": ["main"],
            "external_address": "0x4",
        },
        {
            "sink_id": "sink_2:system",
            "type": "command_execution",
            "function": "system",
            "address": "0x4011f9",
            "arg_index": 0,
            "callers": ["main"],
            "external_address": "0x3",
        },
    ]
    return task


def _require_angr() -> None:
    if importlib.util.find_spec("angr") is None or importlib.util.find_spec("claripy") is None:
        pytest.skip("angr/claripy are not installed")

