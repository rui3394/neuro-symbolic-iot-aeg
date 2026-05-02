from __future__ import annotations

import json
from pathlib import Path

import pytest

from ns_aeg.tasks.loader import TaskLoadError, load_dangerous_path_task
from ns_aeg.verifier.task_adapter import (
    CandidateLoadError,
    load_candidate,
    task_to_verifier_config,
    verify_candidate_for_task,
    verify_candidate_with_task_config,
)


TASK_PATH = "examples/dangerous_tasks/toy_01_task.generated.json"
CANDIDATE_PATH = "examples/candidates/toy_01_candidate.example.json"


def test_task_loader_reads_generated_task() -> None:
    task = load_dangerous_path_task(TASK_PATH)

    assert task["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert task["sources"]
    assert task["sinks"]


def test_task_adapter_extracts_binary_source_and_sink() -> None:
    task = load_dangerous_path_task(TASK_PATH)

    config = task_to_verifier_config(task)

    assert config.binary["path"] == "datasets/toy_cgi/build/toy_01"
    assert config.binary["arch"] == "x86"
    assert config.entry == {"function": "main", "address": "0x401176"}
    assert config.sources[0]["name"] == "ip"
    assert {sink["function"] for sink in config.sinks} == {"system", "snprintf"}
    assert config.oracle == "source_reaches_sink"
    assert config.benign_marker == "__NS_AEG_MARKER__"


def test_candidate_missing_ip_returns_clear_unsupported_result() -> None:
    task = load_dangerous_path_task(TASK_PATH)
    config = task_to_verifier_config(task)
    candidate = {
        "candidate_id": "missing_ip",
        "inputs": {
            "other": "127.0.0.1__NS_AEG_MARKER__",
        },
    }

    result = verify_candidate_with_task_config(config, candidate)

    assert result["status"] == "unsupported"
    assert result["candidate_id"] == "missing_ip"
    assert "missing_candidate_input: ip" == result["reason"]
    assert result["checked_sources"][0]["candidate_input_present"] is False
    assert "symbolic execution backend not fully wired" in result["limitations"][0]
    assert result["executed"] is False


def test_candidate_with_ip_generates_structured_result(tmp_path: Path) -> None:
    output = tmp_path / "verification.json"

    result = verify_candidate_for_task(TASK_PATH, CANDIDATE_PATH, output_path=str(output))

    assert output.exists()
    assert result["status"] == "unknown"
    assert result["mode"] == "task_adapter_dry_run"
    assert result["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert result["candidate_id"] == "toy_01_cand_001"
    assert result["binary"]["path"] == "datasets/toy_cgi/build/toy_01"
    assert result["oracle"] == "source_reaches_sink"
    assert result["benign_marker"] == "__NS_AEG_MARKER__"
    assert result["checked_sources"][0]["name"] == "ip"
    assert result["checked_sources"][0]["candidate_input_present"] is True
    assert result["checked_sources"][0]["benign_marker_present"] is True
    assert {sink["function"] for sink in result["checked_sinks"]} == {"system", "snprintf"}
    assert "symbolic execution backend not fully wired" in result["limitations"][0]


def test_missing_task_path_fails_clearly() -> None:
    with pytest.raises(TaskLoadError, match="dangerous path task does not exist"):
        load_dangerous_path_task("examples/dangerous_tasks/missing.json")


def test_missing_candidate_path_fails_clearly() -> None:
    with pytest.raises(CandidateLoadError, match="candidate JSON does not exist"):
        load_candidate("examples/candidates/missing.json")


def test_task_without_sources_fails_clearly(tmp_path: Path) -> None:
    task = load_dangerous_path_task(TASK_PATH)
    task["sources"] = []
    path = tmp_path / "no_sources.json"
    path.write_text(json.dumps(task), encoding="utf-8")

    with pytest.raises(TaskLoadError, match="sources must contain at least one source"):
        load_dangerous_path_task(str(path))

