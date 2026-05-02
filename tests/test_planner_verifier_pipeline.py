from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ns_aeg.pipeline.run_planner_verifier import run_pipeline, select_best_result


def test_planner_verifier_pipeline_dry_run_writes_batch_artifacts(tmp_path: Path) -> None:
    out_dir = tmp_path / "toy_01_rule_dry_run"

    summary = run_pipeline(
        task_path="examples/dangerous_tasks/toy_01_task.example.json",
        planner="rule",
        mode="dry-run",
        out_dir=str(out_dir),
    )

    assert summary["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert summary["mode"] == "dry-run"
    assert summary["total_candidates"] >= 4
    assert summary["status_counts"]["unknown"] >= 1
    assert summary["best_candidate_id"] is None
    assert (out_dir / "candidates.json").exists()
    assert (out_dir / "summary.json").exists()
    assert (out_dir / "best_candidate.json").exists()
    assert len(list((out_dir / "verifications").glob("*.json"))) == summary["total_candidates"]


def test_planner_verifier_pipeline_llm_offline_dry_run(tmp_path: Path) -> None:
    out_dir = tmp_path / "toy_01_llm_offline_dry_run"

    summary = run_pipeline(
        task_path="examples/dangerous_tasks/toy_01_task.example.json",
        planner="llm",
        mode="dry-run",
        out_dir=str(out_dir),
        offline_example=True,
    )

    assert summary["planner"]["name"] == "api_llm_planner_offline"
    assert summary["total_candidates"] >= 3
    assert summary["status_counts"]["unknown"] >= 1
    assert (out_dir / "candidates.json").exists()
    assert (out_dir / "summary.json").exists()


def test_select_best_result_prefers_sat_then_reachability_then_marker() -> None:
    results = [
        {"candidate_id": "a", "status": "unknown", "marker_observed": True},
        {"candidate_id": "b", "status": "unknown", "sink_reached": True},
        {"candidate_id": "c", "status": "sat", "sink_reached": True},
    ]

    assert select_best_result(results)["candidate_id"] == "c"
    assert select_best_result(results[:2])["candidate_id"] == "b"
    assert select_best_result(results[:1])["candidate_id"] == "a"
    assert select_best_result([{"candidate_id": "x", "status": "unsat"}]) is None


def test_planner_verifier_pipeline_symbolic_toy_01_has_sat_candidate(tmp_path: Path) -> None:
    _require_angr_and_toy_binary()
    out_dir = tmp_path / "toy_01_rule_symbolic"

    summary = run_pipeline(
        task_path="examples/dangerous_tasks/toy_01_task.real.json",
        planner="rule",
        mode="symbolic",
        out_dir=str(out_dir),
    )

    assert summary["total_candidates"] >= 4
    assert summary["sat_count"] >= 1
    assert summary["best_candidate_id"]
    assert summary["selected_sink"]["function"] == "system"
    statuses = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))["status"]
        for path in (out_dir / "verifications").glob("*.json")
    }
    assert "sat" in statuses.values()


def test_planner_verifier_pipeline_llm_offline_symbolic_toy_01_has_sat_candidate(
    tmp_path: Path,
) -> None:
    _require_angr_and_toy_binary()
    out_dir = tmp_path / "toy_01_llm_offline_symbolic"

    summary = run_pipeline(
        task_path="examples/dangerous_tasks/toy_01_task.real.json",
        planner="llm",
        mode="symbolic",
        out_dir=str(out_dir),
        offline_example=True,
    )

    assert summary["planner"]["name"] == "api_llm_planner_offline"
    assert summary["sat_count"] >= 1
    assert summary["best_candidate_id"]


def _require_angr_and_toy_binary() -> None:
    if importlib.util.find_spec("angr") is None or importlib.util.find_spec("claripy") is None:
        pytest.skip("angr/claripy are not installed")
    if not Path("datasets/toy_cgi/build/toy_01").exists():
        pytest.skip("toy_01 binary is not built")
    if not Path("examples/dangerous_tasks/toy_01_task.real.json").exists():
        pytest.skip("toy_01 real dangerous path task is not generated")
