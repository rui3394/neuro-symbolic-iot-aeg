from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.dataset_runner import run_toy_dataset
from ns_aeg.mock_planner import run_mock_planner_dir
from ns_aeg.planner_input_builder import build_planner_inputs_from_reports
from ns_aeg.symbolic_verifier import (
    build_verification_requests_from_dir,
    run_symbolic_verifier_skeleton_dir,
)


def run_demo(
    config_dir: str = "configs",
    reports_dir: str = "reports",
    planner_dir: str = "examples/planner",
    verifier_dir: str = "examples/verifier",
    output_path: str = "reports/demo_summary.json",
) -> dict[str, Any]:
    steps: dict[str, dict[str, Any]] = {}
    status = "ok"
    dataset_summary: dict[str, Any] = {}

    try:
        dataset_summary = run_toy_dataset(
            config_dir=config_dir,
            reports_dir=reports_dir,
            summary_json=str(Path(reports_dir) / "summary.json"),
            summary_md=str(Path(reports_dir) / "summary.md"),
            summary_csv=str(Path(reports_dir) / "summary.csv"),
        )
        steps["toy_dataset"] = {
            "ok": True,
            "summary_json": str(Path(reports_dir) / "summary.json"),
        }

        planner_inputs = build_planner_inputs_from_reports(reports_dir, planner_dir)
        steps["planner_inputs"] = _step_from_batch(planner_inputs)
        _raise_if_step_failed("planner_inputs", planner_inputs)

        mock_planner = run_mock_planner_dir(planner_dir, planner_dir)
        steps["mock_planner"] = _step_from_batch(mock_planner)
        _raise_if_step_failed("mock_planner", mock_planner)

        verification_requests = build_verification_requests_from_dir(
            planner_dir,
            verifier_dir,
        )
        steps["verification_requests"] = _step_from_batch(verification_requests)
        _raise_if_step_failed("verification_requests", verification_requests)

        verifier_skeleton = run_symbolic_verifier_skeleton_dir(
            verifier_dir,
            verifier_dir,
        )
        steps["verifier_skeleton"] = _step_from_batch(verifier_skeleton)
        _raise_if_step_failed("verifier_skeleton", verifier_skeleton)
    except Exception as exc:
        status = "error"
        if not steps:
            steps["toy_dataset"] = {"ok": False, "error": str(exc)}
        else:
            _mark_first_missing_or_failed_step(steps, str(exc))

    summary = {
        "status": status,
        "steps": steps,
        "expected_results": {
            "total_targets": int(dataset_summary.get("total_targets", 0)),
            "source_to_sink_confirmed_count": int(
                dataset_summary.get("source_to_sink_confirmed_count", 0)
            ),
            "sanitizer_like_observed_count": int(
                dataset_summary.get("sanitizer_like_observed_count", 0)
            ),
            "error_count": int(dataset_summary.get("error_count", 0)),
        },
        "artifacts": {
            "summary_json": str(Path(reports_dir) / "summary.json"),
            "summary_md": str(Path(reports_dir) / "summary.md"),
            "summary_csv": str(Path(reports_dir) / "summary.csv"),
            "planner_dir": planner_dir,
            "verifier_dir": verifier_dir,
        },
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def _step_from_batch(batch: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": int(batch.get("errors", 0)) == 0,
        "built": int(batch.get("built", 0)),
        "errors": int(batch.get("errors", 0)),
    }


def _raise_if_step_failed(step_name: str, batch: dict[str, Any]) -> None:
    if int(batch.get("errors", 0)) > 0:
        raise RuntimeError(f"{step_name} failed with {batch['errors']} error(s)")


def _mark_first_missing_or_failed_step(steps: dict[str, dict[str, Any]], error: str) -> None:
    order = [
        "toy_dataset",
        "planner_inputs",
        "mock_planner",
        "verification_requests",
        "verifier_skeleton",
    ]
    for step in order:
        if step not in steps:
            steps[step] = {"ok": False, "error": error}
            return
        if not steps[step].get("ok", False):
            steps[step]["error"] = error
            return
