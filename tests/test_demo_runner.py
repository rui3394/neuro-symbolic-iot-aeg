from __future__ import annotations

import json

from ns_aeg.demo_runner import run_demo


def test_run_demo_chains_five_stages_and_writes_summary(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls: list[str] = []
    _install_successful_stages(monkeypatch, calls)

    summary = run_demo(output_path="reports/demo_summary.json")

    assert calls == [
        "toy_dataset",
        "planner_inputs",
        "mock_planner",
        "verification_requests",
        "verifier_skeleton",
    ]
    assert summary["status"] == "ok"
    assert summary["steps"]["toy_dataset"]["ok"] is True
    assert summary["steps"]["planner_inputs"]["built"] == 5
    assert (tmp_path / "reports" / "demo_summary.json").exists()
    written = json.loads((tmp_path / "reports" / "demo_summary.json").read_text())
    assert written["status"] == "ok"


def test_demo_summary_contains_expected_results_and_artifacts(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _install_successful_stages(monkeypatch, [])

    summary = run_demo(output_path="reports/demo_summary.json")

    assert summary["expected_results"] == {
        "total_targets": 5,
        "source_to_sink_confirmed_count": 4,
        "sanitizer_like_observed_count": 2,
        "error_count": 0,
    }
    assert summary["artifacts"] == {
        "summary_json": "reports/summary.json",
        "summary_md": "reports/summary.md",
        "summary_csv": "reports/summary.csv",
        "planner_dir": "examples/planner",
        "verifier_dir": "examples/verifier",
    }


def test_demo_records_error_and_stops_after_failed_stage(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls: list[str] = []
    _install_successful_stages(monkeypatch, calls, fail_step="mock_planner")

    summary = run_demo(output_path="reports/demo_summary.json")

    assert summary["status"] == "error"
    assert calls == ["toy_dataset", "planner_inputs", "mock_planner"]
    assert summary["steps"]["mock_planner"]["ok"] is False
    assert "mock_planner failed" in summary["steps"]["mock_planner"]["error"]
    assert (tmp_path / "reports" / "demo_summary.json").exists()


def test_demo_records_dataset_exception(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    import ns_aeg.demo_runner as demo_runner

    def fake_dataset(*args, **kwargs):
        raise RuntimeError("dataset boom")

    monkeypatch.setattr(demo_runner, "run_toy_dataset", fake_dataset)

    summary = run_demo(output_path="reports/demo_summary.json")

    assert summary["status"] == "error"
    assert summary["steps"]["toy_dataset"] == {
        "ok": False,
        "error": "dataset boom",
    }


def test_demo_does_not_include_llm_payload_or_poc_terms(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_successful_stages(monkeypatch, [])

    summary = run_demo(output_path="reports/demo_summary.json")
    serialized = json.dumps(summary).lower()

    assert "llm" not in serialized
    assert "payload" not in serialized
    assert "poc" not in serialized
    assert "solver.eval" not in serialized


def _install_successful_stages(
    monkeypatch,
    calls: list[str],
    fail_step: str | None = None,
) -> None:
    import ns_aeg.demo_runner as demo_runner

    def fake_dataset(*args, **kwargs):
        calls.append("toy_dataset")
        return {
            "total_targets": 5,
            "source_to_sink_confirmed_count": 4,
            "sanitizer_like_observed_count": 2,
            "error_count": 0,
        }

    def fake_batch(step_name: str):
        def inner(*args, **kwargs):
            calls.append(step_name)
            if fail_step == step_name:
                return {"built": 0, "errors": 1}
            return {"built": 5, "errors": 0}

        return inner

    monkeypatch.setattr(demo_runner, "run_toy_dataset", fake_dataset)
    monkeypatch.setattr(
        demo_runner,
        "build_planner_inputs_from_reports",
        fake_batch("planner_inputs"),
    )
    monkeypatch.setattr(demo_runner, "run_mock_planner_dir", fake_batch("mock_planner"))
    monkeypatch.setattr(
        demo_runner,
        "build_verification_requests_from_dir",
        fake_batch("verification_requests"),
    )
    monkeypatch.setattr(
        demo_runner,
        "run_symbolic_verifier_skeleton_dir",
        fake_batch("verifier_skeleton"),
    )
