from __future__ import annotations

import json
from pathlib import Path

from ns_aeg.planner_input_builder import (
    build_planner_input_from_report,
    build_planner_inputs_from_reports,
)
from ns_aeg.planner_schema import basic_validate_planner_input


def test_build_planner_input_from_fake_report(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report())

    planner_input = build_planner_input_from_report(str(report_path))

    assert planner_input["target_name"] == "toy_fake"
    assert planner_input["source"]["name"] == "ip"
    assert planner_input["sink"] == {
        "name": "system",
        "address": "0x401090",
        "source_reaches_sink_arg": True,
    }
    assert planner_input["observations"]["source_to_sink_confirmed"] is True
    assert planner_input["observations"]["sanitizer_like_observed"] is True
    assert basic_validate_planner_input(planner_input) == []


def test_default_output_path_is_examples_planner_target_name(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report(target_name="toy_default"))

    build_planner_input_from_report(str(report_path))

    assert (tmp_path / "examples" / "planner" / "toy_default_planner_input.json").exists()


def test_custom_output_path_is_used(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report())
    output_path = tmp_path / "custom" / "planner_input.json"

    build_planner_input_from_report(str(report_path), str(output_path))

    assert output_path.exists()
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["target_name"] == "toy_fake"


def test_source_fields_are_extracted(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report(max_len=32))

    planner_input = build_planner_input_from_report(str(report_path))

    assert planner_input["source"] == {
        "name": "ip",
        "source_type": "http_param",
        "symbolic_name": "sym_ip",
        "runtime_binding": "argv[1]",
        "max_len": 32,
    }


def test_constraint_summaries_include_sanitizer_candidate(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report())

    planner_input = build_planner_input_from_report(str(report_path))

    assert {
        "kind": "sanitizer_candidate",
        "description": "observed sanitizer candidate constraint",
        "raw": "<Bool !(sym_ip_0_248[247:240] == 59)>",
    } in planner_input["constraint_summaries"]


def test_toy_05_style_report_still_generates_planner_input(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(
        tmp_path,
        _fake_report(
            target_name="toy_05_safe_case",
            source_to_sink=False,
            sanitizer_like=False,
            source_reaches_sink_arg=False,
            sanitizer_constraints=[],
        ),
    )

    planner_input = build_planner_input_from_report(str(report_path))

    assert planner_input["sink"]["source_reaches_sink_arg"] is False
    assert planner_input["observations"]["source_to_sink_confirmed"] is False
    assert planner_input["constraint_summaries"] == []
    assert basic_validate_planner_input(planner_input) == []


def test_invalid_generated_planner_input_can_be_reported_without_throwing(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _fake_report()
    report["symbolic_reachability"]["target_sink"] = "printf"
    report_path = _write_report(tmp_path, report)

    planner_input = build_planner_input_from_report(str(report_path))
    errors = basic_validate_planner_input(planner_input)

    assert planner_input["sink"]["name"] == "printf"
    assert any("sink.name" in error for error in errors)


def test_batch_directory_mode_handles_multiple_analysis_reports(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    _write_report(reports_dir, _fake_report(target_name="toy_a"), "toy_a_analysis.json")
    _write_report(reports_dir, _fake_report(target_name="toy_b"), "toy_b_analysis.json")
    (reports_dir / "summary.json").write_text("{}", encoding="utf-8")

    summary = build_planner_inputs_from_reports(str(reports_dir))

    assert summary["reports"] == 2
    assert summary["built"] == 2
    assert summary["errors"] == 0
    assert (tmp_path / "examples" / "planner" / "toy_a_planner_input.json").exists()
    assert (tmp_path / "examples" / "planner" / "toy_b_planner_input.json").exists()


def test_batch_directory_mode_records_failed_report_without_stopping(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    _write_report(reports_dir, _fake_report(target_name="toy_ok"), "toy_ok_analysis.json")
    (reports_dir / "broken_analysis.json").write_text("not-json", encoding="utf-8")

    summary = build_planner_inputs_from_reports(str(reports_dir))

    assert summary["reports"] == 2
    assert summary["built"] == 1
    assert summary["errors"] == 1
    assert any(target["target_name"] == "broken" for target in summary["targets"])


def test_builder_does_not_generate_llm_inputs_payloads_or_poc(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_report(tmp_path, _fake_report())

    planner_input = build_planner_input_from_report(str(report_path))
    serialized = json.dumps(planner_input).lower()

    assert "solver.eval" not in serialized
    assert "exploit" not in serialized
    assert "payload" not in serialized


def _write_report(
    directory: Path,
    report: dict,
    filename: str = "toy_fake_analysis.json",
) -> Path:
    path = directory / filename
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _fake_report(
    *,
    target_name: str = "toy_fake",
    max_len: int = 32,
    source_to_sink: bool = True,
    sanitizer_like: bool = True,
    source_reaches_sink_arg: bool = True,
    sanitizer_constraints: list[str] | None = None,
) -> dict:
    sanitizer_constraints = (
        ["<Bool !(sym_ip_0_248[247:240] == 59)>"]
        if sanitizer_constraints is None
        else sanitizer_constraints
    )
    return {
        "target": {
            "name": target_name,
            "binary": f"datasets/toy_cgi/build/{target_name}",
            "arch": "auto",
            "http_method": "GET",
            "http_path": "/cgi-bin/ping",
            "vulnerability_type": "command_path_observation",
            "configured_sinks": ["system", "snprintf"],
        },
        "source_model": {
            "sources": [
                {
                    "name": "ip",
                    "source_type": "http_param",
                    "max_len": max_len,
                    "symbolic_name": "sym_ip",
                    "runtime_binding": "argv[1]",
                }
            ],
            "error": None,
        },
        "symbolic_reachability": {
            "created": True,
            "reachable": True,
            "source_name": "ip",
            "symbolic_var": "sym_ip",
            "runtime_binding": "argv[1]",
            "input_constraints": ["first 4 symbolic bytes are non-null"],
            "target_sink": "system",
            "target_addr": "0x401090",
            "sink_arg_symbolic": source_reaches_sink_arg,
            "source_var_in_sink_arg": source_reaches_sink_arg,
            "sink_arg_variables": ["sym_ip_0_248"] if source_reaches_sink_arg else [],
            "error": None,
        },
        "constraint_observation": {
            "created": True,
            "reachable": True,
            "source_name": "ip",
            "symbolic_var": "sym_ip",
            "runtime_binding": "argv[1]",
            "target_sink": "system",
            "target_addr": "0x401090",
            "total_constraints": 5,
            "source_related_count": len(sanitizer_constraints),
            "string_modeling_count": 0,
            "string_modeling_constraints": [],
            "input_modeling_count": 0,
            "input_modeling_constraints": [],
            "branch_condition_count": 0,
            "branch_condition_constraints": [],
            "sanitizer_candidate_count": len(sanitizer_constraints),
            "sanitizer_candidate_constraints": sanitizer_constraints,
            "unknown_source_count": 0,
            "unknown_source_constraints": [],
            "sanitizer_like_observed": sanitizer_like,
            "input_constraints": ["first 4 symbolic bytes are non-null"],
            "error": None,
        },
        "summary": {
            "source_to_sink_confirmed": source_to_sink,
            "sanitizer_like_observed": sanitizer_like,
            "status": "ok" if source_to_sink else "not_source_to_sink",
        },
    }
