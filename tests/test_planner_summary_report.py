from __future__ import annotations

import json
from pathlib import Path

from ns_aeg.reports.planner_summary_report import generate_summary_markdown, write_summary_report


def test_planner_summary_report_contains_core_fields(tmp_path: Path) -> None:
    summary = _sample_summary()

    markdown = generate_summary_markdown(summary)

    assert "# Planner Verification Summary" in markdown
    assert "dangerous_path:toy_01_basic_cmd:toy_01" in markdown
    assert "api_llm_planner" in markdown
    assert "mimo-v2.5-pro" in markdown
    assert "symbolic" in markdown
    assert "Planner provider" in markdown
    assert "Validation passed" in markdown
    assert "toy_01_rule_001" in markdown
    assert "No target binary was concretely executed." in markdown
    assert "No system/popen command was executed." in markdown
    assert "No weaponized exploit was generated." in markdown
    assert "Candidates are benign source-to-sink verification inputs." in markdown


def test_planner_summary_report_writes_markdown(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    output_path = tmp_path / "summary.md"
    summary_path.write_text(json.dumps(_sample_summary()), encoding="utf-8")

    markdown = write_summary_report(str(summary_path), str(output_path))

    assert output_path.exists()
    assert "Status Counts" in markdown
    assert "sat" in output_path.read_text(encoding="utf-8")


def test_planner_summary_report_gracefully_handles_missing_fields() -> None:
    markdown = generate_summary_markdown({})

    assert "not available" in markdown
    assert "Safety Note" in markdown


def _sample_summary() -> dict:
    return {
        "task_id": "dangerous_path:toy_01_basic_cmd:toy_01",
        "planner": {
            "name": "api_llm_planner",
            "version": "0.1",
            "mode": "benign_candidate_generation",
            "provider": "openai_compatible",
            "base_url_host": "token-plan-cn.xiaomimimo.com",
            "model": "mimo-v2.5-pro",
            "max_tokens": 12000,
            "temperature": 0.0,
        },
        "mode": "symbolic",
        "candidate_source": "examples/candidates/toy_01_candidates.llm.generated.json",
        "total_candidates": 4,
        "candidate_count": 4,
        "validation_passed_count": 4,
        "validation_failed_count": 0,
        "validation": {
            "candidate_count": 4,
            "validation_passed_count": 4,
            "validation_failed_count": 0,
        },
        "status_counts": {"sat": 1, "unknown": 3},
        "sat_count": 1,
        "timeout_count": 0,
        "unsupported_count": 0,
        "best_candidate_id": "toy_01_rule_001",
        "best_status": "sat",
        "selected_sink": {
            "sink_id": "sink_2:system",
            "function": "system",
            "address": "0x4011f9",
            "type": "command_execution",
            "external_address": "0x3",
        },
        "sink_reached_count": 4,
        "source_bound_count": 4,
        "marker_observed_count": 4,
        "limitations": ["rule planner is a benign deterministic baseline"],
    }
