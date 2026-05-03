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
    assert "Planner Diagnostics" in markdown
    assert "Rejected candidates" in markdown
    assert "Evidence Strength" in markdown
    assert "Format-flow positive count" in markdown
    assert "Truncation negative count" in markdown
    assert "Memcpy positive count" in markdown
    assert "direct_main_symbolic" in markdown
    assert "Direct-main evidence bypasses startup/loader modeling" in markdown
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
        "rejected_count": 1,
        "planner_diagnostics": {
            "sanitizer_count": 1,
            "sanitizer_types": ["length_window"],
            "marker_len": 17,
            "rejected_count": 1,
            "notes": ["benign marker length is incompatible with length_window sanitizer"],
        },
        "rejected_candidates": [
            {
                "strategy": "marker_only",
                "source": "ip",
                "sanitizer": "length_window",
                "reason": "marker_length_exceeds_required_window",
            }
        ],
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
        "safe_negative_count": 0,
        "sink_policy_positive_count": 1,
        "sink_policy_inconclusive_count": 0,
        "sink_policy_unsupported_count": 0,
        "format_flow_positive_count": 1,
        "format_flow_negative_count": 0,
        "format_flow_inconclusive_count": 0,
        "truncation_negative_count": 0,
        "truncation_false_positive_count": 0,
        "memcpy_positive_count": 0,
        "memcpy_truncation_negative_count": 0,
        "inconclusive_count": 3,
        "selected_startup_mode": "direct_main",
        "evidence_strength": {
            "startup_mode": "direct_main",
            "level": "direct_main_symbolic",
            "scope": "toy_benchmark",
            "description": "Symbolic reachability began at main.",
            "can_claim_full_startup_proof": False,
            "requires_explicit_opt_in": False,
        },
        "full_startup_proof_count": 0,
        "direct_main_evidence_count": 4,
        "limitations": ["rule planner is a benign deterministic baseline"],
    }
