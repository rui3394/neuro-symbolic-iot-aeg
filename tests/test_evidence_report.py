from __future__ import annotations

import json
from pathlib import Path

from ns_aeg.reports.evidence_report import (
    DRY_RUN_NOTICE,
    NO_EXECUTION_NOTICE,
    NO_EXPLOIT_NOTICE,
    NO_COMMAND_EXECUTION_NOTICE,
    SYMBOLIC_EVIDENCE_NOTICE,
    SYMBOLIC_NOTICE,
    generate_evidence_markdown,
    write_evidence_report,
)


VERIFICATION_PATH = "reports/evidence/toy_01_verification.generated.json"
SYMBOLIC_VERIFICATION_PATH = "reports/evidence/toy_01_verification.symbolic.json"


def test_generates_markdown_from_toy_01_verification(tmp_path: Path) -> None:
    output = tmp_path / "evidence.md"

    markdown = write_evidence_report(VERIFICATION_PATH, str(output))

    assert output.exists()
    assert "# Dangerous Path Evidence Report" in markdown
    assert "dangerous_path:toy_01_basic_cmd:toy_01" in markdown
    assert "toy_01_cand_001" in markdown
    assert "Verification status: `unknown`" in markdown
    assert "Verification mode: `task_adapter_dry_run`" in markdown
    assert "Oracle: `source_reaches_sink`" in markdown


def test_dry_run_limitations_and_safety_notice_are_present() -> None:
    verification = _load_verification()

    markdown = generate_evidence_markdown(verification)

    assert DRY_RUN_NOTICE in markdown
    assert SYMBOLIC_NOTICE in markdown
    assert NO_EXECUTION_NOTICE in markdown
    assert NO_EXPLOIT_NOTICE in markdown
    assert "not rendered as attack payloads" in markdown


def test_candidate_input_summary_is_safe_and_marker_based() -> None:
    verification = _load_verification()

    markdown = generate_evidence_markdown(verification)

    assert "Source `ip`: input_present=`true`" in markdown
    assert "benign_marker_present=`true`" in markdown
    assert "127.0.0.1__NS_AEG_MARKER__" not in markdown


def test_missing_fields_still_generate_report() -> None:
    markdown = generate_evidence_markdown(
        {
            "task_id": "minimal_task",
            "checked_sources": [
                {
                    "name": "ip",
                    "candidate_input_present": False,
                }
            ],
        }
    )

    assert "# Dangerous Path Evidence Report" in markdown
    assert "minimal_task" in markdown
    assert "Candidate ID: `not available`" in markdown
    assert "Verification status: `not available`" in markdown
    assert "Verification mode: `not available`" in markdown
    assert "Oracle: `not available`" in markdown
    assert "Path: `not available`" in markdown
    assert "_None reported._" in markdown


def test_symbolic_json_generates_symbolic_evidence_section(tmp_path: Path) -> None:
    output = tmp_path / "symbolic.md"

    markdown = write_evidence_report(SYMBOLIC_VERIFICATION_PATH, str(output))

    assert output.exists()
    assert "## Symbolic Evidence" in markdown
    assert SYMBOLIC_EVIDENCE_NOTICE in markdown
    assert "Backend: `angr`" in markdown
    assert "Path status: `sat`" in markdown
    assert "Sink reached: `true`" in markdown
    assert "Source bound: `true`" in markdown
    assert "Marker observed: `true`" in markdown
    assert "### Selected Sink" in markdown
    assert "Function: `system`" in markdown
    assert "Address: `0x4011f9`" in markdown
    assert "### Selected Entry" in markdown
    assert "Function: `main`" in markdown
    assert "constraints_added" in markdown
    assert "## Evidence Strength" in markdown
    assert NO_COMMAND_EXECUTION_NOTICE in markdown
    assert NO_EXPLOIT_NOTICE in markdown
    assert "not full exploit verification" in markdown


def test_symbolic_missing_fields_still_generate_report() -> None:
    markdown = generate_evidence_markdown(
        {
            "mode": "symbolic_task",
            "status": "unknown",
            "task_id": "symbolic_minimal",
            "selected_sink": {
                "function": "system",
            },
        }
    )

    assert "## Symbolic Evidence" in markdown
    assert "Backend: `not available`" in markdown
    assert "Path status: `not available`" in markdown
    assert "Sink reached: `not available`" in markdown
    assert "Source bound: `not available`" in markdown
    assert "Marker observed: `not available`" in markdown
    assert "Function: `system`" in markdown
    assert "Address: `not available`" in markdown


def test_direct_main_evidence_strength_contains_caution_note() -> None:
    markdown = generate_evidence_markdown(
        {
            "mode": "symbolic_task",
            "status": "sat",
            "task_id": "direct_main_task",
            "evidence_strength": {
                "startup_mode": "direct_main",
                "level": "direct_main_symbolic",
                "scope": "toy_benchmark",
                "description": "Symbolic reachability began at main.",
                "can_claim_full_startup_proof": False,
                "requires_explicit_opt_in": False,
            },
        }
    )

    assert "## Evidence Strength" in markdown
    assert "This is direct-main symbolic evidence." in markdown
    assert "It bypasses startup/loader modeling." in markdown
    assert "It does not prove full program startup reachability." in markdown
    assert "It must not be used as a standalone real-firmware claim." in markdown


def test_symbolic_report_renders_format_flow_section() -> None:
    markdown = generate_evidence_markdown(
        {
            "mode": "symbolic_task",
            "status": "sat",
            "task_id": "format_flow_task",
            "format_flow": {
                "observed": True,
                "status": "positive",
                "format_write_count": 1,
                "format_record_count": 1,
                "memory_copy_count": 0,
                "positive_write_count": 1,
                "truncated_write_count": 0,
                "marker_truncated": False,
                "flows_to_command_sink": True,
                "records": [
                    {
                        "flow_kind": "format_write",
                        "format_sink": "snprintf",
                        "format_function": "snprintf",
                        "format_callsite": "0x1000",
                        "dst_buffer": "0x2000",
                        "size_value": 128,
                        "copy_length": 32,
                        "source_or_marker_written": True,
                        "marker_truncated": False,
                        "flows_to_command_sink": True,
                        "evidence_strength": "bounded_auxiliary_evidence",
                    }
                ],
                "limitations": ["final command evidence is determined at system(arg0)"],
            },
        }
    )

    assert "## Format/Memory Flow Evidence" in markdown
    assert "Status: `positive`" in markdown
    assert "snprintf" in markdown
    assert "Marker truncated: `false`" in markdown
    assert "Flows to command sink: `true`" in markdown


def _load_verification() -> dict:
    return json.loads(Path(VERIFICATION_PATH).read_text(encoding="utf-8"))
