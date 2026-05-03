from __future__ import annotations

import json
from pathlib import Path

from ns_aeg.pipeline.run_cross_arch_smoke import (
    build_cross_arch_summary,
    generate_cross_arch_markdown,
    load_manifest,
    run_cross_arch_smoke,
)


def test_load_cross_arch_manifest_object(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "cross_arch_toy_benchmark_manifest_v1",
                "cases": [_case(build_status="skipped_compiler_missing")],
            }
        ),
        encoding="utf-8",
    )

    data = load_manifest(str(manifest))

    assert data["schema_version"] == "cross_arch_toy_benchmark_manifest_v1"
    assert data["cases"][0]["toy_id"] == "toy_01"
    assert data["cases"][0]["arch"] == "arm32"


def test_cross_arch_smoke_skips_unbuilt_cases_without_ghidra(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"cases": [_case(build_status="skipped_compiler_missing")]}),
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"

    summary = run_cross_arch_smoke(
        manifest_path=str(manifest),
        out_dir=str(out_dir),
        mode="symbolic",
    )

    assert summary["total_cases"] == 1
    assert summary["built_cases"] == 0
    assert summary["skipped_build_cases"] == 1
    assert summary["ghidra_success_count"] == 0
    assert summary["per_case"][0]["facts_status"] == "skipped"
    assert (out_dir / "summary.json").exists()
    assert (out_dir / "summary.md").exists()


def test_cross_arch_smoke_skips_built_missing_binary(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"cases": [_case(build_status="built", binary_path=str(tmp_path / "missing"))]}),
        encoding="utf-8",
    )

    summary = run_cross_arch_smoke(
        manifest_path=str(manifest),
        out_dir=str(tmp_path / "out"),
    )

    assert summary["built_cases"] == 1
    assert summary["per_case"][0]["case_status"] == "skipped_missing_binary"
    assert summary["per_case"][0]["verifier_status"] == "skipped"


def test_cross_arch_summary_markdown_contains_generic_matched_sink_metadata() -> None:
    selected_sink = {
        "address": "0x5000",
        "callsites": [{"address": "0x5000"}],
    }
    matched_sink_address = selected_sink["address"]
    summary = build_cross_arch_summary(
        [
            {
                "toy_id": "toy_01",
                "arch": "x86_64",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "sat",
                "status_counts": {"sat": 4},
                "selected_sink": selected_sink,
                "matched_sink_address": matched_sink_address,
                "match_reason": "selected_sink_address",
                "selected_startup_mode": "full_init",
                "evidence_strength_level": "full_program_startup_symbolic",
                "can_claim_full_startup_proof": True,
                "sink_argument_location": "register:rdi",
                "reachability_debug_reason": "matched sink candidate address",
            }
        ],
        mode="symbolic",
        manifest_path="manifest.json",
    )

    markdown = generate_cross_arch_markdown(summary)
    case = summary["per_case"][0]

    assert "Cross-Arch Toy Smoke Summary" in markdown
    assert case["matched_sink_address"] in _candidate_addresses(case["selected_sink"])
    assert _location_matches_abi(case["arch"], case["sink_argument_location"])
    assert "register:rdi" in markdown
    assert "selected_sink_address" in markdown
    assert summary["full_init_sat_count"] == 1
    assert summary["direct_main_sat_count"] == 0
    assert summary["full_startup_proof_count"] == 1
    assert summary["false_positive_count"] == 0
    assert "Full-init sat cases: `1`" in markdown
    assert "matched sink candidate address" in markdown
    assert "No system/popen command was executed." in markdown


def test_cross_arch_summary_records_toy03_planner_rejection() -> None:
    summary = build_cross_arch_summary(
        [
            {
                "toy_id": "toy_03",
                "arch": "mipsel",
                "expected_behavior": "planner_reject_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "no_candidates",
                "candidate_count": 0,
                "rejected_count": 4,
                "rejected_reason": "marker_length_exceeds_required_window",
                "status_counts": {},
                "selected_startup_mode": None,
                "evidence_strength_level": None,
                "can_claim_full_startup_proof": None,
            }
        ],
        mode="symbolic",
        manifest_path="manifest.json",
    )

    markdown = generate_cross_arch_markdown(summary)

    assert summary["planner_reject_expected_count"] == 1
    assert summary["expected_planner_reject_count"] == 1
    assert summary["planner_reject_count"] == 1
    assert summary["false_positive_count"] == 0
    assert summary["symbolic_sat_count"] == 0
    assert "planner_reject_expected" in markdown
    assert "marker_length_exceeds_required_window" in markdown
    assert "toy_03 planner rejection is a sanitizer/marker incompatibility result" in markdown


def test_cross_arch_summary_marks_negative_sat_as_false_positive() -> None:
    summary = build_cross_arch_summary(
        [
            {
                "toy_id": "toy_04",
                "arch": "mips",
                "expected_behavior": "unsat_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "sat",
                "candidate_count": 4,
                "rejected_count": 0,
                "status_counts": {"sat": 1},
                "false_positive": True,
            },
            {
                "toy_id": "toy_05",
                "arch": "mipsel",
                "expected_behavior": "unsat_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "unknown",
                "candidate_count": 4,
                "rejected_count": 0,
                "status_counts": {"unknown": 4},
                "false_positive": False,
            },
        ],
        mode="symbolic",
        manifest_path="manifest.json",
    )

    markdown = generate_cross_arch_markdown(summary)

    assert summary["expected_unsat_count"] == 2
    assert summary["false_positive_count"] == 1
    assert "False positive count: `1`" in markdown
    assert "false positive" in markdown.lower()


def test_cross_arch_summary_records_format_flow_counts() -> None:
    summary = build_cross_arch_summary(
        [
            {
                "toy_id": "toy_06",
                "arch": "x86_64",
                "expected_behavior": "sat_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "sat",
                "candidate_count": 4,
                "status_counts": {"sat": 4},
                "sink_policy_status": "positive_evidence",
                "format_flow_status": "positive",
                "format_flow_to_command_sink": True,
            },
            {
                "toy_id": "toy_07",
                "arch": "x86_64",
                "expected_behavior": "unsat_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "unsat",
                "candidate_count": 4,
                "status_counts": {"unsat": 4},
                "sink_policy_status": "negative_evidence",
                "format_flow_status": "negative",
                "format_flow_to_command_sink": False,
                "false_positive": False,
            },
            {
                "toy_id": "toy_08",
                "arch": "x86_64",
                "expected_behavior": "truncation_negative_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "unknown",
                "candidate_count": 4,
                "status_counts": {"unknown": 4},
                "sink_policy_status": "inconclusive",
                "format_flow_status": "truncated",
                "format_flow_marker_truncated": True,
                "format_flow_to_command_sink": False,
                "false_positive": False,
            },
            {
                "toy_id": "toy_10",
                "arch": "x86_64",
                "expected_behavior": "sat_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "sat",
                "candidate_count": 4,
                "status_counts": {"sat": 4},
                "sink_policy_status": "positive_evidence",
                "format_flow_status": "positive",
                "format_flow_memory_copy_count": 1,
                "format_flow_to_command_sink": True,
            },
            {
                "toy_id": "toy_11",
                "arch": "x86_64",
                "expected_behavior": "truncation_negative_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "unknown",
                "candidate_count": 4,
                "status_counts": {"unknown": 4},
                "sink_policy_status": "inconclusive",
                "format_flow_status": "truncated",
                "format_flow_marker_truncated": True,
                "format_flow_memory_copy_count": 1,
                "format_flow_to_command_sink": False,
                "false_positive": False,
            },
        ],
        mode="symbolic",
        manifest_path="manifest.json",
    )

    markdown = generate_cross_arch_markdown(summary)

    assert summary["format_flow_positive_count"] == 2
    assert summary["format_flow_negative_count"] == 1
    assert summary["truncation_negative_count"] == 2
    assert summary["truncation_false_positive_count"] == 0
    assert summary["memcpy_positive_count"] == 1
    assert summary["memcpy_truncation_negative_count"] == 1
    assert summary["inconclusive_count"] == 2
    assert summary["safe_negative_count"] == 1
    assert summary["false_positive_count"] == 0
    assert "Format-flow positive count: `2`" in markdown
    assert "Truncation negative count: `2`" in markdown
    assert "Memcpy positive count: `1`" in markdown
    assert "toy_07" in markdown
    assert "negative_evidence" in markdown


def test_cross_arch_summary_marks_truncation_sat_as_false_positive() -> None:
    summary = build_cross_arch_summary(
        [
            {
                "toy_id": "toy_08",
                "arch": "mipsel",
                "expected_behavior": "truncation_negative_expected",
                "build_status": "built",
                "case_status": "ok",
                "facts_status": "ok",
                "task_status": "ok",
                "planner_status": "ok",
                "verifier_status": "sat",
                "candidate_count": 4,
                "status_counts": {"sat": 4},
                "format_flow_status": "positive",
                "format_flow_marker_truncated": False,
            }
        ],
        mode="symbolic",
        manifest_path="manifest.json",
    )

    assert summary["false_positive_count"] == 1
    assert summary["truncation_false_positive_count"] == 1


def test_cross_arch_summary_fixtures_capture_startup_repair_regression_shape() -> None:
    cases = []
    for arch, location, repaired in [
        ("x86_64", "register:rdi", False),
        ("arm32", "register:r0", False),
        ("aarch64", "register:x0", False),
        ("mipsel", "register:a0", True),
        ("mips", "register:a0", True),
    ]:
        for toy_id in ("toy_01", "toy_02"):
            cases.append(
                {
                    "toy_id": toy_id,
                    "arch": arch,
                    "expected_behavior": "sat_expected",
                    "build_status": "built",
                    "case_status": "ok",
                    "facts_status": "ok",
                    "task_status": "ok",
                    "planner_status": "ok",
                    "verifier_status": "sat",
                    "candidate_count": 4,
                    "rejected_count": 0,
                    "status_counts": {"sat": 4},
                    "selected_startup_mode": "full_init",
                    "evidence_strength_level": "full_program_startup_symbolic",
                    "can_claim_full_startup_proof": True,
                    "full_init_repair_applied": repaired,
                    "repair_reason": (
                        "mips_full_init_block_level_stepping_for_bal_delay_slot_startup_stub"
                        if repaired
                        else None
                    ),
                    "sink_argument_location": location,
                    "matched_sink_address": "0x500004",
                    "selected_sink": {"address": "0x500004", "callsites": [{"address": "0x500004"}]},
                }
            )

    summary = build_cross_arch_summary(cases, mode="symbolic", manifest_path="manifest.json", startup_mode="full-init")

    assert summary["total_cases"] == 10
    assert summary["symbolic_sat_count"] == 10
    assert summary["full_init_sat_count"] == 10
    assert summary["full_startup_proof_count"] == 10
    assert summary["direct_main_sat_count"] == 0
    assert summary["direct_main_only_count"] == 0
    assert summary["false_positive_count"] == 0
    for case in summary["per_case"]:
        assert case["selected_startup_mode"] == "full_init"
        assert case["sink_argument_location"] == {
            "x86_64": "register:rdi",
            "arm32": "register:r0",
            "aarch64": "register:x0",
            "mipsel": "register:a0",
            "mips": "register:a0",
        }[case["arch"]]
        if case["arch"] in {"mips", "mipsel"}:
            assert case["full_init_repair_applied"] is True
        else:
            assert case["full_init_repair_applied"] is False


def _case(
    *,
    build_status: str,
    binary_path: str = "datasets/toy_cgi/build_cross/arm32/toy_01",
) -> dict[str, str]:
    return {
        "toy_id": "toy_01",
        "arch": "arm32",
        "binary_path": binary_path,
        "target_yaml": "configs/toy_01.yaml",
        "build_status": build_status,
        "compiler": "arm-linux-gnueabihf-gcc",
        "notes": "test case",
        "expected_behavior": "sat_expected",
    }


def _candidate_addresses(selected_sink: dict[str, object]) -> set[str]:
    addresses = {str(selected_sink.get("address"))}
    callsites = selected_sink.get("callsites")
    if isinstance(callsites, list):
        for callsite in callsites:
            if isinstance(callsite, dict) and callsite.get("address"):
                addresses.add(str(callsite["address"]))
    return addresses


def _location_matches_abi(arch: str, location: str) -> bool:
    expected = {
        "x86_64": "register:rdi",
        "arm32": "register:r0",
        "aarch64": "register:x0",
        "mips": "register:a0",
        "mipsel": "register:a0",
    }
    return location == expected[arch]
