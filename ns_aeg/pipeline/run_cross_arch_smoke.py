from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from ns_aeg.ghidra.export_facts import GhidraUnavailableError, export_facts, unavailable_facts
from ns_aeg.planner.rule_planner import RulePlannerError, generate_candidate_set, write_candidate_set
from ns_aeg.pipeline.run_planner_verifier import PlannerVerifierPipelineError, run_pipeline
from ns_aeg.reports.planner_summary_report import generate_summary_markdown
from ns_aeg.tasks.builder import DangerousPathTaskError, build_dangerous_path_task
from ns_aeg.verifier.task_adapter import write_json

SUPPORTED_MODES = {"dry-run", "symbolic"}
SUPPORTED_STARTUP_MODES = {"auto", "full-init", "direct-main"}


class CrossArchSmokeError(ValueError):
    """Raised when cross-arch smoke cannot start."""


def run_cross_arch_smoke(
    *,
    manifest_path: str,
    out_dir: str,
    mode: str = "symbolic",
    startup_mode: str = "auto",
) -> dict[str, Any]:
    if mode not in SUPPORTED_MODES:
        raise CrossArchSmokeError(f"unsupported verifier mode: {mode}")
    if startup_mode not in SUPPORTED_STARTUP_MODES:
        raise CrossArchSmokeError(f"unsupported startup mode: {startup_mode}")

    manifest = load_manifest(manifest_path)
    cases = manifest["cases"]
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = [_run_case(case, output_dir, mode=mode, startup_mode=startup_mode) for case in cases]
    summary = build_cross_arch_summary(
        results,
        mode=mode,
        startup_mode=startup_mode,
        manifest_path=manifest_path,
    )
    write_json(summary, str(output_dir / "summary.json"))
    (output_dir / "summary.md").write_text(generate_cross_arch_markdown(summary), encoding="utf-8")
    return summary


def load_manifest(path: str) -> dict[str, Any]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise CrossArchSmokeError(f"cross-arch manifest does not exist: {path}")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CrossArchSmokeError(f"failed to read cross-arch manifest: {path}: {exc}") from exc

    if isinstance(data, list):
        cases = data
    elif isinstance(data, dict) and isinstance(data.get("cases"), list):
        cases = data["cases"]
    else:
        raise CrossArchSmokeError("cross-arch manifest must be an object with cases[] or a cases list")

    normalized = [_normalize_case(case, index) for index, case in enumerate(cases)]
    return {
        "schema_version": data.get("schema_version") if isinstance(data, dict) else None,
        "cases": normalized,
    }


def build_cross_arch_summary(
    results: list[dict[str, Any]],
    *,
    mode: str,
    manifest_path: str,
    startup_mode: str = "auto",
) -> dict[str, Any]:
    results = [dict(item, false_positive=_is_false_positive(item)) for item in results]
    return {
        "schema_version": "cross_arch_smoke_summary_v1",
        "manifest_path": manifest_path,
        "mode": mode,
        "startup_mode": startup_mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cases": len(results),
        "built_cases": sum(1 for item in results if item.get("build_status") == "built"),
        "skipped_build_cases": sum(1 for item in results if item.get("case_status") == "skipped_build"),
        "ghidra_success_count": sum(1 for item in results if item.get("facts_status") in {"ok", "partial"}),
        "task_success_count": sum(1 for item in results if item.get("task_status") == "ok"),
        "expected_unsat_count": sum(1 for item in results if item.get("expected_behavior") == "unsat_expected"),
        "expected_no_sink_count": sum(1 for item in results if item.get("expected_behavior") == "no_sink_expected"),
        "planner_reject_expected_count": sum(
            1 for item in results if item.get("expected_behavior") == "planner_reject_expected"
        ),
        "expected_planner_reject_count": sum(
            1 for item in results if item.get("expected_behavior") == "planner_reject_expected"
        ),
        "planner_reject_count": sum(
            1
            for item in results
            if int(item.get("candidate_count") or 0) == 0 and int(item.get("rejected_count") or 0) > 0
        ),
        "false_positive_count": sum(1 for item in results if _is_false_positive(item)),
        "safe_negative_count": sum(1 for item in results if item.get("sink_policy_status") == "negative_evidence"),
        "sink_policy_positive_count": sum(1 for item in results if item.get("sink_policy_status") == "positive_evidence"),
        "sink_policy_inconclusive_count": sum(1 for item in results if item.get("sink_policy_status") == "inconclusive"),
        "sink_policy_unsupported_count": sum(1 for item in results if item.get("sink_policy_status") == "unsupported"),
        "format_flow_positive_count": sum(1 for item in results if item.get("format_flow_status") == "positive"),
        "format_flow_negative_count": sum(1 for item in results if item.get("format_flow_status") == "negative"),
        "format_flow_inconclusive_count": sum(1 for item in results if item.get("format_flow_status") == "inconclusive"),
        "truncation_negative_count": sum(1 for item in results if _case_has_marker_truncation(item)),
        "truncation_false_positive_count": sum(
            1
            for item in results
            if item.get("expected_behavior") == "truncation_negative_expected"
            and (_case_has_status(item, "sat") or item.get("verifier_status") == "sat")
        ),
        "memcpy_positive_count": sum(
            1
            for item in results
            if _case_has_memory_copy(item) and item.get("format_flow_status") == "positive"
        ),
        "memcpy_truncation_negative_count": sum(
            1 for item in results if _case_has_memory_copy(item) and _case_has_marker_truncation(item)
        ),
        "inconclusive_count": sum(
            1
            for item in results
            if _case_has_status(item, "unknown")
            or item.get("sink_policy_status") in {"inconclusive", "unsupported"}
            or item.get("format_flow_status") == "inconclusive"
        ),
        "symbolic_sat_count": sum(1 for item in results if _case_has_status(item, "sat")),
        "symbolic_unsat_count": sum(1 for item in results if _case_has_status(item, "unsat") and not _case_has_status(item, "sat")),
        "symbolic_unsupported_count": sum(
            1 for item in results if _case_has_status(item, "unsupported") and not _case_has_status(item, "sat")
        ),
        "full_init_sat_count": sum(
            1 for item in results if _case_has_status(item, "sat") and item.get("selected_startup_mode") == "full_init"
        ),
        "direct_main_sat_count": sum(
            1 for item in results if _case_has_status(item, "sat") and item.get("selected_startup_mode") == "direct_main"
        ),
        "direct_main_case_count": sum(1 for item in results if item.get("selected_startup_mode") == "direct_main"),
        "full_startup_proof_count": sum(
            1
            for item in results
            if _case_has_status(item, "sat") and item.get("can_claim_full_startup_proof") is True
        ),
        "direct_main_only_count": sum(
            1
            for item in results
            if _case_has_status(item, "sat") and item.get("evidence_strength_level") == "direct_main_symbolic"
        ),
        "per_case": results,
        "limitations": [
            "cross-arch smoke does not execute target binaries concretely",
            "cross-arch symbolic support may be unsupported even when Ghidra facts export succeeds",
            "current smoke scope is toy_01 through toy_11, not real firmware",
            "toy_03 planner rejection is a sanitizer/marker incompatibility result, not a verifier crash",
            "toy_04/toy_05/toy_07/toy_08/toy_11 are negative regression fixtures; sat on those cases is treated as a false positive",
        ],
    }


def generate_cross_arch_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Cross-Arch Toy Smoke Summary",
        "",
        "## Summary",
        "",
        f"- Manifest: `{_display(summary.get('manifest_path'))}`",
        f"- Mode: `{_display(summary.get('mode'))}`",
        f"- Startup mode: `{_display(summary.get('startup_mode'))}`",
        f"- Total cases: `{_display(summary.get('total_cases'))}`",
        f"- Built cases: `{_display(summary.get('built_cases'))}`",
        f"- Skipped build cases: `{_display(summary.get('skipped_build_cases'))}`",
        f"- Ghidra success count: `{_display(summary.get('ghidra_success_count'))}`",
        f"- Task success count: `{_display(summary.get('task_success_count'))}`",
        f"- Expected unsat count: `{_display(summary.get('expected_unsat_count'))}`",
        f"- Expected no-sink count: `{_display(summary.get('expected_no_sink_count'))}`",
        f"- Planner reject expected count: `{_display(summary.get('planner_reject_expected_count'))}`",
        f"- Expected planner reject count: `{_display(summary.get('expected_planner_reject_count'))}`",
        f"- Planner reject count: `{_display(summary.get('planner_reject_count'))}`",
        f"- False positive count: `{_display(summary.get('false_positive_count'))}`",
        f"- Safe negative count: `{_display(summary.get('safe_negative_count'))}`",
        f"- Sink policy positive count: `{_display(summary.get('sink_policy_positive_count'))}`",
        f"- Sink policy inconclusive count: `{_display(summary.get('sink_policy_inconclusive_count'))}`",
        f"- Format-flow positive count: `{_display(summary.get('format_flow_positive_count'))}`",
        f"- Format-flow negative count: `{_display(summary.get('format_flow_negative_count'))}`",
        f"- Format-flow inconclusive count: `{_display(summary.get('format_flow_inconclusive_count'))}`",
        f"- Truncation negative count: `{_display(summary.get('truncation_negative_count'))}`",
        f"- Truncation false positive count: `{_display(summary.get('truncation_false_positive_count'))}`",
        f"- Memcpy positive count: `{_display(summary.get('memcpy_positive_count'))}`",
        f"- Memcpy truncation negative count: `{_display(summary.get('memcpy_truncation_negative_count'))}`",
        f"- Inconclusive count: `{_display(summary.get('inconclusive_count'))}`",
        f"- Symbolic sat cases: `{_display(summary.get('symbolic_sat_count'))}`",
        f"- Full-init sat cases: `{_display(summary.get('full_init_sat_count'))}`",
        f"- Direct-main fallback sat cases: `{_display(summary.get('direct_main_sat_count'))}`",
        f"- Symbolic unsat cases: `{_display(summary.get('symbolic_unsat_count'))}`",
        f"- Symbolic unsupported cases: `{_display(summary.get('symbolic_unsupported_count'))}`",
        f"- Full startup proof count: `{_display(summary.get('full_startup_proof_count'))}`",
        f"- Direct-main only count: `{_display(summary.get('direct_main_only_count'))}`",
        "",
        "Direct-main evidence means symbolic execution began at `main(argc, argv)` after full-init failed to reach the sink. It is useful for controlled toy debugging, but it does not prove full program startup reachability and must not be used as a standalone real-firmware claim.",
        "",
        "MIPS full-init diagnostics include `reached_main`, startup failure reason, loader external symbols, PLT/stub candidates, and whether the conservative block-level startup repair was applied.",
        "",
        "False-positive regression treats `sat` on `unsat_expected`, `no_sink_expected`, `planner_reject_expected`, or `truncation_negative_expected` cases as a failure signal. `toy_04`, `toy_05`, `toy_07`, `toy_08`, and `toy_11` are negative fixtures for branch/path, source-not-in-sink, format-safe, and truncation behavior.",
        "",
        "## Per Case",
        "",
        "| Toy | Arch | Expected | False Positive | Build | Facts | Task | Planner | Candidates | Rejected | Rejected Reason | Verifier | Sink Policy | Policy Reason | Format/Memory Flow | Marker Truncated | Memory Copy Count | Format Flow To Command | Startup | Evidence Level | Full Startup Proof | Status Counts | Reached Main | Main | Repair | Matched Sink | Match Reason | Sink Arg | Debug Reason | Startup Failure | Fallback |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in summary.get("per_case") or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _display(item.get("toy_id")),
                    _display(item.get("arch")),
                    _display(item.get("expected_behavior")),
                    _display_bool(item.get("false_positive")),
                    _display(item.get("build_status")),
                    _display(item.get("facts_status")),
                    _display(item.get("task_status")),
                    _display(item.get("planner_status")),
                    _display(item.get("candidate_count")),
                    _display(item.get("rejected_count")),
                    _display(item.get("rejected_reason")),
                    _display(item.get("verifier_status")),
                    _display(item.get("sink_policy_status")),
                    _display(item.get("sink_policy_reason")),
                    _display(item.get("format_flow_status")),
                    _display_bool(item.get("format_flow_marker_truncated")),
                    _display(item.get("format_flow_memory_copy_count")),
                    _display_bool(item.get("format_flow_to_command_sink")),
                    _display(item.get("selected_startup_mode")),
                    _display(item.get("evidence_strength_level")),
                    _display_bool(item.get("can_claim_full_startup_proof")),
                    _display(json.dumps(item.get("status_counts") or {}, sort_keys=True)),
                    _display_bool(item.get("reached_main")),
                    _display(item.get("main_address")),
                    _display_bool(item.get("full_init_repair_applied")),
                    _display(item.get("matched_sink_address")),
                    _display(item.get("match_reason")),
                    _display(item.get("sink_argument_location")),
                    _display(item.get("reachability_debug_reason")),
                    _display(item.get("startup_failure_reason")),
                    _display(item.get("fallback_reason")),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    for limitation in summary.get("limitations") or []:
        lines.append(f"- {_display(limitation)}")
    lines.extend(
        [
            "",
            "## Safety Note",
            "",
            "- No target binary was concretely executed.",
            "- No system/popen command was executed.",
            "- No weaponized exploit was generated.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _run_case(
    case: dict[str, Any],
    output_dir: Path,
    *,
    mode: str,
    startup_mode: str,
) -> dict[str, Any]:
    toy_id = str(case["toy_id"])
    arch = str(case["arch"])
    binary_path = str(case["binary_path"])
    target_yaml = str(case["target_yaml"])
    case_dir = output_dir / _safe_case_id(arch, toy_id)
    case_dir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "toy_id": toy_id,
        "arch": arch,
        "binary_path": binary_path,
        "target_yaml": target_yaml,
        "build_status": str(case.get("build_status") or "unknown"),
        "expected_behavior": str(case.get("expected_behavior") or _default_expected_behavior(toy_id)),
        "compiler": str(case.get("compiler") or ""),
        "notes": str(case.get("notes") or ""),
        "case_dir": str(case_dir),
        "case_status": "started",
        "false_positive": False,
        "facts_status": "not_run",
        "task_status": "not_run",
        "planner_status": "not_run",
        "verifier_status": "not_run",
        "status_counts": {},
        "candidate_count": 0,
        "rejected_count": 0,
        "rejected_reason": None,
        "planner_diagnostics": {},
        "rejected_candidates": [],
        "selected_sink": None,
        "sink_policy_status": None,
        "sink_policy_reason": None,
        "sink_policy_name": None,
        "format_flow": None,
        "format_flow_status": None,
        "format_flow_marker_truncated": None,
        "format_flow_memory_copy_count": 0,
        "format_flow_truncated_write_count": 0,
        "format_flow_to_command_sink": None,
        "matched_sink_address": None,
        "match_reason": None,
        "reachability_debug_reason": None,
        "selected_startup_mode": None,
        "fallback_reason": None,
        "evidence_strength_level": None,
        "can_claim_full_startup_proof": None,
        "requires_explicit_opt_in": None,
        "reached_main": None,
        "main_address": None,
        "startup_failure_reason": None,
        "full_init_repair_applied": None,
        "repair_reason": None,
        "errored_state_details": [],
        "loader_external_symbols": [],
        "plt_or_stub_candidates": [],
        "mips_delay_slot_candidates": [],
        "sink_argument_arch": None,
        "sink_argument_location": None,
        "limitations": [],
    }

    if result["build_status"] != "built":
        result["case_status"] = "skipped_build"
        result["facts_status"] = "skipped"
        result["task_status"] = "skipped"
        result["planner_status"] = "skipped"
        result["verifier_status"] = "skipped"
        result["limitations"].append(f"build status is {result['build_status']}")
        return result

    if not Path(binary_path).exists():
        result["case_status"] = "skipped_missing_binary"
        result["facts_status"] = "skipped_missing_binary"
        result["task_status"] = "skipped"
        result["planner_status"] = "skipped"
        result["verifier_status"] = "skipped"
        result["limitations"].append(f"binary does not exist: {binary_path}")
        return result

    facts_path = case_dir / "facts.real.json"
    task_path = case_dir / "task.real.json"
    candidates_path = case_dir / "candidates.rule.json"
    planner_run_dir = case_dir / "planner_run"
    planner_summary_path = case_dir / "planner_summary.json"
    planner_summary_md_path = case_dir / "planner_summary.md"
    ghidra_project_dir = case_dir / "ghidra_project"

    try:
        facts = export_facts(
            binary_path,
            output_path=str(facts_path),
            include_decompiler=True,
            project_location=str(ghidra_project_dir),
        )
        extraction = facts.get("extraction") if isinstance(facts.get("extraction"), dict) else {}
        result["facts_status"] = str(extraction.get("status") or "ok")
    except GhidraUnavailableError as exc:
        write_json(unavailable_facts(binary_path, str(exc), mode="pyghidra"), str(facts_path))
        result["case_status"] = "ghidra_failed"
        result["facts_status"] = "error"
        result["limitations"].append(f"Ghidra facts export failed: {exc}")
        return result
    except Exception as exc:
        result["case_status"] = "ghidra_failed"
        result["facts_status"] = "error"
        result["limitations"].append(f"Ghidra facts export failed: {exc}")
        return result

    try:
        task = build_dangerous_path_task(str(facts_path), target_yaml, output_path=str(task_path))
        result["task_status"] = "ok"
    except DangerousPathTaskError as exc:
        result["case_status"] = "task_failed"
        result["task_status"] = "error"
        result["limitations"].append(f"task build failed: {exc}")
        return result

    try:
        candidate_set = generate_candidate_set(task)
        write_candidate_set(candidate_set, str(candidates_path))
        result["planner_status"] = "ok"
        result["candidate_count"] = len(candidate_set.get("candidates") or [])
        result["rejected_candidates"] = candidate_set.get("rejected_candidates") or []
        result["rejected_count"] = len(result["rejected_candidates"])
        result["planner_diagnostics"] = candidate_set.get("planning_diagnostics") or {}
        result["rejected_reason"] = _first_rejected_reason(result["rejected_candidates"])
    except RulePlannerError as exc:
        result["case_status"] = "planner_failed"
        result["planner_status"] = "error"
        result["limitations"].append(f"rule planner failed: {exc}")
        return result

    try:
        planner_summary = run_pipeline(
            task_path=str(task_path),
            planner="rule",
            mode=mode,
            out_dir=str(planner_run_dir),
            candidates_path=str(candidates_path),
            startup_mode=startup_mode,
        )
        write_json(planner_summary, str(planner_summary_path))
        planner_summary_md_path.write_text(
            generate_summary_markdown(planner_summary),
            encoding="utf-8",
        )
        _copy_if_exists(planner_run_dir / "summary.json", planner_summary_path)
        _copy_if_exists(planner_run_dir / "candidates.json", candidates_path)
        result["verifier_status"] = _verifier_status(planner_summary)
        result["case_status"] = "ok"
        result["status_counts"] = planner_summary.get("status_counts") or {}
        result["candidate_count"] = int(planner_summary.get("total_candidates") or result["candidate_count"] or 0)
        result["rejected_count"] = int(planner_summary.get("rejected_count") or result["rejected_count"] or 0)
        result["planner_diagnostics"] = planner_summary.get("planner_diagnostics") or result["planner_diagnostics"]
        result["rejected_candidates"] = planner_summary.get("rejected_candidates") or result["rejected_candidates"]
        result["rejected_reason"] = _first_rejected_reason(result["rejected_candidates"])
        result["selected_sink"] = planner_summary.get("selected_sink")
        verification = _first_verification(planner_run_dir / "verifications")
        sink_arg = verification.get("sink_argument") if verification else None
        sink_policy = verification.get("sink_policy") if verification else None
        sink_policy = sink_policy if isinstance(sink_policy, dict) else {}
        format_flow = verification.get("format_flow") if verification else None
        format_flow = format_flow if isinstance(format_flow, dict) else {}
        reachability_debug = verification.get("reachability_debug") if verification else None
        reachability_debug = reachability_debug if isinstance(reachability_debug, dict) else {}
        result["sink_argument_arch"] = sink_arg.get("arch") if isinstance(sink_arg, dict) else None
        result["sink_argument_location"] = sink_arg.get("location") if isinstance(sink_arg, dict) else None
        result["sink_policy_status"] = sink_policy.get("policy_status")
        result["sink_policy_reason"] = sink_policy.get("reason")
        result["sink_policy_name"] = sink_policy.get("policy_name")
        result["format_flow"] = format_flow or None
        result["format_flow_status"] = format_flow.get("status")
        result["format_flow_marker_truncated"] = format_flow.get("marker_truncated")
        result["format_flow_memory_copy_count"] = int(format_flow.get("memory_copy_count") or 0)
        result["format_flow_truncated_write_count"] = int(format_flow.get("truncated_write_count") or 0)
        result["format_flow_to_command_sink"] = format_flow.get("flows_to_command_sink")
        result["matched_sink_address"] = reachability_debug.get("matched_sink_address")
        result["match_reason"] = reachability_debug.get("match_reason")
        result["reachability_debug_reason"] = reachability_debug.get("reason")
        result["reached_main"] = reachability_debug.get("reached_main")
        result["main_address"] = reachability_debug.get("main_address")
        result["startup_failure_reason"] = reachability_debug.get("startup_failure_reason")
        result["full_init_repair_applied"] = reachability_debug.get("full_init_repair_applied")
        result["repair_reason"] = reachability_debug.get("repair_reason")
        result["errored_state_details"] = reachability_debug.get("errored_state_details") or []
        result["loader_external_symbols"] = reachability_debug.get("loader_external_symbols") or []
        result["plt_or_stub_candidates"] = reachability_debug.get("plt_or_stub_candidates") or []
        result["mips_delay_slot_candidates"] = reachability_debug.get("mips_delay_slot_candidates") or []
        startup_debug = verification.get("startup_debug") if verification else None
        startup_debug = startup_debug if isinstance(startup_debug, dict) else {}
        evidence_strength = verification.get("evidence_strength") if verification else None
        evidence_strength = evidence_strength if isinstance(evidence_strength, dict) else {}
        result["selected_startup_mode"] = startup_debug.get("selected_startup_mode")
        result["fallback_reason"] = startup_debug.get("fallback_reason")
        result["evidence_strength_level"] = evidence_strength.get("level")
        result["can_claim_full_startup_proof"] = evidence_strength.get("can_claim_full_startup_proof")
        result["requires_explicit_opt_in"] = evidence_strength.get("requires_explicit_opt_in")
        result["limitations"].extend(str(item) for item in planner_summary.get("limitations") or [])
        result["false_positive"] = _is_false_positive(result)
    except PlannerVerifierPipelineError as exc:
        result["case_status"] = "verifier_failed"
        result["verifier_status"] = "error"
        result["limitations"].append(f"planner-verifier pipeline failed: {exc}")
    except Exception as exc:
        result["case_status"] = "verifier_failed"
        result["verifier_status"] = "error"
        result["limitations"].append(f"planner-verifier pipeline failed: {exc}")
    result["false_positive"] = _is_false_positive(result)
    return result


def _normalize_case(case: Any, index: int) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise CrossArchSmokeError(f"manifest case[{index}] must be an object")
    required = {"toy_id", "arch", "binary_path", "target_yaml", "build_status", "compiler", "notes"}
    missing = sorted(required - set(case))
    if missing:
        raise CrossArchSmokeError(f"manifest case[{index}] missing keys: {', '.join(missing)}")
    normalized = {key: case.get(key) for key in sorted(required)}
    normalized["expected_behavior"] = case.get("expected_behavior") or _default_expected_behavior(str(case.get("toy_id") or ""))
    return normalized


def _verifier_status(summary: dict[str, Any]) -> str:
    counts = Counter(summary.get("status_counts") or {})
    if counts.get("sat", 0) > 0:
        return "sat"
    if counts.get("timeout", 0) > 0:
        return "timeout"
    if counts.get("unsupported", 0) > 0:
        return "unsupported"
    if counts.get("unsat", 0) > 0:
        return "unsat"
    if int(summary.get("total_candidates") or 0) == 0:
        return "no_candidates"
    return "unknown"


def _first_verification(verifications_dir: Path) -> dict[str, Any] | None:
    if not verifications_dir.exists():
        return None
    for path in sorted(verifications_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            return data
    return None


def _case_has_status(item: dict[str, Any], status: str) -> bool:
    counts = item.get("status_counts")
    return isinstance(counts, dict) and int(counts.get(status) or 0) > 0


def _case_has_marker_truncation(item: dict[str, Any]) -> bool:
    if item.get("format_flow_marker_truncated") is True:
        return True
    flow = item.get("format_flow")
    return isinstance(flow, dict) and flow.get("marker_truncated") is True


def _case_has_memory_copy(item: dict[str, Any]) -> bool:
    try:
        if int(item.get("format_flow_memory_copy_count") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    flow = item.get("format_flow")
    return isinstance(flow, dict) and int(flow.get("memory_copy_count") or 0) > 0


def _copy_if_exists(source: Path, destination: Path) -> None:
    if source.exists() and source.resolve() != destination.resolve():
        shutil.copyfile(source, destination)


def _safe_case_id(arch: str, toy_id: str) -> str:
    raw = f"{arch}_{toy_id}"
    return "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in raw)


def _default_expected_behavior(toy_id: str) -> str:
    if toy_id == "toy_03":
        return "planner_reject_expected"
    if toy_id in {"toy_04", "toy_05", "toy_07"}:
        return "unsat_expected"
    if toy_id in {"toy_08", "toy_11"}:
        return "truncation_negative_expected"
    return "sat_expected"


def _first_rejected_reason(rejected_candidates: Any) -> str | None:
    if not isinstance(rejected_candidates, list):
        return None
    reasons: list[str] = []
    for item in rejected_candidates:
        if isinstance(item, dict) and item.get("reason"):
            reason = str(item["reason"])
            if reason not in reasons:
                reasons.append(reason)
    return ", ".join(reasons) if reasons else None


def _is_false_positive(item: dict[str, Any]) -> bool:
    expected = str(item.get("expected_behavior") or "")
    if expected not in {"unsat_expected", "no_sink_expected", "planner_reject_expected", "truncation_negative_expected"}:
        return False
    return _case_has_status(item, "sat") or item.get("verifier_status") == "sat"


def _display(value: Any) -> str:
    if value is None or value == "":
        return "not available"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _display_bool(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return _display(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run cross-architecture toy facts/task/planner/verifier smoke tests.",
    )
    parser.add_argument("--manifest", required=True, help="cross-arch toy benchmark manifest JSON.")
    parser.add_argument("--out-dir", required=True, help="output directory for smoke artifacts.")
    parser.add_argument("--mode", choices=sorted(SUPPORTED_MODES), default="symbolic")
    parser.add_argument(
        "--startup-mode",
        choices=sorted(SUPPORTED_STARTUP_MODES),
        default="auto",
        help="symbolic startup mode: full-init, direct-main, or auto fallback.",
    )
    args = parser.parse_args(argv)

    try:
        summary = run_cross_arch_smoke(
            manifest_path=args.manifest,
            out_dir=args.out_dir,
            mode=args.mode,
            startup_mode=args.startup_mode,
        )
    except CrossArchSmokeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        "cross-arch smoke complete "
        f"cases={summary['total_cases']} ghidra_success={summary['ghidra_success_count']} "
        f"sat_cases={summary['symbolic_sat_count']} out_dir={args.out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
