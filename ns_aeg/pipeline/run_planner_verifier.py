from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any

from ns_aeg.planner.api_planner import ApiPlannerError
from ns_aeg.planner.api_planner import generate_candidate_set as generate_llm_candidate_set
from ns_aeg.planner.rule_planner import RulePlannerError
from ns_aeg.planner.rule_planner import generate_candidate_set as generate_rule_candidate_set
from ns_aeg.tasks.loader import TaskLoadError, load_dangerous_path_task
from ns_aeg.verifier.symbolic_task_runner import run_symbolic_task_verification
from ns_aeg.verifier.task_adapter import (
    VerifierTaskConfig,
    task_to_verifier_config,
    verify_candidate_with_task_config,
    write_json,
)

SUPPORTED_PLANNERS = {"llm", "rule"}
SUPPORTED_MODES = {"dry-run", "symbolic"}


class PlannerVerifierPipelineError(ValueError):
    """Raised when the planner-verifier pipeline cannot start."""


def run_pipeline(
    *,
    task_path: str,
    planner: str,
    mode: str,
    out_dir: str,
    offline_example: bool = False,
) -> dict[str, Any]:
    if planner not in SUPPORTED_PLANNERS:
        raise PlannerVerifierPipelineError(f"unsupported planner: {planner}")
    if mode not in SUPPORTED_MODES:
        raise PlannerVerifierPipelineError(f"unsupported verifier mode: {mode}")

    task = load_dangerous_path_task(task_path)
    config = task_to_verifier_config(task)
    candidate_set = _generate_candidate_set(
        task,
        planner=planner,
        offline_example=offline_example,
    )

    output_dir = Path(out_dir)
    verifications_dir = output_dir / "verifications"
    verifications_dir.mkdir(parents=True, exist_ok=True)
    _write_json(candidate_set, output_dir / "candidates.json")

    results: list[dict[str, Any]] = []
    for candidate in candidate_set["candidates"]:
        result = _verify_one_candidate(config, candidate, mode, task_path, planner)
        results.append(result)
        candidate_id = _safe_filename(str(candidate.get("candidate_id") or "unknown_candidate"))
        write_json(result, str(verifications_dir / f"{candidate_id}.json"))

    summary = build_summary(
        task=task,
        candidate_set=candidate_set,
        mode=mode,
        results=results,
    )
    _write_json(summary, output_dir / "summary.json")
    _write_json(build_best_candidate_payload(candidate_set, results), output_dir / "best_candidate.json")
    return summary


def build_summary(
    *,
    task: dict[str, Any],
    candidate_set: dict[str, Any],
    mode: str,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    status_counts = Counter(str(result.get("status") or "unknown") for result in results)
    best = select_best_result(results)
    selected_sink = _first_selected_sink(results)
    planner_meta = dict(candidate_set.get("planner") or {})
    return {
        "task_id": str(task.get("task_id") or "unknown_task"),
        "planner": planner_meta,
        "mode": mode,
        "total_candidates": len(candidate_set.get("candidates") or []),
        "status_counts": dict(sorted(status_counts.items())),
        "sat_count": status_counts.get("sat", 0),
        "timeout_count": status_counts.get("timeout", 0),
        "unsupported_count": status_counts.get("unsupported", 0),
        "best_candidate_id": best.get("candidate_id") if best else None,
        "best_status": best.get("status") if best else None,
        "selected_sink": selected_sink,
        "sink_reached_count": _count_truthy(results, "sink_reached"),
        "source_bound_count": _count_truthy(results, "source_bound"),
        "marker_observed_count": _count_truthy(results, "marker_observed"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": _summary_limitations(planner_meta),
    }


def build_best_candidate_payload(
    candidate_set: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    best = select_best_result(results)
    if best is None:
        return {
            "best_candidate": None,
            "best_candidate_id": None,
            "reason": "no candidate satisfied sat, sink_reached, or marker_observed selection criteria",
        }
    candidate_id = best.get("candidate_id")
    candidate = _candidate_by_id(candidate_set, candidate_id)
    return {
        "best_candidate": candidate,
        "best_candidate_id": candidate_id,
        "best_status": best.get("status"),
        "reason": "selected by status=sat, sink_reached, then marker_observed priority",
    }


def select_best_result(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    for predicate in (
        lambda result: result.get("status") == "sat",
        lambda result: result.get("sink_reached") is True,
        lambda result: result.get("marker_observed") is True,
    ):
        for result in results:
            if predicate(result):
                return result
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run planner-generated candidates through the task-driven verifier.",
    )
    parser.add_argument("--task", required=True, help="dangerous_path_task JSON path.")
    parser.add_argument("--planner", choices=sorted(SUPPORTED_PLANNERS), default="rule")
    parser.add_argument("--mode", choices=sorted(SUPPORTED_MODES), default="dry-run")
    parser.add_argument(
        "--offline-example",
        action="store_true",
        help="for --planner llm, do not call a remote API; use deterministic benign candidates.",
    )
    parser.add_argument("--out-dir", required=True, help="output directory for batch artifacts.")
    args = parser.parse_args(argv)

    try:
        summary = run_pipeline(
            task_path=args.task,
            planner=args.planner,
            mode=args.mode,
            out_dir=args.out_dir,
            offline_example=args.offline_example,
        )
    except (
        TaskLoadError,
        RulePlannerError,
        ApiPlannerError,
        PlannerVerifierPipelineError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"planner-verifier run complete task_id={summary['task_id']} "
        f"mode={summary['mode']} candidates={summary['total_candidates']} "
        f"best_candidate_id={summary['best_candidate_id']} out_dir={args.out_dir}"
    )
    return 0


def _generate_candidate_set(
    task: dict[str, Any],
    *,
    planner: str,
    offline_example: bool,
) -> dict[str, Any]:
    if planner == "rule":
        if offline_example:
            raise PlannerVerifierPipelineError("--offline-example is only valid with --planner llm")
        return generate_rule_candidate_set(task)
    if planner == "llm":
        return generate_llm_candidate_set(task, offline_example=offline_example)
    raise PlannerVerifierPipelineError(f"unsupported planner: {planner}")


def _verify_one_candidate(
    config: VerifierTaskConfig,
    candidate: dict[str, Any],
    mode: str,
    task_path: str,
    planner: str,
) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidate_id") or "unknown_candidate")
    try:
        if mode == "symbolic":
            result = run_symbolic_task_verification(config, candidate)
        else:
            result = verify_candidate_with_task_config(config, candidate)
        result["provenance"] = {
            "task_path": task_path,
            "candidate_id": candidate_id,
            "planner": planner,
        }
        return result
    except Exception as exc:  # Batch mode records per-candidate failures instead of aborting.
        return {
            "status": "unsupported",
            "task_id": config.task_id,
            "candidate_id": candidate_id,
            "binary": dict(config.binary),
            "checked_sources": [],
            "checked_sinks": [],
            "oracle": config.oracle,
            "benign_marker": config.benign_marker,
            "reason": f"candidate verification error: {exc}",
            "limitations": ["single candidate failed; batch continued with structured error result"],
            "mode": "symbolic_task" if mode == "symbolic" else "task_adapter_dry_run",
            "executed": False,
            "sink_reached": "unknown",
            "source_bound": "unknown",
            "marker_observed": "unknown",
            "path_status": "unsupported",
        }


def _write_json(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_filename(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in value)


def _count_truthy(results: list[dict[str, Any]], key: str) -> int:
    return sum(1 for result in results if result.get(key) is True)


def _first_selected_sink(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    for result in results:
        selected = result.get("selected_sink")
        if isinstance(selected, dict) and selected:
            return selected
    return None


def _candidate_by_id(candidate_set: dict[str, Any], candidate_id: Any) -> dict[str, Any] | None:
    for candidate in candidate_set.get("candidates") or []:
        if isinstance(candidate, dict) and candidate.get("candidate_id") == candidate_id:
            return candidate
    return None


def _summary_limitations(planner_meta: dict[str, Any]) -> list[str]:
    planner_name = str(planner_meta.get("name") or "")
    limitations = [
        "candidate verification does not concretely execute target binaries or system/popen",
        "symbolic mode is currently scoped to local toy argv-based CGI binaries",
    ]
    if planner_name.startswith("api_llm_planner"):
        limitations.insert(
            0,
            "API LLM planner outputs are locally validated as benign candidates before verification",
        )
    else:
        limitations.insert(0, "rule planner is a benign deterministic baseline, not an exploit generator")
    return limitations


if __name__ == "__main__":
    raise SystemExit(main())
