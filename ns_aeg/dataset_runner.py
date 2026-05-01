from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ns_aeg.config import load_target_config
from ns_aeg.reporting import generate_analysis_report


def run_toy_dataset(
    config_dir: str = "configs",
    reports_dir: str = "reports",
    summary_json: str = "reports/summary.json",
    summary_md: str = "reports/summary.md",
    summary_csv: str = "reports/summary.csv",
) -> dict[str, Any]:
    report_dir = Path(reports_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    targets = [_run_one_config(path, report_dir) for path in _toy_config_paths(config_dir)]
    summary = _build_summary(targets)

    summary_json_path = Path(summary_json)
    summary_json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_json_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_summary_md(summary, summary_md)
    _write_summary_csv(summary, summary_csv)

    return summary


def _toy_config_paths(config_dir: str) -> list[Path]:
    return sorted(Path(config_dir).glob("toy_*.yaml"))


def _run_one_config(config_path: Path, reports_dir: Path) -> dict[str, Any]:
    try:
        config = load_target_config(str(config_path))
        report_path = reports_dir / f"{config.name}_analysis.json"
        report = generate_analysis_report(config, str(report_path))
        return _target_from_report(report, config.name, config.binary)
    except Exception as exc:
        return {
            "name": config_path.stem,
            "binary": None,
            "source_to_sink_confirmed": False,
            "sanitizer_like_observed": False,
            "sanitizer_candidate_count": 0,
            "input_modeling_count": 0,
            "branch_condition_count": 0,
            "status": "error",
            "report_path": None,
            "error": str(exc),
        }


def _target_from_report(
    report: dict[str, Any],
    fallback_name: str,
    fallback_binary: str,
) -> dict[str, Any]:
    target = report.get("target", {})
    summary = report.get("summary", {})
    observation = report.get("constraint_observation", {})
    return {
        "name": target.get("name", fallback_name),
        "binary": target.get("binary", fallback_binary),
        "source_to_sink_confirmed": bool(summary.get("source_to_sink_confirmed", False)),
        "sanitizer_like_observed": bool(summary.get("sanitizer_like_observed", False)),
        "sanitizer_candidate_count": int(
            observation.get("sanitizer_candidate_count", 0)
        ),
        "input_modeling_count": int(observation.get("input_modeling_count", 0)),
        "branch_condition_count": int(observation.get("branch_condition_count", 0)),
        "status": str(summary.get("status", "error")),
        "report_path": report.get("report_path"),
        **({"error": summary.get("error")} if summary.get("error") else {}),
    }


def _build_summary(targets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_targets": len(targets),
        "ok_targets": sum(1 for target in targets if target["status"] == "ok"),
        "source_to_sink_confirmed_count": sum(
            1 for target in targets if target["source_to_sink_confirmed"]
        ),
        "sanitizer_like_observed_count": sum(
            1 for target in targets if target["sanitizer_like_observed"]
        ),
        "error_count": sum(1 for target in targets if target["status"] == "error"),
        "targets": targets,
    }


def _write_summary_md(summary: dict[str, Any], path: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "| Target | Source-to-Sink | Sanitizer Observed | Sanitizer Candidates | Input Modeling | Branch Conditions | Status |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for target in summary["targets"]:
        lines.append(
            "| {name} | {source_to_sink} | {sanitizer_observed} | {sanitizer_candidates} | {input_modeling} | {branch_conditions} | {status} |".format(
                name=target["name"],
                source_to_sink=_yes_no(target["source_to_sink_confirmed"]),
                sanitizer_observed=_yes_no(target["sanitizer_like_observed"]),
                sanitizer_candidates=target["sanitizer_candidate_count"],
                input_modeling=target["input_modeling_count"],
                branch_conditions=target["branch_condition_count"],
                status=target["status"],
            )
        )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_summary_csv(summary: dict[str, Any], path: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target",
                "binary",
                "source_to_sink_confirmed",
                "sanitizer_like_observed",
                "sanitizer_candidate_count",
                "input_modeling_count",
                "branch_condition_count",
                "status",
                "report_path",
            ],
        )
        writer.writeheader()
        for target in summary["targets"]:
            writer.writerow(
                {
                    "target": target["name"],
                    "binary": target["binary"],
                    "source_to_sink_confirmed": target["source_to_sink_confirmed"],
                    "sanitizer_like_observed": target["sanitizer_like_observed"],
                    "sanitizer_candidate_count": target["sanitizer_candidate_count"],
                    "input_modeling_count": target["input_modeling_count"],
                    "branch_condition_count": target["branch_condition_count"],
                    "status": target["status"],
                    "report_path": target["report_path"],
                }
            )


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
