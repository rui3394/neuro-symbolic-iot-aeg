from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.config import load_target_config
from ns_aeg.reporting import generate_analysis_report


def generate_batch_summary(
    config_paths: list[str],
    output_path: str = "reports/summary.json",
) -> dict[str, Any]:
    targets = []
    for config_path in config_paths:
        targets.append(_summarize_config(config_path))

    summary = {
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

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def _summarize_config(config_path: str) -> dict[str, Any]:
    try:
        config = load_target_config(config_path)
        report = generate_analysis_report(config)
        report_summary = report.get("summary", {})
        target = report.get("target", {})
        return {
            "name": target.get("name", config.name),
            "binary": target.get("binary", config.binary),
            "source_to_sink_confirmed": bool(
                report_summary.get("source_to_sink_confirmed", False)
            ),
            "sanitizer_like_observed": bool(
                report_summary.get("sanitizer_like_observed", False)
            ),
            "status": str(report_summary.get("status", "error")),
            "report_path": report.get("report_path"),
        }
    except Exception as exc:
        return {
            "name": Path(config_path).stem,
            "binary": None,
            "source_to_sink_confirmed": False,
            "sanitizer_like_observed": False,
            "status": "error",
            "report_path": None,
            "error": str(exc),
        }
