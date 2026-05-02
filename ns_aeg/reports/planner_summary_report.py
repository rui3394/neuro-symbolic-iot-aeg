from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

NOT_AVAILABLE = "not available"
NO_CONCRETE_EXECUTION_NOTICE = "No target binary was concretely executed."
NO_COMMAND_EXECUTION_NOTICE = "No system/popen command was executed."
NO_EXPLOIT_NOTICE = "No weaponized exploit was generated."
CANDIDATE_SAFETY_NOTICE = "Candidates are benign source-to-sink verification inputs."


class PlannerSummaryReportError(ValueError):
    """Raised when a planner summary report cannot be generated."""


def load_summary(path: str) -> dict[str, Any]:
    summary_path = Path(path)
    if not summary_path.exists():
        raise PlannerSummaryReportError(f"summary JSON does not exist: {path}")
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PlannerSummaryReportError(f"failed to read summary JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PlannerSummaryReportError("summary JSON must be an object")
    return data


def generate_summary_markdown(summary: dict[str, Any]) -> str:
    planner = summary.get("planner") if isinstance(summary.get("planner"), dict) else {}
    lines = [
        "# Planner Verification Summary",
        "",
        "## Summary",
        "",
        f"- Task ID: `{_display(summary.get('task_id'))}`",
        f"- Planner: `{_display(planner.get('name'))}`",
        f"- Planner version: `{_display(planner.get('version'))}`",
        f"- Planner mode: `{_display(planner.get('mode'))}`",
        f"- Verification mode: `{_display(summary.get('mode'))}`",
        f"- Total candidates: `{_display(summary.get('total_candidates'))}`",
        f"- Best candidate: `{_display(summary.get('best_candidate_id'))}`",
        f"- Best status: `{_display(summary.get('best_status'))}`",
        "",
        "## Status Counts",
        "",
    ]
    lines.extend(_render_status_counts(summary.get("status_counts")))
    lines.extend(
        [
            "",
            "## Evidence Counts",
            "",
            f"- Sink reached count: `{_display(summary.get('sink_reached_count'))}`",
            f"- Source bound count: `{_display(summary.get('source_bound_count'))}`",
            f"- Marker observed count: `{_display(summary.get('marker_observed_count'))}`",
            "",
            "## Selected Sink",
            "",
        ]
    )
    lines.extend(_render_selected_sink(summary.get("selected_sink")))
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(_render_limitations(summary.get("limitations")))
    lines.extend(
        [
            "",
            "## Safety Note",
            "",
            f"- {NO_CONCRETE_EXECUTION_NOTICE}",
            f"- {NO_COMMAND_EXECUTION_NOTICE}",
            f"- {NO_EXPLOIT_NOTICE}",
            f"- {CANDIDATE_SAFETY_NOTICE}",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def write_summary_report(summary_path: str, output_path: str) -> str:
    summary = load_summary(summary_path)
    markdown = generate_summary_markdown(summary)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown report from planner-verifier summary JSON.",
    )
    parser.add_argument("--summary", required=True, help="Planner summary JSON path.")
    parser.add_argument("--out", required=True, help="Output Markdown path.")
    args = parser.parse_args(argv)

    try:
        write_summary_report(args.summary, args.out)
    except PlannerSummaryReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"wrote planner summary report: {args.out}")
    return 0


def _render_status_counts(value: Any) -> list[str]:
    counts = value if isinstance(value, dict) else {}
    if not counts:
        return ["_None reported._"]
    return [f"- {_display(status)}: `{_display(count)}`" for status, count in sorted(counts.items())]


def _render_selected_sink(value: Any) -> list[str]:
    sink = value if isinstance(value, dict) else {}
    if not sink:
        return ["_Not available._"]
    return [
        f"- Sink ID: `{_display(sink.get('sink_id'))}`",
        f"- Function: `{_display(sink.get('function'))}`",
        f"- Address: `{_display(sink.get('address'))}`",
        f"- Type: `{_display(sink.get('type'))}`",
        f"- External address: `{_display(sink.get('external_address'))}`",
    ]


def _render_limitations(value: Any) -> list[str]:
    limitations = value if isinstance(value, list) else []
    if not limitations:
        return ["- not available"]
    return [f"- {_display(item)}" for item in limitations]


def _display(value: Any) -> str:
    if value is None or value == "":
        return NOT_AVAILABLE
    return str(value).replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())

