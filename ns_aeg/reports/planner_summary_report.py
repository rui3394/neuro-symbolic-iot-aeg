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
DIRECT_MAIN_CAUTION = (
    "Direct-main evidence bypasses startup/loader modeling and must not be used as a standalone real-firmware claim."
)


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
        f"- Planner provider: `{_display(planner.get('provider'))}`",
        f"- Base URL host: `{_display(planner.get('base_url_host'))}`",
        f"- Model: `{_display(planner.get('model'))}`",
        f"- Max tokens: `{_display(planner.get('max_tokens'))}`",
        f"- Temperature: `{_display(planner.get('temperature'))}`",
        f"- Verification mode: `{_display(summary.get('mode'))}`",
        f"- Candidate source: `{_display(summary.get('candidate_source'))}`",
        f"- Total candidates: `{_display(summary.get('total_candidates'))}`",
        f"- Best candidate: `{_display(summary.get('best_candidate_id'))}`",
        f"- Best status: `{_display(summary.get('best_status'))}`",
        "",
        "## Candidate Validation",
        "",
        f"- Candidate count: `{_display(summary.get('candidate_count'))}`",
        f"- Validation passed: `{_display(summary.get('validation_passed_count'))}`",
        f"- Validation failed: `{_display(summary.get('validation_failed_count'))}`",
        f"- Rejected candidates: `{_display(summary.get('rejected_count'))}`",
        "",
        "## Status Counts",
        "",
    ]
    lines.extend(_render_status_counts(summary.get("status_counts")))
    lines.extend(
        [
            "",
            "## Planner Diagnostics",
            "",
        ]
    )
    lines.extend(_render_planner_diagnostics(summary))
    lines.extend(
        [
            "",
            "## Evidence Counts",
            "",
            f"- Sink reached count: `{_display(summary.get('sink_reached_count'))}`",
            f"- Source bound count: `{_display(summary.get('source_bound_count'))}`",
            f"- Marker observed count: `{_display(summary.get('marker_observed_count'))}`",
            f"- Safe negative count: `{_display(summary.get('safe_negative_count'))}`",
            f"- Sink policy positive count: `{_display(summary.get('sink_policy_positive_count'))}`",
            f"- Sink policy inconclusive count: `{_display(summary.get('sink_policy_inconclusive_count'))}`",
            f"- Sink policy unsupported count: `{_display(summary.get('sink_policy_unsupported_count'))}`",
            f"- Format-flow positive count: `{_display(summary.get('format_flow_positive_count'))}`",
            f"- Format-flow negative count: `{_display(summary.get('format_flow_negative_count'))}`",
            f"- Format-flow inconclusive count: `{_display(summary.get('format_flow_inconclusive_count'))}`",
            f"- Truncation negative count: `{_display(summary.get('truncation_negative_count'))}`",
            f"- Truncation false positive count: `{_display(summary.get('truncation_false_positive_count'))}`",
            f"- Memcpy positive count: `{_display(summary.get('memcpy_positive_count'))}`",
            f"- Memcpy truncation negative count: `{_display(summary.get('memcpy_truncation_negative_count'))}`",
            f"- Inconclusive count: `{_display(summary.get('inconclusive_count'))}`",
            f"- Full startup proof count: `{_display(summary.get('full_startup_proof_count'))}`",
            f"- Direct-main evidence count: `{_display(summary.get('direct_main_evidence_count'))}`",
            "",
            "## Evidence Strength",
            "",
        ]
    )
    lines.extend(_render_evidence_strength(summary))
    lines.extend(
        [
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


def _render_planner_diagnostics(summary: dict[str, Any]) -> list[str]:
    diagnostics = summary.get("planner_diagnostics")
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    rejected = summary.get("rejected_candidates")
    rejected = rejected if isinstance(rejected, list) else []
    lines = [
        f"- Sanitizer count: `{_display(diagnostics.get('sanitizer_count'))}`",
        f"- Sanitizer types: `{_display(', '.join(diagnostics.get('sanitizer_types', [])) if isinstance(diagnostics.get('sanitizer_types'), list) else diagnostics.get('sanitizer_types'))}`",
        f"- Marker length: `{_display(diagnostics.get('marker_len'))}`",
        f"- Rejected count: `{_display(summary.get('rejected_count'))}`",
    ]
    notes = diagnostics.get("notes")
    if isinstance(notes, list) and notes:
        lines.append("- Notes: " + "; ".join(_display(note) for note in notes))
    elif summary.get("total_candidates") == 0:
        lines.append("- Notes: no candidates were generated for this planner run")
    if rejected:
        lines.append("")
        lines.append("| Strategy | Source | Sanitizer | Reason |")
        lines.append("| --- | --- | --- | --- |")
        for item in rejected:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        _display(item.get("strategy")),
                        _display(item.get("source")),
                        _display(item.get("sanitizer")),
                        _display(item.get("reason")),
                    ]
                )
                + " |"
            )
    return lines


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


def _render_evidence_strength(summary: dict[str, Any]) -> list[str]:
    strength = summary.get("evidence_strength")
    strength = strength if isinstance(strength, dict) else {}
    lines = [
        f"- Selected startup mode: `{_display(summary.get('selected_startup_mode') or strength.get('startup_mode'))}`",
        f"- Evidence level: `{_display(strength.get('level'))}`",
        f"- Can claim full startup proof: `{_display_bool(strength.get('can_claim_full_startup_proof'))}`",
    ]
    if strength.get("level") == "direct_main_symbolic" or int(summary.get("direct_main_evidence_count") or 0) > 0:
        lines.append(f"- Caution: {DIRECT_MAIN_CAUTION}")
    return lines


def _render_limitations(value: Any) -> list[str]:
    limitations = value if isinstance(value, list) else []
    if not limitations:
        return ["- not available"]
    return [f"- {_display(item)}" for item in limitations]


def _display(value: Any) -> str:
    if value is None or value == "":
        return NOT_AVAILABLE
    return str(value).replace("|", "\\|").replace("\n", " ")


def _display_bool(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return NOT_AVAILABLE


if __name__ == "__main__":
    raise SystemExit(main())
