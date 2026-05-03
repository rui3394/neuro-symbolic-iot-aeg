from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

NOT_AVAILABLE = "not available"
DRY_RUN_NOTICE = "This is an adapter-level dry-run result."
SYMBOLIC_NOTICE = "The symbolic execution backend has not been fully wired for task mode yet."
NO_EXECUTION_NOTICE = "No target binary was executed."
NO_CONCRETE_EXECUTION_NOTICE = "No target binary was concretely executed."
NO_COMMAND_EXECUTION_NOTICE = "No system/popen command was executed."
NO_EXPLOIT_NOTICE = "No weaponized exploit was generated."
SYMBOLIC_EVIDENCE_NOTICE = "This is angr-based symbolic reachability evidence."
NOT_FULL_EXPLOIT_NOTICE = "This is source-to-sink symbolic evidence, not full exploit verification."
DIRECT_MAIN_NOTICE = "This is direct-main symbolic evidence."
DIRECT_MAIN_BYPASS_NOTICE = "It bypasses startup/loader modeling."
DIRECT_MAIN_NO_FULL_PROOF_NOTICE = "It does not prove full program startup reachability."
DIRECT_MAIN_TOY_NOTICE = "It is acceptable for controlled toy benchmark debugging."
DIRECT_MAIN_FIRMWARE_NOTICE = "It must not be used as a standalone real-firmware claim."


class EvidenceReportError(ValueError):
    """Raised when an evidence report input cannot be read."""


def load_verification_result(path: str) -> dict[str, Any]:
    verification_path = Path(path)
    if not verification_path.exists():
        raise EvidenceReportError(f"verification JSON does not exist: {path}")
    try:
        data = json.loads(verification_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceReportError(f"failed to read verification JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise EvidenceReportError("verification JSON must be an object")
    return data


def generate_evidence_markdown(verification: dict[str, Any]) -> str:
    binary = verification.get("binary") if isinstance(verification.get("binary"), dict) else {}
    lines = [
        "# Dangerous Path Evidence Report",
        "",
        "## Summary",
        "",
        f"- Task ID: `{_display(verification.get('task_id'))}`",
        f"- Candidate ID: `{_display(verification.get('candidate_id'))}`",
        f"- Verification status: `{_display(verification.get('status'))}`",
        f"- Verification mode: `{_display(verification.get('mode'))}`",
        f"- Executed target binary: `{_display_bool(verification.get('executed'))}`",
        f"- Oracle: `{_display(verification.get('oracle'))}`",
        f"- Benign marker: `{_display(verification.get('benign_marker'))}`",
        "",
        "## Binary",
        "",
        f"- Path: `{_display(binary.get('path'))}`",
        f"- Name: `{_display(binary.get('name'))}`",
        f"- Arch: `{_display(binary.get('arch'))}`",
        "",
        "## Sources Checked",
        "",
    ]
    lines.extend(_render_sources(verification.get("checked_sources")))
    lines.extend(
        [
            "",
            "## Sinks Checked",
            "",
        ]
    )
    lines.extend(_render_sinks(verification.get("checked_sinks")))
    lines.extend(_render_symbolic_evidence(verification))
    lines.extend(_render_sink_policy(verification))
    lines.extend(_render_format_flow(verification))
    lines.extend(_render_evidence_strength(verification))
    lines.extend(
        [
            "",
            "## Candidate Input Summary",
            "",
        ]
    )
    lines.extend(_render_candidate_input_summary(verification.get("checked_sources")))
    lines.extend(
        [
            "",
            "## Reason",
            "",
            _paragraph(verification.get("reason")),
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(_render_limitations(verification))
    lines.extend(
        [
            "",
            "## Safety Note",
            "",
            f"- {_execution_notice(verification)}",
            f"- {NO_COMMAND_EXECUTION_NOTICE}",
            f"- {NO_EXPLOIT_NOTICE}",
            f"- {NOT_FULL_EXPLOIT_NOTICE}",
            "- Candidate inputs are summarized as benign source probes, not rendered as attack payloads.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def write_evidence_report(verification_path: str, output_path: str) -> str:
    verification = load_verification_result(verification_path)
    markdown = generate_evidence_markdown(verification)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown evidence report from verifier JSON.",
    )
    parser.add_argument("--verification", required=True, help="Verification result JSON path.")
    parser.add_argument("--out", required=True, help="Output Markdown path.")
    args = parser.parse_args(argv)

    try:
        write_evidence_report(args.verification, args.out)
    except EvidenceReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"wrote evidence report: {args.out}")
    return 0


def _render_sources(value: Any) -> list[str]:
    sources = value if isinstance(value, list) else []
    if not sources:
        return ["_None reported._"]
    rows = [
        "| Source ID | Name | Carrier | Symbolic | Input Present | Benign Marker Hit | Input Length |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for source in sources:
        if not isinstance(source, dict):
            continue
        rows.append(
            "| "
            + " | ".join(
                [
                    _display(source.get("source_id")),
                    _display(source.get("name")),
                    _display(source.get("carrier")),
                    _display(source.get("symbolic")),
                    _display_bool(source.get("candidate_input_present")),
                    _display_bool(source.get("benign_marker_present")),
                    _display(source.get("candidate_input_len")),
                ]
            )
            + " |"
        )
    return rows if len(rows) > 2 else ["_None reported._"]


def _render_sinks(value: Any) -> list[str]:
    sinks = value if isinstance(value, list) else []
    if not sinks:
        return ["_None reported._"]
    rows = [
        "| Sink ID | Function | Address | Arg Index | Callers |",
        "| --- | --- | --- | --- | --- |",
    ]
    for sink in sinks:
        if not isinstance(sink, dict):
            continue
        callers = sink.get("callers")
        rows.append(
            "| "
            + " | ".join(
                [
                    _display(sink.get("sink_id")),
                    _display(sink.get("function")),
                    _display(sink.get("address")),
                    _display(sink.get("arg_index")),
                    _display(", ".join(str(caller) for caller in callers) if isinstance(callers, list) else callers),
                ]
            )
            + " |"
        )
    return rows if len(rows) > 2 else ["_None reported._"]


def _render_candidate_input_summary(value: Any) -> list[str]:
    sources = value if isinstance(value, list) else []
    if not sources:
        return ["- Candidate source input summary: not available"]
    lines = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        name = _display(source.get("name"))
        present = _display_bool(source.get("candidate_input_present"))
        marker = _display_bool(source.get("benign_marker_present"))
        length = _display(source.get("candidate_input_len"))
        lines.append(
            f"- Source `{name}`: input_present=`{present}`, "
            f"benign_marker_present=`{marker}`, input_len=`{length}`"
        )
    return lines or ["- Candidate source input summary: not available"]


def _render_symbolic_evidence(verification: dict[str, Any]) -> list[str]:
    if verification.get("mode") != "symbolic_task":
        return []
    lines = [
        "",
        "## Symbolic Evidence",
        "",
        f"- {SYMBOLIC_EVIDENCE_NOTICE}",
        f"- Backend: `{_display(verification.get('backend'))}`",
        f"- Path status: `{_display(verification.get('path_status'))}`",
        f"- Sink reached: `{_display_tri_state(verification.get('sink_reached'))}`",
        f"- Source bound: `{_display_tri_state(verification.get('source_bound'))}`",
        f"- Marker observed: `{_display_tri_state(verification.get('marker_observed'))}`",
        "",
        "### Selected Entry",
        "",
    ]
    lines.extend(_render_selected_entry(verification.get("selected_entry")))
    lines.extend(
        [
            "",
            "### Selected Sink",
            "",
        ]
    )
    lines.extend(_render_selected_sink(verification.get("selected_sink")))
    lines.extend(
        [
            "",
            "### Constraints Summary",
            "",
        ]
    )
    lines.extend(_render_constraints_summary(verification.get("constraints_summary")))
    return lines


def _render_evidence_strength(verification: dict[str, Any]) -> list[str]:
    strength = verification.get("evidence_strength")
    strength = strength if isinstance(strength, dict) else {}
    if not strength and verification.get("mode") != "symbolic_task":
        return []
    startup_mode = str(strength.get("startup_mode") or NOT_AVAILABLE)
    lines = [
        "",
        "## Evidence Strength",
        "",
        f"- Startup mode: `{_display(startup_mode)}`",
        f"- Level: `{_display(strength.get('level'))}`",
        f"- Scope: `{_display(strength.get('scope'))}`",
        f"- Can claim full startup proof: `{_display_bool(strength.get('can_claim_full_startup_proof'))}`",
        f"- Requires explicit opt-in: `{_display_bool(strength.get('requires_explicit_opt_in'))}`",
        f"- Description: {_paragraph(strength.get('description'))}",
    ]
    if startup_mode == "full_init":
        lines.append("- This is symbolic reachability evidence from the program initialization path.")
    elif startup_mode == "direct_main":
        lines.extend(
            [
                f"- {DIRECT_MAIN_NOTICE}",
                f"- {DIRECT_MAIN_BYPASS_NOTICE}",
                f"- {DIRECT_MAIN_NO_FULL_PROOF_NOTICE}",
                f"- {DIRECT_MAIN_TOY_NOTICE}",
                f"- {DIRECT_MAIN_FIRMWARE_NOTICE}",
            ]
        )
    return lines


def _render_sink_policy(verification: dict[str, Any]) -> list[str]:
    policy = verification.get("sink_policy")
    policy = policy if isinstance(policy, dict) else {}
    if not policy and verification.get("mode") != "symbolic_task":
        return []
    return [
        "",
        "## Sink Policy",
        "",
        f"- Policy name: `{_display(policy.get('policy_name'))}`",
        f"- Policy status: `{_display(policy.get('policy_status'))}`",
        f"- Reason: `{_display(policy.get('reason'))}`",
        f"- Source reaches sink: `{_display_tri_state(policy.get('source_reaches_sink'))}`",
        f"- Marker reaches sink: `{_display_tri_state(policy.get('marker_reaches_sink'))}`",
        f"- Fixed safe argument: `{_display_tri_state(policy.get('fixed_safe_argument'))}`",
    ]


def _render_format_flow(verification: dict[str, Any]) -> list[str]:
    flow = verification.get("format_flow")
    flow = flow if isinstance(flow, dict) else {}
    if not flow and verification.get("mode") != "symbolic_task":
        return []
    lines = [
        "",
        "## Format/Memory Flow Evidence",
        "",
        f"- Observed: `{_display_bool(flow.get('observed'))}`",
        f"- Status: `{_display(flow.get('status'))}`",
        f"- Format write count: `{_display(flow.get('format_write_count'))}`",
        f"- Format record count: `{_display(flow.get('format_record_count'))}`",
        f"- Memory copy count: `{_display(flow.get('memory_copy_count'))}`",
        f"- Positive write count: `{_display(flow.get('positive_write_count'))}`",
        f"- Truncated write count: `{_display(flow.get('truncated_write_count'))}`",
        f"- Marker truncated: `{_display_bool(flow.get('marker_truncated'))}`",
        f"- Flows to command sink: `{_display_bool(flow.get('flows_to_command_sink'))}`",
    ]
    records = flow.get("records")
    if isinstance(records, list) and records:
        lines.extend(
            [
                "",
                "| Flow Kind | Function | Callsite | Destination Buffer | Size | Copy Length | Source/Marker Written | Marker Truncated | Flows To Command Sink | Evidence Strength |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in records:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        _display(item.get("flow_kind")),
                        _display(item.get("format_function")),
                        _display(item.get("format_callsite")),
                        _display(item.get("dst_buffer")),
                        _display(item.get("size_value")),
                        _display(item.get("copy_length")),
                        _display_bool(item.get("source_or_marker_written")),
                        _display_bool(item.get("marker_truncated")),
                        _display_bool(item.get("flows_to_command_sink")),
                        _display(item.get("evidence_strength")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- Records: not available")
    limitations = flow.get("limitations")
    if isinstance(limitations, list) and limitations:
        lines.append("")
        lines.append("Limitations:")
        for item in limitations:
            lines.append(f"- {_display(item)}")
    return lines


def _render_selected_entry(value: Any) -> list[str]:
    entry = value if isinstance(value, dict) else {}
    return [
        f"- Function: `{_display(entry.get('function'))}`",
        f"- Address: `{_display(entry.get('address'))}`",
    ]


def _render_selected_sink(value: Any) -> list[str]:
    sink = value if isinstance(value, dict) else {}
    callers = sink.get("callers")
    callers_text = ", ".join(str(caller) for caller in callers) if isinstance(callers, list) else callers
    return [
        f"- Sink ID: `{_display(sink.get('sink_id'))}`",
        f"- Function: `{_display(sink.get('function'))}`",
        f"- Type: `{_display(sink.get('type'))}`",
        f"- Address: `{_display(sink.get('address'))}`",
        f"- External address: `{_display(sink.get('external_address'))}`",
        f"- Arg index: `{_display(sink.get('arg_index'))}`",
        f"- Callers: `{_display(callers_text)}`",
    ]


def _render_constraints_summary(value: Any) -> list[str]:
    summary = value if isinstance(value, dict) else {}
    if not summary:
        return ["_Not available._"]
    return [f"- {_display(key)}: `{_display(summary[key])}`" for key in sorted(summary)]


def _render_limitations(verification: dict[str, Any]) -> list[str]:
    mode = str(verification.get("mode") or "")
    limitations = verification.get("limitations")
    items: list[str] = []
    if mode == "task_adapter_dry_run":
        items.extend([DRY_RUN_NOTICE, SYMBOLIC_NOTICE])
    elif mode == "symbolic_task":
        items.append(SYMBOLIC_EVIDENCE_NOTICE)
    if isinstance(limitations, list):
        for limitation in limitations:
            text = str(limitation)
            if _is_symbolic_backend_limitation(text) and SYMBOLIC_NOTICE in items:
                continue
            if text and text not in items:
                items.append(text)
    if not items:
        items.append(NOT_AVAILABLE)
    return [f"- {item}" for item in items]


def _paragraph(value: Any) -> str:
    text = _display(value)
    return text if text != NOT_AVAILABLE else "_Not available._"


def _is_symbolic_backend_limitation(text: str) -> bool:
    lowered = text.lower()
    return (
        "symbolic execution backend" in lowered
        and "not fully wired" in lowered
        and "task mode" in lowered
    )


def _display(value: Any) -> str:
    if value is None or value == "":
        return NOT_AVAILABLE
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _display_bool(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return NOT_AVAILABLE


def _display_tri_state(value: Any) -> str:
    if isinstance(value, bool):
        return _display_bool(value)
    if value in {"unknown", "not available"}:
        return str(value)
    return _display(value)


def _execution_notice(verification: dict[str, Any]) -> str:
    if verification.get("mode") == "symbolic_task":
        return NO_CONCRETE_EXECUTION_NOTICE
    return NO_EXECUTION_NOTICE


if __name__ == "__main__":
    raise SystemExit(main())
