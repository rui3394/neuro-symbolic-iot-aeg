from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from ns_aeg.tasks.loader import load_dangerous_path_task

RESULT_STATUSES = {"sat", "unsat", "timeout", "unknown", "unsupported"}
TASK_MODE_LIMITATION = "symbolic execution backend not fully wired for task mode yet"


class CandidateLoadError(ValueError):
    """Raised when a task-mode candidate file is missing or malformed."""


@dataclass(frozen=True)
class VerifierTaskConfig:
    task_id: str
    binary: dict[str, Any]
    entry: dict[str, Any]
    sources: list[dict[str, Any]]
    sinks: list[dict[str, Any]]
    oracle: str
    benign_marker: str
    evidence: dict[str, Any]
    scope: str = "unknown"
    allow_direct_main: bool = False


def load_candidate(path: str) -> dict[str, Any]:
    candidate_path = Path(path)
    if not candidate_path.exists():
        raise CandidateLoadError(f"candidate JSON does not exist: {path}")

    try:
        data = json.loads(candidate_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CandidateLoadError(f"failed to read candidate JSON: {path}: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("candidates"), list):
        if not data["candidates"]:
            raise CandidateLoadError("candidate JSON contains no candidates")
        first = data["candidates"][0]
        if not isinstance(first, dict):
            raise CandidateLoadError("candidate entry must be an object")
        return first
    if not isinstance(data, dict):
        raise CandidateLoadError("candidate JSON must be an object")
    return data


def task_to_verifier_config(task: dict[str, Any]) -> VerifierTaskConfig:
    sources = task.get("sources")
    sinks = task.get("sinks")
    if not isinstance(sources, list) or not sources:
        raise ValueError("dangerous path task has no sources")
    if not isinstance(sinks, list) or not sinks:
        raise ValueError("dangerous path task has no sinks")

    expected = task.get("expected") if isinstance(task.get("expected"), dict) else {}
    scope = _task_scope(task)
    return VerifierTaskConfig(
        task_id=str(task.get("task_id") or "unknown_task"),
        binary=dict(task.get("binary") or {}),
        entry=dict(task.get("entry") or {}),
        sources=[dict(source) for source in sources if isinstance(source, dict)],
        sinks=[dict(sink) for sink in sinks if isinstance(sink, dict)],
        oracle=str(expected.get("oracle") or "source_reaches_sink"),
        benign_marker=str(expected.get("benign_marker") or "__NS_AEG_MARKER__"),
        evidence=dict(task.get("evidence") or {}),
        scope=scope,
        allow_direct_main=bool(task.get("allow_direct_main") is True),
    )


def verify_candidate_for_task(
    task_path: str,
    candidate_path: str,
    *,
    output_path: str | None = None,
) -> dict[str, Any]:
    task = load_dangerous_path_task(task_path)
    candidate = load_candidate(candidate_path)
    config = task_to_verifier_config(task)
    result = verify_candidate_with_task_config(config, candidate)
    result["provenance"] = {
        "task_path": task_path,
        "candidate_path": candidate_path,
    }

    if output_path is not None:
        write_json(result, output_path)
    return result


def verify_candidate_with_task_config(
    config: VerifierTaskConfig,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidate_id") or "unknown_candidate")
    inputs = candidate.get("inputs")
    if not isinstance(inputs, dict):
        return _result(
            status="unsupported",
            config=config,
            candidate_id=candidate_id,
            checked_sources=[],
            reason="missing_candidate_inputs",
            limitations=[TASK_MODE_LIMITATION],
        )

    checked_sources = _checked_sources(config.sources, inputs, config.benign_marker)
    missing_sources = [
        source["name"]
        for source in checked_sources
        if source["candidate_input_present"] is False
    ]
    if missing_sources:
        return _result(
            status="unsupported",
            config=config,
            candidate_id=candidate_id,
            checked_sources=checked_sources,
            reason=f"missing_candidate_input: {', '.join(missing_sources)}",
            limitations=[TASK_MODE_LIMITATION],
        )

    return _result(
        status="unknown",
        config=config,
        candidate_id=candidate_id,
        checked_sources=checked_sources,
        reason="task adapter dry-run completed; candidate inputs mapped to task sources",
        limitations=[TASK_MODE_LIMITATION],
    )


def write_json(data: dict[str, Any], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _checked_sources(
    sources: list[dict[str, Any]],
    inputs: dict[str, Any],
    benign_marker: str,
) -> list[dict[str, Any]]:
    checked = []
    for source in sources:
        name = str(source.get("name") or "")
        value = inputs.get(name)
        present = name in inputs
        checked.append(
            {
                "source_id": source.get("source_id"),
                "name": name,
                "carrier": source.get("carrier"),
                "symbolic": source.get("symbolic"),
                "candidate_input_present": present,
                "candidate_input_len": len(str(value)) if present else None,
                "benign_marker_present": (
                    benign_marker in str(value) if present and benign_marker else False
                ),
            }
        )
    return checked


def _checked_sinks(sinks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "sink_id": sink.get("sink_id"),
            "function": sink.get("function"),
            "address": sink.get("address"),
            "arg_index": sink.get("arg_index"),
            "callers": sink.get("callers", []),
        }
        for sink in sinks
    ]


def _task_scope(task: dict[str, Any]) -> str:
    explicit = task.get("scope") or task.get("target_kind")
    if explicit:
        return str(explicit)
    binary = task.get("binary") if isinstance(task.get("binary"), dict) else {}
    binary_path = str(binary.get("path") or "")
    if "datasets/toy_cgi" in binary_path or "build_cross" in binary_path or "examples/cross_arch" in binary_path:
        return "toy_benchmark"
    return "unknown"


def _result(
    *,
    status: str,
    config: VerifierTaskConfig,
    candidate_id: str,
    checked_sources: list[dict[str, Any]],
    reason: str,
    limitations: list[str],
) -> dict[str, Any]:
    if status not in RESULT_STATUSES:
        raise ValueError(f"invalid verifier status: {status}")

    return {
        "status": status,
        "task_id": config.task_id,
        "candidate_id": candidate_id,
        "binary": {
            "path": config.binary.get("path"),
            "name": config.binary.get("name"),
            "arch": config.binary.get("arch"),
        },
        "entry": dict(config.entry),
        "checked_sources": checked_sources,
        "checked_sinks": _checked_sinks(config.sinks),
        "oracle": config.oracle,
        "benign_marker": config.benign_marker,
        "reason": reason,
        "limitations": limitations,
        "evidence": {
            "string_count": len(config.evidence.get("strings", []))
            if isinstance(config.evidence.get("strings"), list)
            else 0,
            "decompiled_snippet_count": len(config.evidence.get("decompiled_snippets", []))
            if isinstance(config.evidence.get("decompiled_snippets"), list)
            else 0,
        },
        "mode": "task_adapter_dry_run",
        "executed": False,
    }
