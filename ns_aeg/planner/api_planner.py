from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from ns_aeg.planner.providers import (
    OpenAICompatibleConfig,
    ProviderError,
    call_openai_compatible_chat,
)
from ns_aeg.planner.rule_planner import DEFAULT_BENIGN_MARKER, DANGEROUS_CHARS
from ns_aeg.tasks.loader import TaskLoadError, load_dangerous_path_task

PLANNER_NAME = "api_llm_planner"
OFFLINE_PLANNER_NAME = "api_llm_planner_offline"
PLANNER_VERSION = "0.1"
PLANNER_MODE = "benign_candidate_generation"
DEFAULT_PROVIDER = "openai_compatible"
MAX_CANDIDATES = 5


class ApiPlannerError(ValueError):
    """Raised when the API planner cannot safely produce candidates."""


def generate_candidate_set_for_task_path(
    task_path: str,
    *,
    offline_example: bool = False,
) -> dict[str, Any]:
    task = load_dangerous_path_task(task_path)
    return generate_candidate_set(task, offline_example=offline_example)


def generate_candidate_set(
    task: dict[str, Any],
    *,
    offline_example: bool = False,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    if offline_example:
        candidate_set = _offline_candidate_set(task)
        validate_candidate_set(candidate_set, task)
        return candidate_set

    env = dict(os.environ if env is None else env)
    provider = env.get("NS_AEG_LLM_PROVIDER", DEFAULT_PROVIDER)
    if provider != DEFAULT_PROVIDER:
        raise ApiPlannerError(f"unsupported LLM provider: {provider}")

    base_url = env.get("NS_AEG_LLM_BASE_URL", "")
    api_key = env.get("NS_AEG_LLM_API_KEY", "")
    model = env.get("NS_AEG_LLM_MODEL", "")
    missing = [
        name
        for name, value in (
            ("NS_AEG_LLM_BASE_URL", base_url),
            ("NS_AEG_LLM_API_KEY", api_key),
            ("NS_AEG_LLM_MODEL", model),
        )
        if not value
    ]
    if missing:
        raise ApiPlannerError(
            "LLM planner is offline by default; set "
            + ", ".join(missing)
            + " or pass --offline-example"
        )

    messages = build_messages(task)
    try:
        content = call_openai_compatible_chat(
            config=OpenAICompatibleConfig(
                base_url=base_url,
                api_key=api_key,
                model=model,
            ),
            messages=messages,
        )
    except ProviderError as exc:
        raise ApiPlannerError(str(exc)) from exc

    candidate_set = parse_candidate_response(content, task, provider=provider, model=model)
    validate_candidate_set(candidate_set, task)
    return candidate_set


def build_messages(task: dict[str, Any]) -> list[dict[str, str]]:
    source_summary = _source_summary(task)
    sink_summary = _sink_summary(task)
    marker = _benign_marker(task)
    return [
        {
            "role": "system",
            "content": (
                "You generate benign source-to-sink verification candidates for an IoT CGI "
                "dangerous-path verification demo. Output only JSON. Do not generate exploit "
                "payloads or shell command injection strings."
            ),
        },
        {
            "role": "user",
            "content": (
                "Generate at most 5 benign candidates compatible with this JSON shape: "
                "{\"candidates\":[{\"candidate_id\":\"...\",\"strategy\":\"...\","
                "\"inputs\":{\"source_name\":\"value\"},\"assumptions\":[\"...\"],"
                "\"safety\":{\"benign\":true,\"weaponized\":false}}]}.\n"
                f"Task ID: {task.get('task_id')}\n"
                f"Sources: {json.dumps(source_summary, sort_keys=True)}\n"
                f"Sinks: {json.dumps(sink_summary, sort_keys=True)}\n"
                f"Benign marker: {marker}\n"
                "Rules: only benign source-to-sink verification inputs; no shell command "
                "injection payloads; do not use any of these characters: ; & | ` $ ( ) > <; "
                "do not use newlines; each input must not exceed its source max_len; include "
                "the benign marker when one is available; safety.weaponized must be false; "
                "do not include explanatory prose."
            ),
        },
    ]


def parse_candidate_response(
    content: str,
    task: dict[str, Any],
    *,
    provider: str,
    model: str,
) -> dict[str, Any]:
    try:
        parsed = json.loads(_extract_json_text(content))
    except json.JSONDecodeError as exc:
        raise ApiPlannerError("LLM planner response was not valid candidate JSON") from exc

    if isinstance(parsed, dict) and isinstance(parsed.get("candidates"), list):
        candidates = parsed["candidates"]
    elif isinstance(parsed, list):
        candidates = parsed
    else:
        raise ApiPlannerError("LLM planner response must contain a candidates list")

    return {
        "planner": {
            "name": PLANNER_NAME,
            "version": PLANNER_VERSION,
            "provider": provider,
            "model": model,
            "mode": PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
    }


def validate_candidate_set(candidate_set: dict[str, Any], task: dict[str, Any]) -> None:
    candidates = candidate_set.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ApiPlannerError("LLM planner produced no candidates")
    if len(candidates) > MAX_CANDIDATES:
        raise ApiPlannerError(f"LLM planner produced too many candidates: {len(candidates)}")

    sources = _sources_by_name(task)
    if not sources:
        raise ApiPlannerError("dangerous path task has no sources")
    marker = _benign_marker(task)

    seen_ids: set[str] = set()
    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, dict):
            raise ApiPlannerError(f"candidate {index} must be an object")
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            raise ApiPlannerError(f"candidate {index} is missing candidate_id")
        if candidate_id in seen_ids:
            raise ApiPlannerError(f"duplicate candidate_id: {candidate_id}")
        seen_ids.add(candidate_id)

        inputs = candidate.get("inputs")
        if not isinstance(inputs, dict):
            raise ApiPlannerError(f"candidate {candidate_id} is missing inputs object")
        missing = [name for name in sources if name not in inputs]
        if missing:
            raise ApiPlannerError(
                f"candidate {candidate_id} missing source inputs: {', '.join(missing)}"
            )

        for name, source in sources.items():
            value = inputs.get(name)
            if not isinstance(value, str):
                raise ApiPlannerError(f"candidate {candidate_id} input {name} must be a string")
            max_len = _source_max_len(source)
            if len(value) > max_len:
                raise ApiPlannerError(
                    f"candidate {candidate_id} input {name} exceeds max_len {max_len}"
                )
            if "\n" in value or "\r" in value:
                raise ApiPlannerError(f"candidate {candidate_id} input {name} contains newline")
            if any(char in value for char in DANGEROUS_CHARS):
                raise ApiPlannerError(
                    f"candidate {candidate_id} input {name} contains disallowed shell character"
                )
            if marker and marker not in value:
                raise ApiPlannerError(
                    f"candidate {candidate_id} input {name} does not contain benign marker"
                )

        safety = candidate.get("safety")
        if not isinstance(safety, dict):
            raise ApiPlannerError(f"candidate {candidate_id} is missing safety object")
        if safety.get("benign") is not True or safety.get("weaponized") is not False:
            raise ApiPlannerError(
                f"candidate {candidate_id} safety must be benign=true and weaponized=false"
            )


def write_candidate_set(candidate_set: dict[str, Any], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(candidate_set, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate benign candidates with an API-based LLM planner interface.",
    )
    parser.add_argument("--task", required=True, help="dangerous_path_task JSON path.")
    parser.add_argument("--out", required=True, help="output candidate set JSON path.")
    parser.add_argument(
        "--offline-example",
        "--mock",
        action="store_true",
        help="do not call a remote API; emit deterministic LLM-style benign candidates.",
    )
    args = parser.parse_args(argv)

    try:
        candidate_set = generate_candidate_set_for_task_path(
            args.task,
            offline_example=args.offline_example,
        )
        write_candidate_set(candidate_set, args.out)
    except (TaskLoadError, ApiPlannerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"generated {len(candidate_set['candidates'])} benign LLM-style candidates "
        f"planner={candidate_set['planner']['name']} task_id={candidate_set['task_id']} out={args.out}"
    )
    return 0


def _offline_candidate_set(task: dict[str, Any]) -> dict[str, Any]:
    sources = _sources_by_name(task)
    if not sources:
        raise ApiPlannerError("dangerous path task has no sources")
    marker = _benign_marker(task)
    prefix = _candidate_prefix(task)
    strategies = [
        ("llm_benign_marker_direct", lambda max_len: _fit(f"127.0.0.1{marker}", marker, max_len)),
        ("llm_marker_only", lambda max_len: _fit(marker, marker, max_len)),
        ("llm_safe_prefix_marker", lambda max_len: _fit(f"SAFE{marker}", marker, max_len)),
    ]
    candidates: list[dict[str, Any]] = []
    for index, (strategy, builder) in enumerate(strategies, start=1):
        inputs = {
            name: builder(_source_max_len(source))
            for name, source in sources.items()
        }
        candidates.append(
            {
                "candidate_id": f"{prefix}_llm_offline_{index:03d}",
                "strategy": strategy,
                "inputs": inputs,
                "assumptions": [
                    "LLM planner offline-example uses deterministic benign probes",
                    "benign marker is required for source-to-sink evidence",
                ],
                "safety": {
                    "benign": True,
                    "weaponized": False,
                },
            }
        )
    return {
        "planner": {
            "name": OFFLINE_PLANNER_NAME,
            "version": PLANNER_VERSION,
            "provider": "offline_example",
            "model": "deterministic",
            "mode": PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
    }


def _fit(value: str, marker: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    if marker and len(marker) <= max_len:
        return marker
    raise ApiPlannerError("benign marker is longer than source max_len")


def _extract_json_text(content: str) -> str:
    text = content.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if fence:
        return fence.group(1).strip()
    return text


def _sources_by_name(task: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = task.get("sources")
    if not isinstance(sources, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for source in sources:
        if isinstance(source, dict) and source.get("name"):
            result[str(source["name"])] = source
    return result


def _source_summary(task: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "type": source.get("type"),
            "carrier": source.get("carrier"),
            "max_len": _source_max_len(source),
        }
        for name, source in _sources_by_name(task).items()
    ]


def _sink_summary(task: dict[str, Any]) -> list[dict[str, Any]]:
    sinks = task.get("sinks") if isinstance(task.get("sinks"), list) else []
    return [
        {
            "function": sink.get("function"),
            "type": sink.get("type"),
            "address": sink.get("address"),
        }
        for sink in sinks
        if isinstance(sink, dict)
    ]


def _source_max_len(source: dict[str, Any]) -> int:
    try:
        return int(source.get("max_len"))
    except (TypeError, ValueError):
        return 64


def _benign_marker(task: dict[str, Any]) -> str:
    expected = task.get("expected") if isinstance(task.get("expected"), dict) else {}
    return str(expected.get("benign_marker") or DEFAULT_BENIGN_MARKER)


def _candidate_prefix(task: dict[str, Any]) -> str:
    binary = task.get("binary") if isinstance(task.get("binary"), dict) else {}
    raw = str(binary.get("name") or task.get("task_id") or "task")
    prefix = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")
    return prefix or "task"


if __name__ == "__main__":
    raise SystemExit(main())

