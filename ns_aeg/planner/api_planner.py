from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
DEFAULT_PLANNER_MAX_TOKENS = 8192
DEFAULT_PING_MAX_TOKENS = 512


class ApiPlannerError(ValueError):
    """Raised when the API planner cannot safely produce candidates."""


def generate_candidate_set_for_task_path(
    task_path: str,
    *,
    offline_example: bool = False,
    debug_response: bool = False,
) -> dict[str, Any]:
    task = load_dangerous_path_task(task_path)
    return generate_candidate_set(
        task,
        offline_example=offline_example,
        debug_response=debug_response,
    )


def generate_candidate_set(
    task: dict[str, Any],
    *,
    offline_example: bool = False,
    env: dict[str, str] | None = None,
    debug_response: bool = False,
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
    max_tokens = _env_int(env, "NS_AEG_LLM_MAX_TOKENS", DEFAULT_PLANNER_MAX_TOKENS)
    temperature = _env_float(env, "NS_AEG_LLM_TEMPERATURE", 0.0)
    try:
        content = call_openai_compatible_chat(
            config=OpenAICompatibleConfig(
                base_url=base_url,
                api_key=api_key,
                model=model,
            ),
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=env.get("NS_AEG_LLM_RESPONSE_FORMAT") or None,
            debug_response=debug_response,
        )
    except ProviderError as exc:
        raise ApiPlannerError(str(exc)) from exc

    candidate_set = parse_candidate_response(
        content,
        task,
        provider=provider,
        model=model,
        base_url=base_url,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    validate_candidate_set(candidate_set, task)
    return candidate_set


def ping_provider(env: dict[str, str] | None = None, *, debug_response: bool = False) -> dict[str, Any]:
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
        raise ApiPlannerError("LLM ping requires " + ", ".join(missing))

    try:
        content = call_openai_compatible_chat(
            config=OpenAICompatibleConfig(
                base_url=base_url,
                api_key=api_key,
                model=model,
            ),
            messages=[
                {"role": "user", "content": 'Return only this JSON: {"ok": true}'},
            ],
            max_tokens=_env_int(env, "NS_AEG_LLM_MAX_TOKENS", DEFAULT_PING_MAX_TOKENS),
            response_format=env.get("NS_AEG_LLM_RESPONSE_FORMAT") or None,
            debug_response=debug_response,
        )
    except ProviderError as exc:
        raise ApiPlannerError(str(exc)) from exc

    try:
        parsed = json.loads(_extract_json_text(content))
    except json.JSONDecodeError as exc:
        raise ApiPlannerError("LLM ping response was not valid JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        raise ApiPlannerError("LLM ping response did not contain ok=true")
    return parsed


def build_messages(task: dict[str, Any]) -> list[dict[str, str]]:
    source_summary = _source_summary(task)
    marker = _benign_marker(task)
    return [
        {
            "role": "system",
            "content": (
                "Output JSON only. Generate benign source-to-sink verification inputs. "
                "Do not output reasoning. Do not generate exploit payloads."
            ),
        },
        {
            "role": "user",
            "content": (
                "Return one compact JSON object with at most 3 candidates and this exact shape: "
                "{\"candidates\":[{\"candidate_id\":\"c1\",\"strategy\":\"benign_marker\","
                "\"inputs\":{\"ip\":\"127.0.0.1__NS_AEG_MARKER__\"},"
                "\"assumptions\":[\"benign source probe\"],"
                "\"safety\":{\"benign\":true,\"weaponized\":false}}]}.\n"
                f"Task ID: {task.get('task_id')}\n"
                f"Sources: {json.dumps(source_summary, sort_keys=True)}\n"
                f"Benign marker: {marker}\n"
                "Rules: values must include the benign marker; no characters ; & | ` $ ( ) > <; "
                "no newlines; stay within max_len; safety.weaponized must be false; no prose."
            ),
        },
    ]


def parse_candidate_response(
    content: str,
    task: dict[str, Any],
    *,
    provider: str,
    model: str,
    base_url: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> dict[str, Any]:
    try:
        parsed = json.loads(_extract_json_text(content))
    except json.JSONDecodeError as exc:
        preview = content.strip().replace("\n", " ")[:300]
        raise ApiPlannerError(
            f"LLM planner response was not valid candidate JSON; content_preview={preview!r}"
        ) from exc

    if isinstance(parsed, dict) and isinstance(parsed.get("candidates"), list):
        candidates = parsed["candidates"]
    elif isinstance(parsed, list):
        candidates = parsed
    else:
        raise ApiPlannerError("LLM planner response must contain a candidates list")

    candidate_set = {
        "planner": {
            "name": PLANNER_NAME,
            "version": PLANNER_VERSION,
            "provider": provider,
            "base_url_host": _base_url_host(base_url),
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "mode": PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
    }
    candidate_set["validation"] = build_candidate_validation_report(candidate_set, task)
    return candidate_set


def validate_candidate_set(candidate_set: dict[str, Any], task: dict[str, Any]) -> None:
    report = build_candidate_validation_report(candidate_set, task)
    candidate_set["validation"] = report
    if report["validation_failed_count"]:
        failed = [
            f"{item.get('candidate_id')}: {', '.join(item.get('errors') or [])}"
            for item in report.get("candidates", [])
            if not item.get("validation_passed")
        ]
        raise ApiPlannerError("LLM candidate validation failed: " + "; ".join(failed))


def build_candidate_validation_report(
    candidate_set: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    candidates = candidate_set.get("candidates")
    sources = _sources_by_name(task)
    marker = _benign_marker(task)
    candidate_reports: list[dict[str, Any]] = []

    if not isinstance(candidates, list):
        return {
            "candidate_count": 0,
            "validation_passed_count": 0,
            "validation_failed_count": 1,
            "candidates": [
                {
                    "candidate_id": None,
                    "validation_passed": False,
                    "errors": ["candidate set has no candidates list"],
                    "checks": {},
                }
            ],
        }

    for index, candidate in enumerate(candidates, start=1):
        candidate_reports.append(_validate_one_candidate(candidate, index, sources, marker))

    set_errors: list[str] = []
    if not candidates:
        set_errors.append("LLM planner produced no candidates")
    if len(candidates) > MAX_CANDIDATES:
        set_errors.append(f"LLM planner produced too many candidates: {len(candidates)}")
    if not sources:
        set_errors.append("dangerous path task has no sources")

    if set_errors and not candidate_reports:
        candidate_reports.append(
            {
                "candidate_id": None,
                "validation_passed": False,
                "errors": set_errors,
                "checks": {},
            }
        )
    elif set_errors:
        for report in candidate_reports:
            report["errors"].extend(set_errors)
            report["validation_passed"] = False

    duplicate_ids = set(_check_duplicate_candidate_ids(candidate_set))
    if duplicate_ids:
        for report in candidate_reports:
            if report.get("candidate_id") in duplicate_ids:
                report["errors"].append(f"duplicate candidate_id: {report.get('candidate_id')}")
                report["validation_passed"] = False

    passed_count = sum(1 for report in candidate_reports if report.get("validation_passed"))
    failed_count = len(candidate_reports) - passed_count
    return {
        "candidate_count": len(candidates),
        "validation_passed_count": passed_count,
        "validation_failed_count": failed_count,
        "candidates": candidate_reports,
    }

def _validate_one_candidate(
    candidate: Any,
    index: int,
    sources: dict[str, dict[str, Any]],
    marker: str,
) -> dict[str, Any]:
    errors: list[str] = []
    checks = {
        "covers_all_sources": False,
        "contains_benign_marker": False,
        "within_max_len": False,
        "contains_dangerous_chars": False,
        "weaponized_false": False,
    }
    if not isinstance(candidate, dict):
        return {
            "candidate_id": None,
            "validation_passed": False,
            "errors": [f"candidate {index} must be an object"],
            "checks": checks,
        }

    candidate_id = str(candidate.get("candidate_id") or "")
    if not candidate_id:
        errors.append(f"candidate {index} is missing candidate_id")

    inputs = candidate.get("inputs")
    if not isinstance(inputs, dict):
        errors.append(f"candidate {candidate_id or index} is missing inputs object")
        inputs = {}

    missing = [name for name in sources if name not in inputs]
    checks["covers_all_sources"] = not missing and bool(sources)
    if missing:
        errors.append(f"missing source inputs: {', '.join(missing)}")

    contains_marker_values: list[bool] = []
    within_max_len_values: list[bool] = []
    dangerous_values: list[bool] = []
    for name, source in sources.items():
        value = inputs.get(name)
        if not isinstance(value, str):
            errors.append(f"input {name} must be a string")
            contains_marker_values.append(False)
            within_max_len_values.append(False)
            dangerous_values.append(False)
            continue
        max_len = _source_max_len(source)
        within = len(value) <= max_len
        contains_dangerous = (
            "\n" in value
            or "\r" in value
            or any(char in value for char in DANGEROUS_CHARS)
        )
        contains_marker = marker in value if marker else True
        contains_marker_values.append(contains_marker)
        within_max_len_values.append(within)
        dangerous_values.append(contains_dangerous)
        if not within:
            errors.append(f"input {name} exceeds max_len {max_len}")
        if "\n" in value or "\r" in value:
            errors.append(f"input {name} contains newline")
        if any(char in value for char in DANGEROUS_CHARS):
            errors.append(f"input {name} contains disallowed shell character")
        if marker and not contains_marker:
            errors.append(f"input {name} does not contain benign marker")

    checks["contains_benign_marker"] = all(contains_marker_values) if sources else False
    checks["within_max_len"] = all(within_max_len_values) if sources else False
    checks["contains_dangerous_chars"] = any(dangerous_values)

    safety = candidate.get("safety")
    checks["weaponized_false"] = isinstance(safety, dict) and safety.get("weaponized") is False
    if not isinstance(safety, dict):
        errors.append("missing safety object")
    elif safety.get("benign") is not True or safety.get("weaponized") is not False:
        errors.append("safety must be benign=true and weaponized=false")

    return {
        "candidate_id": candidate_id or None,
        "validation_passed": not errors,
        "errors": errors,
        "checks": checks,
    }


def _check_duplicate_candidate_ids(candidate_set: dict[str, Any]) -> list[str]:
    candidates = candidate_set.get("candidates")
    if not isinstance(candidates, list):
        return []
    seen_ids: set[str] = set()
    duplicates: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        candidate_id = str(candidate.get("candidate_id") or "")
        if candidate_id and candidate_id in seen_ids:
            duplicates.append(candidate_id)
        if candidate_id:
            seen_ids.add(candidate_id)
    return duplicates


def write_candidate_set(candidate_set: dict[str, Any], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(candidate_set, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate benign candidates with an API-based LLM planner interface.",
    )
    parser.add_argument("--task", help="dangerous_path_task JSON path.")
    parser.add_argument("--out", help="output candidate set JSON path.")
    parser.add_argument(
        "--ping",
        action="store_true",
        help="send a minimal OpenAI-compatible chat/completions ping and validate {'ok': true}.",
    )
    parser.add_argument(
        "--offline-example",
        "--mock",
        action="store_true",
        help="do not call a remote API; emit deterministic LLM-style benign candidates.",
    )
    parser.add_argument(
        "--debug-response",
        action="store_true",
        help="write redacted provider diagnostics to reports/llm_debug/last_response.redacted.json.",
    )
    args = parser.parse_args(argv)

    try:
        if args.ping:
            parsed = ping_provider(debug_response=args.debug_response)
            print(f"LLM ping ok: {json.dumps(parsed, sort_keys=True)}")
            return 0
        if not args.task or not args.out:
            parser.error("--task and --out are required unless --ping is used")
        candidate_set = generate_candidate_set_for_task_path(
            args.task,
            offline_example=args.offline_example,
            debug_response=args.debug_response,
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
    candidate_set = {
        "planner": {
            "name": OFFLINE_PLANNER_NAME,
            "version": PLANNER_VERSION,
            "provider": "offline_example",
            "base_url_host": None,
            "model": "deterministic",
            "max_tokens": None,
            "temperature": 0.0,
            "mode": PLANNER_MODE,
        },
        "task_id": str(task.get("task_id") or "unknown_task"),
        "candidates": candidates,
    }
    candidate_set["validation"] = build_candidate_validation_report(candidate_set, task)
    return candidate_set


def _fit(value: str, marker: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    if marker and len(marker) <= max_len:
        return marker
    raise ApiPlannerError("benign marker is longer than source max_len")


def _extract_json_text(content: str) -> str:
    text = content.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if fence:
        return fence.group(1).strip()
    if text.startswith("{") or text.startswith("["):
        return text
    obj = _extract_first_json_object(text)
    if obj is not None:
        return obj
    return text


def _extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


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


def _env_int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ApiPlannerError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ApiPlannerError(f"{name} must be positive")
    return value


def _env_float(env: dict[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ApiPlannerError(f"{name} must be a number") from exc


def _base_url_host(base_url: str | None) -> str | None:
    if not base_url:
        return None
    parsed = urlparse(base_url)
    return parsed.netloc or parsed.path or None


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
