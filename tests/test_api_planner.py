from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.request

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.planner.api_planner import (
    ApiPlannerError,
    build_candidate_validation_report,
    generate_candidate_set,
    generate_candidate_set_for_task_path,
    parse_candidate_response,
    ping_provider,
    validate_candidate_set,
)
from ns_aeg.planner.providers import (
    OpenAICompatibleConfig,
    ProviderError,
    build_openai_compatible_body,
    call_openai_compatible_chat,
    extract_chat_content,
    write_redacted_debug_response,
)


def test_api_planner_offline_example_generates_llm_style_candidates() -> None:
    candidate_set = generate_candidate_set_for_task_path(
        "examples/dangerous_tasks/toy_01_task.example.json",
        offline_example=True,
    )

    assert candidate_set["planner"]["name"] == "api_llm_planner_offline"
    assert candidate_set["planner"]["provider"] == "offline_example"
    assert candidate_set["planner"]["model"] == "deterministic"
    assert candidate_set["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert len(candidate_set["candidates"]) >= 3
    assert candidate_set["validation"]["validation_passed_count"] == len(candidate_set["candidates"])
    assert all(candidate["safety"]["weaponized"] is False for candidate in candidate_set["candidates"])


def test_api_planner_requires_env_or_offline_example() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")

    with pytest.raises(ApiPlannerError, match="offline by default"):
        generate_candidate_set(task, env={})


def test_api_planner_validator_rejects_dangerous_characters() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    candidate_set = {
        "planner": {"name": "api_llm_planner", "version": "0.1"},
        "task_id": task["task_id"],
        "candidates": [
            {
                "candidate_id": "bad",
                "strategy": "bad",
                "inputs": {"ip": "127.0.0.1;__NS_AEG_MARKER__"},
                "assumptions": [],
                "safety": {"benign": True, "weaponized": False},
            }
        ],
    }

    with pytest.raises(ApiPlannerError, match="disallowed shell character"):
        validate_candidate_set(candidate_set, task)


def test_api_planner_parse_response_wraps_candidate_set_metadata() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    content = """
    {
      "candidates": [
        {
          "candidate_id": "llm_001",
          "strategy": "marker",
          "inputs": {"ip": "__NS_AEG_MARKER__"},
          "assumptions": ["benign marker"],
          "safety": {"benign": true, "weaponized": false}
        }
      ]
    }
    """

    candidate_set = parse_candidate_response(
        content,
        task,
        provider="openai_compatible",
        model="test-model",
        base_url="https://token-plan-cn.xiaomimimo.com/v1",
        max_tokens=12000,
        temperature=0.0,
    )
    validate_candidate_set(candidate_set, task)

    assert candidate_set["planner"]["name"] == "api_llm_planner"
    assert candidate_set["planner"]["model"] == "test-model"
    assert candidate_set["planner"]["base_url_host"] == "token-plan-cn.xiaomimimo.com"
    assert candidate_set["planner"]["max_tokens"] == 12000
    assert candidate_set["validation"]["validation_failed_count"] == 0


def test_api_planner_validation_report_records_failed_checks() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    candidate_set = {
        "planner": {"name": "api_llm_planner"},
        "task_id": task["task_id"],
        "candidates": [
            {
                "candidate_id": "bad",
                "strategy": "bad",
                "inputs": {"ip": "1.2.3.4;BAD"},
                "assumptions": [],
                "safety": {"benign": True, "weaponized": True},
            }
        ],
    }

    report = build_candidate_validation_report(candidate_set, task)

    assert report["candidate_count"] == 1
    assert report["validation_passed_count"] == 0
    assert report["validation_failed_count"] == 1
    checks = report["candidates"][0]["checks"]
    assert checks["covers_all_sources"] is True
    assert checks["contains_benign_marker"] is False
    assert checks["contains_dangerous_chars"] is True
    assert checks["weaponized_false"] is False


def test_api_planner_parse_response_accepts_markdown_json_fence() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    content = """```json
    {"candidates":[{"candidate_id":"llm_001","strategy":"marker","inputs":{"ip":"__NS_AEG_MARKER__"},"assumptions":["benign"],"safety":{"benign":true,"weaponized":false}}]}
    ```"""

    candidate_set = parse_candidate_response(
        content,
        task,
        provider="openai_compatible",
        model="test-model",
    )

    assert candidate_set["candidates"][0]["candidate_id"] == "llm_001"


def test_api_planner_parse_response_extracts_first_json_object_from_text() -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    content = (
        "Here is the JSON:\n"
        '{"candidates":[{"candidate_id":"llm_001","strategy":"marker",'
        '"inputs":{"ip":"__NS_AEG_MARKER__"},"assumptions":["benign"],'
        '"safety":{"benign":true,"weaponized":false}}]}\nDone.'
    )

    candidate_set = parse_candidate_response(
        content,
        task,
        provider="openai_compatible",
        model="test-model",
    )

    assert candidate_set["candidates"][0]["inputs"]["ip"] == "__NS_AEG_MARKER__"


def test_provider_extracts_normal_string_content() -> None:
    content = extract_chat_content(
        {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}
    )

    assert content == '{"ok": true}'


def test_provider_extracts_list_content_text_fields() -> None:
    content = extract_chat_content(
        {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": '{"ok": '},
                            {"type": "text", "text": "true}"},
                        ]
                    }
                }
            ]
        }
    )

    assert content == '{"ok": true}'


def test_provider_empty_content_with_reasoning_has_clear_error() -> None:
    with pytest.raises(ProviderError, match="reasoning_content_present=True"):
        extract_chat_content(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": "I should return JSON.",
                        }
                    }
                ]
            }
        )


def test_provider_finish_reason_length_reports_truncation() -> None:
    with pytest.raises(ProviderError, match="response was truncated"):
        extract_chat_content(
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {
                            "content": '{"candidates": [',
                            "reasoning_content": "long reasoning",
                        },
                    }
                ]
            }
        )


def test_provider_falls_back_to_choice_text() -> None:
    content = extract_chat_content({"choices": [{"text": '{"ok": true}'}]})

    assert content == '{"ok": true}'


def test_response_format_is_not_sent_by_default() -> None:
    body = build_openai_compatible_body(
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=2048,
    )

    assert set(body) == {"model", "messages", "temperature", "max_tokens"}


def test_response_format_is_optional_json_object() -> None:
    body = build_openai_compatible_body(
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        temperature=0.0,
        max_tokens=2048,
        response_format="json_object",
    )

    assert body["response_format"] == {"type": "json_object"}


def test_debug_redaction_does_not_include_api_key(tmp_path: Path) -> None:
    output = tmp_path / "last_response.redacted.json"

    write_redacted_debug_response(
        {
            "id": "chatcmpl-test",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": '{"ok": true}',
                        "reasoning_content": "internal reasoning",
                    },
                }
            ],
        },
        debug_path=str(output),
        status_code=200,
    )

    text = output.read_text(encoding="utf-8")
    assert "secret-token" not in text
    assert "Authorization" not in text
    data = json.loads(text)
    assert data["content_len"] == len('{"ok": true}')
    assert data["reasoning_content_present"] is True


def test_call_openai_compatible_chat_writes_debug_and_omits_response_format_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}
            ).encode("utf-8")

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> FakeResponse:
        captured["body"] = json.loads(request.data.decode("utf-8"))  # type: ignore[union-attr]
        captured["auth"] = request.headers.get("Authorization")
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    debug_path = tmp_path / "debug.json"

    content = call_openai_compatible_chat(
        config=OpenAICompatibleConfig(
            base_url="https://example.invalid/v1",
            api_key="secret-token",
            model="mimo-v2.5-pro",
            timeout_seconds=7,
        ),
        messages=[{"role": "user", "content": 'Return {"ok": true}'}],
        debug_response=True,
        debug_path=str(debug_path),
    )

    assert content == '{"ok": true}'
    assert "response_format" not in captured["body"]
    assert captured["timeout"] == 7
    assert "secret-token" not in debug_path.read_text(encoding="utf-8")


def test_ping_provider_parses_ok_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_call_openai_compatible_chat(**kwargs: object) -> str:
        return '{"ok": true}'

    monkeypatch.setattr(
        "ns_aeg.planner.api_planner.call_openai_compatible_chat",
        fake_call_openai_compatible_chat,
    )

    assert ping_provider(
        env={
            "NS_AEG_LLM_BASE_URL": "https://example.invalid/v1",
            "NS_AEG_LLM_API_KEY": "secret-token",
            "NS_AEG_LLM_MODEL": "mimo-v2.5-pro",
        }
    ) == {"ok": True}


def test_api_planner_uses_env_max_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    captured: dict[str, object] = {}

    def fake_call_openai_compatible_chat(**kwargs: object) -> str:
        captured["max_tokens"] = kwargs["max_tokens"]
        return (
            '{"candidates":[{"candidate_id":"llm_001","strategy":"marker",'
            '"inputs":{"ip":"__NS_AEG_MARKER__"},"assumptions":["benign"],'
            '"safety":{"benign":true,"weaponized":false}}]}'
        )

    monkeypatch.setattr(
        "ns_aeg.planner.api_planner.call_openai_compatible_chat",
        fake_call_openai_compatible_chat,
    )

    generate_candidate_set(
        task,
        env={
            "NS_AEG_LLM_BASE_URL": "https://example.invalid/v1",
            "NS_AEG_LLM_API_KEY": "secret-token",
            "NS_AEG_LLM_MODEL": "mimo-v2.5-pro",
            "NS_AEG_LLM_MAX_TOKENS": "9000",
        },
    )

    assert captured["max_tokens"] == 9000


def test_api_planner_live_openai_compatible_opt_in() -> None:
    if os.environ.get("NS_AEG_RUN_LLM_TESTS") != "1":
        pytest.skip("live LLM tests are opt-in")
    required = [
        "NS_AEG_LLM_BASE_URL",
        "NS_AEG_LLM_API_KEY",
        "NS_AEG_LLM_MODEL",
    ]
    if any(not os.environ.get(name) for name in required):
        pytest.skip("live LLM test requires base URL, API key, and model")

    content = call_openai_compatible_chat(
        config=OpenAICompatibleConfig(
            base_url=os.environ["NS_AEG_LLM_BASE_URL"],
            api_key=os.environ["NS_AEG_LLM_API_KEY"],
            model=os.environ["NS_AEG_LLM_MODEL"],
            timeout_seconds=60,
        ),
        messages=[
            {"role": "system", "content": "Output JSON only."},
            {"role": "user", "content": "Return {\"ok\": true}."},
        ],
        max_tokens=512,
    )

    assert content
