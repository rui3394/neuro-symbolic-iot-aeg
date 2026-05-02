from __future__ import annotations

import os

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.planner.api_planner import (
    ApiPlannerError,
    generate_candidate_set,
    generate_candidate_set_for_task_path,
    parse_candidate_response,
    validate_candidate_set,
)
from ns_aeg.planner.providers import OpenAICompatibleConfig, call_openai_compatible_chat


def test_api_planner_offline_example_generates_llm_style_candidates() -> None:
    candidate_set = generate_candidate_set_for_task_path(
        "examples/dangerous_tasks/toy_01_task.example.json",
        offline_example=True,
    )

    assert candidate_set["planner"]["name"] == "api_llm_planner_offline"
    assert candidate_set["planner"]["provider"] == "offline_example"
    assert candidate_set["task_id"] == "dangerous_path:toy_01_basic_cmd:toy_01"
    assert len(candidate_set["candidates"]) >= 3
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
    )
    validate_candidate_set(candidate_set, task)

    assert candidate_set["planner"]["name"] == "api_llm_planner"
    assert candidate_set["planner"]["model"] == "test-model"


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
        max_tokens=50,
    )

    assert content

