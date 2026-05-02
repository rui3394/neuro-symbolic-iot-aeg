from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from typing import Any


class ProviderError(ValueError):
    """Raised when an LLM provider request fails safely."""


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    base_url: str
    api_key: str
    model: str
    timeout_seconds: int = 60


def call_openai_compatible_chat(
    *,
    config: OpenAICompatibleConfig,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    max_tokens: int = 8192,
    response_format: str | None = None,
    debug_response: bool = False,
    debug_path: str = "reports/llm_debug/last_response.redacted.json",
) -> str:
    if not config.base_url:
        raise ProviderError("NS_AEG_LLM_BASE_URL is required for openai_compatible provider")
    if not config.api_key:
        raise ProviderError("NS_AEG_LLM_API_KEY is required for openai_compatible provider")
    if not config.model:
        raise ProviderError("NS_AEG_LLM_MODEL is required for openai_compatible provider")

    endpoint = config.base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        build_openai_compatible_body(
            model=config.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            status_code = getattr(response, "status", None) or getattr(response, "code", None)
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        diagnostic = exc.read().decode("utf-8", errors="replace")[:500]
        raise ProviderError(
            f"openai_compatible provider returned HTTP {exc.code}: {_redact(diagnostic)}"
        ) from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"openai_compatible provider request failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ProviderError("openai_compatible provider request timed out") from exc

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ProviderError("openai_compatible provider returned non-JSON response") from exc

    debug_enabled = debug_response or os.environ.get("NS_AEG_LLM_DEBUG") == "1"
    if debug_enabled:
        write_redacted_debug_response(data, debug_path=debug_path, status_code=status_code)

    return extract_chat_content(data)


def build_openai_compatible_body(
    *,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
    response_format: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if response_format == "json_object":
        body["response_format"] = {"type": "json_object"}
    return body


def extract_chat_content(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("openai_compatible response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("openai_compatible response choice is malformed")
    finish_reason = first.get("finish_reason")
    message = first.get("message")
    if isinstance(message, dict):
        content = _content_to_text(message.get("content"))
        reasoning = message.get("reasoning_content")
        reasoning_len = len(reasoning) if isinstance(reasoning, str) else 0
        if finish_reason == "length":
            raise ProviderError(
                "openai_compatible response was truncated "
                f"(finish_reason=length, content_len={len(content)}, "
                f"reasoning_content_present={reasoning_len > 0}, "
                f"reasoning_content_len={reasoning_len}); increase NS_AEG_LLM_MAX_TOKENS"
            )
        if content.strip():
            return content

        fallback_text = _content_to_text(first.get("text"))
        if fallback_text.strip():
            return fallback_text

        message_keys = sorted(str(key) for key in message)
        raise ProviderError(
            "openai_compatible response message has empty content "
            f"(reasoning_content_present={reasoning_len > 0}, "
            f"reasoning_content_len={reasoning_len}, message_keys={message_keys})"
        )

    fallback_text = _content_to_text(first.get("text"))
    if finish_reason == "length":
        raise ProviderError(
            "openai_compatible response was truncated "
            f"(finish_reason=length, content_len={len(fallback_text)}); "
            "increase NS_AEG_LLM_MAX_TOKENS"
        )
    if fallback_text.strip():
        return fallback_text
    raise ProviderError("openai_compatible response choice has no message content or text")


def write_redacted_debug_response(
    data: dict[str, Any],
    *,
    debug_path: str,
    status_code: int | None,
) -> None:
    choices = data.get("choices") if isinstance(data.get("choices"), list) else []
    first = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = _content_to_text(message.get("content")) if message else _content_to_text(first.get("text"))
    reasoning = message.get("reasoning_content") if message else None
    diagnostic = {
        "status_code": status_code,
        "response_keys": sorted(str(key) for key in data),
        "choices_count": len(choices),
        "finish_reason": first.get("finish_reason"),
        "choice_keys": sorted(str(key) for key in first) if first else [],
        "message_keys": sorted(str(key) for key in message) if message else [],
        "content_len": len(content),
        "content_preview": _redact(content[:500]),
        "reasoning_content_len": len(reasoning) if isinstance(reasoning, str) else 0,
        "reasoning_content_present": isinstance(reasoning, str) and bool(reasoning),
    }
    output = Path(debug_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(diagnostic, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts).strip()
    return ""


def _redact(value: str) -> str:
    # Keep diagnostics useful without echoing bearer tokens or secret-looking fields.
    return value.replace("Bearer ", "Bearer <redacted>")[:500]
