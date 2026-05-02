from __future__ import annotations

from dataclasses import dataclass
import json
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
    max_tokens: int = 1200,
) -> str:
    if not config.base_url:
        raise ProviderError("NS_AEG_LLM_BASE_URL is required for openai_compatible provider")
    if not config.api_key:
        raise ProviderError("NS_AEG_LLM_API_KEY is required for openai_compatible provider")
    if not config.model:
        raise ProviderError("NS_AEG_LLM_MODEL is required for openai_compatible provider")

    endpoint = config.base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
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

    return _extract_chat_content(data)


def _extract_chat_content(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("openai_compatible response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("openai_compatible response choice is malformed")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ProviderError("openai_compatible response choice has no message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("openai_compatible response message has empty content")
    return content


def _redact(value: str) -> str:
    # Keep diagnostics useful without echoing bearer tokens or secret-looking fields.
    return value.replace("Bearer ", "Bearer <redacted>")[:500]
