from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class SourceParam:
    name: str
    max_len: int | None = None


@dataclass(frozen=True)
class TargetConfig:
    name: str
    binary: str
    arch: str
    http_method: str
    http_path: str
    params: dict[str, Any]
    source_params: list[SourceParam]
    vulnerability_type: str
    sinks: list[str]
    dry_run: bool
    sanitizers: list[dict[str, Any]] = field(default_factory=list)


def load_target_config(path: str) -> TargetConfig:
    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as f:
        raw_config = yaml.safe_load(f)

    validate_config(raw_config)
    assert isinstance(raw_config, dict)

    params = raw_config["http"].get("params") or {}
    source_params = _extract_source_params(params)

    return TargetConfig(
        name=raw_config["name"],
        binary=raw_config["binary"],
        arch=raw_config.get("arch", "auto"),
        http_method=raw_config["http"]["method"],
        http_path=raw_config["http"]["path"],
        params=params,
        source_params=source_params,
        vulnerability_type=raw_config["analysis"]["vulnerability_type"],
        sinks=list(raw_config["analysis"]["sinks"]),
        sanitizers=_extract_sanitizers(raw_config["analysis"].get("sanitizers")),
        dry_run=bool((raw_config.get("mode") or {}).get("dry_run", False)),
    )


def validate_config(config: Any) -> None:
    if not isinstance(config, dict):
        raise ValueError("Target config must be a YAML mapping.")

    _require(config, "name")
    _require(config, "binary")
    _require(config, "http")
    _require(config, "analysis")

    if not isinstance(config["http"], dict):
        raise ValueError("Field 'http' must be a mapping.")
    _require(config["http"], "method", "http.method")
    _require(config["http"], "path", "http.path")

    params = config["http"].get("params", {})
    if params is not None and not isinstance(params, dict):
        raise ValueError("Field 'http.params' must be a mapping when provided.")

    if not isinstance(config["analysis"], dict):
        raise ValueError("Field 'analysis' must be a mapping.")
    _require(config["analysis"], "vulnerability_type", "analysis.vulnerability_type")
    _require(config["analysis"], "sinks", "analysis.sinks")

    sinks = config["analysis"]["sinks"]
    if not isinstance(sinks, list) or not sinks:
        raise ValueError("Field 'analysis.sinks' must be a non-empty list.")
    if not all(isinstance(sink, str) and sink for sink in sinks):
        raise ValueError("Field 'analysis.sinks' must contain non-empty strings.")

    sanitizers = config["analysis"].get("sanitizers", [])
    if sanitizers is not None and not isinstance(sanitizers, list):
        raise ValueError("Field 'analysis.sanitizers' must be a list when provided.")


def _extract_source_params(params: dict[str, Any]) -> list[SourceParam]:
    source_params: list[SourceParam] = []
    for name, spec in params.items():
        if isinstance(spec, dict) and spec.get("source") is True:
            source_params.append(SourceParam(name=name, max_len=spec.get("max_len")))
    return source_params


def _extract_sanitizers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _require(config: dict[str, Any], key: str, display_name: str | None = None) -> None:
    if key not in config or config[key] in (None, ""):
        raise ValueError(f"Missing required field: {display_name or key}")
