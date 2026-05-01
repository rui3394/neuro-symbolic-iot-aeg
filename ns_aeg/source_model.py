from __future__ import annotations

from dataclasses import dataclass
import re

from ns_aeg.config import TargetConfig


DEFAULT_MAX_LEN = 64


@dataclass(frozen=True)
class SourceSpec:
    name: str
    source_type: str
    max_len: int
    symbolic_name: str
    runtime_binding: str
    required: bool


@dataclass(frozen=True)
class SourceModel:
    sources: list[SourceSpec]


def build_source_model(config: TargetConfig) -> SourceModel:
    sources: list[SourceSpec] = []
    for index, (name, spec) in enumerate(_iter_source_params(config), start=1):
        sources.append(
            SourceSpec(
                name=name,
                source_type="http_param",
                max_len=_max_len(spec),
                symbolic_name=f"sym_{_sanitize_symbol_part(name)}",
                runtime_binding=f"argv[{index}]",
                required=True,
            )
        )

    return SourceModel(sources=sources)


def _iter_source_params(config: TargetConfig):
    for name, spec in config.params.items():
        if isinstance(spec, dict) and spec.get("source") is True:
            if not isinstance(name, str) or not name:
                raise ValueError("Source parameter name must be non-empty.")
            yield name, spec


def _max_len(spec: dict) -> int:
    value = spec.get("max_len")
    if value is None:
        return DEFAULT_MAX_LEN
    return int(value)


def _sanitize_symbol_part(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)
