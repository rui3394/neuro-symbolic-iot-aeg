from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AngrLoadInfo:
    binary_path: str
    loaded: bool
    arch: str | None
    bits: int | None
    entry: str | None
    base_addr: str | None
    main_object: str | None
    plt: dict[str, str]
    missing_plt: list[str]
    error: str | None


def load_with_angr(binary_path: str, sinks: list[str]) -> AngrLoadInfo:
    if not Path(binary_path).exists():
        return _failed(binary_path, sinks, f"binary does not exist: {binary_path}")

    try:
        import angr
    except ImportError:
        return _failed(binary_path, sinks, "angr is not installed")

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
    except Exception as exc:
        return _failed(binary_path, sinks, f"failed to load binary with angr: {exc}")

    main_object = getattr(project.loader, "main_object", None)
    plt = _collect_plt(main_object, sinks)

    return AngrLoadInfo(
        binary_path=binary_path,
        loaded=True,
        arch=getattr(project.arch, "name", None),
        bits=getattr(project.arch, "bits", None),
        entry=_to_hex(getattr(project, "entry", None)),
        base_addr=_to_hex(_get_first_attr(main_object, ["mapped_base", "min_addr"])),
        main_object=_main_object_name(main_object),
        plt=plt,
        missing_plt=[sink for sink in sinks if sink not in plt],
        error=None,
    )


def _failed(binary_path: str, sinks: list[str], error: str) -> AngrLoadInfo:
    return AngrLoadInfo(
        binary_path=binary_path,
        loaded=False,
        arch=None,
        bits=None,
        entry=None,
        base_addr=None,
        main_object=None,
        plt={},
        missing_plt=list(sinks),
        error=error,
    )


def _collect_plt(main_object: Any, sinks: list[str]) -> dict[str, str]:
    raw_plt = getattr(main_object, "plt", {}) if main_object is not None else {}
    if not isinstance(raw_plt, dict):
        return {}

    normalized_plt: dict[str, str] = {}
    for name, address in raw_plt.items():
        normalized_name = _normalize_symbol_name(str(name))
        if normalized_name:
            normalized_plt[normalized_name] = _to_hex(address) or ""

    return {
        sink: normalized_plt[sink]
        for sink in sinks
        if sink in normalized_plt and normalized_plt[sink]
    }


def _normalize_symbol_name(symbol: str) -> str:
    if symbol.endswith("@plt"):
        symbol = symbol[: -len("@plt")]
    return symbol.split("@", 1)[0]


def _get_first_attr(obj: Any, names: list[str]) -> Any:
    if obj is None:
        return None
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _main_object_name(main_object: Any) -> str | None:
    if main_object is None:
        return None

    for attr in ("binary_basename", "provides"):
        value = getattr(main_object, attr, None)
        if value:
            return str(value)

    binary = getattr(main_object, "binary", None)
    if binary:
        return Path(str(binary)).name

    return str(main_object)


def _to_hex(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return f"0x{int(value):x}"
    except (TypeError, ValueError):
        return None
