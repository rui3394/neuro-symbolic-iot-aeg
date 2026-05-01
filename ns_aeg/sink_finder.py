from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess


@dataclass(frozen=True)
class SinkMatch:
    name: str
    found: bool
    symbol_name: str | None
    imported: bool
    plt_address: str | None
    source: str | None
    reason: str | None


@dataclass(frozen=True)
class SinkReport:
    binary_path: str
    configured_sinks: list[str]
    matches: list[SinkMatch]


def find_sinks(binary_path: str, configured_sinks: list[str]) -> SinkReport:
    if not configured_sinks:
        return SinkReport(
            binary_path=binary_path,
            configured_sinks=[],
            matches=[],
        )

    symbols, readelf_error = _read_symbols(binary_path)
    plt_stubs, objdump_error = _read_plt_stubs(binary_path)

    matches = [
        _match_sink(sink, symbols, plt_stubs, readelf_error, objdump_error)
        for sink in configured_sinks
    ]
    return SinkReport(
        binary_path=binary_path,
        configured_sinks=list(configured_sinks),
        matches=matches,
    )


def _match_sink(
    sink: str,
    symbols: dict[str, bool],
    plt_stubs: dict[str, str],
    readelf_error: str | None,
    objdump_error: str | None,
) -> SinkMatch:
    symbol_found = sink in symbols
    plt_address = plt_stubs.get(sink)

    if symbol_found or plt_address is not None:
        return SinkMatch(
            name=sink,
            found=True,
            symbol_name=sink if symbol_found else f"{sink}@plt",
            imported=symbols.get(sink, False),
            plt_address=plt_address,
            source=_source(symbol_found, plt_address is not None),
            reason=None,
        )

    reason_parts = []
    if readelf_error is not None:
        reason_parts.append(readelf_error)
    if objdump_error is not None:
        reason_parts.append(objdump_error)
    reason_parts.append("sink symbol/PLT not found")

    return SinkMatch(
        name=sink,
        found=False,
        symbol_name=None,
        imported=False,
        plt_address=None,
        source=None,
        reason="; ".join(reason_parts),
    )


def _source(symbol_found: bool, plt_found: bool) -> str:
    if symbol_found and plt_found:
        return "readelf+objdump"
    if symbol_found:
        return "readelf"
    return "objdump"


def _read_symbols(binary_path: str) -> tuple[dict[str, bool], str | None]:
    result, error = _run_command(["readelf", "-Ws", binary_path])
    if error is not None:
        return {}, error
    assert result is not None
    return _parse_readelf_symbols(result.stdout), None


def _read_plt_stubs(binary_path: str) -> tuple[dict[str, str], str | None]:
    result, error = _run_command(["objdump", "-d", binary_path])
    if error is not None:
        return {}, error
    assert result is not None
    return _parse_objdump_plt(result.stdout), None


def _run_command(args: list[str]) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, OSError) as exc:
        return None, f"{args[0]} failed: {exc}"

    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        return None, f"{args[0]} failed: {detail}"

    return result, None


def _parse_readelf_symbols(readelf_output: str) -> dict[str, bool]:
    symbols: dict[str, bool] = {}
    for line in readelf_output.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].endswith(":"):
            continue

        ndx = parts[6]
        symbol = _normalize_symbol_name(parts[7].split()[0])
        if not symbol:
            continue

        imported = ndx == "UND"
        symbols[symbol] = symbols.get(symbol, False) or imported

    return symbols


def _parse_objdump_plt(objdump_output: str) -> dict[str, str]:
    stubs: dict[str, str] = {}
    for line in objdump_output.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:", line)
        if match is None:
            continue

        symbol = _normalize_symbol_name(match.group(2))
        if not symbol:
            continue

        address = f"0x{int(match.group(1), 16):x}"
        stubs[symbol] = address

    return stubs


def _normalize_symbol_name(symbol: str) -> str:
    if symbol.endswith("@plt"):
        symbol = symbol[: -len("@plt")]
    return symbol.split("@", 1)[0]
