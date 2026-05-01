from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess


ELF_MAGIC = b"\x7fELF"


@dataclass(frozen=True)
class BinaryInfo:
    path: str
    exists: bool
    is_elf: bool
    elf_class: str | None
    endianness: str | None
    machine: str | None
    found_sinks: list[str]
    missing_sinks: list[str]


def inspect_binary(path: str, sinks: list[str]) -> BinaryInfo:
    binary_path = Path(path)
    if not binary_path.exists():
        return _info(path, exists=False, missing_sinks=sinks)

    with binary_path.open("rb") as f:
        header = f.read(20)
    if not header.startswith(ELF_MAGIC):
        return _info(path, exists=True, missing_sinks=sinks)

    elf_class = _parse_elf_class(header[4] if len(header) > 4 else None)
    endianness = _parse_endianness(header[5] if len(header) > 5 else None)
    machine = _parse_machine(header[18:20], endianness)
    found_sinks = _find_sink_symbols(path, sinks)
    missing_sinks = [sink for sink in sinks if sink not in found_sinks]

    return BinaryInfo(
        path=path,
        exists=True,
        is_elf=True,
        elf_class=elf_class,
        endianness=endianness,
        machine=machine,
        found_sinks=found_sinks,
        missing_sinks=missing_sinks,
    )


def _info(
    path: str,
    *,
    exists: bool,
    missing_sinks: list[str],
) -> BinaryInfo:
    return BinaryInfo(
        path=path,
        exists=exists,
        is_elf=False,
        elf_class=None,
        endianness=None,
        machine=None,
        found_sinks=[],
        missing_sinks=list(missing_sinks),
    )


def _parse_elf_class(value: int | None) -> str | None:
    if value == 1:
        return "ELF32"
    if value == 2:
        return "ELF64"
    if value is None:
        return None
    return "unknown"


def _parse_endianness(value: int | None) -> str | None:
    if value == 1:
        return "little"
    if value == 2:
        return "big"
    if value is None:
        return None
    return "unknown"


def _parse_machine(raw: bytes, endianness: str | None) -> str | None:
    if len(raw) < 2:
        return None

    byteorder = "big" if endianness == "big" else "little"
    value = int.from_bytes(raw, byteorder=byteorder)
    machines = {
        0x03: "x86",
        0x3E: "x86-64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
    }
    return machines.get(value, f"unknown(0x{value:x})")


def _find_sink_symbols(path: str, sinks: list[str]) -> list[str]:
    if not sinks:
        return []

    try:
        result = subprocess.run(
            ["readelf", "-Ws", path],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, OSError):
        return []

    if result.returncode != 0:
        return []

    symbols = _extract_symbol_names(result.stdout)
    return [sink for sink in sinks if sink in symbols]


def _extract_symbol_names(readelf_output: str) -> set[str]:
    symbols: set[str] = set()
    for line in readelf_output.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].endswith(":"):
            continue

        symbol = parts[7].split()[0]
        symbol = symbol.split("@", 1)[0]
        if symbol:
            symbols.add(symbol)

    return symbols
