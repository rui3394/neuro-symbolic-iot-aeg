from pathlib import Path
from types import SimpleNamespace

from ns_aeg.binary_inspector import inspect_binary


def test_missing_file_returns_exists_false(tmp_path: Path) -> None:
    info = inspect_binary(str(tmp_path / "missing"), ["system"])

    assert info.exists is False
    assert info.is_elf is False
    assert info.found_sinks == []
    assert info.missing_sinks == ["system"]


def test_non_elf_file_is_not_elf(tmp_path: Path) -> None:
    binary = tmp_path / "not_elf"
    binary.write_text("plain text", encoding="utf-8")

    info = inspect_binary(str(binary), ["system"])

    assert info.exists is True
    assert info.is_elf is False
    assert info.elf_class is None
    assert info.endianness is None
    assert info.machine is None


def test_minimal_elf64_little_x86_64_header(tmp_path: Path) -> None:
    binary = tmp_path / "minimal_elf"
    header = bytearray(20)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[18:20] = (0x3E).to_bytes(2, byteorder="little")
    binary.write_bytes(header)

    info = inspect_binary(str(binary), ["system"])

    assert info.exists is True
    assert info.is_elf is True
    assert info.elf_class == "ELF64"
    assert info.endianness == "little"
    assert info.machine == "x86-64"


def test_readelf_failure_does_not_raise(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "minimal_elf"
    header = bytearray(20)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[18:20] = (0x3E).to_bytes(2, byteorder="little")
    binary.write_bytes(header)

    def fail_readelf(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("ns_aeg.binary_inspector.subprocess.run", fail_readelf)

    info = inspect_binary(str(binary), ["system", "snprintf"])

    assert info.found_sinks == []
    assert info.missing_sinks == ["system", "snprintf"]


def test_sink_matching_uses_symbol_names_not_substrings(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "minimal_elf"
    header = bytearray(20)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[18:20] = (0x3E).to_bytes(2, byteorder="little")
    binary.write_bytes(header)

    readelf_output = """
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND systemctl
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND snprintf@GLIBC_2.2.5
"""

    def fake_readelf(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=readelf_output)

    monkeypatch.setattr("ns_aeg.binary_inspector.subprocess.run", fake_readelf)

    info = inspect_binary(str(binary), ["system", "snprintf"])

    assert info.found_sinks == ["snprintf"]
    assert info.missing_sinks == ["system"]
