from types import SimpleNamespace

from ns_aeg.sink_finder import find_sinks


def test_empty_configured_sinks_returns_empty_matches() -> None:
    report = find_sinks("dummy", [])

    assert report.binary_path == "dummy"
    assert report.configured_sinks == []
    assert report.matches == []


def test_readelf_and_objdump_failure_does_not_raise(monkeypatch) -> None:
    def fail_command(*args, **kwargs):
        raise FileNotFoundError("missing tool")

    monkeypatch.setattr("ns_aeg.sink_finder.subprocess.run", fail_command)

    report = find_sinks("dummy", ["system"])

    assert len(report.matches) == 1
    assert report.matches[0].name == "system"
    assert report.matches[0].found is False
    assert "readelf failed" in (report.matches[0].reason or "")
    assert "objdump failed" in (report.matches[0].reason or "")


def test_plt_line_extracts_address(monkeypatch) -> None:
    def fake_command(args, **kwargs):
        if args[0] == "readelf":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="0000000000401050 <system@plt>:\n",
            stderr="",
        )

    monkeypatch.setattr("ns_aeg.sink_finder.subprocess.run", fake_command)

    report = find_sinks("dummy", ["system"])
    match = report.matches[0]

    assert match.found is True
    assert match.symbol_name == "system@plt"
    assert match.imported is False
    assert match.plt_address == "0x401050"


def test_sink_matching_does_not_match_substrings(monkeypatch) -> None:
    readelf_output = """
Symbol table '.dynsym' contains 1 entry:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mysystem_wrapper
"""

    def fake_command(args, **kwargs):
        if args[0] == "readelf":
            return SimpleNamespace(returncode=0, stdout=readelf_output, stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="0000000000401050 <mysystem_wrapper@plt>:\n",
            stderr="",
        )

    monkeypatch.setattr("ns_aeg.sink_finder.subprocess.run", fake_command)

    report = find_sinks("dummy", ["system"])

    assert report.matches[0].found is False


def test_versioned_symbol_matches_base_sink(monkeypatch) -> None:
    readelf_output = """
Symbol table '.dynsym' contains 1 entry:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@@GLIBC_2.2.5
"""

    def fake_command(args, **kwargs):
        if args[0] == "readelf":
            return SimpleNamespace(returncode=0, stdout=readelf_output, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("ns_aeg.sink_finder.subprocess.run", fake_command)

    report = find_sinks("dummy", ["system"])
    match = report.matches[0]

    assert match.found is True
    assert match.symbol_name == "system"
    assert match.imported is True


def test_missing_sink_returns_found_false(monkeypatch) -> None:
    def fake_command(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("ns_aeg.sink_finder.subprocess.run", fake_command)

    report = find_sinks("dummy", ["popen"])

    assert report.matches[0].name == "popen"
    assert report.matches[0].found is False
