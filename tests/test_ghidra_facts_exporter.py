from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ns_aeg.ghidra.export_facts import (
    GhidraUnavailableError,
    basic_validate_ghidra_facts,
    export_facts,
    export_facts_with_pyghidra,
    load_json,
    main,
    unavailable_facts,
)
from ns_aeg.ghidra.sink_catalog import get_sink_definition, normalize_symbol_name


def test_toy_01_ghidra_facts_example_is_valid() -> None:
    data = load_json("examples/ghidra_exports/toy_01_facts.example.json")

    assert basic_validate_ghidra_facts(data) == []
    assert data["binary"]["name"] == "toy_01"
    assert {sink["name"] for sink in data["dangerous_sinks"]} == {"system", "snprintf"}


def test_json_schema_validates_example_when_available() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    data = load_json("examples/ghidra_exports/toy_01_facts.example.json")
    schema = json.loads(open("schemas/ghidra_facts.schema.json", encoding="utf-8").read())

    jsonschema.Draft202012Validator(schema).validate(data)


def test_unavailable_facts_are_schema_shaped_and_clear() -> None:
    facts = unavailable_facts(
        "datasets/toy_cgi/build/toy_01",
        "PyGhidra is not installed or not importable.",
        mode="pyghidra",
    )

    assert basic_validate_ghidra_facts(facts) == []
    assert facts["extraction"]["status"] == "error"
    assert facts["extraction"]["ghidra_available"] is False
    assert "PyGhidra" in facts["extraction"]["errors"][0]


def test_current_program_mode_fails_cleanly_without_ghidra() -> None:
    with pytest.raises(GhidraUnavailableError, match="No supported Ghidra runtime"):
        export_facts("datasets/toy_cgi/build/toy_01", mode="current-program")


def test_invalid_ghidra_install_dir_fails_clearly(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing_ghidra"

    with pytest.raises(GhidraUnavailableError, match="GHIDRA_INSTALL_DIR does not exist"):
        export_facts_with_pyghidra(
            "datasets/toy_cgi/build/toy_01",
            ghidra_install_dir=str(missing_dir),
        )


def test_example_cli_writes_without_ghidra(tmp_path: Path) -> None:
    output = tmp_path / "facts.example.json"

    rc = main(["--example", "--out", str(output)])

    assert rc == 0
    data = load_json(str(output))
    assert data["binary"]["name"] == "toy_01"
    assert basic_validate_ghidra_facts(data) == []


def test_ghidra_facts_allow_callsites_and_external_address() -> None:
    data = load_json("examples/ghidra_exports/toy_01_facts.example.json")
    data["dangerous_sinks"][0]["external_address"] = "0x4"
    data["dangerous_sinks"][0]["callsites"] = [
        {
            "address": "0x4011ea",
            "caller": "main",
            "caller_entry": "0x401176",
        }
    ]

    assert basic_validate_ghidra_facts(data) == []


def test_real_pyghidra_export_smoke_when_enabled(tmp_path: Path) -> None:
    if os.environ.get("NS_AEG_RUN_GHIDRA_TESTS") != "1":
        pytest.skip("set NS_AEG_RUN_GHIDRA_TESTS=1 to run real Ghidra smoke tests")
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not Path(ghidra_dir).exists():
        pytest.skip("GHIDRA_INSTALL_DIR is not set to an existing Ghidra install")

    output = tmp_path / "toy_01_facts.real.json"
    try:
        facts = export_facts_with_pyghidra(
            "datasets/toy_cgi/build/toy_01",
            output_path=str(output),
            ghidra_install_dir=ghidra_dir,
        )
    except GhidraUnavailableError as exc:
        pytest.skip(f"real Ghidra environment is not usable in this test run: {exc}")

    assert output.exists()
    assert facts["extraction"]["ghidra_available"] is True
    assert facts["functions"]
    assert {sink["name"] for sink in facts["dangerous_sinks"]} >= {"system", "snprintf"}
    assert basic_validate_ghidra_facts(facts) == []


def test_sink_catalog_normalizes_versioned_and_plt_symbols() -> None:
    assert normalize_symbol_name("system@GLIBC_2.2.5") == "system"
    assert normalize_symbol_name("snprintf@plt") == "snprintf"
    assert get_sink_definition("system@plt").category == "command_execution"
