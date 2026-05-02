from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
import tempfile
from typing import Any

from ns_aeg.ghidra.sink_catalog import (
    dangerous_sink_names,
    get_sink_definition,
    normalize_symbol_name,
)

SCHEMA_VERSION = "ghidra_facts_v1"
EXPORTER_VERSION = "0.1"
DEFAULT_EXAMPLE_FACTS = Path("examples") / "ghidra_exports" / "toy_01_facts.example.json"

TOP_LEVEL_REQUIRED = {
    "schema_version",
    "binary",
    "functions",
    "imports",
    "externals",
    "dangerous_sinks",
    "xrefs",
    "strings",
    "decompiled_snippets",
    "extraction",
}


class GhidraUnavailableError(RuntimeError):
    """Raised when no Ghidra program context or PyGhidra runtime is available."""


def load_json(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    return data


def write_json(data: dict[str, Any], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def empty_facts(binary_path: str | None, *, status: str, mode: str | None) -> dict[str, Any]:
    path = binary_path or ""
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": {
            "path": path,
            "name": Path(path).name if path else "",
            "architecture": None,
            "language_id": None,
            "compiler_spec_id": None,
            "image_base": None,
        },
        "functions": [],
        "imports": [],
        "externals": [],
        "dangerous_sinks": [],
        "xrefs": [],
        "strings": [],
        "decompiled_snippets": [],
        "extraction": {
            "status": status,
            "ghidra_available": False,
            "mode": mode,
            "exporter": f"ns_aeg.ghidra.export_facts:{EXPORTER_VERSION}",
            "warnings": [],
            "errors": [],
        },
    }


def unavailable_facts(binary_path: str | None, error: str, *, mode: str | None = None) -> dict[str, Any]:
    facts = empty_facts(binary_path, status="error", mode=mode)
    facts["extraction"]["errors"].append(error)
    return facts


def export_facts_from_current_program(
    *,
    output_path: str | None = None,
    include_decompiler: bool = False,
    max_strings: int = 200,
    max_decompiled: int = 20,
) -> dict[str, Any]:
    program = _current_program()
    if program is None:
        raise GhidraUnavailableError(
            "Ghidra currentProgram is not available. Run inside Ghidra Headless "
            "or use --mode pyghidra with PyGhidra installed."
        )

    facts = export_facts_from_program(
        program,
        mode="current-program",
        include_decompiler=include_decompiler,
        max_strings=max_strings,
        max_decompiled=max_decompiled,
    )
    if output_path is not None:
        write_json(facts, output_path)
    return facts


def export_facts_from_program(
    program: Any,
    *,
    mode: str,
    include_decompiler: bool = False,
    max_strings: int = 200,
    max_decompiled: int = 20,
) -> dict[str, Any]:
    warnings: list[str] = []
    functions = _collect_functions(program, warnings)
    imports = _collect_imports(program, warnings)
    externals = _collect_externals(program, imports, warnings)
    dangerous_sinks = _collect_dangerous_sinks(functions, imports, externals)
    xrefs = _collect_xrefs(program, dangerous_sinks, functions, warnings)
    strings = _collect_strings(program, warnings, max_strings=max_strings)
    snippets = _collect_decompiled_snippets(
        program,
        functions,
        warnings,
        max_decompiled=max_decompiled,
        target_functions=_caller_names(dangerous_sinks),
        include_fallback_functions=include_decompiler,
    )

    facts = {
        "schema_version": SCHEMA_VERSION,
        "binary": _collect_binary(program),
        "functions": functions,
        "imports": imports,
        "externals": externals,
        "dangerous_sinks": dangerous_sinks,
        "xrefs": xrefs,
        "strings": strings,
        "decompiled_snippets": snippets,
        "extraction": {
            "status": "partial" if warnings else "ok",
            "ghidra_available": True,
            "mode": mode,
            "exporter": f"ns_aeg.ghidra.export_facts:{EXPORTER_VERSION}",
            "warnings": warnings,
            "errors": [],
        },
    }
    return facts


def export_facts_with_pyghidra(
    binary_path: str,
    *,
    output_path: str | None = None,
    include_decompiler: bool = False,
    max_strings: int = 200,
    max_decompiled: int = 20,
    ghidra_install_dir: str | None = None,
    project_location: str | None = None,
) -> dict[str, Any]:
    binary = Path(binary_path)
    if not binary.exists():
        raise GhidraUnavailableError(f"binary does not exist: {binary_path}")
    install_dir = _resolve_ghidra_install_dir(ghidra_install_dir)
    errors: list[str] = []
    for backend_name, bundled in _pyghidra_backend_order(install_dir):
        try:
            pyghidra = _import_pyghidra_backend(install_dir, bundled=bundled)
        except ImportError as exc:
            errors.append(f"{backend_name} PyGhidra import failed: {exc}")
            continue

        backend_path = str(getattr(pyghidra, "__file__", "unknown"))
        try:
            pyghidra.start(install_dir=install_dir)
            with pyghidra.open_program(
                binary,
                project_location=_pyghidra_project_location(project_location),
                project_name=f"{binary.stem}_ns_aeg_ghidra_{os.getpid()}",
            ) as flat_api:
                program = getattr(flat_api, "currentProgram", None) or flat_api.getCurrentProgram()
                facts = export_facts_from_program(
                    program,
                    mode="pyghidra",
                    include_decompiler=include_decompiler,
                    max_strings=max_strings,
                    max_decompiled=max_decompiled,
                )
                facts["extraction"]["warnings"].append(
                    f"pyghidra backend: {backend_name} ({backend_path})"
                )
        except Exception as exc:
            errors.append(
                f"{backend_name} PyGhidra backend ({backend_path}) failed with "
                f"Ghidra install {install_dir}: {exc}"
            )
            continue
        break
    else:
        raise GhidraUnavailableError(
            "failed to initialize PyGhidra/Ghidra. Tried backends: "
            + " | ".join(errors)
        )

    if output_path is not None:
        write_json(facts, output_path)
    return facts


def export_facts(
    binary_path: str,
    *,
    output_path: str | None = None,
    mode: str = "auto",
    include_decompiler: bool = False,
    ghidra_install_dir: str | None = None,
    project_location: str | None = None,
) -> dict[str, Any]:
    if mode not in {"auto", "current-program", "pyghidra"}:
        raise ValueError("mode must be auto, current-program, or pyghidra")

    try:
        if mode in {"auto", "current-program"} and _current_program() is not None:
            return export_facts_from_current_program(
                output_path=output_path,
                include_decompiler=include_decompiler,
            )
        if mode in {"auto", "pyghidra"}:
            return export_facts_with_pyghidra(
                binary_path,
                output_path=output_path,
                include_decompiler=include_decompiler,
                ghidra_install_dir=ghidra_install_dir,
                project_location=project_location,
            )
    except GhidraUnavailableError:
        raise

    raise GhidraUnavailableError(
        "No supported Ghidra runtime is available. Use Ghidra Headless with "
        "currentProgram or install/configure PyGhidra."
    )


def basic_validate_ghidra_facts(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in sorted(TOP_LEVEL_REQUIRED - set(data)):
        errors.append(f"missing required key: {key}")
    for key in sorted(set(data) - TOP_LEVEL_REQUIRED):
        errors.append(f"unexpected key: $.{key}")

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")

    _require_object(data, "binary", errors)
    _require_object(data, "extraction", errors)
    for key in (
        "functions",
        "imports",
        "externals",
        "dangerous_sinks",
        "xrefs",
        "strings",
        "decompiled_snippets",
    ):
        if key in data and not isinstance(data[key], list):
            errors.append(f"{key} must be an array")

    if isinstance(data.get("binary"), dict):
        _validate_binary(data["binary"], errors)
    if isinstance(data.get("extraction"), dict):
        _validate_extraction(data["extraction"], errors)
    _validate_items(data.get("functions"), "functions", {"name", "entry"}, errors)
    _validate_items(
        data.get("imports"),
        "imports",
        {"name", "address", "namespace", "external"},
        errors,
    )
    _validate_items(
        data.get("externals"),
        "externals",
        {"name", "address", "namespace", "external"},
        errors,
    )
    _validate_items(
        data.get("dangerous_sinks"),
        "dangerous_sinks",
        None,
        errors,
        required={"name", "category", "address", "imported", "source", "description", "callers"},
        optional={"external_address", "callsites"},
    )
    _validate_callsites(data.get("dangerous_sinks"), errors)
    _validate_items(
        data.get("xrefs"),
        "xrefs",
        {"from_function", "from_address", "to_sink", "to_address", "type"},
        errors,
    )
    _validate_items(data.get("strings"), "strings", {"address", "value"}, errors)
    _validate_items(
        data.get("decompiled_snippets"),
        "decompiled_snippets",
        {"function", "entry", "text"},
        errors,
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export minimal Ghidra static facts as JSON.")
    parser.add_argument("--binary", help="Binary path for PyGhidra mode.")
    parser.add_argument(
        "--output",
        "--out",
        dest="output",
        required=True,
        help="Output JSON path.",
    )
    parser.add_argument(
        "--example",
        action="store_true",
        help="Write the bundled toy_01 example facts without starting Ghidra.",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "current-program", "pyghidra"],
        default="auto",
        help="Ghidra runtime mode.",
    )
    parser.add_argument(
        "--include-decompiler",
        action="store_true",
        help="Include best-effort decompiled snippets when a decompiler is available.",
    )
    parser.add_argument(
        "--write-error-json",
        action="store_true",
        help="Write schema-shaped error facts when Ghidra is unavailable.",
    )
    parser.add_argument(
        "--ghidra-install-dir",
        help="Optional Ghidra install directory. Defaults to GHIDRA_INSTALL_DIR.",
    )
    parser.add_argument(
        "--project-location",
        help="Optional PyGhidra project directory. Defaults to /tmp/ns_aeg_pyghidra_projects.",
    )
    args = parser.parse_args(argv)

    if args.example:
        try:
            facts = load_json(str(DEFAULT_EXAMPLE_FACTS))
        except Exception as exc:
            print(f"error: failed to load example facts: {exc}", file=sys.stderr)
            return 2
        write_json(facts, args.output)
        return 0

    if args.mode in {"auto", "pyghidra"} and not args.binary and _current_program() is None:
        parser.error("--binary is required outside a Ghidra currentProgram context")

    try:
        facts = export_facts(
            args.binary or "",
            output_path=args.output,
            mode=args.mode,
            include_decompiler=args.include_decompiler,
            ghidra_install_dir=args.ghidra_install_dir,
            project_location=args.project_location,
        )
    except GhidraUnavailableError as exc:
        message = str(exc)
        if args.write_error_json:
            write_json(unavailable_facts(args.binary, message, mode=args.mode), args.output)
        print(f"error: {message}", file=sys.stderr)
        return 2

    errors = basic_validate_ghidra_facts(facts)
    if errors:
        print("warning: exported facts failed local validation:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    return 0


def _resolve_ghidra_install_dir(ghidra_install_dir: str | None = None) -> Path:
    raw_path = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
    if not raw_path:
        raise GhidraUnavailableError(
            "GHIDRA_INSTALL_DIR is not set. Set it to the Ghidra install directory "
            "or pass --ghidra-install-dir."
        )
    install_dir = Path(raw_path)
    if not install_dir.exists():
        raise GhidraUnavailableError(f"GHIDRA_INSTALL_DIR does not exist: {install_dir}")
    analyze_headless = install_dir / "support" / "analyzeHeadless"
    if not analyze_headless.exists():
        raise GhidraUnavailableError(
            f"GHIDRA_INSTALL_DIR does not look like a Ghidra install: "
            f"missing {analyze_headless}"
        )
    return install_dir


def _prepend_bundled_pyghidra(install_dir: Path) -> None:
    bundled_src = install_dir / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "src"
    if bundled_src.exists():
        bundled_text = str(bundled_src)
        if bundled_text not in sys.path:
            sys.path.insert(0, bundled_text)


def _pyghidra_backend_order(install_dir: Path) -> list[tuple[str, bool]]:
    bundled_src = install_dir / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "src"
    order = [("installed", False)]
    if bundled_src.exists():
        order.append(("bundled", True))
    return order


def _import_pyghidra_backend(install_dir: Path, *, bundled: bool) -> Any:
    _clear_pyghidra_modules()
    if bundled:
        _prepend_bundled_pyghidra(install_dir)
    import pyghidra  # type: ignore[import-not-found]

    return pyghidra


def _clear_pyghidra_modules() -> None:
    for name in list(sys.modules):
        if name == "pyghidra" or name.startswith("pyghidra."):
            del sys.modules[name]


def _pyghidra_project_location(project_location: str | None = None) -> Path:
    if project_location:
        path = Path(project_location)
    else:
        path = Path(tempfile.gettempdir()) / "ns_aeg_pyghidra_projects"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _collect_binary(program: Any) -> dict[str, Any]:
    executable_path = _safe_call(program, "getExecutablePath")
    image_base = _safe_call(program, "getImageBase")
    compiler = _safe_call(program, "getCompilerSpec")
    compiler_id = _safe_call(compiler, "getCompilerSpecID") if compiler is not None else None
    return {
        "path": str(executable_path or ""),
        "name": str(_safe_call(program, "getName") or Path(str(executable_path or "")).name),
        "architecture": _arch_name(program),
        "language_id": _string_or_none(_safe_call(program, "getLanguageID")),
        "compiler_spec_id": _string_or_none(compiler_id),
        "image_base": _addr_to_hex(image_base),
    }


def _collect_functions(program: Any, warnings: list[str]) -> list[dict[str, Any]]:
    try:
        manager = program.getFunctionManager()
        functions = manager.getFunctions(True)
        return [
            {
                "name": str(function.getName()),
                "entry": _addr_to_hex(function.getEntryPoint()),
            }
            for function in functions
        ]
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect functions: {exc}")
        return []


def _collect_imports(program: Any, warnings: list[str]) -> list[dict[str, Any]]:
    imports: dict[str, dict[str, Any]] = {}
    try:
        for symbol in program.getSymbolTable().getExternalSymbols():
            name = normalize_symbol_name(str(symbol.getName()))
            if not name:
                continue
            imports[name] = {
                "name": name,
                "address": _addr_to_hex(_safe_call(symbol, "getAddress")),
                "namespace": _string_or_none(_safe_call(symbol, "getParentNamespace")),
                "external": True,
            }
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect external symbols: {exc}")

    try:
        manager = program.getExternalManager()
        for external in manager.getExternalFunctions():
            name = normalize_symbol_name(str(external.getName()))
            if not name:
                continue
            imports[name] = {
                "name": name,
                "address": _addr_to_hex(_safe_call(external, "getAddress")),
                "namespace": _string_or_none(_safe_call(external, "getParentName")),
                "external": True,
            }
    except Exception:
        pass

    return sorted(imports.values(), key=lambda item: item["name"])


def _collect_externals(
    program: Any,
    imports: list[dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    if imports:
        return imports
    try:
        symbols = []
        for symbol in program.getSymbolTable().getExternalSymbols():
            name = normalize_symbol_name(str(symbol.getName()))
            symbols.append(
                {
                    "name": name,
                    "address": _addr_to_hex(_safe_call(symbol, "getAddress")),
                    "namespace": _string_or_none(_safe_call(symbol, "getParentNamespace")),
                    "external": True,
                }
            )
        return sorted(symbols, key=lambda item: item["name"])
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect externals: {exc}")
        return []


def _collect_dangerous_sinks(
    functions: list[dict[str, Any]],
    imports: list[dict[str, Any]],
    externals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for source, imported, rows in (
        ("import", True, imports),
        ("external", True, externals),
        ("function", False, functions),
    ):
        for row in rows:
            name = normalize_symbol_name(str(row.get("name", "")))
            definition = get_sink_definition(name)
            if definition is None:
                continue
            existing = by_name.get(name)
            if existing is not None and existing.get("address"):
                continue
            if existing is not None and not existing.get("address"):
                existing["address"] = row.get("entry") or row.get("address")
                continue
            by_name[name] = {
                "name": name,
                "category": definition.category,
                "address": row.get("entry") or row.get("address"),
                "external_address": row.get("address") if imported else None,
                "imported": imported,
                "source": source,
                "description": definition.description,
                "callers": [],
                "callsites": [],
            }
    return [by_name[name] for name in dangerous_sink_names() if name in by_name]


def _collect_xrefs(
    program: Any,
    dangerous_sinks: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    xrefs: list[dict[str, Any]] = []
    try:
        reference_manager = program.getReferenceManager()
        function_manager = program.getFunctionManager()
        for sink in dangerous_sinks:
            target_addresses = _sink_target_addresses(program, sink, functions)
            if not target_addresses:
                if sink.get("external_address"):
                    warnings.append(
                        f"no concrete call target found for {sink['name']}; "
                        "sink.address falls back to external_address"
                    )
                continue
            callers: list[str] = []
            callsites: list[dict[str, Any]] = []
            seen_callsites: set[str] = set()
            for target_address in target_addresses:
                for ref in reference_manager.getReferencesTo(target_address):
                    ref_type = str(ref.getReferenceType())
                    if "CALL" not in ref_type:
                        continue
                    from_address = ref.getFromAddress()
                    function = function_manager.getFunctionContaining(from_address)
                    if _is_sink_thunk_function(function, sink["name"]):
                        continue
                    from_function = str(function.getName()) if function is not None else None
                    caller_entry = (
                        _addr_to_hex(function.getEntryPoint()) if function is not None else None
                    )
                    callsite_address = _addr_to_hex(from_address)
                    if from_function and from_function not in callers:
                        callers.append(from_function)
                    if callsite_address and callsite_address not in seen_callsites:
                        seen_callsites.add(callsite_address)
                        callsites.append(
                            {
                                "address": callsite_address,
                                "caller": from_function,
                                "caller_entry": caller_entry,
                            }
                        )
                    xrefs.append(
                        {
                            "from_function": from_function,
                            "from_address": callsite_address,
                            "to_sink": sink["name"],
                            "to_address": _addr_to_hex(target_address),
                            "type": ref_type,
                        }
                    )
            for callsite in _instruction_callsites_to_sink(program, sink["name"]):
                callsite_address = callsite["address"]
                if callsite_address in seen_callsites:
                    continue
                seen_callsites.add(callsite_address)
                callsites.append(
                    {
                        "address": callsite.get("address"),
                        "caller": callsite.get("caller"),
                        "caller_entry": callsite.get("caller_entry"),
                    }
                )
                caller = callsite.get("caller")
                if caller and caller not in callers:
                    callers.append(caller)
                xrefs.append(
                    {
                        "from_function": caller,
                        "from_address": callsite_address,
                        "to_sink": sink["name"],
                        "to_address": callsite.get("target_address"),
                        "type": "INSTRUCTION_CALL_FLOW",
                    }
                )
            sink["callers"] = callers
            sink["callsites"] = callsites
            if callsites:
                sink["address"] = callsites[0]["address"]
            elif sink.get("external_address"):
                sink["address"] = sink["external_address"]
                warnings.append(
                    f"no callsites found for {sink['name']}; "
                    "sink.address falls back to external_address"
                )
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect sink xrefs: {exc}")
    return xrefs


def _instruction_callsites_to_sink(program: Any, sink_name: str) -> list[dict[str, Any]]:
    callsites: list[dict[str, Any]] = []
    try:
        listing = program.getListing()
        function_manager = program.getFunctionManager()
        for instruction in listing.getInstructions(True):
            flow_type = instruction.getFlowType()
            if not flow_type.isCall():
                continue
            caller_function = function_manager.getFunctionContaining(instruction.getAddress())
            if _is_sink_thunk_function(caller_function, sink_name):
                continue
            for target in instruction.getFlows():
                target_function = function_manager.getFunctionAt(target)
                if not _function_targets_sink(target_function, sink_name):
                    continue
                callsites.append(
                    {
                        "address": _addr_to_hex(instruction.getAddress()),
                        "caller": str(caller_function.getName())
                        if caller_function is not None
                        else None,
                        "caller_entry": _addr_to_hex(caller_function.getEntryPoint())
                        if caller_function is not None
                        else None,
                        "target_address": _addr_to_hex(target),
                    }
                )
    except Exception:
        return []
    return callsites


def _function_targets_sink(function: Any, sink_name: str) -> bool:
    if function is None:
        return False
    function_name = normalize_symbol_name(str(function.getName()))
    if function_name == sink_name:
        return True
    return _is_sink_thunk_function(function, sink_name)


def _is_sink_thunk_function(function: Any, sink_name: str) -> bool:
    if function is None:
        return False
    try:
        if not function.isThunk():
            return False
        thunked = function.getThunkedFunction(True)
        if thunked is None:
            return False
        return normalize_symbol_name(str(thunked.getName())) == sink_name
    except Exception:
        return False


def _sink_target_addresses(
    program: Any,
    sink: dict[str, Any],
    functions: list[dict[str, Any]],
) -> list[Any]:
    addresses: list[Any] = []
    seen: set[str] = set()
    for value in _sink_target_address_values(program, sink, functions):
        address = _address_from_hex(program, value)
        address_text = _addr_to_hex(address)
        if address is not None and address_text not in seen:
            seen.add(str(address_text))
            addresses.append(address)
    return addresses


def _sink_target_address_values(
    program: Any,
    sink: dict[str, Any],
    functions: list[dict[str, Any]],
) -> list[Any]:
    sink_name = normalize_symbol_name(str(sink.get("name") or ""))
    values = [sink.get("address"), sink.get("external_address")]
    values.extend(
        function.get("entry")
        for function in functions
        if normalize_symbol_name(str(function.get("name") or "")) == sink_name
    )
    values.extend(_thunk_function_entries_for_sink(program, sink_name))
    return values


def _thunk_function_entries_for_sink(program: Any, sink_name: str) -> list[str]:
    entries: list[str] = []
    try:
        for function in program.getFunctionManager().getFunctions(True):
            thunked = function.getThunkedFunction(True) if function.isThunk() else None
            if thunked is None:
                continue
            thunked_name = normalize_symbol_name(str(thunked.getName()))
            if thunked_name == sink_name:
                entry = _addr_to_hex(function.getEntryPoint())
                if entry is not None:
                    entries.append(entry)
    except Exception:
        return []
    return entries


def _collect_strings(
    program: Any,
    warnings: list[str],
    *,
    max_strings: int,
) -> list[dict[str, Any]]:
    try:
        from ghidra.program.util import DefinedDataIterator  # type: ignore[import-not-found]

        strings = []
        if hasattr(DefinedDataIterator, "definedStrings"):
            iterator = DefinedDataIterator.definedStrings(program)
        else:
            iterator = program.getListing().getDefinedData(True)
        for data in iterator:
            value = data.getValue()
            if not isinstance(value, str):
                continue
            strings.append(
                {
                    "address": _addr_to_hex(data.getAddress()),
                    "value": value,
                }
            )
            if len(strings) >= max_strings:
                break
        return strings
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect strings: {exc}")
        return []


def _collect_decompiled_snippets(
    program: Any,
    functions: list[dict[str, Any]],
    warnings: list[str],
    *,
    max_decompiled: int,
    target_functions: list[str] | None = None,
    include_fallback_functions: bool = False,
) -> list[dict[str, Any]]:
    try:
        from ghidra.app.decompiler import DecompInterface  # type: ignore[import-not-found]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]

        interface = DecompInterface()
        interface.openProgram(program)
        manager = program.getFunctionManager()
        monitor = ConsoleTaskMonitor()
        snippets: list[dict[str, Any]] = []
        rows = _decompile_target_rows(
            functions,
            target_functions or [],
            include_fallback_functions=include_fallback_functions,
            max_decompiled=max_decompiled,
        )
        for row in rows:
            address = _address_from_hex(program, row.get("entry"))
            if address is None:
                continue
            function = manager.getFunctionAt(address)
            if function is None:
                continue
            result = interface.decompileFunction(function, 20, monitor)
            decompiled = result.getDecompiledFunction() if result.decompileCompleted() else None
            if decompiled is None:
                continue
            snippets.append(
                {
                    "function": row["name"],
                    "entry": row["entry"],
                    "text": str(decompiled.getC()),
                }
            )
        return snippets
    except Exception as exc:  # pragma: no cover - requires Ghidra
        warnings.append(f"failed to collect decompiled snippets: {exc}")
        return []


def _decompile_target_rows(
    functions: list[dict[str, Any]],
    target_functions: list[str],
    *,
    include_fallback_functions: bool,
    max_decompiled: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_entries: set[str] = set()
    target_set = set(target_functions)
    for row in functions:
        entry = str(row.get("entry") or "")
        if row.get("name") in target_set and entry not in seen_entries:
            seen_entries.add(entry)
            rows.append(row)
    if include_fallback_functions:
        for row in functions:
            entry = str(row.get("entry") or "")
            if entry and entry not in seen_entries:
                seen_entries.add(entry)
                rows.append(row)
            if len(rows) >= max_decompiled:
                break
    return rows[:max_decompiled]


def _caller_names(dangerous_sinks: list[dict[str, Any]]) -> list[str]:
    callers: list[str] = []
    for sink in dangerous_sinks:
        for caller in sink.get("callers", []):
            if isinstance(caller, str) and caller and caller not in callers:
                callers.append(caller)
    return callers


def _current_program() -> Any | None:
    return globals().get("currentProgram")


def _safe_call(obj: Any, method: str) -> Any | None:
    if obj is None:
        return None
    attr = getattr(obj, method, None)
    if attr is None:
        return None
    try:
        return attr()
    except Exception:
        return None


def _arch_name(program: Any) -> str | None:
    language_id = _safe_call(program, "getLanguageID")
    if language_id is not None:
        return str(language_id).split(":", 1)[0]
    language = _safe_call(program, "getLanguage")
    processor = _safe_call(language, "getProcessor") if language is not None else None
    return _string_or_none(processor)


def _addr_to_hex(address: Any) -> str | None:
    if address is None:
        return None
    try:
        offset = address.getOffset()
        return f"0x{int(offset):x}"
    except Exception:
        text = str(address)
        if not text:
            return None
        if text.startswith("0x"):
            return text
        try:
            return f"0x{int(text, 16):x}"
        except ValueError:
            return None


def _address_from_hex(program: Any, value: Any) -> Any | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return program.getAddressFactory().getAddress(value)
    except Exception:
        return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _require_object(data: dict[str, Any], key: str, errors: list[str]) -> None:
    if key in data and not isinstance(data[key], dict):
        errors.append(f"{key} must be an object")


def _validate_binary(binary: dict[str, Any], errors: list[str]) -> None:
    required = {"path", "name", "architecture", "language_id", "compiler_spec_id", "image_base"}
    _check_keys(binary, "binary", required, errors)
    for key in required:
        if key in binary and binary[key] is not None and not isinstance(binary[key], str):
            errors.append(f"binary.{key} must be a string or null")


def _validate_extraction(extraction: dict[str, Any], errors: list[str]) -> None:
    required = {"status", "ghidra_available", "mode", "exporter", "warnings", "errors"}
    _check_keys(extraction, "extraction", required, errors)
    if extraction.get("status") not in {"ok", "partial", "error"}:
        errors.append("extraction.status is invalid")
    if "ghidra_available" in extraction and not isinstance(
        extraction["ghidra_available"],
        bool,
    ):
        errors.append("extraction.ghidra_available must be a boolean")
    for key in ("warnings", "errors"):
        if key in extraction and not isinstance(extraction[key], list):
            errors.append(f"extraction.{key} must be an array")


def _validate_items(
    value: Any,
    path: str,
    allowed: set[str] | None = None,
    errors: list[str] | None = None,
    *,
    required: set[str] | None = None,
    optional: set[str] | None = None,
) -> None:
    if errors is None:
        errors = []
    if not isinstance(value, list):
        return
    required_keys = required if required is not None else allowed or set()
    allowed_keys = required_keys | (optional or set())
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{path}[{index}] must be an object")
            continue
        _check_keys(item, f"{path}[{index}]", allowed_keys, errors, required=required_keys)


def _validate_callsites(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list):
        return
    for sink_index, sink in enumerate(value):
        if not isinstance(sink, dict) or "callsites" not in sink:
            continue
        callsites = sink["callsites"]
        if not isinstance(callsites, list):
            errors.append(f"dangerous_sinks[{sink_index}].callsites must be an array")
            continue
        for callsite_index, callsite in enumerate(callsites):
            if not isinstance(callsite, dict):
                errors.append(
                    f"dangerous_sinks[{sink_index}].callsites[{callsite_index}] "
                    "must be an object"
                )
                continue
            _check_keys(
                callsite,
                f"dangerous_sinks[{sink_index}].callsites[{callsite_index}]",
                {"address", "caller", "caller_entry"},
                errors,
            )


def _check_keys(
    data: dict[str, Any],
    path: str,
    allowed: set[str],
    errors: list[str],
    *,
    required: set[str] | None = None,
) -> None:
    required_keys = required if required is not None else allowed
    for key in sorted(required_keys - set(data)):
        errors.append(f"missing required key: {path}.{key}")
    for key in sorted(set(data) - allowed):
        errors.append(f"unexpected key: {path}.{key}")


if __name__ == "__main__":
    raise SystemExit(main())
