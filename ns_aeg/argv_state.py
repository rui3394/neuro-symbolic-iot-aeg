from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from ns_aeg.source_model import SourceModel


DEFAULT_ARG_VALUE = "127.0.0.1"


@dataclass(frozen=True)
class ArgvStateInfo:
    binary_path: str
    created: bool
    state_kind: str
    argv: list[str]
    source_bindings: dict[str, str]
    symbolic: bool
    symbolic_vars: dict[str, str]
    symbolic_sizes: dict[str, int]
    constraints: list[str]
    error: str | None


def create_argv_state(
    binary_path: str,
    source_model: SourceModel,
    concrete_values: dict[str, str] | None = None,
) -> ArgvStateInfo:
    if not Path(binary_path).exists():
        return _failed(binary_path, f"binary does not exist: {binary_path}")

    concrete_values = concrete_values or {}
    argv_result = _build_argv(binary_path, source_model, concrete_values)
    if isinstance(argv_result, str):
        return _failed(binary_path, argv_result)
    argv, source_bindings = argv_result

    try:
        import angr
    except ImportError:
        return _failed(binary_path, "angr is not installed", argv, source_bindings)

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        project.factory.full_init_state(args=argv)
    except Exception as exc:
        return _failed(
            binary_path,
            f"failed to create angr argv state: {exc}",
            argv,
            source_bindings,
        )

    return ArgvStateInfo(
        binary_path=binary_path,
        created=True,
        state_kind="full_init_state",
        argv=argv,
        source_bindings=source_bindings,
        symbolic=False,
        symbolic_vars={},
        symbolic_sizes={},
        constraints=[],
        error=None,
    )


def create_symbolic_argv_state(
    binary_path: str,
    source_model: SourceModel,
) -> ArgvStateInfo:
    if not Path(binary_path).exists():
        return _failed(
            binary_path,
            f"binary does not exist: {binary_path}",
            symbolic=True,
        )

    try:
        import angr
    except ImportError:
        return _failed(binary_path, "angr is not installed", symbolic=True)

    try:
        import claripy
    except ImportError:
        return _failed(binary_path, "claripy is not installed", symbolic=True)

    argv_result = _build_symbolic_argv(binary_path, source_model, claripy)
    if isinstance(argv_result, str):
        return _failed(binary_path, argv_result, symbolic=True)

    (
        state_argv,
        display_argv,
        source_bindings,
        symbolic_vars,
        symbolic_sizes,
        constraints,
    ) = argv_result

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        project.factory.full_init_state(args=state_argv)
    except Exception as exc:
        return _failed(
            binary_path,
            f"failed to create symbolic angr argv state: {exc}",
            display_argv,
            source_bindings,
            symbolic=True,
            symbolic_vars=symbolic_vars,
            symbolic_sizes=symbolic_sizes,
            constraints=constraints,
        )

    return ArgvStateInfo(
        binary_path=binary_path,
        created=True,
        state_kind="full_init_state",
        argv=display_argv,
        source_bindings=source_bindings,
        symbolic=True,
        symbolic_vars=symbolic_vars,
        symbolic_sizes=symbolic_sizes,
        constraints=constraints,
        error=None,
    )


def _build_argv(
    binary_path: str,
    source_model: SourceModel,
    concrete_values: dict[str, str],
) -> tuple[list[str], dict[str, str]] | str:
    index_by_name: dict[str, int] = {}
    for source in source_model.sources:
        index = _parse_argv_binding(source.runtime_binding)
        if index is None or index == 0:
            return f"unsupported runtime binding: {source.runtime_binding}"
        index_by_name[source.name] = index

    max_index = max(index_by_name.values(), default=0)
    argv = ["" for _ in range(max_index + 1)]
    argv[0] = binary_path

    source_bindings: dict[str, str] = {}
    for source in source_model.sources:
        index = index_by_name[source.name]
        argv[index] = concrete_values.get(source.name, DEFAULT_ARG_VALUE)
        source_bindings[source.name] = source.runtime_binding

    return argv, source_bindings


def _build_symbolic_argv(
    binary_path: str,
    source_model: SourceModel,
    claripy: Any,
) -> (
    tuple[
        list[Any],
        list[str],
        dict[str, str],
        dict[str, str],
        dict[str, int],
        list[str],
    ]
    | str
):
    index_by_name: dict[str, int] = {}
    for source in source_model.sources:
        index = _parse_argv_binding(source.runtime_binding)
        if index is None or index == 0:
            return f"unsupported runtime binding: {source.runtime_binding}"
        if source.max_len <= 1:
            return f"source max_len must be greater than 1: {source.name}"
        index_by_name[source.name] = index

    max_index = max(index_by_name.values(), default=0)
    state_argv: list[Any] = ["" for _ in range(max_index + 1)]
    display_argv = ["" for _ in range(max_index + 1)]
    state_argv[0] = binary_path
    display_argv[0] = binary_path

    source_bindings: dict[str, str] = {}
    symbolic_vars: dict[str, str] = {}
    symbolic_sizes: dict[str, int] = {}
    constraints: list[str] = []

    for source in source_model.sources:
        index = index_by_name[source.name]
        sym = claripy.BVS(source.symbolic_name, (source.max_len - 1) * 8)
        state_argv[index] = sym.concat(claripy.BVV(0, 8))
        display_argv[index] = source.symbolic_name
        source_bindings[source.name] = source.runtime_binding
        symbolic_vars[source.name] = source.symbolic_name
        symbolic_sizes[source.name] = source.max_len
        constraints.append(f"{source.symbolic_name} is null-terminated")

    return (
        state_argv,
        display_argv,
        source_bindings,
        symbolic_vars,
        symbolic_sizes,
        constraints,
    )


def _parse_argv_binding(runtime_binding: str) -> int | None:
    match = re.fullmatch(r"argv\[(\d+)\]", runtime_binding)
    if match is None:
        return None
    return int(match.group(1))


def _failed(
    binary_path: str,
    error: str,
    argv: list[str] | None = None,
    source_bindings: dict[str, str] | None = None,
    symbolic: bool = False,
    symbolic_vars: dict[str, str] | None = None,
    symbolic_sizes: dict[str, int] | None = None,
    constraints: list[str] | None = None,
) -> ArgvStateInfo:
    return ArgvStateInfo(
        binary_path=binary_path,
        created=False,
        state_kind="full_init_state",
        argv=argv or [],
        source_bindings=source_bindings or {},
        symbolic=symbolic,
        symbolic_vars=symbolic_vars or {},
        symbolic_sizes=symbolic_sizes or {},
        constraints=constraints or [],
        error=error,
    )
