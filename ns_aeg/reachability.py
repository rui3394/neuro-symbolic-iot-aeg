from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from ns_aeg.source_model import SourceModel


SINK_PRIORITY = ["system", "popen", "snprintf"]


@dataclass(frozen=True)
class ReachabilityResult:
    binary_path: str
    created: bool
    reachable: bool
    input_mode: str
    argv: list[str]
    target_sink: str | None
    target_addr: str | None
    max_steps: int
    steps: int
    found_states: int
    error: str | None


@dataclass(frozen=True)
class SymbolicReachabilityResult:
    binary_path: str
    created: bool
    reachable: bool
    input_mode: str
    source_name: str | None
    symbolic_var: str | None
    runtime_binding: str | None
    input_constraints: list[str]
    target_sink: str | None
    target_addr: str | None
    max_steps: int
    steps: int
    found_states: int
    sink_arg_register: str | None
    sink_arg_symbolic: bool
    sink_arg_variables: list[str]
    source_var_in_sink_arg: bool
    error: str | None


def smoke_reach_sink(
    binary_path: str,
    sinks: list[str],
    concrete_argv1: str = "127.0.0.1",
    max_steps: int = 200,
) -> ReachabilityResult:
    argv = [binary_path, concrete_argv1]
    if not Path(binary_path).exists():
        return _result(
            binary_path,
            argv,
            max_steps,
            created=False,
            error=f"binary does not exist: {binary_path}",
        )

    try:
        import angr
    except ImportError:
        return _result(
            binary_path,
            argv,
            max_steps,
            created=False,
            error="angr is not installed",
        )

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        target_sink, target_addr = _select_target_sink(project, sinks)
        if target_sink is None or target_addr is None:
            return _result(
                binary_path,
                argv,
                max_steps,
                created=True,
                error="no configured sink PLT found",
            )

        state = project.factory.full_init_state(args=argv)
        simgr = project.factory.simulation_manager(state)
        reachable, steps, found_states = _run_until_addr(simgr, target_addr, max_steps)
    except Exception as exc:
        return _result(
            binary_path,
            argv,
            max_steps,
            created=False,
            error=f"failed to run sink reachability smoke test: {exc}",
        )

    return ReachabilityResult(
        binary_path=binary_path,
        created=True,
        reachable=reachable,
        input_mode="concrete argv",
        argv=argv,
        target_sink=target_sink,
        target_addr=_to_hex(target_addr),
        max_steps=max_steps,
        steps=steps,
        found_states=found_states,
        error=None if reachable else "target sink was not reached",
    )


def symbolic_reach_sink(
    binary_path: str,
    sinks: list[str],
    source_model: SourceModel,
    max_steps: int = 300,
    sink_arg_read_size: int = 128,
) -> SymbolicReachabilityResult:
    if not Path(binary_path).exists():
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            error=f"binary does not exist: {binary_path}",
        )

    if not source_model.sources:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            error="no source configured",
        )

    source = source_model.sources[0]
    argv_index = _parse_argv_binding(source.runtime_binding)
    if argv_index is None or argv_index == 0:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error=f"unsupported runtime binding: {source.runtime_binding}",
        )
    if source.max_len <= 1:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error=f"source max_len must be greater than 1: {source.name}",
        )

    try:
        import angr
    except ImportError:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error="angr is not installed",
        )

    try:
        import claripy
    except ImportError:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error="claripy is not installed",
        )

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        target_sink, target_addr = _select_target_sink(project, sinks)
        if target_sink is None or target_addr is None:
            return _symbolic_result(
                binary_path,
                max_steps,
                created=True,
                source_name=source.name,
                symbolic_var=source.symbolic_name,
                runtime_binding=source.runtime_binding,
                error="no configured sink PLT found",
            )

        sym = claripy.BVS(source.symbolic_name, (source.max_len - 1) * 8)
        argv_value = sym.concat(claripy.BVV(0, 8))
        argv: list[Any] = ["" for _ in range(argv_index + 1)]
        argv[0] = binary_path
        argv[argv_index] = argv_value

        state = project.factory.full_init_state(args=argv)
        input_constraints = _add_non_null_prefix_constraints(
            state,
            sym,
            source.max_len,
        )
        simgr = project.factory.simulation_manager(state)
        found_states, steps = _find_states_until_addr(simgr, target_addr, max_steps)
    except Exception as exc:
        return _symbolic_result(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error=f"failed to run symbolic sink reachability: {exc}",
        )

    if not found_states:
        return SymbolicReachabilityResult(
            binary_path=binary_path,
            created=True,
            reachable=False,
            input_mode="symbolic argv",
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            input_constraints=input_constraints,
            target_sink=target_sink,
            target_addr=_to_hex(target_addr),
            max_steps=max_steps,
            steps=steps,
            found_states=0,
            sink_arg_register=None,
            sink_arg_symbolic=False,
            sink_arg_variables=[],
            source_var_in_sink_arg=False,
            error="target sink was not reached",
        )

    arg_register, arg_symbolic, arg_variables, var_in_arg, error = _inspect_sink_argument(
        project,
        found_states[0],
        source.symbolic_name,
        sink_arg_read_size,
    )
    return SymbolicReachabilityResult(
        binary_path=binary_path,
        created=True,
        reachable=True,
        input_mode="symbolic argv",
        source_name=source.name,
        symbolic_var=source.symbolic_name,
        runtime_binding=source.runtime_binding,
        input_constraints=input_constraints,
        target_sink=target_sink,
        target_addr=_to_hex(target_addr),
        max_steps=max_steps,
        steps=steps,
        found_states=len(found_states),
        sink_arg_register=arg_register,
        sink_arg_symbolic=arg_symbolic,
        sink_arg_variables=arg_variables,
        source_var_in_sink_arg=var_in_arg,
        error=error,
    )


def _select_target_sink(project: Any, sinks: list[str]) -> tuple[str | None, int | None]:
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    raw_plt = getattr(main_object, "plt", {}) if main_object is not None else {}
    if not isinstance(raw_plt, dict):
        return None, None

    normalized_plt: dict[str, int] = {}
    for name, address in raw_plt.items():
        normalized_name = _normalize_symbol_name(str(name))
        try:
            normalized_plt[normalized_name] = int(address)
        except (TypeError, ValueError):
            continue

    configured = set(sinks)
    for sink in SINK_PRIORITY:
        if sink in configured and sink in normalized_plt:
            return sink, normalized_plt[sink]
    return None, None


def _run_until_addr(simgr: Any, target_addr: int, max_steps: int) -> tuple[bool, int, int]:
    steps = 0
    while True:
        found = [state for state in getattr(simgr, "active", []) if state.addr == target_addr]
        if found:
            return True, steps, len(found)
        if steps >= max_steps:
            return False, steps, 0
        simgr.step()
        steps += 1


def _find_states_until_addr(simgr: Any, target_addr: int, max_steps: int) -> tuple[list[Any], int]:
    steps = 0
    while True:
        found = [state for state in getattr(simgr, "active", []) if state.addr == target_addr]
        if found:
            return found, steps
        if steps >= max_steps:
            return [], steps
        simgr.step()
        steps += 1


def _inspect_sink_argument(
    project: Any,
    found_state: Any,
    symbolic_var: str,
    read_size: int,
) -> tuple[str | None, bool, list[str], bool, str | None]:
    arch_name = getattr(getattr(project, "arch", None), "name", None)
    if arch_name != "AMD64":
        return (
            None,
            False,
            [],
            False,
            f"unsupported arch for sink argument inspection: {arch_name}",
        )

    try:
        arg_ptr = found_state.regs.rdi
        cmd_expr = found_state.memory.load(arg_ptr, read_size)
        sink_arg_symbolic = bool(found_state.solver.symbolic(cmd_expr))
        variables = sorted(str(var) for var in getattr(cmd_expr, "variables", set()))
        source_var_in_sink_arg = any(
            variable_matches_symbolic_name(var, symbolic_var) for var in variables
        )
    except Exception as exc:
        return "rdi", False, [], False, f"failed to inspect sink argument: {exc}"

    return "rdi", sink_arg_symbolic, variables, source_var_in_sink_arg, None


def _add_non_null_prefix_constraints(state: Any, sym: Any, max_len: int) -> list[str]:
    prefix_len = min(4, max_len - 1)
    if prefix_len <= 0:
        return []

    total_bits = (max_len - 1) * 8
    constraints = []
    for index in range(prefix_len):
        high = total_bits - 1 - (index * 8)
        low = high - 7
        state.solver.add(sym[high:low] != 0)

    constraints.append(f"first {prefix_len} symbolic bytes are non-null")
    return constraints


def variable_matches_symbolic_name(var_name: str, symbolic_name: str) -> bool:
    return var_name == symbolic_name or var_name.startswith(symbolic_name + "_")


def _parse_argv_binding(runtime_binding: str) -> int | None:
    match = re.fullmatch(r"argv\[(\d+)\]", runtime_binding)
    if match is None:
        return None
    return int(match.group(1))


def _normalize_symbol_name(symbol: str) -> str:
    if symbol.endswith("@plt"):
        symbol = symbol[: -len("@plt")]
    return symbol.split("@", 1)[0]


def _result(
    binary_path: str,
    argv: list[str],
    max_steps: int,
    *,
    created: bool,
    error: str,
) -> ReachabilityResult:
    return ReachabilityResult(
        binary_path=binary_path,
        created=created,
        reachable=False,
        input_mode="concrete argv",
        argv=argv,
        target_sink=None,
        target_addr=None,
        max_steps=max_steps,
        steps=0,
        found_states=0,
        error=error,
    )


def _symbolic_result(
    binary_path: str,
    max_steps: int,
    *,
    created: bool,
    error: str,
    source_name: str | None = None,
    symbolic_var: str | None = None,
    runtime_binding: str | None = None,
) -> SymbolicReachabilityResult:
    return SymbolicReachabilityResult(
        binary_path=binary_path,
        created=created,
        reachable=False,
        input_mode="symbolic argv",
        source_name=source_name,
        symbolic_var=symbolic_var,
        runtime_binding=runtime_binding,
        input_constraints=[],
        target_sink=None,
        target_addr=None,
        max_steps=max_steps,
        steps=0,
        found_states=0,
        sink_arg_register=None,
        sink_arg_symbolic=False,
        sink_arg_variables=[],
        source_var_in_sink_arg=False,
        error=error,
    )


def _to_hex(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{value:x}"
