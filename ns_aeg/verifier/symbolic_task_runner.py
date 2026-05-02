from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from ns_aeg.reachability import variable_matches_symbolic_name
from ns_aeg.verifier.task_adapter import VerifierTaskConfig

SYMBOLIC_LIMITATIONS = [
    "task symbolic mode is currently scoped to local toy argv-based CGI binaries",
    "sink argument inspection currently supports AMD64 first-argument register rdi",
    "snprintf is modeled with a minimal local SimProcedure for toy source propagation",
    "this is source-to-sink reachability evidence, not exploit verification",
]


def run_symbolic_task_verification(
    config: VerifierTaskConfig,
    candidate: dict[str, Any],
    *,
    max_steps: int = 500,
    sink_arg_read_size: int = 256,
) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidate_id") or "unknown_candidate")
    inputs = candidate.get("inputs")
    if not isinstance(inputs, dict):
        return _unsupported(config, candidate_id, "missing_candidate_inputs")

    binary_path = str(config.binary.get("path") or "")
    if not binary_path or not Path(binary_path).exists():
        return _unsupported(config, candidate_id, f"binary does not exist: {binary_path}")
    if not config.sources:
        return _unsupported(config, candidate_id, "dangerous path task has no sources")
    if not config.sinks:
        return _unsupported(config, candidate_id, "dangerous path task has no sinks")

    source = config.sources[0]
    source_name = str(source.get("name") or "")
    if source_name not in inputs:
        return _unsupported(config, candidate_id, f"missing_candidate_input: {source_name}")

    selected_sink = _select_sink(config.sinks)
    selected_entry = _select_entry(config, selected_sink)
    target_addr = _parse_hex_address(selected_sink.get("address"))
    if target_addr is None:
        return _unsupported(
            config,
            candidate_id,
            f"selected sink has no concrete callsite address: {selected_sink.get('function')}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
        )

    argv_index = _parse_argv_binding(str(source.get("carrier") or ""))
    if argv_index is None or argv_index == 0:
        return _unsupported(
            config,
            candidate_id,
            f"unsupported source carrier: {source.get('carrier')}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
        )

    candidate_value = str(inputs[source_name])
    max_len = _source_max_len(source, candidate_value)
    symbolic_name = str(source.get("symbolic") or f"sym_{source_name}")

    try:
        import angr
        import claripy
    except ImportError as exc:
        return _unsupported(
            config,
            candidate_id,
            f"angr symbolic backend is unavailable: {exc}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
        )

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        _install_toy_hooks(project, angr, max(len(candidate_value) + 1, 2))
        sym = claripy.BVS(symbolic_name, max_len * 8)
        argv_value = sym.concat(claripy.BVV(0, 8))
        argv: list[Any] = ["" for _ in range(argv_index + 1)]
        argv[0] = binary_path
        argv[argv_index] = argv_value

        state = project.factory.full_init_state(args=argv)
        constraints_summary = _constrain_symbol_to_candidate(
            state,
            sym,
            candidate_value,
            max_len,
        )
        simgr = project.factory.simulation_manager(state)
        found_states, steps, timed_out = _find_states_until_addr(simgr, target_addr, max_steps)
    except Exception as exc:
        return _unsupported(
            config,
            candidate_id,
            f"failed to run symbolic task verification: {exc}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
        )

    if timed_out:
        return _symbolic_result(
            status="timeout",
            config=config,
            candidate_id=candidate_id,
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            sink_reached="unknown",
            source_bound="unknown",
            marker_observed="unknown",
            path_status="timeout",
            constraints_summary=constraints_summary,
            reason=f"symbolic exploration timed out after {max_steps} steps",
            steps=steps,
            found_states=0,
        )

    if not found_states:
        return _symbolic_result(
            status="unsat",
            config=config,
            candidate_id=candidate_id,
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            sink_reached=False,
            source_bound="unknown",
            marker_observed="unknown",
            path_status="unsat",
            constraints_summary=constraints_summary,
            reason="selected sink callsite was not reached",
            steps=steps,
            found_states=0,
        )

    sink_arg = _inspect_amd64_sink_arg(
        project,
        found_states[0],
        symbolic_name,
        config.benign_marker,
        sink_arg_read_size,
    )
    source_bound = bool(sink_arg["source_var_in_sink_arg"])
    marker_observed = bool(sink_arg["marker_observed"])
    status = "sat" if source_bound and marker_observed else "unknown"
    reason = (
        "selected sink reached and benign marker/source evidence observed in sink argument"
        if status == "sat"
        else "selected sink reached, but source/marker evidence in sink argument is incomplete"
    )
    limitations = list(SYMBOLIC_LIMITATIONS)
    if status == "unknown":
        limitations.append(
            "sink reached, but current argument inspection did not prove both source binding and marker observation"
        )

    result = _symbolic_result(
        status=status,
        config=config,
        candidate_id=candidate_id,
        selected_sink=selected_sink,
        selected_entry=selected_entry,
        sink_reached=True,
        source_bound=source_bound,
        marker_observed=marker_observed,
        path_status=status,
        constraints_summary=constraints_summary,
        reason=reason,
        steps=steps,
        found_states=len(found_states),
        limitations=limitations,
    )
    result["sink_argument"] = sink_arg
    return result


def _select_sink(sinks: list[dict[str, Any]]) -> dict[str, Any]:
    for sink in sinks:
        if sink.get("type") == "command_execution" and sink.get("function") == "system":
            return dict(sink)
    for sink in sinks:
        if sink.get("type") == "command_execution":
            return dict(sink)
    return dict(sinks[0])


def _select_entry(config: VerifierTaskConfig, selected_sink: dict[str, Any]) -> dict[str, Any]:
    entry = dict(config.entry)
    if entry.get("address"):
        return entry
    callers = selected_sink.get("callers")
    caller_name = callers[0] if isinstance(callers, list) and callers else None
    return {
        "function": caller_name,
        "address": None,
    }


def _find_states_until_addr(simgr: Any, target_addr: int, max_steps: int) -> tuple[list[Any], int, bool]:
    steps = 0
    while True:
        found = [state for state in getattr(simgr, "active", []) if state.addr == target_addr]
        if found:
            return found, steps, False
        if steps >= max_steps:
            return [], steps, True
        simgr.step(num_inst=1)
        steps += 1


def _install_toy_hooks(project: Any, angr: Any, copy_size: int) -> None:
    class ToySnprintf(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, size: Any, fmt: Any, value: Any) -> Any:  # noqa: ANN401
            data = self.state.memory.load(value, copy_size)
            self.state.memory.store(dst, data)
            return copy_size - 1

    try:
        project.hook_symbol("snprintf", ToySnprintf(), replace=True)
    except Exception:
        pass

    plt = getattr(getattr(project.loader, "main_object", None), "plt", {})
    address = plt.get("snprintf") if isinstance(plt, dict) else None
    if address is not None:
        try:
            project.hook(int(address), ToySnprintf(), replace=True)
        except Exception:
            pass


def _inspect_amd64_sink_arg(
    project: Any,
    state: Any,
    symbolic_name: str,
    benign_marker: str,
    read_size: int,
) -> dict[str, Any]:
    arch_name = getattr(getattr(project, "arch", None), "name", None)
    if arch_name != "AMD64":
        return {
            "arg_register": None,
            "arg_symbolic": False,
            "arg_variables": [],
            "source_var_in_sink_arg": False,
            "marker_observed": "unknown",
            "concrete_preview": None,
            "error": f"unsupported arch for sink argument inspection: {arch_name}",
        }

    try:
        arg_ptr = state.regs.rdi
        arg_expr = state.memory.load(arg_ptr, read_size)
        variables = sorted(str(var) for var in getattr(arg_expr, "variables", set()))
        source_var_in_arg = any(
            variable_matches_symbolic_name(var, symbolic_name) for var in variables
        )
        concrete = state.solver.eval(arg_expr, cast_to=bytes)
        concrete = concrete.split(b"\x00", 1)[0]
        text = concrete.decode("utf-8", errors="replace")
        return {
            "arg_register": "rdi",
            "arg_symbolic": bool(state.solver.symbolic(arg_expr)),
            "arg_variables": variables,
            "source_var_in_sink_arg": source_var_in_arg,
            "marker_observed": benign_marker in text if benign_marker else False,
            "concrete_preview": _safe_preview(text),
            "error": None,
        }
    except Exception as exc:
        return {
            "arg_register": "rdi",
            "arg_symbolic": False,
            "arg_variables": [],
            "source_var_in_sink_arg": False,
            "marker_observed": "unknown",
            "concrete_preview": None,
            "error": f"failed to inspect sink argument: {exc}",
        }


def _constrain_symbol_to_candidate(
    state: Any,
    sym: Any,
    candidate_value: str,
    max_len: int,
) -> dict[str, Any]:
    raw = candidate_value.encode("utf-8", errors="replace")[:max_len]
    padded = raw.ljust(max_len, b"\x00")
    total_bits = max_len * 8
    for index, byte in enumerate(padded):
        high = total_bits - 1 - (index * 8)
        low = high - 7
        state.solver.add(sym[high:low] == byte)
    return {
        "candidate_input_len": len(candidate_value),
        "symbolic_bytes": max_len,
        "constraints_added": max_len,
        "candidate_value_truncated": len(candidate_value.encode("utf-8", errors="replace")) > max_len,
    }


def _source_max_len(source: dict[str, Any], candidate_value: str) -> int:
    configured = source.get("max_len")
    try:
        configured_int = int(configured)
    except (TypeError, ValueError):
        configured_int = 0
    return max(configured_int, len(candidate_value.encode("utf-8", errors="replace")), 1)


def _parse_argv_binding(carrier: str) -> int | None:
    match = re.fullmatch(r"argv\[(\d+)\]", carrier)
    if match is None:
        return None
    return int(match.group(1))


def _parse_hex_address(value: Any) -> int | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def _safe_preview(value: str, max_len: int = 96) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + "...<truncated>"


def _unsupported(
    config: VerifierTaskConfig,
    candidate_id: str,
    reason: str,
    *,
    selected_sink: dict[str, Any] | None = None,
    selected_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _symbolic_result(
        status="unsupported",
        config=config,
        candidate_id=candidate_id,
        selected_sink=selected_sink,
        selected_entry=selected_entry,
        sink_reached="unknown",
        source_bound="unknown",
        marker_observed="unknown",
        path_status="unsupported",
        constraints_summary={},
        reason=reason,
        steps=0,
        found_states=0,
        limitations=SYMBOLIC_LIMITATIONS,
    )


def _symbolic_result(
    *,
    status: str,
    config: VerifierTaskConfig,
    candidate_id: str,
    selected_sink: dict[str, Any] | None,
    selected_entry: dict[str, Any] | None,
    sink_reached: bool | str,
    source_bound: bool | str,
    marker_observed: bool | str,
    path_status: str,
    constraints_summary: dict[str, Any],
    reason: str,
    steps: int,
    found_states: int,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "task_id": config.task_id,
        "candidate_id": candidate_id,
        "binary": {
            "path": config.binary.get("path"),
            "name": config.binary.get("name"),
            "arch": config.binary.get("arch"),
        },
        "entry": dict(config.entry),
        "checked_sources": _checked_sources(config),
        "checked_sinks": _checked_sinks(config),
        "oracle": config.oracle,
        "benign_marker": config.benign_marker,
        "reason": reason,
        "limitations": list(limitations or SYMBOLIC_LIMITATIONS),
        "mode": "symbolic_task",
        "executed": False,
        "backend": "angr",
        "sink_reached": sink_reached,
        "source_bound": source_bound,
        "marker_observed": marker_observed,
        "selected_sink": selected_sink,
        "selected_entry": selected_entry,
        "path_status": path_status,
        "constraints_summary": constraints_summary,
        "steps": steps,
        "found_states": found_states,
    }


def _checked_sources(config: VerifierTaskConfig) -> list[dict[str, Any]]:
    return [
        {
            "source_id": source.get("source_id"),
            "name": source.get("name"),
            "carrier": source.get("carrier"),
            "symbolic": source.get("symbolic"),
        }
        for source in config.sources
    ]


def _checked_sinks(config: VerifierTaskConfig) -> list[dict[str, Any]]:
    return [
        {
            "sink_id": sink.get("sink_id"),
            "function": sink.get("function"),
            "address": sink.get("address"),
            "arg_index": sink.get("arg_index"),
            "callers": sink.get("callers", []),
            "external_address": sink.get("external_address"),
        }
        for sink in config.sinks
    ]
