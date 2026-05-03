from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from ns_aeg.verifier.sink_argument_inspector import argument_register_for_arch, inspect_sink_argument
from ns_aeg.verifier.sink_policy import evaluate_sink_policy
from ns_aeg.verifier.task_adapter import VerifierTaskConfig
from ns_aeg.reachability import variable_matches_symbolic_name

FORMAT_WRITES_KEY = "ns_aeg_format_writes"

SYMBOLIC_LIMITATIONS = [
    "task symbolic mode is currently scoped to local toy argv-based CGI binaries",
    "sink argument inspection uses ABI register mapping; stack arguments and some architectures are partial/unsupported",
    "snprintf/sprintf/memcpy are modeled with minimal local SimProcedures for toy source propagation",
    "this is source-to-sink reachability evidence, not exploit verification",
]

STARTUP_MODES = {"auto", "full_init", "direct_main"}


def run_symbolic_task_verification(
    config: VerifierTaskConfig,
    candidate: dict[str, Any],
    *,
    max_steps: int = 2000,
    sink_arg_read_size: int = 256,
    startup_mode: str = "auto",
    allow_direct_main_for_non_toy: bool = False,
) -> dict[str, Any]:
    requested_startup_mode = _normalize_startup_mode(startup_mode)
    if requested_startup_mode not in STARTUP_MODES:
        return _unsupported(
            config,
            str(candidate.get("candidate_id") or "unknown_candidate"),
            f"unsupported startup mode: {startup_mode}",
            startup_debug=_startup_debug(requested_startup_mode=startup_mode),
        )

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
    direct_main_policy = _direct_main_policy(config, allow_direct_main_for_non_toy)
    if requested_startup_mode == "direct_main" and not direct_main_policy["allowed"]:
        return _unsupported(
            config,
            candidate_id,
            f"direct_main startup disabled by safe startup policy: {direct_main_policy['reason']}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            startup_debug=_startup_debug(
                requested_startup_mode=requested_startup_mode,
                selected_startup_mode=None,
                direct_main_policy_reason=direct_main_policy["reason"],
            ),
        )
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
        sink_address_candidates = _sink_address_candidates(project, selected_sink, target_addr)
        sym = claripy.BVS(symbolic_name, max_len * 8)
        argv_value = sym.concat(claripy.BVV(0, 8))
        attempt = _run_attempts(
            project=project,
            config=config,
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            sink_address_candidates=sink_address_candidates,
            sym=sym,
            argv_value=argv_value,
            argv_index=argv_index,
            binary_path=binary_path,
            candidate_value=candidate_value,
            max_len=max_len,
            max_steps=max_steps,
            requested_startup_mode=requested_startup_mode,
            allow_direct_main_for_non_toy=allow_direct_main_for_non_toy,
        )
    except Exception as exc:
        return _unsupported(
            config,
            candidate_id,
            f"failed to run symbolic task verification: {exc}",
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            startup_debug=_startup_debug(requested_startup_mode=requested_startup_mode),
        )

    constraints_summary = attempt.get("constraints_summary", {})
    found_states = attempt.get("found_states", [])
    steps = int(attempt.get("steps") or 0)
    reachability_debug = dict(attempt.get("reachability_debug") or {})
    startup_debug = dict(attempt.get("startup_debug") or {})

    if attempt.get("unsupported_reason"):
        return _unsupported(
            config,
            candidate_id,
            str(attempt["unsupported_reason"]),
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            startup_debug=startup_debug,
            reachability_debug=reachability_debug,
        )

    if attempt.get("timed_out"):
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
            reachability_debug=reachability_debug,
            startup_debug=startup_debug,
        )

    if not found_states:
        reason = str(attempt.get("result_reason") or "selected sink callsite was not reached")
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
            reason=reason,
            steps=steps,
            found_states=0,
            reachability_debug=reachability_debug,
            startup_debug=startup_debug,
        )

    matched_sink_address = _state_addr(found_states[0])
    matched_candidate = sink_address_candidates.get(matched_sink_address)
    if matched_candidate is not None:
        selected_sink["matched_address"] = matched_candidate["address"]
        selected_sink["match_reason"] = matched_candidate["reason"]
    reachability_debug["matched_sink_address"] = _hex_or_none(matched_sink_address)
    reachability_debug["match_reason"] = (
        matched_candidate["reason"] if matched_candidate is not None else "matched active state address"
    )
    reachability_debug["reason"] = "matched sink candidate address"
    sink_arg = inspect_sink_argument(
        found_states[0],
        project,
        selected_sink,
        selected_sink.get("arg_index"),
        source_symbolic_name=symbolic_name,
        benign_marker=config.benign_marker,
        read_size=sink_arg_read_size,
    )
    format_flow = _format_flow_evidence(
        found_states[0],
        selected_sink=selected_sink,
        sink_argument=sink_arg,
        source_symbolic_name=symbolic_name,
        benign_marker=config.benign_marker,
    )
    sink_policy = evaluate_sink_policy(selected_sink, sink_arg, _policy_task(config), candidate, found_states[0])
    source_bound = sink_policy.get("source_reaches_sink")
    marker_observed = sink_policy.get("marker_reaches_sink")
    policy_status = sink_policy.get("policy_status")
    if policy_status == "positive_evidence":
        status = "sat"
        base_reason = "selected sink reached and sink policy found positive source/marker evidence"
    elif policy_status == "negative_evidence":
        status = "unsat"
        base_reason = "selected sink reached, but sink policy found negative source-to-sink evidence"
    else:
        status = "unknown"
        base_reason = "selected sink reached, but sink policy evidence is inconclusive"
    reason = _startup_adjusted_reason(base_reason, startup_debug)
    limitations = list(SYMBOLIC_LIMITATIONS)
    limitations.extend(str(item) for item in sink_arg.get("limitations", []) if item)
    limitations.extend(str(item) for item in sink_policy.get("limitations", []) if item)
    limitations.extend(str(item) for item in format_flow.get("limitations", []) if item)
    limitations.extend(str(item) for item in startup_debug.get("limitations", []) if item)
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
        reason=f"{reason}: {sink_policy.get('reason')}",
        steps=steps,
        found_states=len(found_states),
        limitations=limitations,
        reachability_debug=reachability_debug,
        startup_debug=startup_debug,
    )
    result["sink_argument"] = sink_arg
    result["sink_policy"] = sink_policy
    result["format_flow"] = format_flow
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


def _normalize_startup_mode(value: str) -> str:
    return value.replace("-", "_")


def _find_states_until_addr(simgr: Any, target_addr: int, max_steps: int) -> tuple[list[Any], int, bool]:
    found, steps, timed_out, _debug = _find_states_until_any_addr(
        simgr,
        {target_addr: {"address": _hex(target_addr), "reason": "exact_selected_sink_address"}},
        max_steps,
    )
    return found, steps, timed_out


def _run_attempts(
    *,
    project: Any,
    config: VerifierTaskConfig,
    selected_sink: dict[str, Any],
    selected_entry: dict[str, Any],
    sink_address_candidates: dict[int, dict[str, Any]],
    sym: Any,
    argv_value: Any,
    argv_index: int,
    binary_path: str,
    candidate_value: str,
    max_len: int,
    max_steps: int,
    requested_startup_mode: str,
    allow_direct_main_for_non_toy: bool,
) -> dict[str, Any]:
    attempted: list[dict[str, Any]] = []
    direct_main_policy = _direct_main_policy(config, allow_direct_main_for_non_toy)

    def run(mode: str) -> dict[str, Any]:
        result = _run_single_startup_mode(
            project=project,
            config=config,
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            sink_address_candidates=sink_address_candidates,
            sym=sym,
            argv_value=argv_value,
            argv_index=argv_index,
            binary_path=binary_path,
            candidate_value=candidate_value,
            max_len=max_len,
            max_steps=max_steps,
            startup_mode=mode,
        )
        attempted.append(result)
        return result

    if requested_startup_mode == "full_init":
        selected = run("full_init")
        return _attach_startup_debug(selected, requested_startup_mode, attempted, selected_mode="full_init")

    if requested_startup_mode == "direct_main":
        selected = run("direct_main")
        return _attach_startup_debug(selected, requested_startup_mode, attempted, selected_mode="direct_main")

    full = run("full_init")
    if full.get("found_states") or full.get("timed_out"):
        return _attach_startup_debug(full, requested_startup_mode, attempted, selected_mode="full_init")

    if not _should_try_direct_main(project, selected_entry, full):
        return _attach_startup_debug(full, requested_startup_mode, attempted, selected_mode="full_init")

    if not direct_main_policy["allowed"]:
        return _attach_startup_debug(
            full,
            requested_startup_mode,
            attempted,
            selected_mode="full_init",
            direct_main_policy_reason=direct_main_policy["reason"],
        )

    direct = run("direct_main")
    if direct.get("found_states"):
        return _attach_startup_debug(
            direct,
            requested_startup_mode,
            attempted,
            selected_mode="direct_main",
            fallback_reason="full_init failed to reach sink; direct_main fallback reached sink",
        )

    return _attach_startup_debug(
        direct,
        requested_startup_mode,
        attempted,
        selected_mode="direct_main",
        fallback_reason="full_init failed to reach sink; direct_main fallback also failed",
        result_reason="full_init failed to reach sink; direct_main fallback also failed",
    )


def _run_single_startup_mode(
    *,
    project: Any,
    config: VerifierTaskConfig,
    selected_sink: dict[str, Any],
    selected_entry: dict[str, Any],
    sink_address_candidates: dict[int, dict[str, Any]],
    sym: Any,
    argv_value: Any,
    argv_index: int,
    binary_path: str,
    candidate_value: str,
    max_len: int,
    max_steps: int,
    startup_mode: str,
) -> dict[str, Any]:
    try:
        if startup_mode == "full_init":
            state, argv_summary = _full_init_state(
                project,
                binary_path=binary_path,
                argv_index=argv_index,
                argv_value=argv_value,
            )
        elif startup_mode == "direct_main":
            state, argv_summary = _direct_main_state(
                project,
                selected_entry=selected_entry,
                binary_path=binary_path,
                argv_index=argv_index,
                argv_value=argv_value,
            )
        else:
            raise ValueError(f"unsupported startup mode: {startup_mode}")

        constraints_summary = _constrain_symbol_to_candidate(
            state,
            sym,
            candidate_value,
            max_len,
        )
        simgr = project.factory.simulation_manager(state)
        found_states, steps, timed_out, reachability_debug = _find_states_until_any_addr(
            simgr,
            sink_address_candidates,
            max_steps,
            project=project,
            config=config,
            selected_sink=selected_sink,
            selected_entry=selected_entry,
            startup_mode=startup_mode,
        )
        return {
            "startup_mode": startup_mode,
            "found_states": found_states,
            "steps": steps,
            "timed_out": timed_out,
            "reachability_debug": reachability_debug,
            "constraints_summary": constraints_summary,
            "status": _attempt_status(found_states, timed_out),
            "argv_model_summary": argv_summary,
        }
    except Exception as exc:
        return {
            "startup_mode": startup_mode,
            "found_states": [],
            "steps": 0,
            "timed_out": False,
            "reachability_debug": {},
            "constraints_summary": {},
            "status": "unsupported",
            "unsupported_reason": f"{startup_mode} startup failed: {exc}",
            "argv_model_summary": {},
        }


def _full_init_state(
    project: Any,
    *,
    binary_path: str,
    argv_index: int,
    argv_value: Any,
) -> tuple[Any, dict[str, Any]]:
    argv: list[Any] = ["" for _ in range(argv_index + 1)]
    argv[0] = binary_path
    argv[argv_index] = argv_value
    state = project.factory.full_init_state(args=argv)
    return state, {
        "mode": "full_init",
        "argc": argv_index + 1,
        "symbolic_argv_index": argv_index,
        "argv0": binary_path,
    }


def _direct_main_state(
    project: Any,
    *,
    selected_entry: dict[str, Any],
    binary_path: str,
    argv_index: int,
    argv_value: Any,
) -> tuple[Any, dict[str, Any]]:
    main_addr = _parse_hex_address(selected_entry.get("address"))
    if main_addr is None or selected_entry.get("function") not in {None, "main"}:
        raise ValueError("missing_main_entry")

    argc = argv_index + 1
    state = project.factory.call_state(main_addr, argc, 0)
    ptr_size = int(getattr(project.arch, "bytes", 4))
    argv_ptrs = []
    for index in range(argc):
        if index == 0:
            value = binary_path.encode("utf-8", errors="replace") + b"\x00"
            ptr = _state_heap_allocate(state, len(value))
            state.memory.store(ptr, value)
        elif index == argv_index:
            ptr = _state_heap_allocate(state, max((_bit_length(argv_value) // 8), 1))
            state.memory.store(ptr, argv_value)
        else:
            value = b"\x00"
            ptr = _state_heap_allocate(state, len(value))
            state.memory.store(ptr, value)
        argv_ptrs.append(ptr)

    argv_array = _state_heap_allocate(state, (argc + 1) * ptr_size)
    for index, ptr in enumerate(argv_ptrs):
        state.memory.store(
            argv_array + (index * ptr_size),
            ptr,
            size=ptr_size,
            endness=project.arch.memory_endness,
        )
    state.memory.store(
        argv_array + (argc * ptr_size),
        0,
        size=ptr_size,
        endness=project.arch.memory_endness,
    )

    # `call_state` materializes argument registers before argv memory exists; update argc/argv
    # explicitly without changing the entry address or skipping any code inside main.
    _set_register_argument(state, project, 0, argc)
    _set_register_argument(state, project, 1, argv_array)
    return state, {
        "mode": "direct_main",
        "argc": argc,
        "symbolic_argv_index": argv_index,
        "argv_pointer": _hex(int(state.solver.eval(argv_array))),
        "main_address": _hex(main_addr),
    }


def _set_register_argument(state: Any, project: Any, arg_index: int, value: int) -> None:
    register = argument_register_for_arch(_project_arch_name(project), arg_index)
    if register is None:
        raise ValueError(
            f"unsupported direct_main register argument for arch={_project_arch_name(project)} arg{arg_index}"
        )
    setattr(state.regs, register, value)


def _state_heap_allocate(state: Any, size: int) -> int:
    ptr = state.heap.allocate(size)
    return int(state.solver.eval(ptr))


def _bit_length(value: Any) -> int:
    raw = getattr(value, "length", None)
    if isinstance(raw, int):
        return raw
    try:
        return int(value.size())
    except Exception:
        return 8


def _attempt_status(found_states: list[Any], timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    if found_states:
        return "reached"
    return "unsat"


def _attach_startup_debug(
    selected: dict[str, Any],
    requested_startup_mode: str,
    attempted: list[dict[str, Any]],
    *,
    selected_mode: str,
    fallback_reason: str | None = None,
    result_reason: str | None = None,
    direct_main_policy_reason: str | None = None,
) -> dict[str, Any]:
    selected = dict(selected)
    selected["startup_debug"] = _startup_debug(
        requested_startup_mode=requested_startup_mode,
        attempted=attempted,
        selected_startup_mode=selected_mode,
        fallback_reason=fallback_reason,
        direct_main_policy_reason=direct_main_policy_reason,
    )
    if result_reason:
        selected["result_reason"] = result_reason
    return selected


def _startup_debug(
    *,
    requested_startup_mode: str,
    attempted: list[dict[str, Any]] | None = None,
    selected_startup_mode: str | None = None,
    fallback_reason: str | None = None,
    direct_main_policy_reason: str | None = None,
) -> dict[str, Any]:
    attempted = attempted or []
    by_mode = {str(item.get("startup_mode")): item for item in attempted}
    selected = by_mode.get(selected_startup_mode or "")
    return {
        "requested_startup_mode": requested_startup_mode,
        "attempted_modes": [str(item.get("startup_mode")) for item in attempted],
        "selected_startup_mode": selected_startup_mode,
        "fallback_reason": fallback_reason,
        "direct_main_policy_reason": direct_main_policy_reason,
        "full_init_status": _attempt_status_label(by_mode.get("full_init")),
        "direct_main_status": _attempt_status_label(by_mode.get("direct_main")),
        "main_address": _selected_main_address(selected),
        "argv_model_summary": dict(selected.get("argv_model_summary") or {}) if selected else {},
        "limitations": _startup_limitations(selected_startup_mode, fallback_reason, direct_main_policy_reason),
    }


def _attempt_status_label(attempt: dict[str, Any] | None) -> str | None:
    if attempt is None:
        return None
    if attempt.get("unsupported_reason"):
        return "unsupported"
    return str(attempt.get("status") or "unknown")


def _selected_main_address(attempt: dict[str, Any] | None) -> str | None:
    if not attempt:
        return None
    summary = attempt.get("argv_model_summary")
    if isinstance(summary, dict) and summary.get("main_address"):
        return str(summary["main_address"])
    debug = attempt.get("reachability_debug")
    if isinstance(debug, dict):
        return debug.get("entry_address")
    return None


def _startup_limitations(
    selected_startup_mode: str | None,
    fallback_reason: str | None,
    direct_main_policy_reason: str | None = None,
) -> list[str]:
    limitations: list[str] = []
    if selected_startup_mode == "direct_main":
        limitations.append(
            "direct_main startup begins at task.entry/main and does not validate full program startup"
        )
    if fallback_reason:
        limitations.append(str(fallback_reason))
    if direct_main_policy_reason:
        limitations.append(str(direct_main_policy_reason))
    return limitations


def _startup_adjusted_reason(reason: str, startup_debug: dict[str, Any]) -> str:
    fallback = startup_debug.get("fallback_reason")
    if fallback:
        return f"{fallback}; {reason}"
    return reason


def _should_try_direct_main(
    project: Any,
    selected_entry: dict[str, Any],
    full_attempt: dict[str, Any],
) -> bool:
    if full_attempt.get("found_states") or full_attempt.get("timed_out"):
        return False
    if _parse_hex_address(selected_entry.get("address")) is None:
        return False
    return _normalize_arch_for_debug(_project_arch_name(project)) == "MIPS32"


def _direct_main_policy(config: VerifierTaskConfig, allow_direct_main_for_non_toy: bool) -> dict[str, Any]:
    scope = _normalize_scope(getattr(config, "scope", "unknown"))
    if scope == "toy_benchmark":
        return {"allowed": True, "scope": scope, "reason": None}
    if getattr(config, "allow_direct_main", False):
        return {"allowed": True, "scope": scope, "reason": "task allow_direct_main=true"}
    if allow_direct_main_for_non_toy:
        return {"allowed": True, "scope": scope, "reason": "CLI allow_direct_main_for_non_toy=true"}
    return {
        "allowed": False,
        "scope": scope,
        "reason": f"direct_main requires explicit opt-in for scope={scope}",
    }


def _normalize_scope(value: Any) -> str:
    scope = str(value or "unknown").strip().lower().replace("-", "_")
    if scope in {"toy", "toy_cgi", "toy_benchmark", "benchmark"}:
        return "toy_benchmark"
    if scope in {"firmware", "real_firmware", "non_toy"}:
        return "firmware" if scope == "real_firmware" else scope
    return scope or "unknown"


def _evidence_strength(config: VerifierTaskConfig, startup_debug: dict[str, Any] | None) -> dict[str, Any]:
    startup_debug = startup_debug if isinstance(startup_debug, dict) else {}
    selected_mode = startup_debug.get("selected_startup_mode")
    scope = _normalize_scope(getattr(config, "scope", "unknown"))
    if selected_mode == "full_init":
        return {
            "startup_mode": "full_init",
            "level": "full_program_startup_symbolic",
            "scope": scope,
            "description": "Symbolic reachability began from the program initialization path.",
            "can_claim_full_startup_proof": True,
            "requires_explicit_opt_in": False,
        }
    if selected_mode == "direct_main":
        return {
            "startup_mode": "direct_main",
            "level": "direct_main_symbolic",
            "scope": scope,
            "description": "Symbolic reachability began at task.entry/main and bypassed startup/loader modeling.",
            "can_claim_full_startup_proof": False,
            "requires_explicit_opt_in": scope != "toy_benchmark",
        }
    return {
        "startup_mode": str(selected_mode or "unknown"),
        "level": "unknown",
        "scope": scope,
        "description": "Startup evidence strength is not available.",
        "can_claim_full_startup_proof": False,
        "requires_explicit_opt_in": False,
    }


def _policy_task(config: VerifierTaskConfig) -> dict[str, Any]:
    return {
        "task_id": config.task_id,
        "binary": dict(config.binary),
        "entry": dict(config.entry),
        "sources": list(config.sources),
        "sinks": list(config.sinks),
        "oracle": config.oracle,
        "benign_marker": config.benign_marker,
    }


def _find_states_until_any_addr(
    simgr: Any,
    target_candidates: dict[int, dict[str, Any]],
    max_steps: int,
    *,
    project: Any | None = None,
    config: VerifierTaskConfig | None = None,
    selected_sink: dict[str, Any] | None = None,
    selected_entry: dict[str, Any] | None = None,
    startup_mode: str = "full_init",
) -> tuple[list[Any], int, bool, dict[str, Any]]:
    steps = 0
    target_addrs = set(target_candidates)
    recent_bbl_addrs: list[str] = []
    reached_near_sink: set[int] = set()
    main_addr = _parse_hex_address((selected_entry or {}).get("address"))
    reached_main = False
    debug = _reachability_debug(
        project=project,
        config=config,
        selected_sink=selected_sink,
        selected_entry=selected_entry,
        target_candidates=target_candidates,
        steps=steps,
        reason="search started",
        startup_mode=startup_mode,
        reached_main=reached_main,
    )

    while True:
        active = list(getattr(simgr, "active", []))
        active_addrs = {_state_addr(state) for state in active if _state_addr(state) is not None}
        if main_addr is not None and main_addr in active_addrs:
            reached_main = True
        found = [state for state in active if _state_addr(state) in target_addrs]
        reached_near_sink.update(_near_sink_addresses(active_addrs, target_addrs))
        recent_bbl_addrs.extend(_recent_bbl_addrs(active))
        if main_addr is not None and _hex(main_addr) in recent_bbl_addrs:
            reached_main = True
        recent_bbl_addrs = recent_bbl_addrs[-32:]
        if found:
            matched = _state_addr(found[0])
            debug.update(
                _reachability_debug(
                    project=project,
                    config=config,
                    selected_sink=selected_sink,
                    selected_entry=selected_entry,
                    target_candidates=target_candidates,
                    steps=steps,
                    reason="matched sink candidate address",
                    reached_addresses_near_sink=sorted(reached_near_sink),
                    recent_bbl_addrs=recent_bbl_addrs,
                    simgr=simgr,
                    matched_sink_address=matched,
                    match_reason=target_candidates.get(matched, {}).get("reason"),
                    startup_mode=startup_mode,
                    reached_main=reached_main,
                )
            )
            return found, steps, False, debug
        if not active:
            debug.update(
                _reachability_debug(
                    project=project,
                    config=config,
                    selected_sink=selected_sink,
                    selected_entry=selected_entry,
                    target_candidates=target_candidates,
                    steps=steps,
                    reason="no active states remain before reaching sink candidates",
                    reached_addresses_near_sink=sorted(reached_near_sink),
                    recent_bbl_addrs=recent_bbl_addrs,
                    simgr=simgr,
                    startup_mode=startup_mode,
                    reached_main=reached_main,
                )
            )
            return [], steps, False, debug
        if steps >= max_steps:
            debug.update(
                _reachability_debug(
                    project=project,
                    config=config,
                    selected_sink=selected_sink,
                    selected_entry=selected_entry,
                    target_candidates=target_candidates,
                    steps=steps,
                    reason=f"symbolic exploration timed out after {max_steps} steps",
                    reached_addresses_near_sink=sorted(reached_near_sink),
                    recent_bbl_addrs=recent_bbl_addrs,
                    simgr=simgr,
                    startup_mode=startup_mode,
                    reached_main=reached_main,
                )
            )
            return [], steps, True, debug
        _step_simgr(simgr, project, startup_mode=startup_mode)
        steps += 1


def _step_simgr(simgr: Any, project: Any | None, *, startup_mode: str) -> None:
    # MIPS single-instruction stepping can fail on branch/delay-slot decoding in angr
    # startup stubs (for example `bal` in __start). Block-level stepping is the
    # conservative repair: it does not jump to main/sink, but lets angr lift the
    # complete basic block including delay-slot semantics.
    if _normalize_arch_for_debug(_project_arch_name(project)) == "MIPS32":
        simgr.step()
    else:
        simgr.step(num_inst=1)


def _install_toy_hooks(project: Any, angr: Any, copy_size: int) -> None:
    class FormatWriteRecorder:
        format_function = "format"

        def _copy_and_record(self, dst: Any, value: Any, *, size: Any | None = None) -> int:  # noqa: ANN401
            copy_length, size_value, bounded, limitations = _bounded_copy_length(self.state, size, copy_size)
            data = None
            if copy_length > 0:
                data = self.state.memory.load(value, copy_length)
                self.state.memory.store(dst, data)
            if copy_length >= 0:
                try:
                    self.state.memory.store(dst + copy_length, b"\x00")
                except Exception:
                    pass
            self._record_format_write(
                dst,
                data,
                copy_length=copy_length,
                requested_length=copy_size,
                size_value=size_value,
                bounded=bounded,
                limitations=limitations,
            )
            return copy_length

        def _record_format_write(
            self,
            dst: Any,
            data: Any,
            *,
            copy_length: int,
            requested_length: int,
            size_value: int | str | None,
            bounded: bool,
            limitations: list[str],
        ) -> None:  # noqa: ANN401
            writes = list(self.state.globals.get(FORMAT_WRITES_KEY, []))
            callsite = None
            try:
                callsite = _hex(int(self.state.solver.eval(self.state.history.addr)))
            except Exception:
                callsite = _hex_or_none(_state_addr(self.state))
            dst_address = None
            try:
                dst_address = _hex(int(self.state.solver.eval(dst)))
            except Exception:
                dst_address = None
            writes.append(
                {
                    "flow_kind": "format_write",
                    "format_sink": self.format_function,
                    "format_function": self.format_function,
                    "format_callsite": callsite,
                    "dst_buffer": dst_address,
                    "size_value": size_value,
                    "bounded": bounded,
                    "copy_length": copy_length,
                    "requested_length": requested_length,
                    "written_variables": sorted(str(var) for var in getattr(data, "variables", set())),
                    "source_or_marker_written": "unknown",
                    "flows_to_command_sink": "unknown",
                    "limitations": limitations + [
                        "minimal toy format SimProcedure copies the formatted source argument into dst",
                    ],
                }
            )
            self.state.globals[FORMAT_WRITES_KEY] = writes

    class ToySnprintf(FormatWriteRecorder, angr.SimProcedure):  # type: ignore[misc]
        format_function = "snprintf"

        def run(self, dst: Any, size: Any, fmt: Any, value: Any) -> Any:  # noqa: ANN401
            del fmt
            return self._copy_and_record(dst, value, size=size)

    class ToySprintf(FormatWriteRecorder, angr.SimProcedure):  # type: ignore[misc]
        format_function = "sprintf"

        def run(self, dst: Any, fmt: Any, value: Any) -> Any:  # noqa: ANN401
            del fmt
            return self._copy_and_record(dst, value, size=None)

    class ToyMemcpy(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, src: Any, n: Any) -> Any:  # noqa: ANN401
            copy_length, size_value, bounded, limitations = _bounded_memcpy_length(self.state, n, copy_size)
            data = None
            if copy_length > 0:
                data = self.state.memory.load(src, copy_length)
                self.state.memory.store(dst, data)
            self._record_memory_copy(dst, data, copy_length, size_value, bounded, limitations)
            return dst

        def _record_memory_copy(
            self,
            dst: Any,
            data: Any,
            copy_length: int,
            size_value: int | str | None,
            bounded: bool,
            limitations: list[str],
        ) -> None:  # noqa: ANN401
            writes = list(self.state.globals.get(FORMAT_WRITES_KEY, []))
            try:
                callsite = _hex(int(self.state.solver.eval(self.state.history.addr)))
            except Exception:
                callsite = _hex_or_none(_state_addr(self.state))
            try:
                dst_address = _hex(int(self.state.solver.eval(dst)))
            except Exception:
                dst_address = None
            writes.append(
                {
                    "flow_kind": "memory_copy",
                    "format_sink": "memcpy",
                    "format_function": "memcpy",
                    "format_callsite": callsite,
                    "dst_buffer": dst_address,
                    "size_value": size_value,
                    "bounded": bounded,
                    "copy_length": copy_length,
                    "requested_length": copy_size,
                    "written_variables": sorted(str(var) for var in getattr(data, "variables", set())),
                    "source_or_marker_written": "unknown",
                    "flows_to_command_sink": "unknown",
                    "limitations": limitations
                    + ["minimal toy memcpy SimProcedure copies src bytes into dst without alias analysis"],
                }
            )
            self.state.globals[FORMAT_WRITES_KEY] = writes

    if _loader_symbol_address(project, "snprintf") is not None:
        try:
            project.hook_symbol("snprintf", ToySnprintf(), replace=True)
        except Exception:
            pass
    if _loader_symbol_address(project, "sprintf") is not None:
        try:
            project.hook_symbol("sprintf", ToySprintf(), replace=True)
        except Exception:
            pass
    if _loader_symbol_address(project, "memcpy") is not None:
        try:
            project.hook_symbol("memcpy", ToyMemcpy(), replace=True)
        except Exception:
            pass

    plt = getattr(getattr(project.loader, "main_object", None), "plt", {})
    for name, procedure in (("snprintf", ToySnprintf), ("sprintf", ToySprintf), ("memcpy", ToyMemcpy)):
        address = plt.get(name) if isinstance(plt, dict) else None
        if address is not None:
            try:
                project.hook(int(address), procedure(), replace=True)
            except Exception:
                pass


def _bounded_copy_length(state: Any, size: Any | None, copy_size: int) -> tuple[int, int | str | None, bool, list[str]]:
    if size is None:
        return copy_size, None, False, ["sprintf has no size argument; evidence is less bounded"]
    size_value = _concrete_int_or_unknown(state, size)
    if not isinstance(size_value, int):
        return copy_size, "unknown", False, ["snprintf size is symbolic/unknown; truncation evidence is inconclusive"]
    if size_value <= 0:
        return 0, size_value, True, ["snprintf size is zero; no bytes are copied"]
    return max(min(copy_size, size_value - 1), 0), size_value, True, []


def _bounded_memcpy_length(state: Any, n: Any, copy_size: int) -> tuple[int, int | str | None, bool, list[str]]:
    n_value = _concrete_int_or_unknown(state, n)
    if not isinstance(n_value, int):
        return copy_size, "unknown", False, ["memcpy length is symbolic/unknown; truncation evidence is inconclusive"]
    return max(min(copy_size, n_value), 0), n_value, True, []


def _concrete_int_or_unknown(state: Any, value: Any) -> int | str:
    try:
        if state.solver.symbolic(value):
            return "unknown"
    except Exception:
        pass
    try:
        return int(state.solver.eval(value))
    except Exception:
        try:
            return int(value)
        except Exception:
            return "unknown"


def _format_flow_evidence(
    state: Any,
    *,
    selected_sink: dict[str, Any],
    sink_argument: dict[str, Any],
    source_symbolic_name: str,
    benign_marker: str,
) -> dict[str, Any]:
    writes = state.globals.get(FORMAT_WRITES_KEY, [])
    writes = writes if isinstance(writes, list) else []
    sink_variables = set(str(var) for var in sink_argument.get("arg_variables", []) or [])
    contains_sink_source = sink_argument.get("contains_source")
    contains_sink_marker = sink_argument.get("contains_marker")
    records: list[dict[str, Any]] = []
    positive_count = 0
    truncated_count = 0
    memory_copy_count = 0
    format_write_count = 0
    for write in writes:
        if not isinstance(write, dict):
            continue
        variables = [str(var) for var in write.get("written_variables", []) or []]
        source_written = any(variable_matches_symbolic_name(var, source_symbolic_name) for var in variables)
        marker_written: bool | str = "unknown"
        marker_truncated: bool | str = False
        copy_length = _int_or_none(write.get("copy_length"))
        requested_length = _int_or_none(write.get("requested_length"))
        copied_text = _concrete_written_text(state, write)
        if benign_marker:
            marker_written = benign_marker in copied_text
        if source_written and marker_written is False and copy_length is not None and requested_length is not None:
            marker_truncated = copy_length < requested_length
        if marker_truncated is True:
            truncated_count += 1
        flows_to_command_sink = bool(sink_variables and set(variables).intersection(sink_variables))
        if selected_sink.get("function") == "system" and contains_sink_source is True and contains_sink_marker is True:
            flows_to_command_sink = True
            marker_written = True
        elif contains_sink_marker is False:
            marker_written = bool(marker_written is True)
        if source_written and flows_to_command_sink and marker_written is True and marker_truncated is not True:
            positive_count += 1
        flow_kind = str(write.get("flow_kind") or "format_write")
        if flow_kind == "memory_copy":
            memory_copy_count += 1
        else:
            format_write_count += 1
        records.append(
            {
                "flow_kind": flow_kind,
                "format_sink": write.get("format_sink"),
                "format_function": write.get("format_function") or write.get("format_sink"),
                "format_callsite": write.get("format_callsite"),
                "dst_buffer": write.get("dst_buffer"),
                "size_value": write.get("size_value"),
                "copy_length": write.get("copy_length"),
                "requested_length": write.get("requested_length"),
                "source_or_marker_written": bool(source_written or marker_written is True),
                "source_written": bool(source_written),
                "marker_written": marker_written,
                "marker_truncated": marker_truncated,
                "flows_to_command_sink": bool(flows_to_command_sink),
                "evidence_strength": _flow_record_strength(
                    marker_written=marker_written,
                    marker_truncated=marker_truncated,
                    flows_to_command_sink=flows_to_command_sink,
                    flow_kind=flow_kind,
                    bounded=write.get("bounded"),
                ),
                "written_variables": variables,
                "limitations": list(write.get("limitations") or []),
            }
        )
    status = "not_observed"
    if records:
        status = "positive" if positive_count else ("truncated" if truncated_count else "negative")
    return {
        "observed": bool(records),
        "status": status,
        "format_write_count": len(records),
        "format_record_count": format_write_count,
        "memory_copy_count": memory_copy_count,
        "positive_write_count": positive_count,
        "truncated_write_count": truncated_count,
        "marker_truncated": bool(truncated_count),
        "flows_to_command_sink": bool(positive_count),
        "records": records,
        "limitations": [
            "format/memory-flow evidence is auxiliary; final command evidence is determined at system(arg0)"
        ],
    }


def _concrete_written_text(state: Any, write: dict[str, Any]) -> str:
    dst = _parse_hex_address(write.get("dst_buffer"))
    copy_length = _int_or_none(write.get("copy_length"))
    if dst is None or copy_length is None or copy_length <= 0:
        return ""
    try:
        raw = state.solver.eval(state.memory.load(dst, copy_length), cast_to=bytes)
    except Exception:
        return ""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _flow_record_strength(
    *,
    marker_written: Any,
    marker_truncated: Any,
    flows_to_command_sink: bool,
    flow_kind: str,
    bounded: Any,
) -> str:
    if marker_truncated is True:
        return "truncated_auxiliary_evidence"
    if flows_to_command_sink and marker_written is True:
        return "bounded_auxiliary_evidence" if bounded is True else "less_bounded_auxiliary_evidence"
    if flow_kind == "memory_copy" and bounded is not True:
        return "inconclusive_memory_copy_evidence"
    return "auxiliary_negative_or_non_command_evidence"


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        if value is None or value == "unknown":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _sink_address_candidates(
    project: Any,
    selected_sink: dict[str, Any],
    selected_address: int,
) -> dict[int, dict[str, Any]]:
    arch_name = _project_arch_name(project)
    normalized_arch = _normalize_arch_for_debug(arch_name)
    candidates: dict[int, dict[str, Any]] = {}

    def add(address: int | None, reason: str, *, replace: bool = False) -> None:
        if address is None:
            return
        if address < 0x1000 and reason == "external_symbol_address":
            return
        if replace or address not in candidates:
            candidates[address] = {"address": _hex(address), "reason": reason}

    add(selected_address, "selected_sink_address")
    loader_symbol = _loader_symbol_address(project, selected_sink.get("function"))
    add(loader_symbol, "loader_external_symbol_address")
    for callsite in selected_sink.get("callsites") or []:
        if isinstance(callsite, dict):
            add(_parse_hex_address(callsite.get("address")), "sink_callsite_address")
    add(_parse_hex_address(selected_sink.get("external_address")), "external_symbol_address")

    if normalized_arch == "ARM32":
        instruction_size = _instruction_size_for_arch(normalized_arch)
        add(selected_address - instruction_size, "previous_instruction_candidate")
        add(selected_address + instruction_size, "next_instruction_candidate")
        add(selected_address | 1, "thumb_bit_candidate")
        add(selected_address & ~1, "thumb_cleared_candidate")
        add(selected_address + 2, "thumb_next_halfword_candidate")
        add(selected_address - 2, "thumb_previous_halfword_candidate")
    if normalized_arch == "MIPS32":
        add(selected_address + 4, "mips_delay_slot_candidate", replace=True)
        add(selected_address + 8, "mips_after_delay_slot_candidate", replace=True)
        add(selected_address - 4, "mips_branch_instruction_candidate", replace=True)

    return dict(sorted(candidates.items()))


def _instruction_size_for_arch(normalized_arch: str) -> int:
    if normalized_arch in {"ARM32", "MIPS32", "AARCH64"}:
        return 4
    return 1


def _loader_symbol_address(project: Any, symbol_name: Any) -> int | None:
    if not symbol_name:
        return None
    try:
        symbol = project.loader.find_symbol(str(symbol_name))
    except Exception:
        return None
    if symbol is None:
        return None
    try:
        return int(symbol.rebased_addr)
    except Exception:
        return None


def _reachability_debug(
    *,
    project: Any | None,
    config: VerifierTaskConfig | None,
    selected_sink: dict[str, Any] | None,
    selected_entry: dict[str, Any] | None,
    target_candidates: dict[int, dict[str, Any]],
    steps: int,
    reason: str,
    reached_addresses_near_sink: list[int] | None = None,
    recent_bbl_addrs: list[str] | None = None,
    simgr: Any | None = None,
    matched_sink_address: int | None = None,
    match_reason: str | None = None,
    startup_mode: str = "full_init",
    reached_main: bool = False,
) -> dict[str, Any]:
    arch = _project_arch_name(project) if project is not None else None
    selected_sink = selected_sink or {}
    selected_entry = selected_entry or {}
    normalized_arch = _normalize_arch_for_debug(arch)
    main_address = selected_entry.get("address")
    full_init_repair = _full_init_repair_info(normalized_arch, startup_mode)
    return {
        "arch": arch,
        "binary_path": (config.binary.get("path") if config is not None else None),
        "entry_address": selected_entry.get("address"),
        "main_address": main_address,
        "reached_main": bool(reached_main),
        "selected_sink_address": selected_sink.get("address"),
        "selected_sink_external_address": selected_sink.get("external_address"),
        "selected_sink_callsites": selected_sink.get("callsites", []),
        "sink_address_candidates": list(target_candidates.values()),
        "mips_delay_slot_candidates": [
            dict(candidate)
            for candidate in target_candidates.values()
            if "mips" in str(candidate.get("reason") or "")
        ],
        "loader_external_symbols": _loader_external_symbols(project),
        "plt_or_stub_candidates": _plt_or_stub_candidates(project, selected_sink),
        "matched_sink_address": _hex_or_none(matched_sink_address),
        "match_reason": match_reason,
        "thumb_adjusted": bool(match_reason and "thumb" in match_reason),
        "delay_slot_adjusted": bool(match_reason and "mips" in match_reason),
        "reached_addresses_near_sink": [_hex(address) for address in (reached_addresses_near_sink or [])],
        "active_state_count": _stash_count(simgr, "active"),
        "deadended_state_count": _stash_count(simgr, "deadended"),
        "errored_state_count": len(getattr(simgr, "errored", []) or []) if simgr is not None else 0,
        "errored_state_details": _errored_state_details(simgr),
        "recent_bbl_addrs": list(recent_bbl_addrs or [])[-32:],
        "steps": steps,
        "reason": reason,
        "startup_failure_reason": _startup_failure_reason(
            normalized_arch=normalized_arch,
            startup_mode=startup_mode,
            reached_main=reached_main,
            reason=reason,
            simgr=simgr,
        ),
        "full_init_repair_applied": full_init_repair["applied"],
        "repair_reason": full_init_repair["reason"],
    }


def _full_init_repair_info(normalized_arch: str, startup_mode: str) -> dict[str, Any]:
    if normalized_arch == "MIPS32" and startup_mode == "full_init":
        return {
            "applied": True,
            "reason": "mips_full_init_block_level_stepping_for_bal_delay_slot_startup_stub",
        }
    return {"applied": False, "reason": None}


def _startup_failure_reason(
    *,
    normalized_arch: str,
    startup_mode: str,
    reached_main: bool,
    reason: str,
    simgr: Any | None,
) -> str | None:
    if "matched sink" in reason or "timed out" in reason:
        return None
    if normalized_arch == "MIPS32" and startup_mode == "full_init" and not reached_main:
        return "mips_full_init_stopped_before_main"
    if _stash_count(simgr, "errored"):
        return "errored_state_before_sink"
    if "no active states" in reason:
        return "no_active_states_before_sink"
    return None


def _errored_state_details(simgr: Any | None) -> list[dict[str, Any]]:
    if simgr is None:
        return []
    details: list[dict[str, Any]] = []
    for errored in list(getattr(simgr, "errored", []) or [])[:3]:
        state = getattr(errored, "state", None)
        details.append(
            {
                "address": _hex_or_none(_state_addr(state)),
                "error": str(getattr(errored, "error", "")),
                "recent_bbl_addrs": _recent_bbl_addrs([state])[-8:] if state is not None else [],
            }
        )
    return details


def _loader_external_symbols(project: Any | None) -> list[dict[str, Any]]:
    if project is None:
        return []
    names = ["__libc_start_main", "snprintf", "system", "__stack_chk_fail"]
    symbols = []
    for name in names:
        address = _loader_symbol_address(project, name)
        if address is not None:
            symbols.append({"name": name, "address": _hex(address)})
    return symbols


def _plt_or_stub_candidates(project: Any | None, selected_sink: dict[str, Any]) -> list[dict[str, Any]]:
    if project is None:
        return []
    candidates: list[dict[str, Any]] = []
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    plt = getattr(main_object, "plt", {}) if main_object is not None else {}
    if isinstance(plt, dict):
        for name in [selected_sink.get("function"), "snprintf", "system", "__libc_start_main"]:
            if name in plt:
                candidates.append({"name": str(name), "address": _hex(int(plt[name])), "source": "plt"})
    for name in [selected_sink.get("function"), "__libc_start_main"]:
        address = _loader_symbol_address(project, name)
        if address is not None:
            candidates.append({"name": str(name), "address": _hex(address), "source": "loader_symbol"})
    return candidates


def _recent_bbl_addrs(states: list[Any]) -> list[str]:
    addresses: list[str] = []
    for state in states:
        try:
            history = getattr(state, "history", None)
            bbl_addrs = list(getattr(history, "bbl_addrs", []) or [])
            for address in bbl_addrs[-4:]:
                addresses.append(_hex(int(address)))
        except Exception:
            addr = _state_addr(state)
            if addr is not None:
                addresses.append(_hex(addr))
    return addresses


def _near_sink_addresses(active_addrs: set[int], target_addrs: set[int]) -> set[int]:
    near: set[int] = set()
    for address in active_addrs:
        for target in target_addrs:
            if abs(address - target) <= 16:
                near.add(address)
    return near


def _stash_count(simgr: Any | None, name: str) -> int:
    if simgr is None:
        return 0
    return len(getattr(simgr, name, []) or [])


def _state_addr(state: Any) -> int | None:
    try:
        return int(state.addr)
    except Exception:
        return None


def _project_arch_name(project: Any | None) -> str | None:
    return getattr(getattr(project, "arch", None), "name", None) if project is not None else None


def _normalize_arch_for_debug(arch_name: str | None) -> str:
    value = (arch_name or "").upper()
    if value in {"ARMEL", "ARMHF"} or value.startswith("ARM"):
        return "ARM32"
    if value.startswith("MIPS"):
        return "MIPS32"
    if value in {"AARCH64", "AMD64"}:
        return value
    return value or "unknown"


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


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _hex_or_none(value: int | None) -> str | None:
    if value is None:
        return None
    return _hex(value)


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
    startup_debug: dict[str, Any] | None = None,
    reachability_debug: dict[str, Any] | None = None,
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
        startup_debug=startup_debug,
        reachability_debug=reachability_debug,
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
    reachability_debug: dict[str, Any] | None = None,
    startup_debug: dict[str, Any] | None = None,
) -> dict[str, Any]:
    matched_sink_address = None
    match_reason = None
    if reachability_debug:
        matched_sink_address = reachability_debug.get("matched_sink_address")
        match_reason = reachability_debug.get("match_reason")
    if not matched_sink_address and selected_sink:
        matched_sink_address = selected_sink.get("matched_address")
    if not match_reason and selected_sink:
        match_reason = selected_sink.get("match_reason")

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
        "matched_sink_address": matched_sink_address,
        "match_reason": match_reason,
        "selected_entry": selected_entry,
        "path_status": path_status,
        "constraints_summary": constraints_summary,
        "steps": steps,
        "found_states": found_states,
        "reachability_debug": reachability_debug or {},
        "startup_debug": startup_debug or {},
        "evidence_strength": _evidence_strength(config, startup_debug),
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
            "callsites": sink.get("callsites", []),
        }
        for sink in config.sinks
    ]
