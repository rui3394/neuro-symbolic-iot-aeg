from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from ns_aeg.reachability import variable_matches_symbolic_name
from ns_aeg.source_model import SourceModel


SINK_PRIORITY = ["system", "popen", "snprintf"]


@dataclass(frozen=True)
class ConstraintObservationResult:
    binary_path: str
    created: bool
    reachable: bool
    source_name: str | None
    symbolic_var: str | None
    runtime_binding: str | None
    input_constraints: list[str]
    target_sink: str | None
    target_addr: str | None
    total_constraints: int
    source_related_constraints: list[str]
    source_related_count: int
    string_modeling_constraints: list[str]
    string_modeling_count: int
    input_modeling_constraints: list[str]
    input_modeling_count: int
    branch_condition_constraints: list[str]
    branch_condition_count: int
    sanitizer_candidate_constraints: list[str]
    sanitizer_candidate_count: int
    unknown_source_constraints: list[str]
    unknown_source_count: int
    sanitizer_like_observed: bool
    max_steps: int
    steps: int
    error: str | None


def observe_constraints_to_sink(
    binary_path: str,
    sinks: list[str],
    source_model: SourceModel,
    max_steps: int = 300,
    max_constraint_text_len: int = 240,
) -> ConstraintObservationResult:
    if not Path(binary_path).exists():
        return _failed(
            binary_path,
            max_steps,
            created=False,
            error=f"binary does not exist: {binary_path}",
        )

    if not source_model.sources:
        return _failed(binary_path, max_steps, created=False, error="no source configured")

    source = source_model.sources[0]
    argv_index = _parse_argv_binding(source.runtime_binding)
    if argv_index is None or argv_index == 0:
        return _failed(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error=f"unsupported runtime binding: {source.runtime_binding}",
        )
    if source.max_len <= 1:
        return _failed(
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
        return _failed(
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
        return _failed(
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
            return _failed(
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
        return _failed(
            binary_path,
            max_steps,
            created=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            error=f"failed to observe constraints to sink: {exc}",
        )

    if not found_states:
        return ConstraintObservationResult(
            binary_path=binary_path,
            created=True,
            reachable=False,
            source_name=source.name,
            symbolic_var=source.symbolic_name,
            runtime_binding=source.runtime_binding,
            input_constraints=input_constraints,
            target_sink=target_sink,
            target_addr=_to_hex(target_addr),
            total_constraints=0,
            source_related_constraints=[],
            source_related_count=0,
            string_modeling_constraints=[],
            string_modeling_count=0,
            input_modeling_constraints=[],
            input_modeling_count=0,
            branch_condition_constraints=[],
            branch_condition_count=0,
            sanitizer_candidate_constraints=[],
            sanitizer_candidate_count=0,
            unknown_source_constraints=[],
            unknown_source_count=0,
            sanitizer_like_observed=False,
            max_steps=max_steps,
            steps=steps,
            error="target sink was not reached",
        )

    constraints = list(getattr(found_states[0].solver, "constraints", []))
    source_related: list[str] = []
    string_modeling: list[str] = []
    input_modeling: list[str] = []
    branch_conditions: list[str] = []
    sanitizer_candidates: list[str] = []
    unknown_source: list[str] = []
    for constraint in constraints:
        if not _constraint_mentions_source(constraint, source.symbolic_name):
            continue

        text = _truncate_constraint(str(constraint), max_constraint_text_len)
        classification = classify_source_constraint_text(text, source.symbolic_name)
        if classification == "string_modeling":
            string_modeling.append(text)
            source_related.append(text)
        elif classification == "input_modeling":
            input_modeling.append(text)
            source_related.append(text)
        elif classification == "branch_condition":
            branch_conditions.append(text)
            source_related.append(text)
        elif classification == "sanitizer_candidate":
            sanitizer_candidates.append(text)
            source_related.append(text)
        else:
            unknown_source.append(text)
            source_related.append(text)

    sanitizer_candidates, unknown_source = _promote_length_check_candidates(
        input_modeling,
        string_modeling,
        sanitizer_candidates,
        unknown_source,
    )

    return ConstraintObservationResult(
        binary_path=binary_path,
        created=True,
        reachable=True,
        source_name=source.name,
        symbolic_var=source.symbolic_name,
        runtime_binding=source.runtime_binding,
        input_constraints=input_constraints,
        target_sink=target_sink,
        target_addr=_to_hex(target_addr),
        total_constraints=len(constraints),
        source_related_constraints=source_related,
        source_related_count=len(source_related),
        string_modeling_constraints=string_modeling,
        string_modeling_count=len(string_modeling),
        input_modeling_constraints=input_modeling,
        input_modeling_count=len(input_modeling),
        branch_condition_constraints=branch_conditions,
        branch_condition_count=len(branch_conditions),
        sanitizer_candidate_constraints=sanitizer_candidates,
        sanitizer_candidate_count=len(sanitizer_candidates),
        unknown_source_constraints=unknown_source,
        unknown_source_count=len(unknown_source),
        sanitizer_like_observed=bool(sanitizer_candidates),
        max_steps=max_steps,
        steps=steps,
        error=None,
    )


def _constraint_mentions_source(constraint: Any, symbolic_name: str) -> bool:
    variables = getattr(constraint, "variables", set())
    return any(
        variable_matches_symbolic_name(str(variable), symbolic_name)
        for variable in variables
    )


def _add_non_null_prefix_constraints(state: Any, sym: Any, max_len: int) -> list[str]:
    prefix_len = min(4, max_len - 1)
    if prefix_len <= 0:
        return []

    total_bits = (max_len - 1) * 8
    for index in range(prefix_len):
        high = total_bits - 1 - (index * 8)
        low = high - 7
        state.solver.add(sym[high:low] != 0)

    return [f"first {prefix_len} symbolic bytes are non-null"]


def _truncate_constraint(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...<truncated>"


def classify_source_constraint_text(text: str, symbolic_name: str) -> str:
    lower = text.lower()
    mentions_symbol = symbolic_name in text

    if mentions_symbol and _looks_like_input_modeling_constraint(text):
        return "input_modeling"
    if mentions_symbol and _looks_like_string_modeling(text, lower):
        return "string_modeling"
    if mentions_symbol and _looks_like_branch_condition(text):
        return "branch_condition"
    if mentions_symbol and _looks_like_sanitizer_candidate(text, lower):
        return "sanitizer_candidate"
    return "unknown"


def _looks_like_input_modeling_constraint(text: str) -> bool:
    byte_slice = r"[\w_]+(?:_\d+)*\[\d+:\d+\]"
    return bool(
        re.search(rf"!\(\s*{byte_slice}\s*==\s*0\s*\)", text)
        or re.search(rf"{byte_slice}\s*!=\s*0(?!x)", text)
    )


def _looks_like_single_null_byte_check(text: str, lower: str) -> bool:
    if any(token in lower for token in ("||", " or ", "if", "then", "else")):
        return False

    stripped = text.strip()
    if stripped.startswith("<Bool ") and stripped.endswith(">"):
        stripped = stripped[len("<Bool ") : -1].strip()

    return bool(re.fullmatch(r"[\w_]+(?:_\d+)*\[\d+:\d+\]\s*==\s*0", stripped))


def _looks_like_branch_condition(text: str) -> bool:
    stripped = text.strip()
    if stripped.startswith("<Bool ") and stripped.endswith(">"):
        stripped = stripped[len("<Bool ") : -1].strip()

    byte_slice = r"[\w_]+(?:_\d+)*\[\d+:\d+\]"
    return bool(re.fullmatch(rf"{byte_slice}\s*==\s*(65|66|0x41|0x42)", stripped))


def _promote_length_check_candidates(
    input_modeling: list[str],
    string_modeling: list[str],
    sanitizer_candidates: list[str],
    unknown_source: list[str],
) -> tuple[list[str], list[str]]:
    # A lone byte == 0 is often ordinary C-string modeling. Treat it as a
    # length-check candidate only when paired with explicit non-null prefix
    # constraints and no larger string-modeling expression was observed.
    if not input_modeling or string_modeling:
        return sanitizer_candidates, unknown_source

    promoted = [
        constraint
        for constraint in unknown_source
        if _looks_like_single_null_byte_check(constraint, constraint.lower())
    ]
    if not promoted:
        return sanitizer_candidates, unknown_source

    remaining_unknown = [
        constraint for constraint in unknown_source if constraint not in promoted
    ]
    return sanitizer_candidates + promoted, remaining_unknown


def _looks_like_string_modeling(text: str, lower: str) -> bool:
    byte_slices = re.findall(r"\[\d+:\d+\]", text)
    if text.count("== 0") >= 2 and len(byte_slices) >= 2:
        return True
    if len(byte_slices) >= 2 and "== 0" in text:
        return True
    if "if" in lower and "then" in lower and "== 0" in text:
        return True
    return any(token in lower for token in ("strlen", "strchr", "strnlen"))


def _looks_like_sanitizer_candidate(text: str, lower: str) -> bool:
    if any(token in lower for token in ("reject", "deny", "bad", "filter")):
        return True
    if re.search(r"(!=|==)\s*(0x3b|59|';')", text):
        return True
    if re.search(r"(!=|==)\s*(0x26|38|'&')", text):
        return True
    if re.search(r"(!=|==)\s*(0x7c|124|'\|')", text):
        return True
    if re.search(r"(!=|==)\s*(0x60|96|'`')", text):
        return True
    if re.search(r"(!=|==)\s*(0x24|36|'\$')", text):
        return True
    if re.search(r"(!=|==)\s*(0x0a|10|'\\n')", text):
        return True
    return bool(re.search(r"(<=|<)\s*(0x[0-9a-fA-F]+|\d+)", text))


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


def _parse_argv_binding(runtime_binding: str) -> int | None:
    match = re.fullmatch(r"argv\[(\d+)\]", runtime_binding)
    if match is None:
        return None
    return int(match.group(1))


def _normalize_symbol_name(symbol: str) -> str:
    if symbol.endswith("@plt"):
        symbol = symbol[: -len("@plt")]
    return symbol.split("@", 1)[0]


def _failed(
    binary_path: str,
    max_steps: int,
    *,
    created: bool,
    error: str,
    source_name: str | None = None,
    symbolic_var: str | None = None,
    runtime_binding: str | None = None,
) -> ConstraintObservationResult:
    return ConstraintObservationResult(
        binary_path=binary_path,
        created=created,
        reachable=False,
        source_name=source_name,
        symbolic_var=symbolic_var,
        runtime_binding=runtime_binding,
        input_constraints=[],
        target_sink=None,
        target_addr=None,
        total_constraints=0,
        source_related_constraints=[],
        source_related_count=0,
        string_modeling_constraints=[],
        string_modeling_count=0,
        input_modeling_constraints=[],
        input_modeling_count=0,
        branch_condition_constraints=[],
        branch_condition_count=0,
        sanitizer_candidate_constraints=[],
        sanitizer_candidate_count=0,
        unknown_source_constraints=[],
        unknown_source_count=0,
        sanitizer_like_observed=False,
        max_steps=max_steps,
        steps=0,
        error=error,
    )


def _to_hex(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{value:x}"
