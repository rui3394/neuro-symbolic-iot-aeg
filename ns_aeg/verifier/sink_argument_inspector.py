from __future__ import annotations

from typing import Any

from ns_aeg.ghidra.sink_catalog import get_sink_definition, normalize_symbol_name
from ns_aeg.reachability import variable_matches_symbolic_name

UNKNOWN = "unknown"

ABI_REGISTER_ARGUMENTS: dict[str, tuple[str, ...]] = {
    "AMD64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "ARM32": ("r0", "r1", "r2", "r3"),
    "AARCH64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    "MIPS32": ("a0", "a1", "a2", "a3"),
}

STACK_ARGUMENT_ARCHES = {"X86", "I386"}


def inspect_sink_argument(
    state: Any,
    project: Any,
    sink: dict[str, Any],
    arg_index: int | None = None,
    *,
    source_symbolic_name: str | None = None,
    benign_marker: str | None = None,
    read_size: int = 256,
    arch: str | None = None,
) -> dict[str, Any]:
    """Inspect a sink argument from a symbolic state without executing the sink."""

    limitations: list[str] = []
    resolved_arg_index = _resolve_arg_index(sink, arg_index, limitations)
    arch_name = normalize_arch_name(arch or _project_arch_name(project))

    if resolved_arg_index is None:
        return _base_result(
            arch=arch_name,
            arg_index=None,
            register=None,
            location=None,
            method="unsupported_missing_arg_index",
            limitations=limitations + ["sink arg_index is missing and no catalog fallback is available"],
        )

    if arch_name in STACK_ARGUMENT_ARCHES:
        return _base_result(
            arch=arch_name,
            arg_index=resolved_arg_index,
            register=None,
            location=f"stack:arg{resolved_arg_index}",
            method="unsupported_stack_argument_inspection",
            limitations=limitations
            + ["stack-based argument inspection for i386 is not implemented yet"],
        )

    register = argument_register_for_arch(arch_name, resolved_arg_index)
    if register is None:
        supported = sorted(ABI_REGISTER_ARGUMENTS)
        return _base_result(
            arch=arch_name,
            arg_index=resolved_arg_index,
            register=None,
            location=None,
            method="unsupported_abi_argument_mapping",
            limitations=limitations
            + [
                f"unsupported architecture or arg_index for register argument inspection: "
                f"arch={arch_name}, arg_index={resolved_arg_index}, supported_arches={supported}"
            ],
        )

    location = f"register:{register}"
    try:
        arg_ptr = getattr(state.regs, register)
        arg_expr = state.memory.load(arg_ptr, read_size)
        variables = sorted(str(var) for var in getattr(arg_expr, "variables", set()))
        contains_source = (
            any(variable_matches_symbolic_name(var, source_symbolic_name) for var in variables)
            if source_symbolic_name
            else UNKNOWN
        )
        concrete = state.solver.eval(arg_expr, cast_to=bytes).split(b"\x00", 1)[0]
        text = concrete.decode("utf-8", errors="replace")
        contains_marker: bool | str = (
            benign_marker in text if benign_marker else UNKNOWN
        )
        value_repr = _safe_preview(text)
        return {
            "arch": arch_name,
            "arg_index": resolved_arg_index,
            "register": register,
            "location": location,
            "value_repr": value_repr,
            "contains_marker": contains_marker,
            "contains_source": contains_source,
            "method": "register_pointer_memory_string",
            "limitations": limitations,
            "arg_symbolic": bool(state.solver.symbolic(arg_expr)),
            "arg_variables": variables,
            "concrete_preview": value_repr,
            "error": None,
            "arg_register": register,
            "source_var_in_sink_arg": contains_source,
            "marker_observed": contains_marker,
        }
    except Exception as exc:
        return {
            "arch": arch_name,
            "arg_index": resolved_arg_index,
            "register": register,
            "location": location,
            "value_repr": None,
            "contains_marker": UNKNOWN,
            "contains_source": UNKNOWN,
            "method": "register_pointer_memory_string",
            "limitations": limitations + [f"failed to inspect sink argument: {exc}"],
            "arg_symbolic": False,
            "arg_variables": [],
            "concrete_preview": None,
            "error": f"failed to inspect sink argument: {exc}",
            "arg_register": register,
            "source_var_in_sink_arg": UNKNOWN,
            "marker_observed": UNKNOWN,
        }


def argument_register_for_arch(arch: str | None, arg_index: int | None) -> str | None:
    if arg_index is None:
        return None
    registers = ABI_REGISTER_ARGUMENTS.get(normalize_arch_name(arch))
    if registers is None or arg_index < 0 or arg_index >= len(registers):
        return None
    return registers[arg_index]


def normalize_arch_name(arch: str | None) -> str:
    if not arch:
        return UNKNOWN
    value = arch.upper()
    if "X86:LE:64" in value or value in {"AMD64", "X86_64", "X64"}:
        return "AMD64"
    if value in {"X86", "I386", "I686", "386"} or "X86:LE:32" in value:
        return "X86"
    if value in {"ARM", "ARM32", "ARMEL", "ARMHF"} or value.startswith("ARM:"):
        return "ARM32"
    if value in {"AARCH64", "ARM64"} or value.startswith("AARCH64:"):
        return "AARCH64"
    if value in {"MIPS", "MIPS32", "MIPSEL"} or value.startswith("MIPS:"):
        return "MIPS32"
    return value


def _resolve_arg_index(
    sink: dict[str, Any],
    arg_index: int | None,
    limitations: list[str],
) -> int | None:
    if arg_index is None:
        raw = sink.get("arg_index")
        if isinstance(raw, int):
            return raw
        try:
            if raw is not None:
                return int(raw)
        except (TypeError, ValueError):
            limitations.append(f"invalid sink arg_index value ignored: {raw}")
    else:
        try:
            return int(arg_index)
        except (TypeError, ValueError):
            limitations.append(f"invalid explicit arg_index value ignored: {arg_index}")

    fallback = default_arg_index_for_sink(sink)
    if fallback is not None:
        limitations.append("sink arg_index missing; used sink catalog default")
    return fallback


def default_arg_index_for_sink(sink: dict[str, Any]) -> int | None:
    function = normalize_symbol_name(str(sink.get("function") or sink.get("name") or ""))
    definition = get_sink_definition(function)
    if definition is None:
        return None
    for role in ("command", "format", "source", "path"):
        if role in definition.argument_roles:
            return definition.argument_roles.index(role)
    return None


def _project_arch_name(project: Any) -> str | None:
    return getattr(getattr(project, "arch", None), "name", None)


def _base_result(
    *,
    arch: str,
    arg_index: int | None,
    register: str | None,
    location: str | None,
    method: str,
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "arch": arch,
        "arg_index": arg_index,
        "register": register,
        "location": location,
        "value_repr": None,
        "contains_marker": UNKNOWN,
        "contains_source": UNKNOWN,
        "method": method,
        "limitations": limitations,
        "arg_symbolic": False,
        "arg_variables": [],
        "concrete_preview": None,
        "error": limitations[-1] if limitations else None,
        "arg_register": register,
        "source_var_in_sink_arg": UNKNOWN,
        "marker_observed": UNKNOWN,
    }


def _safe_preview(value: str, max_len: int = 96) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + "...<truncated>"
