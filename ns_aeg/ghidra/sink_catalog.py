from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SinkDefinition:
    name: str
    category: str
    description: str
    argument_roles: tuple[str, ...]


DANGEROUS_SINKS: tuple[SinkDefinition, ...] = (
    SinkDefinition(
        name="system",
        category="command_execution",
        description="Executes a shell command string supplied by the caller.",
        argument_roles=("command",),
    ),
    SinkDefinition(
        name="popen",
        category="command_execution",
        description="Runs a command string and opens a process stream.",
        argument_roles=("command", "mode"),
    ),
    SinkDefinition(
        name="execl",
        category="process_execution",
        description="Starts a process with caller-controlled path and arguments.",
        argument_roles=("path", "arg0"),
    ),
    SinkDefinition(
        name="execv",
        category="process_execution",
        description="Starts a process with caller-controlled path and argument vector.",
        argument_roles=("path", "argv"),
    ),
    SinkDefinition(
        name="snprintf",
        category="string_formatting",
        description="Formats data into a bounded destination buffer.",
        argument_roles=("destination", "size", "format"),
    ),
    SinkDefinition(
        name="sprintf",
        category="string_formatting",
        description="Formats data into an unbounded destination buffer.",
        argument_roles=("destination", "format"),
    ),
    SinkDefinition(
        name="strcpy",
        category="unsafe_copy",
        description="Copies a string into a destination without a size argument.",
        argument_roles=("destination", "source"),
    ),
    SinkDefinition(
        name="strcat",
        category="unsafe_concat",
        description="Appends a string into a destination without a size argument.",
        argument_roles=("destination", "source"),
    ),
)

_BY_NAME = {sink.name: sink for sink in DANGEROUS_SINKS}


def dangerous_sink_names() -> list[str]:
    return sorted(_BY_NAME)


def get_sink_definition(name: str) -> SinkDefinition | None:
    return _BY_NAME.get(normalize_symbol_name(name))


def is_dangerous_sink(name: str) -> bool:
    return get_sink_definition(name) is not None


def normalize_symbol_name(symbol: str) -> str:
    symbol = symbol.strip()
    if symbol.endswith("@plt"):
        symbol = symbol[: -len("@plt")]
    return symbol.split("@", 1)[0]

