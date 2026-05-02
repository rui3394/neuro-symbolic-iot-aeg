# Ghidra Xref And Caller Extraction

## Address Types

Ghidra models imported functions with several distinct addresses:

- `external_address`: the external symbol address used by Ghidra's external manager, such as `0x3` or `0x4` for imports in a small toy ELF.
- PLT or thunk function address: the local code stub that transfers control to the imported function, such as `0x401070` for `system`.
- Callsite address: the instruction address in a caller function that invokes the sink, such as `0x4011f9` in `main`.
- Caller function entry: the entry point of the function containing the callsite, such as `0x401176` for `main`.

The verifier needs callsite and caller context more than the external symbol address. External addresses identify imported symbols, but they are not executable program locations for source-to-sink path reasoning.

## Exporter Behavior

For each dangerous imported sink, the exporter now records:

- `external_address`: the original Ghidra external symbol address.
- `callsites`: objects with `address`, `caller`, and `caller_entry`.
- `callers`: a de-duplicated list of caller function names.
- `address`: the first callsite address when available, otherwise a fallback to `external_address`.

The exporter combines Ghidra reference-manager results with instruction flow scanning. The flow scanner handles calls to PLT/thunk functions that Ghidra links back to imported sinks.

## Decompiler Snippets

Decompiler output is best-effort. The exporter first attempts to decompile sink caller functions. If decompilation fails, export continues and records a warning. The facts schema allows `decompiled_snippets` to be empty.

## Current Limits

Caller extraction is still conservative. It focuses on direct call flows and imported sink thunks. Indirect calls, function pointers, stripped binaries with unusual import stubs, and architecture-specific thunk patterns may need additional handling.

The downstream verifier is still `task_adapter_dry_run`; these facts improve static evidence quality but are not yet a symbolic proof.

