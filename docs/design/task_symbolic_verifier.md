# Task Symbolic Verifier

## Purpose

Step 34 reconnects task-driven verification to the existing angr-based source-to-sink analysis path. The verifier can now run in either dry-run mode or symbolic mode from the same `dangerous_path_task.json` input.

This step remains scoped to local toy binaries. It does not execute target binaries, invoke shell commands, generate exploit material, call an LLM, or analyze real firmware images.

## Dry-Run Versus Symbolic Mode

Dry-run mode validates that a candidate maps onto task sources and emits structured evidence with `mode=task_adapter_dry_run`. It does not start angr and its status is normally `unknown`.

Symbolic mode starts angr with a symbolic argv source derived from the task source model. It constrains that symbolic source to the benign candidate input, explores to the selected sink callsite, and inspects the sink argument at that point. Its result uses `mode=symbolic_task`, `backend=angr`, and `executed=false`.

## Task Mapping

The first implementation maps:

- `task.binary.path` to the angr project binary.
- `task.sources[0].carrier`, currently `argv[1]`, to a symbolic argv value.
- `candidate.inputs[source.name]` to equality constraints on that symbolic argv value.
- The selected sink to `system` when a `command_execution` system sink exists, otherwise the first command execution sink, otherwise the first sink.
- `task.sinks[].address` to the target callsite address.

For `toy_01`, the selected sink is `system` at callsite `0x4011f9`, called from `main`.

## Toy Scope

The runner currently supports AMD64 argv-based toy CGI binaries. It installs a minimal local `snprintf` SimProcedure so toy source bytes can propagate into the stack command buffer before the `system` callsite. This is source-to-sink reachability evidence, not a model of libc or exploitability.

## Current Limits

The runner proves only a narrow property: a constrained benign source can reach a selected sink callsite and appear in the first sink argument under the toy model. It does not prove general exploitability, sanitizer bypass, shell execution, or real device impact. Non-AMD64 calling conventions, indirect calls, heap-heavy flows, and real firmware loader setup are out of scope.

## Step 35

Step 35 should update the evidence Markdown report to render symbolic proof fields such as `backend`, `sink_reached`, `source_bound`, `marker_observed`, `selected_sink`, `path_status`, and constraint summaries.

