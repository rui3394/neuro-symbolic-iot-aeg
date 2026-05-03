# Current System Summary

## Positioning

The project is currently positioned as:

```text
Ghidra-Assisted Neuro-Symbolic Dangerous-Path Verification and Input Synthesis for IoT CGI Binaries
```

The current end-to-end flow is:

```text
Ghidra real facts -> Dangerous Path Task -> Planner candidates -> Symbolic Verifier -> Summary/Evidence Reports
```

## Completed Capabilities

- Ghidra/PyGhidra real facts export.
- Dangerous sink catalog and static sink extraction.
- xrefs, callsites, callers, and best-effort decompiled snippet extraction.
- Dangerous Path Task builder from Ghidra facts and YAML target metadata.
- Task-driven verifier dry-run adapter.
- Symbolic task verifier for `toy_01`.
- Evidence Markdown report with symbolic evidence fields.
- Rule-based planner baseline.
- Planner-verifier batch pipeline.
- Planner evaluation summary JSON and Markdown report.
- API-based LLM planner interface with offline deterministic mode and OpenAI-compatible Chat Completions provider.
- Generic sink argument inspection layer with ABI register mapping for AMD64, ARM32, AArch64, and MIPS32.

## Current toy_01 Result

Current `toy_01` real facts include functions, imports, dangerous sinks, xrefs/callsites, strings, and decompiled snippets. The important real sink facts are:

- `snprintf`: callsite `0x4011ea`, caller `main`, caller entry `0x401176`.
- `system`: callsite `0x4011f9`, caller `main`, caller entry `0x401176`.

The symbolic verifier result for `toy_01` is:

- `status=sat`
- `mode=symbolic_task`
- `backend=angr`
- `selected_sink=system @ 0x4011f9`
- `selected_entry=main @ 0x401176`
- `sink_reached=true`
- `source_bound=true`
- `marker_observed=true`
- `sink_argument.arch=AMD64`
- `sink_argument.arg_index=0`
- `sink_argument.location=register:rdi`
- `sink_argument.contains_source=true`
- `sink_argument.contains_marker=true`

The rule planner baseline currently generates four benign candidates for `toy_01`; all four are `sat` in the symbolic planner-verifier pipeline.

## Current Limits

- Symbolic backend support is primarily scoped to toy argv-based CGI binaries.
- Sink argument inspection is no longer hardcoded in the verifier main loop, but real regression is still focused on AMD64 toy binaries; i386 stack arguments and non-AMD64 real binaries remain future work.
- `snprintf` is modeled with a minimal local SimProcedure for toy source propagation.
- The system provides source-to-sink symbolic evidence, not full exploit verification.
- The system does not execute `system` or `popen`.
- The system does not execute target binaries concretely.
- The system has not yet been evaluated on real firmware case studies.
- The API-based LLM planner interface is implemented, but live provider testing is left to the user via opt-in environment variables.

## Next Roadmap

- Extend non-AMD64 sink argument inspection from ABI mapping to real binary regression.
- Compare LLM planner output against the rule planner baseline.
- Add real firmware case studies.
- Build dataset, baseline, and ablation evaluation scripts.
