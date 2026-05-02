# Dangerous Path Task Builder

## Purpose

Step 29 introduces the bridge between static Ghidra facts and the local verifier contract. The builder reads a Ghidra facts JSON file plus the existing YAML target config and emits a `dangerous_path_task.json` document for later verification and benign input synthesis.

This preserves the existing demo pipeline. The task builder is additive and does not change report generation, mock planning, candidate validation, or angr reachability.

## Relationship Between Inputs

The YAML target remains the source-of-intent file. It identifies the local binary, HTTP route, source parameters, and configured analysis scope.

The Ghidra facts JSON is the source-of-static-evidence file. It lists binary metadata, functions, dangerous sinks, callers, strings, and optional decompiled snippets.

The Dangerous Path Task is the normalized handoff. It combines:

- Binary identity from facts, with YAML as fallback.
- Sources from YAML-derived HTTP source modeling.
- Sinks from Ghidra facts.
- Evidence from Ghidra strings and decompiler snippets.
- Expected verifier oracle defaults for source-to-sink checking.

## Core Interface For Later Verifier And Planner Work

The task schema becomes the stable boundary for Step 30 and later work. The verifier should not need to parse Ghidra output or target YAML directly for dangerous-path checks; it should consume a bounded task object with sources, sinks, evidence, and expected oracle fields.

This also gives a future LLM planner a constrained input format. The planner can reason over static evidence and verifier goals without receiving raw binaries, executing anything, or inventing payloads outside the local benign contract.

## Current Non-Goals

The builder does not execute binaries. It does not synthesize concrete exploit inputs, run shell commands, call a real LLM, contact a network service, or modify the existing verifier. It only constructs a static JSON task for later benign local verification.

## CLI

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.example.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.generated.json
```

The command fails with a clear error if the facts file, target file, sources, or dangerous sinks are missing.

