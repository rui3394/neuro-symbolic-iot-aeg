# Planner-Verifier Pipeline

## Purpose

Step 37 connects planners to the task-driven candidate verifier:

```text
Dangerous Path Task -> Planner -> Candidate Set -> Symbolic Verifier -> Summary
```

The pipeline is an orchestration layer. It does not replace the existing verifier and does not change the older YAML demo pipeline.

## Execution Model

`ns_aeg.pipeline.run_planner_verifier` loads a dangerous path task, generates a candidate set with the selected planner, and verifies each candidate through the existing task verifier functions.

Supported planners:

- `rule`: deterministic benign baseline.
- `llm`: API-based LLM planner interface.
- `llm --offline-example`: deterministic LLM-style offline candidates for tests and demos.

Supported modes:

- `dry-run`: adapter-level source/sink/input mapping checks.
- `symbolic`: angr-backed symbolic reachability where the existing task symbolic runner supports it.

Each candidate writes an individual verification result under `verifications/<candidate_id>.json`. A single candidate failure is recorded as a structured `unsupported` result instead of aborting the batch.

## Summary Selection

The pipeline writes `summary.json` and `best_candidate.json`.

Best candidate priority:

1. `status=sat`
2. `sink_reached=true`
3. `marker_observed=true`

If no candidate meets these criteria, `best_candidate.json` records `null` and the reason.

## Safety Boundary

The pipeline reuses verifier adapters and symbolic execution. It does not concretely execute the target binary, does not execute `system` or `popen`, and does not generate weaponized exploit inputs.

## Current Limits

Symbolic mode is currently scoped to the toy argv-based CGI binary support implemented in Step 34. For unsupported binaries, missing angr dependencies, missing LLM provider configuration, or insufficient task metadata, candidates produce structured errors or the pipeline exits with a clear configuration error.

The LLM planner path uses local validation before verification. Candidate values containing obvious shell composition characters, newlines, over-length strings, or `weaponized=true` are rejected.

