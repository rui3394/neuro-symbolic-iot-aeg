# Rule-Based Planner Baseline

## Purpose

Step 36 adds a deterministic planner baseline for the dangerous-path workflow:

```text
Dangerous Path Task -> Rule-based Planner -> Candidate Set
```

The planner consumes `dangerous_path_task.json` and generates benign candidate inputs for source-to-sink verification. It does not call an LLM and does not attempt to construct an exploit.

## Inputs And Outputs

Input:

- `task.sources`: source names, carriers, symbolic variable names, and `max_len`.
- `task.expected.benign_marker`: marker used to observe benign source propagation.

Output:

- A candidate set JSON with planner metadata and candidate objects.
- Each candidate has `candidate_id`, `strategy`, `inputs`, `assumptions`, and a safety block.

## Baseline Strategies

The first baseline emits simple benign marker probes:

- `benign_marker_direct`: `127.0.0.1__NS_AEG_MARKER__`
- `marker_only`: `__NS_AEG_MARKER__`
- `prefix_with_marker`: `SAFE__NS_AEG_MARKER__`
- `length_boundary_safe`: a max-length-safe value that still contains the marker

Candidates are rejected if they contain obvious shell composition characters, newlines, or exceed the source `max_len`.

## Safety Boundary

This planner is intentionally conservative:

- It only generates benign source-to-sink verification inputs.
- It marks all generated candidates as `weaponized=false`.
- It does not generate command separators or shell payloads.
- It does not execute the target binary.

## Current Limits

The planner is rule-based and task-schema driven. It does not reason over decompiled code, branch predicates, or sanitizer semantics yet. Step 39 will introduce an API-based LLM planner interface, with this rule planner retained as the deterministic baseline.

