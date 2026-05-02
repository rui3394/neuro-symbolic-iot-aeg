# Planner Evaluation Summary

## Purpose

Step 38 adds a batch-level Markdown report for planner-verifier runs. It turns `summary.json` into a compact analyst-facing view of planner performance and verifier outcomes.

## Relationship To Evidence Reports

Per-candidate evidence reports describe one verification result. Planner summary reports aggregate a candidate set:

- number of candidates generated
- status counts
- best candidate
- selected sink
- source/sink/marker evidence counts
- limitations and safety notes

This lets reviewers compare planner behavior without opening every individual verification JSON.

## Report Contents

The Markdown report includes:

- task ID
- planner name/version/mode
- verification mode
- total candidates
- status counts
- best candidate
- sink/source/marker observation counts
- selected sink
- limitations
- safety note

## Safety Boundary

The summary explicitly records that no target binary was concretely executed, no `system` or `popen` command was executed, no weaponized exploit was generated, and candidates are benign source-to-sink verification inputs.

## Current Limits

The summary is descriptive. It does not perform additional verification beyond the batch results and does not rank candidates by exploitability. Step 39 will add the API-based LLM planner interface while preserving this summary format for planner comparison.

