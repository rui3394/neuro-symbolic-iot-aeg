# Task-Driven Candidate Verifier

## Purpose

Step 30 adds a candidate verifier task adapter. The adapter lets the verifier consume `dangerous_path_task.json` as the unified input interface instead of directly depending on both Ghidra facts and YAML target files.

This is additive. The existing YAML demo pipeline, candidate contract verifier, planner skeleton, and symbolic verifier skeleton remain unchanged.

## Why The Task Is The Unified Entry

The Dangerous Path Task already joins the two upstream evidence sources:

- Ghidra facts provide binary metadata, dangerous sinks, callers, strings, and optional decompiled snippets.
- YAML target config provides HTTP source modeling and local verification scope.

The verifier should operate on that normalized task shape. This keeps task-mode verification independent from Ghidra runtime availability and avoids duplicating YAML parsing inside later verifier backends.

## What Task Mode Does Now

The current implementation provides:

- `ns_aeg.tasks.loader.load_dangerous_path_task` for strict task loading and clear errors.
- `ns_aeg.verifier.task_adapter.task_to_verifier_config` for extracting binary, entry, sources, sinks, oracle, marker, and evidence.
- `ns_aeg.verifier.candidate_verifier` CLI for task-mode verification output.
- Candidate input mapping by source name, including clear `missing_candidate_input` handling.
- Structured verification result JSON with status, task ID, candidate ID, binary, checked sources, checked sinks, oracle, marker, reason, limitations, and safety-relevant execution flag.

The result is intentionally marked as `task_adapter_dry_run` and `executed=false`.

## What Is Not Done Yet

Task mode does not yet wire the full symbolic execution backend. It does not execute the candidate, run the binary, generate exploit payloads, call an LLM, access the network, or interact with devices.

For a candidate with all required source inputs, the current status is `unknown` with this explicit limitation:

`symbolic execution backend not fully wired for task mode yet`

For a candidate missing a required source input, the status is `unsupported` and the reason names the missing input.

## Step 31

Step 31 should generate a Markdown evidence report from the task-mode verification JSON. That report should summarize the task, candidate, source/sink coverage, dry-run limitations, and whether the result is ready for real symbolic verification.

