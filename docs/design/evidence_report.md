# Evidence Markdown Report

## Purpose

Step 31 added a Markdown evidence report generator for task-mode verifier output. Step 35 extends it so symbolic verifier output has a dedicated symbolic evidence summary. The report converts structured verification JSON into a short, reviewable artifact for analysts and project reviewers.

This report generator does not execute binaries, generate exploit material, call an LLM, or modify the symbolic backend.

## Verification JSON To Markdown

The verifier JSON is the machine-readable result. It captures the task ID, candidate ID, binary identity, checked sources, checked sinks, oracle, benign marker, reason, limitations, execution flag, and for symbolic mode, backend/path/source-to-sink evidence fields.

The evidence Markdown is the human-readable projection of that same result. It is intended for quick review and for attaching to demo artifacts without requiring readers to inspect raw JSON.

## Why This Is Useful For Analysts

The report highlights the fields that matter for dangerous-path review:

- Which task and candidate were evaluated.
- Which local binary and architecture were in scope.
- Which source inputs were mapped.
- Which dangerous sinks were checked.
- Whether the benign marker was observed in candidate source input.
- Whether the result is a dry-run adapter result or angr symbolic reachability evidence.
- What safety guarantees were enforced.

Candidate input values are summarized by presence, length, and benign marker hit. They are not rendered as weaponized payloads.

## Dry-Run And Symbolic Reports

For `task_adapter_dry_run`, the report explicitly states:

- This is an adapter-level dry-run result.
- The symbolic execution backend has not been fully wired for task mode yet.
- No target binary was executed.
- No weaponized exploit was generated.

For `symbolic_task`, the report adds a `Symbolic Evidence` section with:

- backend, currently `angr`;
- path status;
- selected entry;
- selected sink;
- sink reached;
- source bound;
- marker observed;
- constraints summary.

## What Symbolic Evidence Can Show

For the current toy scope, a `sat` symbolic report means angr reached the selected sink callsite under the benign candidate constraints and observed the source/benign marker evidence in the inspected sink argument.

This is source-to-sink symbolic evidence. It is not full exploit verification.

## What It Cannot Prove Yet

The report does not prove real-world exploitability, sanitizer bypass, shell execution, device impact, or complete libc semantics. It preserves these safety notes even for `status=sat`:

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- This is source-to-sink symbolic evidence, not full exploit verification.

## Step 36

Step 36 should introduce a rule-based planner baseline that consumes the task and verification evidence without relying on an LLM.
