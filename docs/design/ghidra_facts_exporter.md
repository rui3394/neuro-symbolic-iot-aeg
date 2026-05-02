# Ghidra Facts Exporter

## Why This Exists

The current demo proves a local YAML-to-angr pipeline for toy CGI binaries. That is useful for controlled tests, but it does not provide enough static program context for the next direction: Ghidra-assisted dangerous-path verification and input synthesis.

The Ghidra facts exporter adds a static analysis bridge. It records binary metadata, discovered functions, imports/externals, dangerous sink matches, caller xrefs, strings, and optional decompiled snippets. Downstream components can consume these facts without embedding Ghidra into every test or verifier run.

## Relationship To Current YAML Targets And Verifier

YAML targets remain the runtime intent layer: target name, binary path, HTTP source model, and configured sink list. The Ghidra facts JSON is a separate static evidence layer for the same binary.

The existing verifier currently uses angr plus YAML-derived source modeling to ask whether a source reaches a sink argument. The Ghidra facts exporter does not replace that. It provides extra context that angr can use later, such as:

- Which dangerous sinks are present even if not listed in YAML.
- Which functions call those sinks.
- Which strings and decompiled snippets may explain path predicates or formatting behavior.
- Which sink addresses should be prioritized for symbolic reachability.

This keeps `reports/demo_summary.json` and the current demo pipeline unchanged.

## Current Scope

The first version is intentionally minimal:

- `ns_aeg/ghidra/sink_catalog.py` defines a small static catalog of dangerous sink names and categories.
- `ns_aeg/ghidra/export_facts.py` can export facts from a Ghidra `currentProgram` context or from PyGhidra when available.
- `schemas/ghidra_facts.schema.json` defines the expected JSON shape.
- `examples/ghidra_exports/toy_01_facts.example.json` is a stable example for tests and downstream contract work.

The exporter is best-effort. If Ghidra APIs for strings, xrefs, or decompilation are unavailable, it records warnings and still returns the facts it can collect. If no Ghidra runtime is available, it raises a clear `GhidraUnavailableError`; the CLI can also write a schema-shaped error JSON with `--write-error-json`.

The exporter only extracts static facts. It does not execute target binaries, candidate inputs, shell commands, network actions, or device interactions.

## Next Integration Point

The Dangerous Path Task builder should join three inputs:

- YAML target config for intended HTTP source and local verification scope.
- Ghidra facts for static sink/caller/string/decompiler evidence.
- Existing angr/verifier observations for source-to-sink feasibility.

The first task-builder pass should select dangerous sinks from `dangerous_sinks`, rank caller functions from `xrefs`, attach nearby strings/decompiled snippets as explanation-only context, and emit a bounded verification request for angr. Input synthesis should remain benign and local, with the candidate contract continuing to reject executable or real-world action payloads.

