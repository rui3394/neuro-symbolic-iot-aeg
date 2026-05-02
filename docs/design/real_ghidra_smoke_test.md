# Real Ghidra/PyGhidra Smoke Test

## Purpose

Step 32 verifies that the Ghidra facts exporter can run against a real Ghidra/PyGhidra installation for the local `toy_01` CGI binary. This moves the pipeline from example facts to real static facts while keeping verification in dry-run task adapter mode.

This smoke test does not execute the target binary, generate exploit material, call an LLM, or modify the symbolic backend.

## Environment

Set the Ghidra install directory before running the real exporter:

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_11.3.2_PUBLIC
```

The exporter checks that this directory exists and contains:

```text
/home/kali/tool/ghidra_11.3.2_PUBLIC/support/analyzeHeadless
```

PyGhidra should be importable from the active Python environment:

```bash
.venv/bin/python -c "import pyghidra; print(pyghidra.__file__)"
```

## Real Facts Export

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_01 \
  --out examples/ghidra_exports/toy_01_facts.real.json
```

The exporter starts PyGhidra using `GHIDRA_INSTALL_DIR`, opens the binary, runs Ghidra analysis through `pyghidra.open_program`, and writes a facts JSON file. If PyGhidra, Java, or Ghidra initialization fails, the command exits with a clear error instead of writing misleading successful facts.

By default, the temporary PyGhidra project directory is created under `/tmp/ns_aeg_pyghidra_projects` so the repository workspace is not polluted. Use `--project-location` to override this path.

The legacy example path remains available and does not start Ghidra:

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --example \
  --out examples/ghidra_exports/toy_01_facts.example.copy.json
```

## Full Smoke Pipeline

After generating real facts, feed them into the existing Step 29-31 chain:

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.real.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.real.json

.venv/bin/python -m ns_aeg.verifier.candidate_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --candidate examples/candidates/toy_01_candidate.example.json \
  --out reports/evidence/toy_01_verification.real.json

.venv/bin/python -m ns_aeg.reports.evidence_report \
  --verification reports/evidence/toy_01_verification.real.json \
  --out reports/evidence/toy_01_evidence.real.md
```

## Opt-In Tests

Default pytest does not require Ghidra:

```bash
.venv/bin/python -m pytest
```

Run the real Ghidra smoke test only when explicitly requested:

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_11.3.2_PUBLIC
export NS_AEG_RUN_GHIDRA_TESTS=1
.venv/bin/python -m pytest tests/test_ghidra_facts_exporter.py
```

## Current Limitations

Real facts include binary metadata, functions, imports/externals, dangerous sink matches, strings, best-effort xrefs/callers, callsites, and best-effort decompiled snippets. Imported sinks keep both `external_address` and a verifier-oriented `address`. When a callsite is available, `address` is the callsite address; otherwise it falls back to `external_address` and the exporter records a warning.

The downstream verifier remains `task_adapter_dry_run`; evidence reports generated from this pipeline are not symbolic proofs.

Step 33 strengthened xref/caller extraction for imported sink calls through PLT/thunk functions. Step 34 should connect the task-driven verifier back to symbolic reachability.
