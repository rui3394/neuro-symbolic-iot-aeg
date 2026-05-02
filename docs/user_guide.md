# User Guide

## Environment

Create or activate the Python virtual environment, then install project dependencies as usual for this repository.

Set Ghidra 12.0.4:

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC
```

Check PyGhidra availability if running real facts export. If PyGhidra or Ghidra initialization fails, the exporter should return a clear error instead of producing misleading facts.

## Run The Ghidra-Assisted Pipeline

Export real Ghidra facts:

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_01 \
  --out examples/ghidra_exports/toy_01_facts.real.json
```

Build a Dangerous Path Task:

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.real.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.real.json
```

Generate rule planner candidates:

```bash
.venv/bin/python -m ns_aeg.planner.rule_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.rule.generated.json
```

Run the rule planner through symbolic verification:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_rule_symbolic
```

Generate the planner summary Markdown:

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_rule_symbolic/summary.json \
  --out reports/planner_runs/toy_01_rule_symbolic/summary.md
```

Generate a per-candidate evidence report from any verification JSON:

```bash
.venv/bin/python -m ns_aeg.reports.evidence_report \
  --verification reports/planner_runs/toy_01_rule_symbolic/verifications/toy_01_rule_001.json \
  --out reports/planner_runs/toy_01_rule_symbolic/toy_01_rule_001.md
```

## LLM Planner Usage

Offline deterministic LLM-style output:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --offline-example \
  --out examples/candidates/toy_01_candidates.llm.example.json
```

Offline LLM-style planner-verifier pipeline:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --offline-example \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_offline_symbolic
```

MiMo Token Plan live API test uses OpenAI-compatible Chat Completions:

```bash
export NS_AEG_LLM_PROVIDER=openai_compatible
export NS_AEG_LLM_BASE_URL=https://token-plan-cn.xiaomimimo.com/v1
export NS_AEG_LLM_API_KEY=<your-token>
export NS_AEG_LLM_MODEL=<your-model>
export NS_AEG_RUN_LLM_TESTS=1
```

Run the API planner:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json
```

Run the LLM planner pipeline:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

Do not commit API keys or generated logs containing secrets. The project does not print API keys.

## Safety Notes

- The pipeline does not concretely execute target binaries.
- The pipeline does not execute `system` or `popen`.
- The planners do not generate weaponized exploit payloads.
- Candidates are benign source-to-sink verification inputs.
- A `sat` symbolic result is source-to-sink evidence, not complete exploit verification.

## Common Errors

- Ghidra path error: verify `GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC`.
- PyGhidra mismatch: ensure the installed PyGhidra version can initialize the configured Ghidra.
- API key missing: set `NS_AEG_LLM_API_KEY` or use `--offline-example`.
- API timeout: retry with a reachable OpenAI-compatible endpoint and model.
- JSON parse failure: the provider did not return valid candidate JSON; no candidate is passed to the verifier.
- angr cannot find binary: verify `task.binary.path` points to an existing toy binary.
- symbolic mode unsupported: the current backend is scoped to toy argv-based CGI binaries.

