# Quickstart: Ghidra-Assisted Pipeline

Run from the repository root.

## 1. Environment

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC
```

## 2. Tests

```bash
.venv/bin/python -m pytest
```

## 3. Export Real Facts

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_01 \
  --out examples/ghidra_exports/toy_01_facts.real.json
```

## 4. Build Dangerous Path Task

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.real.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.real.json
```

## 5. Run Rule Planner Symbolic Pipeline

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_rule_symbolic
```

## 6. Generate Summary Markdown

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_rule_symbolic/summary.json \
  --out reports/planner_runs/toy_01_rule_symbolic/summary.md
```

## 7. Optional LLM Offline Example

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --offline-example \
  --out examples/candidates/toy_01_candidates.llm.example.json

.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --offline-example \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_offline_symbolic
```

## 8. Optional MiMo Token Plan Live API Test

```bash
export NS_AEG_LLM_PROVIDER=openai_compatible
export NS_AEG_LLM_BASE_URL=https://token-plan-cn.xiaomimimo.com/v1
export NS_AEG_LLM_API_KEY=<your-token>
export NS_AEG_LLM_MODEL=<your-model>
export NS_AEG_RUN_LLM_TESTS=1

.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json

.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

## Safety Boundary

This quickstart does not concretely execute target binaries, does not execute `system` or `popen`, and does not generate weaponized exploit payloads. It produces benign source-to-sink verification evidence.

