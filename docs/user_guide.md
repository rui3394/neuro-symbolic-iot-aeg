# User Guide

## Environment

Create or activate the Python virtual environment, then install project dependencies as usual for this repository.

Set Ghidra 12.0.4:

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC
```

Check PyGhidra availability if running real facts export. If PyGhidra or Ghidra initialization fails, the exporter should return a clear error instead of producing misleading facts.

For a detailed explanation of generated JSON/Markdown artifacts, read [Output Artifacts Explained](reports/output_artifacts_explained.md). For a repository map and core file guide, read [Project Structure Explained](reports/project_structure_explained.md).
For sanitizer-aware planning behavior, read [Sanitizer-Aware Planner](design/sanitizer_aware_planner.md).

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

The recommended base URL is `https://token-plan-cn.xiaomimimo.com/v1`. The planner calls `{base_url}/chat/completions` and sends only `model`, `messages`, `temperature`, and `max_tokens` by default. It does not send `response_format` unless explicitly requested:

```bash
export NS_AEG_LLM_RESPONSE_FORMAT=json_object
```

Planner generation defaults to `max_tokens=8192`. If `reports/llm_debug/last_response.redacted.json` shows `finish_reason=length`, increase the budget:

```bash
export NS_AEG_LLM_MAX_TOKENS=12000
```

First run a minimal ping:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner --ping
```

If the provider returns empty `message.content`, enable redacted diagnostics:

```bash
export NS_AEG_LLM_DEBUG=1
.venv/bin/python -m ns_aeg.planner.api_planner --ping
```

The debug file is `reports/llm_debug/last_response.redacted.json`. It records response keys, finish reason, message keys, content length, and reasoning-content length, but not the API key or Authorization header.

Run the API planner:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json \
  --debug-response
```

Verify an existing LLM candidate set without another API call:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --candidates examples/candidates/toy_01_candidates.llm.generated.json \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

Run the LLM planner pipeline:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

To compare models, keep the same task and change only `NS_AEG_LLM_MODEL` and output paths:

```bash
export NS_AEG_LLM_MODEL=mimo-v2.5-pro
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.mimo-v2.5-pro.json

export NS_AEG_LLM_MODEL=mimo-v2.5
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.mimo-v2.5.json
```

Then run `run_planner_verifier --candidates ...` for each file. Summaries record provider, base URL host, model, max tokens, temperature, validation counts, and symbolic status counts.

Do not commit API keys or generated logs containing secrets. The project does not print API keys.

## Cross-Arch Toy Benchmark

Step 49 adds a scaffold for cross-compiled toy binaries. This is optional and does not install packages automatically.

Expected optional compilers:

- `gcc`
- `arm-linux-gnueabihf-gcc`
- `aarch64-linux-gnu-gcc`
- `mipsel-linux-gnu-gcc`
- `mips-linux-gnu-gcc`

Build the cross-arch toy benchmark matrix:

```bash
bash tools/build_cross_arch_toys.sh
```

The script writes:

```text
examples/cross_arch/toy_benchmark_manifest.json
datasets/toy_cgi/build_cross/<arch>/<toy>
```

If a compiler is missing, the build script records `skipped_compiler_missing` in the manifest and continues.

Run the cross-arch smoke pipeline:

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC

.venv/bin/python -m ns_aeg.pipeline.run_cross_arch_smoke \
  --manifest examples/cross_arch/toy_benchmark_manifest.json \
  --out-dir reports/cross_arch/toy_smoke
```

Outputs:

```text
reports/cross_arch/toy_smoke/summary.json
reports/cross_arch/toy_smoke/summary.md
reports/cross_arch/toy_smoke/<arch>_<toy>/
```

`unsupported` is an acceptable result for non-AMD64 symbolic cases. It means the scaffold reached a known backend limitation, not that a vulnerability was proven absent.

For Step 54 regression, toy_03 is expected to produce planner-level rejection rather than verifier `sat`: `candidate_count=0`, `rejected_count>0`, and `rejected_reason=marker_length_exceeds_required_window`. This validates that startup repair does not bypass sanitizer/path constraints.

For Step 55 regression, toy_04/toy_05 are negative fixtures. `false_positive_count` must stay `0`; any `sat` result for `unsat_expected`, `no_sink_expected`, or `planner_reject_expected` cases should be treated as a verifier regression.

For Step 56, toy_05 should be reported as sink-policy negative evidence: `system` is reached, but `system(arg0)` does not contain the source or benign marker, so the verifier reports `unsat` instead of `unknown`.

For Step 57-59, toy_06/toy_07 exercise format-flow evidence:

- toy_06: source/marker flows through `snprintf` into a command buffer and then into `system(arg0)`, so it should be `sat`.
- toy_07: source/marker reaches a formatting/log buffer, but `system(arg0)` is fixed and source-free, so it should be `negative_evidence`/`unsat`.
- Do not treat “source reaches snprintf” alone as command execution evidence; the final evidence point is `system(arg0)`.

For Step 60, toy_08/toy_09/toy_10/toy_11 exercise stricter format/memory boundaries:

- toy_08: `snprintf` truncates the benign marker; expected result is not `sat`.
- toy_09: `snprintf` has enough space; marker reaches `system(arg0)` and should be `sat`.
- toy_10: `memcpy` copies enough source bytes into the command buffer and should be `sat`.
- toy_11: `memcpy` length truncates the marker; expected result is not `sat`.
- `false_positive_count` and `truncation_false_positive_count` must stay `0`.

Design details:

- `docs/design/cross_arch_toy_benchmark.md`
- `docs/design/cross_arch_reachability_debugging.md`
- `docs/design/mips_direct_main_fallback.md`
- `docs/design/startup_evidence_strength.md`
- `docs/design/mips_full_init_root_cause.md`
- `docs/design/startup_repair_regression.md`
- `docs/design/false_positive_regression_toys.md`
- `docs/design/sink_specific_argument_policy.md`
- `docs/design/format_flow_policy.md`
- `docs/design/format_memory_modeling_boundaries.md`
- `docs/reports/toy_benchmark_status.md`

Startup evidence:

- `full-init` evidence starts from program initialization and can support full startup symbolic reachability claims.
- `direct-main` evidence starts at `main(argc, argv)` and bypasses startup/loader modeling.
- For real firmware, `direct-main` is disabled by default unless you explicitly pass `--allow-direct-main-for-non-toy` or annotate the task with `allow_direct_main=true`.
- Treat direct-main as modeling/debug evidence, not a standalone real-firmware claim.
- Step 53 repairs MIPS toy full-init by using block-level stepping for MIPS branch/delay-slot startup blocks; current MIPS/MIPSEL toy_01/toy_02 auto results should be full-init evidence.

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
- Empty content with reasoning content: inspect `reports/llm_debug/last_response.redacted.json`; the planner does not use `reasoning_content` as candidate JSON.
- Truncated content: if `finish_reason=length`, increase `NS_AEG_LLM_MAX_TOKENS` or use a smaller/non-reasoning model.
- JSON parse failure: the provider did not return valid candidate JSON; no candidate is passed to the verifier.
- angr cannot find binary: verify `task.binary.path` points to an existing toy binary.
- symbolic mode unsupported: the current backend is scoped to toy argv-based CGI binaries.
