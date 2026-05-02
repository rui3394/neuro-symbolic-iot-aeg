# LLM Model Comparison Hooks

## Purpose

Step 42 adds metadata and validation fields needed to compare API-based planner models without changing verifier logic.

The comparison flow is:

```text
Dangerous Path Task -> LLM Planner -> Candidate Set -> Local Validation -> Symbolic Pipeline -> Summary
```

## Recommended Models

- MiMo-V2.5-Pro is the recommended default planner model.
- MiMo-V2.5 can be used as a cost/effectiveness comparison point.
- MiMo-V2-Pro can be used as an older agent-style baseline.
- TTS, VoiceClone, and VoiceDesign models are not appropriate planner models because they are not text reasoning/candidate-generation models.
- Omni is not needed for the current planner interface because the task input and candidate output are text/JSON only.

## Metadata Captured

Candidate sets and summaries can record:

- provider
- base URL host, not the full secret-bearing request
- model
- max tokens
- temperature
- candidate count
- validation passed count
- validation failed count

These fields are enough to compare candidate quality and verifier outcomes across models.

## Validation Report

Each LLM candidate is checked locally before verification:

- covers every task source
- contains the benign marker
- stays within source `max_len`
- avoids obvious shell composition characters
- has `safety.weaponized=false`

Invalid candidates are rejected before symbolic verification.

## Reproducible Offline Verification

Generate candidates once:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json \
  --debug-response
```

Then verify repeatedly without another API call:

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --candidates examples/candidates/toy_01_candidates.llm.generated.json \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

## Safety Boundary

Model comparison is candidate-generation evaluation, not exploit generation. The system does not concretely execute target binaries, does not execute `system` or `popen`, and rejects weaponized candidate metadata.

