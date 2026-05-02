# API-Based LLM Planner Interface

## Purpose

Step 39 adds an API-based planner interface after the deterministic rule planner baseline. The LLM planner consumes a `dangerous_path_task.json` and emits the same candidate set format used by the rule planner, so the existing planner-verifier pipeline can verify candidates without changing verifier logic.

## Provider Model

Runtime planner integration uses a provider abstraction, not Claude Code or OpenCode as a runtime planner. The first provider is OpenAI-compatible Chat Completions:

```text
{NS_AEG_LLM_BASE_URL}/chat/completions
```

MiMo Token Plan can be tested by setting:

```bash
export NS_AEG_LLM_PROVIDER=openai_compatible
export NS_AEG_LLM_BASE_URL=https://token-plan-cn.xiaomimimo.com/v1
export NS_AEG_LLM_API_KEY=<your-token>
export NS_AEG_LLM_MODEL=<your-model>
```

No API key is stored in code, tests, docs, generated artifacts, or logs.

## Offline By Default

Default pytest and default local development do not access the network. The planner supports:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --offline-example \
  --out examples/candidates/toy_01_candidates.llm.example.json
```

`--offline-example` emits deterministic LLM-style benign candidates with planner metadata `api_llm_planner_offline`.

## Prompt Contract

The prompt instructs the model to:

- generate only benign source-to-sink verification inputs
- output JSON only
- include source inputs for all task sources
- include the benign marker when available
- stay within each source `max_len`
- avoid shell composition characters: `; & | \` $ ( ) > <`
- avoid newlines
- set `safety.benign=true`
- set `safety.weaponized=false`

## Local Validation

LLM output is never trusted directly. The local validator enforces:

- non-empty candidate list
- maximum five candidates
- source input coverage
- string input values
- per-source length limits
- no newlines
- no obvious shell composition characters
- benign marker presence when configured
- `safety.weaponized=false`

Invalid model output fails with a clear error and is not passed to the verifier.

## Safety Boundary

The API planner does not execute target binaries, does not execute `system` or `popen`, and does not generate weaponized exploit payloads. It only proposes benign inputs for source-to-sink evidence collection.

## Current Limits

The provider currently supports OpenAI-compatible Chat Completions only. It does not use Responses API. Live API tests are opt-in with `NS_AEG_RUN_LLM_TESTS=1` and require base URL, API key, and model environment variables.

