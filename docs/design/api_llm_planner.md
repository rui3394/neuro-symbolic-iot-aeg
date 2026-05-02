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

The provider sends a minimal request body by default:

- `model`
- `messages`
- `temperature`
- `max_tokens`

It does not send `response_format`, `tools`, `tool_choice`, `stream`, or `max_completion_tokens` by default. If a provider explicitly supports JSON mode, opt in with:

```bash
export NS_AEG_LLM_RESPONSE_FORMAT=json_object
```

Planner generation defaults to `max_tokens=8192` because reasoning models may spend part of the output budget on `reasoning_content`. Override it if the debug file shows `finish_reason=length`:

```bash
export NS_AEG_LLM_MAX_TOKENS=12000
```

No API key is stored in code, tests, docs, generated artifacts, or logs.

## MiMo Compatibility Check

Before running full candidate generation, use the ping command:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner --ping
```

The ping sends only:

```text
Return only this JSON: {"ok": true}
```

and validates that the provider response can be parsed as `{"ok": true}`.

If debugging is needed:

```bash
export NS_AEG_LLM_DEBUG=1
.venv/bin/python -m ns_aeg.planner.api_planner --ping
```

or:

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json \
  --debug-response
```

This writes redacted diagnostics to `reports/llm_debug/last_response.redacted.json`. The file includes response shape, finish reason, message keys, content length, and reasoning-content length. It does not include the API key or Authorization header.

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

Some reasoning models may return `reasoning_content` alongside an empty `message.content`. The planner does not use `reasoning_content` as final candidate JSON. If this happens, the error reports whether reasoning content was present and the redacted debug file should be inspected.

If `finish_reason=length`, the provider truncated the final answer. The local parser will reject the incomplete JSON. Increase `NS_AEG_LLM_MAX_TOKENS` or use a smaller/non-reasoning model.
