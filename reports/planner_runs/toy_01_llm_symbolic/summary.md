# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Planner: `api_llm_planner`
- Planner version: `0.1`
- Planner mode: `benign_candidate_generation`
- Planner provider: `openai_compatible`
- Base URL host: `not available`
- Model: `mimo-v2.5-pro`
- Max tokens: `not available`
- Temperature: `not available`
- Verification mode: `symbolic`
- Candidate source: `examples/candidates/toy_01_candidates.llm.generated.json`
- Total candidates: `3`
- Best candidate: `c1`
- Best status: `sat`

## Candidate Validation

- Candidate count: `3`
- Validation passed: `3`
- Validation failed: `0`

## Status Counts

- sat: `3`

## Evidence Counts

- Sink reached count: `3`
- Source bound count: `3`
- Marker observed count: `3`

## Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Address: `0x4011f9`
- Type: `command_execution`
- External address: `0x3`

## Limitations

- API LLM planner outputs are locally validated as benign candidates before verification
- candidate verification does not concretely execute target binaries or system/popen
- symbolic mode is currently scoped to local toy argv-based CGI binaries

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- Candidates are benign source-to-sink verification inputs.
