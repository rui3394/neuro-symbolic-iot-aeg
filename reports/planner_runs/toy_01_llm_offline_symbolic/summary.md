# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Planner: `api_llm_planner_offline`
- Planner version: `0.1`
- Planner mode: `benign_candidate_generation`
- Verification mode: `symbolic`
- Total candidates: `3`
- Best candidate: `toy_01_llm_offline_001`
- Best status: `sat`

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
