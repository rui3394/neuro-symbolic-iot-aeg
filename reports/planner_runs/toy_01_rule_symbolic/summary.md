# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Planner: `rule_based_planner`
- Planner version: `0.1`
- Planner mode: `benign_baseline`
- Verification mode: `symbolic`
- Total candidates: `4`
- Best candidate: `toy_01_rule_001`
- Best status: `sat`

## Status Counts

- sat: `4`

## Evidence Counts

- Sink reached count: `4`
- Source bound count: `4`
- Marker observed count: `4`

## Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Address: `0x4011f9`
- Type: `command_execution`
- External address: `0x3`

## Limitations

- rule planner is a benign deterministic baseline, not an exploit generator
- candidate verification does not concretely execute target binaries or system/popen
- symbolic mode is currently scoped to local toy argv-based CGI binaries

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- Candidates are benign source-to-sink verification inputs.
