# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Planner: `rule_based_planner`
- Planner version: `0.1`
- Planner mode: `benign_baseline`
- Planner provider: `not available`
- Base URL host: `not available`
- Model: `not available`
- Max tokens: `not available`
- Temperature: `not available`
- Verification mode: `symbolic`
- Candidate source: `reports/cross_arch/toy_smoke_direct_main/mipsel_toy_01/candidates.rule.json`
- Total candidates: `4`
- Best candidate: `toy_01_rule_001`
- Best status: `sat`

## Candidate Validation

- Candidate count: `4`
- Validation passed: `4`
- Validation failed: `0`
- Rejected candidates: `0`

## Status Counts

- sat: `4`

## Planner Diagnostics

- Sanitizer count: `0`
- Sanitizer types: `not available`
- Marker length: `17`
- Rejected count: `0`

## Evidence Counts

- Sink reached count: `4`
- Source bound count: `4`
- Marker observed count: `4`
- Full startup proof count: `0`
- Direct-main evidence count: `4`

## Evidence Strength

- Selected startup mode: `direct_main`
- Evidence level: `direct_main_symbolic`
- Can claim full startup proof: `false`
- Caution: Direct-main evidence bypasses startup/loader modeling and must not be used as a standalone real-firmware claim.

## Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Address: `0x400834`
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
