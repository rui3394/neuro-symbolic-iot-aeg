# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_05_safe_case:toy_05`
- Planner: `rule_based_planner`
- Planner version: `0.1`
- Planner mode: `benign_baseline`
- Planner provider: `not available`
- Base URL host: `not available`
- Model: `not available`
- Max tokens: `not available`
- Temperature: `not available`
- Verification mode: `symbolic`
- Candidate source: `reports/cross_arch/toy_smoke_full_init/aarch64_toy_05/candidates.rule.json`
- Total candidates: `4`
- Best candidate: `not available`
- Best status: `not available`

## Candidate Validation

- Candidate count: `4`
- Validation passed: `4`
- Validation failed: `0`
- Rejected candidates: `0`

## Status Counts

- unsat: `4`

## Planner Diagnostics

- Sanitizer count: `0`
- Sanitizer types: `not available`
- Marker length: `17`
- Rejected count: `0`

## Evidence Counts

- Sink reached count: `0`
- Source bound count: `0`
- Marker observed count: `0`
- Safe negative count: `0`
- Sink policy positive count: `0`
- Sink policy inconclusive count: `0`
- Sink policy unsupported count: `0`
- Format-flow positive count: `0`
- Format-flow negative count: `0`
- Format-flow inconclusive count: `0`
- Truncation negative count: `0`
- Truncation false positive count: `0`
- Memcpy positive count: `0`
- Memcpy truncation negative count: `0`
- Inconclusive count: `0`
- Full startup proof count: `4`
- Direct-main evidence count: `0`

## Evidence Strength

- Selected startup mode: `full_init`
- Evidence level: `full_program_startup_symbolic`
- Can claim full startup proof: `true`

## Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Address: `0x4007bc`
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
