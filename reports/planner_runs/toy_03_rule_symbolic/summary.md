# Planner Verification Summary

## Summary

- Task ID: `dangerous_path:toy_03_length_limit:toy_03`
- Planner: `rule_based_planner`
- Planner version: `0.1`
- Planner mode: `sanitizer_aware_benign_baseline`
- Planner provider: `not available`
- Base URL host: `not available`
- Model: `not available`
- Max tokens: `not available`
- Temperature: `not available`
- Verification mode: `symbolic`
- Candidate source: `generated`
- Total candidates: `0`
- Best candidate: `not available`
- Best status: `not available`

## Candidate Validation

- Candidate count: `0`
- Validation passed: `0`
- Validation failed: `0`
- Rejected candidates: `4`

## Status Counts

_None reported._

## Planner Diagnostics

- Sanitizer count: `1`
- Sanitizer types: `length_window`
- Marker length: `17`
- Rejected count: `4`
- Notes: benign marker length is incompatible with length_window sanitizer (marker_len=17, requires_nul_within=16); no valid candidates generated because sanitizer constraints are incompatible with the benign marker strategy

| Strategy | Source | Sanitizer | Reason |
| --- | --- | --- | --- |
| benign_marker_direct | ip | length_window | marker_length_exceeds_required_window |
| marker_only | ip | length_window | marker_length_exceeds_required_window |
| prefix_with_marker | ip | length_window | marker_length_exceeds_required_window |
| length_boundary_safe | ip | length_window | marker_length_exceeds_required_window |

## Evidence Counts

- Sink reached count: `0`
- Source bound count: `0`
- Marker observed count: `0`

## Selected Sink

_Not available._

## Limitations

- rule planner is a benign deterministic baseline, not an exploit generator
- candidate verification does not concretely execute target binaries or system/popen
- symbolic mode is currently scoped to local toy argv-based CGI binaries

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- Candidates are benign source-to-sink verification inputs.
