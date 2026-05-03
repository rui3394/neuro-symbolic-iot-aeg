# Sanitizer-Aware Planner

## Purpose

Step 47 makes the rule planner aware of manually annotated sanitizer metadata in the Dangerous Path Task. The goal is not to force every toy case to become `sat`; the goal is to avoid generating candidates that are predictably incompatible with sanitizer constraints and to explain those cases clearly.

## Metadata Source

Current sanitizer metadata comes from target YAML manual annotations under `analysis.sanitizers`. The task builder carries those annotations into `dangerous_path_task.json`.

This step does not attempt full sanitizer recovery from decompiled code. Automatic extraction from Ghidra decompiler output is a later enhancement.

## Supported Sanitizers

### blacklist

Example:

```json
{
  "type": "blacklist",
  "chars": [";"]
}
```

The planner rejects candidates containing blacklisted characters. Existing global safety checks also reject obvious shell composition characters such as `;`, `&`, `|`, backticks, `$`, parentheses, and redirection characters.

### length_window

Example:

```json
{
  "type": "length_window",
  "max_prefix_len": 16,
  "requires_nul_within": 16
}
```

This models code that requires the input string terminator to appear within a fixed prefix window. If the benign marker length is greater than or equal to `requires_nul_within`, the marker cannot appear completely before the required NUL terminator. In that case, marker-based source-to-sink evidence is incompatible with the sanitizer.

## Candidate Set Diagnostics

Rule planner outputs can include:

- `planning_diagnostics.sanitizer_count`
- `planning_diagnostics.sanitizer_types`
- `planning_diagnostics.marker_len`
- `planning_diagnostics.rejected_count`
- `planning_diagnostics.notes`
- `rejected_candidates`

The verifier pipeline only verifies `candidates`; it does not send `rejected_candidates` to symbolic execution.

## toy_02

toy_02 filters semicolon. The rule planner candidates do not contain semicolon or other disallowed shell composition characters, so the sanitizer-aware planner still emits valid candidates. Symbolic verification reaches `system`, and the current summary remains `sat: 4`.

## toy_03

toy_03 requires a NUL terminator within the first 16 bytes. The current benign marker `__NS_AEG_MARKER__` has length 17. Therefore, the marker cannot fit within the allowed window while also being observed as a complete marker.

The sanitizer-aware planner emits zero valid candidates and records rejected candidates with reason `marker_length_exceeds_required_window`. This is not a verifier failure and not an exploit failure; it means the current benign marker verification strategy is incompatible with the length-window sanitizer.

## Current Limits

- Sanitizer metadata is manually annotated in YAML.
- Only blacklist and length-window patterns are modeled.
- The symbolic verifier still enforces real program constraints; planner diagnostics do not bypass sanitizer branches.
- Future work should add sanitizer-aware LLM prompting and alternative evidence strategies for short windows.

