# Strict Format/Memory Modeling Boundaries

Step 60 adds stricter evidence boundaries for toy-level format and memory-copy modeling.

## Purpose

The verifier now has positive format-flow cases (`toy_06`) and needs regression cases that prevent overclaiming. In real binaries, simplified libc models can easily become false-positive sources if truncation, length, or copy bounds are ignored.

Step 60 therefore adds four boundary toys:

- `toy_08_snprintf_truncation_negative`: `snprintf` writes into a buffer whose size is too small for the full benign marker.
- `toy_09_snprintf_truncation_positive`: `snprintf` has enough space for the marker and the buffer reaches `system(arg0)`.
- `toy_10_memcpy_flow_positive`: `memcpy` copies enough source bytes into a command buffer that reaches `system(arg0)`.
- `toy_11_memcpy_truncation_negative`: `memcpy` length is too small for the full marker before the buffer reaches `system(arg0)`.

## snprintf Boundary

For `snprintf(dst, size, fmt, value)`, the toy SimProcedure records:

- `size_value`
- `copy_length`
- `requested_length`
- `marker_written`
- `marker_truncated`
- `flows_to_command_sink`

If `size` is concrete, copied bytes are bounded to `size - 1`. If the marker is truncated, `marker_observed` must not become `true`, and the result must not be upgraded to `sat`.

If `size` is symbolic or unknown, evidence should be downgraded to inconclusive.

## sprintf Boundary

`sprintf` has no size argument. The current model can record source propagation, but marks evidence as less bounded. It remains auxiliary evidence and cannot independently produce command-sink positive evidence.

## memcpy Boundary

The first memcpy model supports only controlled toy propagation:

- `memcpy(dst, src, n)` copies at most the concrete `n` bytes.
- If `n` covers the full benign marker and the buffer reaches `system(arg0)`, the final system policy can report positive evidence.
- If `n` truncates the marker, `marker_truncated=true` and the result must not be `sat`.
- If `n` is symbolic or unknown, the result should be inconclusive.

This is not alias analysis and not a complete memory model.

## Evidence Rule

The final command evidence point remains `system(arg0)`:

- source/marker in `system(arg0)` => positive evidence / `sat`.
- sink reached but source/marker absent => negative evidence / `unsat`.
- source reaches only a format/memory helper but not `system(arg0)` => not `sat`.
- marker truncated before `system(arg0)` => not `sat`.

## Current Cross-Arch Result

After Step 60, the cross-arch benchmark contains 55 cases:

- `toy_01/toy_02/toy_06/toy_09/toy_10`: positive cases, 25 total `sat`.
- `toy_03`: 5 planner rejections.
- `toy_04`: 5 `unsat`.
- `toy_05/toy_07`: safe negative / negative evidence.
- `toy_08/toy_11`: 10 truncation negative cases, `unknown`/inconclusive rather than `sat`.
- `false_positive_count=0`.

## Safety Boundary

The model only reads and mutates symbolic state. It does not execute target binaries, does not execute `system`/`popen`, and does not generate weaponized exploit payloads.

## Remaining Work

- Full libc varargs semantics.
- Format width/precision parsing.
- Return-value semantics for `snprintf`.
- Robust alias analysis.
- Symbolic length reasoning for `memcpy`.
- Additional libc routines such as `strncpy`, `strlcpy`, `strcat`, and `memmove`.
