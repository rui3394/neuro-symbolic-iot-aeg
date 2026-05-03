# Sink-Specific Argument Policy

Step 56 adds a sink-specific policy layer between generic ABI argument inspection and final verifier status.

## Purpose

Generic sink argument inspection can answer low-level questions such as:

- which ABI location holds the argument;
- whether the argument memory contains the source symbolic variable;
- whether the argument text contains the benign marker.

That is not enough for negative evidence. A sink can be reached while still being safe for the current candidate, for example when `system(arg0)` receives a fixed benign command that does not include source-controlled data. The policy layer turns this into explicit source-to-sink evidence classification.

## Interface

`ns_aeg.verifier.sink_policy.evaluate_sink_policy(...)` returns:

- `sink_type`
- `sink_function`
- `policy_name`
- `policy_status`
- `reason`
- `source_reaches_sink`
- `marker_reaches_sink`
- `fixed_safe_argument`
- `limitations`

`policy_status` values:

- `positive_evidence`: source and marker reach the sink argument.
- `negative_evidence`: sink is reached, but policy proves source/marker do not reach the relevant argument.
- `inconclusive`: sink is reached, but argument evidence is insufficient.
- `unsupported`: no policy exists for the sink type/function.

## system(arg0) Policy

The first implemented policy is `command_execution/system`:

- source and marker both observed in `system(arg0)` => `positive_evidence`, verifier status `sat`;
- neither source nor marker observed in `system(arg0)` => `negative_evidence`, verifier status `unsat`;
- argument unreadable or partial evidence => `inconclusive`, verifier status `unknown`.

This prevents “sink reached” from being treated as sufficient evidence.

## toy_05

`toy_05` reaches `system`, but the command string is fixed and does not include the source parameter. Before Step 56 it was reported as `unknown`. After Step 56:

- `sink_reached=true`
- `sink_policy.policy_status=negative_evidence`
- `sink_policy.reason=safe_fixed_sink_argument_without_source`
- verifier status becomes `unsat`

This is negative source-to-sink evidence, not proof that the binary has no other issue.

## snprintf/sprintf Format-Flow Policy

Step 57 extends the policy layer with auxiliary format-flow evidence for `snprintf` and `sprintf`.

The key rule is conservative:

- source/marker reaching `snprintf` or `sprintf` is useful evidence, but it is not enough to claim command execution reachability;
- the final positive command evidence must still be observed at `system(arg0)`;
- if source/marker reaches a format buffer but `system(arg0)` is fixed or source-free, the final result remains negative evidence.

The symbolic runner records `format_flow` when the local toy `snprintf`/`sprintf` SimProcedure writes source-controlled bytes into a destination buffer:

- `format_sink`
- `format_callsite`
- `dst_buffer`
- `source_or_marker_written`
- `flows_to_command_sink`
- `limitations`

`toy_06` is the positive case: source enters `snprintf(cmd, ...)`, and `system(cmd)` later consumes that buffer. The verifier reports both `format_flow.status=positive` and `sink_policy.policy_status=positive_evidence`.

`toy_07` is the safe-negative case: source enters a formatting/log buffer, but `system` consumes a fixed command string. The verifier reports `format_flow.status=negative` and `sink_policy.policy_status=negative_evidence`.

## Unsupported Policies

Step 60 tightens the format/memory boundary:

- `snprintf` records concrete `size` and truncation evidence.
- `sprintf` remains less bounded because it has no size argument.
- `memcpy` has a minimal toy propagation model that respects concrete `n`.
- `marker_truncated=true` prevents `sat`; the verifier reports `unknown`/inconclusive instead of positive evidence.

The following are intentionally left as future work:

- full libc-accurate `snprintf` / `sprintf` varargs semantics;
- multi-source format strings and complex output length constraints;
- robust `memcpy`/`memmove` alias analysis and symbolic length policy;
- stack argument policies for i386.

Unsupported policies return `unsupported` or `inconclusive`; they must not be upgraded to `sat` without source/marker evidence.

## Safety Boundary

The policy layer only reads symbolic state and structured sink metadata. It does not execute the target binary, does not execute `system`/`popen`, and does not generate weaponized exploit payloads.
