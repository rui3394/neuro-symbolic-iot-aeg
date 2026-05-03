# Format-Flow Policy

Step 57-60 add a conservative format/memory-flow evidence layer for toy CGI binaries.

## Motivation

Many CGI command paths do not call `system(argv[1])` directly. A common shape is:

```c
snprintf(cmd, sizeof(cmd), "echo %s", ip);
system(cmd);
```

For verification, source reaching `snprintf` is not enough. `snprintf` might write into a log buffer or unused buffer. The command evidence point is still `system(arg0)`.

## Policy Rule

The verifier records format writes as auxiliary evidence:

- source/marker written to `snprintf`/`sprintf` destination buffer;
- destination buffer address if available;
- whether that symbolic data later appears in `system(arg0)`.

Final command-path status is determined by the command sink policy:

- `system(arg0)` contains source and marker: `sat`, `positive_evidence`;
- `system(arg0)` is reached but lacks source/marker: `unsat`, `negative_evidence`;
- source reaches only `snprintf`/`sprintf`: not sufficient for `sat`.
- source/marker is truncated before reaching `system(arg0)`: not sufficient for `sat`.

## Toy Cases

`toy_06_format_flow`:

- source `ip` enters `snprintf(cmd, ...)`;
- `cmd` is passed to `system`;
- expected behavior: `sat_expected`;
- expected format-flow: `format_flow.status=positive`.

`toy_07_format_safe_negative`:

- source `ip` enters a formatting/log buffer;
- `system` uses a fixed benign command;
- expected behavior: `unsat_expected`;
- expected format-flow: `format_flow.status=negative`;
- expected sink policy: `negative_evidence`.

`toy_08_snprintf_truncation_negative`:

- `snprintf` uses a small concrete size;
- the benign marker is truncated before `system(cmd)`;
- expected behavior: `truncation_negative_expected`;
- expected format-flow: `format_flow.status=truncated`, `marker_truncated=true`;
- expected verifier status: not `sat`.

`toy_09_snprintf_truncation_positive`:

- `snprintf` uses a large enough size;
- the benign marker reaches `system(arg0)` intact;
- expected behavior: `sat_expected`.

## Current Implementation

The current SimProcedure is intentionally minimal:

- it models only toy source propagation through `snprintf`/`sprintf`;
- it copies the formatted source argument into the destination buffer;
- for `snprintf`, it bounds copied bytes by concrete `size - 1`;
- for `sprintf`, it records evidence as less bounded because there is no size argument;
- it records write metadata in symbolic state globals;
- it does not implement complete libc varargs, formatting width/precision, locale, or return-value semantics.

This is enough for toy benchmark source-to-command-buffer evidence, but not a full libc model.

## Memory-Copy Extension

Step 60 adds minimal toy `memcpy(dst, src, n)` propagation:

- concrete `n` bounds copied bytes;
- enough `n` can produce positive evidence only if `system(arg0)` observes source/marker;
- too small `n` sets `marker_truncated=true` and must not become `sat`;
- symbolic/unknown `n` should be treated as inconclusive.

`toy_10_memcpy_flow_positive` is the positive case, and `toy_11_memcpy_truncation_negative` is the truncation negative case.

## Safety Boundary

The policy reads symbolic state only. It does not concretely execute target binaries, does not execute `system`/`popen`, and does not generate weaponized payloads.
