# False-Positive Regression Toys

Step 55 adds branch-negative and safe-negative toy cases to check that startup repair and sink callsite matching do not turn unreachable or source-independent paths into false `sat` evidence.

## Why Negative Toys Are Needed

The cross-arch pipeline already proves positive toy cases:

- `toy_01`: direct source-to-`system` path.
- `toy_02`: blacklist sanitizer that the benign candidates naturally satisfy.
- `toy_03`: planner-level rejection because the benign marker is incompatible with a length-window sanitizer.

Positive cases are not enough. A symbolic verifier also needs negative regressions to detect false positives, especially after Step 53 introduced MIPS block-level startup stepping.

## toy_04 Branch Negative

`toy_04` contains a source parameter and a `system` sink, but the path to `system` requires the input to start with `AB`.

The rule planner intentionally generates benign marker candidates such as:

- `127.0.0.1__NS_AEG_MARKER__`
- `__NS_AEG_MARKER__`
- `SAFE__NS_AEG_MARKER__`

These candidates do not satisfy the `AB` branch guard, so the expected behavior is:

- `expected_behavior=unsat_expected`
- verifier should not return `sat`
- if any architecture returns `sat`, `false_positive=true`

## toy_05 Safe Negative

`toy_05` has a source and reaches a fixed benign `system` command, but the source is not embedded into the command string.

The expected behavior is:

- `expected_behavior=unsat_expected`
- sink reachability alone is insufficient
- marker/source must not be observed in the sink argument
- `sat` would be a false positive

The current verifier may report `unknown` when it reaches a sink but cannot prove source/marker evidence. That is acceptable for this negative fixture because the false-positive criterion is specifically `sat`.

## false_positive_count

Cross-arch smoke summary computes `false_positive_count` from per-case expected behavior:

- `unsat_expected` + `sat` => false positive
- `no_sink_expected` + `sat` => false positive
- `planner_reject_expected` + `sat` => false positive

This keeps positive reachability evidence separate from negative regression failures.

## Evidence Categories

- `sat`: source/marker evidence reaches the selected sink argument.
- `unsat`: verifier did not find a feasible path for an existing candidate.
- `unknown`: sink may be reached, but current evidence is insufficient to claim source-to-sink proof.
- `no_candidates`: planner rejected all strategies before verification.
- `false_positive`: a case expected to be negative returned `sat`.

## Safety Boundary

The negative toys are symbolic-only fixtures:

- no target binary is concretely executed;
- no `system`/`popen` command is executed;
- candidates remain benign marker inputs;
- no weaponized exploit is generated;
- real firmware conclusions are out of scope.
