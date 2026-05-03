# Startup Evidence Strength

Step 52 adds an explicit evidence-strength layer for task-driven symbolic verification.
The goal is to prevent a `sat` result from being over-read when the verifier used a
controlled `main(argc, argv)` entry instead of full program startup.

## Startup Modes

- `full_init`: angr starts from the program initialization path. If this reaches a
  sink, the result is `full_program_startup_symbolic` evidence.
- `direct_main`: angr creates a controlled `call_state` at `main(argc, argv)`. This
  still executes `main` normally and does not jump to the sink, but it bypasses
  startup and loader modeling.
- `auto`: the verifier first tries `full_init`. For toy MIPS/MIPSEL cases where
  full-init stops in startup/loader before reaching `main`, auto may try
  `direct_main` if the safe startup policy allows it.

## Evidence Strength Field

Symbolic verification JSON now includes:

```json
{
  "evidence_strength": {
    "startup_mode": "direct_main",
    "level": "direct_main_symbolic",
    "scope": "toy_benchmark",
    "description": "Symbolic reachability began at task.entry/main and bypassed startup/loader modeling.",
    "can_claim_full_startup_proof": false,
    "requires_explicit_opt_in": false
  }
}
```

For `full_init`, `can_claim_full_startup_proof=true`. For `direct_main`,
`can_claim_full_startup_proof=false` because startup/loader reachability was not
proved.

## Safe Startup Policy

`direct_main` is allowed by default only for controlled toy benchmark tasks. The
verifier infers `toy_benchmark` from task scope or toy binary paths such as
`datasets/toy_cgi` and `build_cross`.

For `firmware`, `non_toy`, or `unknown` scope:

- `auto` does not silently fall back to `direct_main`.
- `direct-main` mode is blocked unless explicitly allowed.
- Explicit opt-in can be provided by `--allow-direct-main-for-non-toy` or by a task
  annotation `allow_direct_main=true`.

This is conservative by design. Direct-main evidence can be useful for debugging
startup modeling, but it must not be used as a standalone real-firmware claim.

## Reading Reports

Evidence Markdown and planner summaries now show:

- selected startup mode;
- evidence strength level;
- whether full startup proof can be claimed;
- direct-main caution notes when applicable.

Cross-arch smoke summary separates total `sat` from `full-init sat` and
`direct-main fallback sat`. For the current toy benchmark, MIPS/MIPSEL `sat`
results are direct-main evidence, while x86_64, ARM32, and AArch64 are full-init
evidence.

## Safety Boundary

The verifier does not execute target binaries concretely, does not execute
`system`/`popen`, and does not generate weaponized exploit payloads. The evidence
is source-to-sink symbolic reachability evidence.
