# MIPS Full-Init Root-Cause Diagnosis

Step 53 investigates why MIPS/MIPSEL toy full-init symbolic execution did not
reach the `system` sink before Step 53, even though direct-main mode could reach
the same sink.

## Symptom Before Repair

Cross-arch smoke showed:

- x86_64, AArch64, ARM32: `full_init` reached the sink.
- MIPS/MIPSEL: `full_init` ended before reaching the sink.
- MIPS/MIPSEL `direct_main` reached the loader external `system` symbol at
  `0x500004`.

The full-init debug was shallow:

```text
recent_bbl_addrs = 0xb01000, 0xb01000, 0x400600
reason = no active states remain before reaching sink candidates
```

This made it unclear whether startup reached `main`, whether a PLT/stub target
was mismatched, or whether MIPS delay-slot lifting was the problem.

## Root Cause

Disassembly of the MIPS startup block shows:

```text
0x400600: move  $zero, $ra
0x400604: bal   0x40060c
0x400608: nop
```

The previous symbolic loop used `simgr.step(num_inst=1)` for full-init. On MIPS,
single-instruction stepping at the `bal` instruction can fail because branch and
delay-slot semantics need to be lifted together. A local diagnostic reproduced an
IR decoding error at `0x400604`.

This means the full-init failure was not caused by Ghidra callsite mismatch or by
an inability to inspect `a0`. It was primarily a MIPS startup stepping/lifting
issue.

## Minimal Repair

The verifier now uses block-level stepping for MIPS symbolic execution:

- It does not jump to `main`.
- It does not jump to the sink.
- It does not skip constraints inside `main`.
- It lets angr lift MIPS branch and delay-slot semantics as a complete block.

The repair is recorded in verification JSON:

```json
{
  "reachability_debug": {
    "reached_main": true,
    "main_address": "0x4007a0",
    "full_init_repair_applied": true,
    "repair_reason": "mips_full_init_block_level_stepping_for_bal_delay_slot_startup_stub"
  }
}
```

## Address Findings

For MIPS/MIPSEL toy_01:

- `main = 0x4007a0`
- Ghidra callsite for `system = 0x400834`
- MIPS conservative candidates include branch/delay-slot addresses around the
  callsite.
- angr loader external `system = 0x500004`
- matched sink address after repair: `0x500004`
- sink argument location: `register:a0`

The match at `0x500004` is expected because angr models imported symbols in the
extern object. The verifier records this as `loader_external_symbol_address`.

## Current Result

After the repair:

- full-init smoke: `sat=10`, including MIPS/MIPSEL toy_01/toy_02.
- auto smoke: `sat=10`, all selected startup mode values are `full_init`.
- direct-main smoke remains available for comparison/debugging, but it is no
  longer needed for MIPS toy_01/toy_02 auto mode.

## Evidence Boundary

The full-init MIPS result is stronger than the previous direct-main result
because symbolic execution now reaches the sink from program startup. However,
this is still a toy benchmark result, not a real firmware claim.

The pipeline still does not execute target binaries concretely, does not execute
`system`/`popen`, and does not generate weaponized exploit payloads.

## Remaining Work

- Validate the same block-level stepping policy on more MIPS toy cases.
- Add explicit tests for MIPS startup basic blocks if a lightweight fixture is
  added.
- Continue treating direct-main as a debugging fallback for cases where startup
  modeling is incomplete.
