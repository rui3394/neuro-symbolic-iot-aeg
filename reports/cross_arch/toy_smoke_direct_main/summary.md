# Cross-Arch Toy Smoke Summary

## Summary

- Manifest: `examples/cross_arch/toy_benchmark_manifest.json`
- Mode: `symbolic`
- Startup mode: `direct-main`
- Total cases: `10`
- Built cases: `10`
- Skipped build cases: `0`
- Ghidra success count: `10`
- Task success count: `10`
- Symbolic sat cases: `8`
- Full-init sat cases: `0`
- Direct-main fallback sat cases: `8`
- Symbolic unsat cases: `2`
- Symbolic unsupported cases: `0`
- Full startup proof count: `0`
- Direct-main only count: `8`

Direct-main evidence means symbolic execution began at `main(argc, argv)` after full-init failed to reach the sink. It is useful for controlled toy debugging, but it does not prove full program startup reachability and must not be used as a standalone real-firmware claim.

MIPS full-init diagnostics include `reached_main`, startup failure reason, loader external symbols, PLT/stub candidates, and whether the conservative block-level startup repair was applied.

## Per Case

| Toy | Arch | Build | Facts | Task | Planner | Verifier | Startup | Evidence Level | Full Startup Proof | Status Counts | Reached Main | Main | Repair | Matched Sink | Match Reason | Sink Arg | Debug Reason | Startup Failure | Fallback |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| toy_01 | x86_64 | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x401176 | false | 0x4011f9 | selected_sink_address | register:rdi | matched sink candidate address | not available | not available |
| toy_02 | x86_64 | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x401196 | false | 0x40127a | selected_sink_address | register:rdi | matched sink candidate address | not available | not available |
| toy_01 | arm32 | built | ok | ok | ok | unsat | direct_main | direct_main_symbolic | false | {"unsat": 4} | true | 0x104cc | false | not available | not available | not available | no active states remain before reaching sink candidates | errored_state_before_sink | not available |
| toy_02 | arm32 | built | ok | ok | ok | unsat | direct_main | direct_main_symbolic | false | {"unsat": 4} | true | 0x104fc | false | not available | not available | not available | no active states remain before reaching sink candidates | errored_state_before_sink | not available |
| toy_01 | aarch64 | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x400704 | false | 0x400770 | selected_sink_address | register:x0 | matched sink candidate address | not available | not available |
| toy_02 | aarch64 | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x400744 | false | 0x400814 | selected_sink_address | register:x0 | matched sink candidate address | not available | not available |
| toy_01 | mipsel | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x4007a0 | false | 0x500004 | loader_external_symbol_address | register:a0 | matched sink candidate address | not available | not available |
| toy_02 | mipsel | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x4007c0 | false | 0x500004 | loader_external_symbol_address | register:a0 | matched sink candidate address | not available | not available |
| toy_01 | mips | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x4007a0 | false | 0x500004 | loader_external_symbol_address | register:a0 | matched sink candidate address | not available | not available |
| toy_02 | mips | built | ok | ok | ok | sat | direct_main | direct_main_symbolic | false | {"sat": 4} | true | 0x4007c0 | false | 0x500004 | loader_external_symbol_address | register:a0 | matched sink candidate address | not available | not available |

## Limitations

- cross-arch smoke does not execute target binaries concretely
- cross-arch symbolic support may be unsupported even when Ghidra facts export succeeds
- current smoke scope is toy_01/toy_02, not real firmware

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
