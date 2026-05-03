# Dangerous Path Evidence Report

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Candidate ID: `toy_01_rule_001`
- Verification status: `sat`
- Verification mode: `symbolic_task`
- Executed target binary: `false`
- Oracle: `source_reaches_sink`
- Benign marker: `__NS_AEG_MARKER__`

## Binary

- Path: `/home/kali/projects/neuro-symbolic-iot-aeg/datasets/toy_cgi/build_cross/mipsel/toy_01`
- Name: `toy_01`
- Arch: `MIPS`

## Sources Checked

| Source ID | Name | Carrier | Symbolic | Input Present | Benign Marker Hit | Input Length |
| --- | --- | --- | --- | --- | --- | --- |
| source_1:ip | ip | argv[1] | sym_ip | not available | not available | not available |

## Sinks Checked

| Sink ID | Function | Address | Arg Index | Callers |
| --- | --- | --- | --- | --- |
| sink_1:snprintf | snprintf | 0x400818 | 2 | main |
| sink_2:system | system | 0x400834 | 0 | main |

## Symbolic Evidence

- This is angr-based symbolic reachability evidence.
- Backend: `angr`
- Path status: `sat`
- Sink reached: `true`
- Source bound: `true`
- Marker observed: `true`

### Selected Entry

- Function: `main`
- Address: `0x4007a0`

### Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Type: `command_execution`
- Address: `0x400834`
- External address: `0x3`
- Arg index: `0`
- Callers: `main`

### Constraints Summary

- candidate_input_len: `26`
- candidate_value_truncated: `False`
- constraints_added: `64`
- symbolic_bytes: `64`

## Evidence Strength

- Startup mode: `direct_main`
- Level: `direct_main_symbolic`
- Scope: `toy_benchmark`
- Can claim full startup proof: `false`
- Requires explicit opt-in: `false`
- Description: Symbolic reachability began at task.entry/main and bypassed startup/loader modeling.
- This is direct-main symbolic evidence.
- It bypasses startup/loader modeling.
- It does not prove full program startup reachability.
- It is acceptable for controlled toy benchmark debugging.
- It must not be used as a standalone real-firmware claim.

## Candidate Input Summary

- Source `ip`: input_present=`not available`, benign_marker_present=`not available`, input_len=`not available`

## Reason

full_init failed to reach sink; direct_main fallback reached sink; selected sink reached and benign marker/source evidence observed in sink argument

## Limitations

- This is angr-based symbolic reachability evidence.
- task symbolic mode is currently scoped to local toy argv-based CGI binaries
- sink argument inspection uses ABI register mapping; stack arguments and some architectures are partial/unsupported
- snprintf is modeled with a minimal local SimProcedure for toy source propagation
- this is source-to-sink reachability evidence, not exploit verification
- direct_main startup begins at task.entry/main and does not validate full program startup
- full_init failed to reach sink; direct_main fallback reached sink

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- This is source-to-sink symbolic evidence, not full exploit verification.
- Candidate inputs are summarized as benign source probes, not rendered as attack payloads.
