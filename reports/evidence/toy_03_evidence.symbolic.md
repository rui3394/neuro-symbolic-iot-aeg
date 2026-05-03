# Dangerous Path Evidence Report

## Summary

- Task ID: `dangerous_path:toy_03_length_limit:toy_03`
- Candidate ID: `toy_03_rule_001`
- Verification status: `unsat`
- Verification mode: `symbolic_task`
- Executed target binary: `false`
- Oracle: `source_reaches_sink`
- Benign marker: `__NS_AEG_MARKER__`

## Binary

- Path: `/home/kali/projects/neuro-symbolic-iot-aeg/datasets/toy_cgi/build/toy_03`
- Name: `toy_03`
- Arch: `x86`

## Sources Checked

| Source ID | Name | Carrier | Symbolic | Input Present | Benign Marker Hit | Input Length |
| --- | --- | --- | --- | --- | --- | --- |
| source_1:ip | ip | argv[1] | sym_ip | not available | not available | not available |

## Sinks Checked

| Sink ID | Function | Address | Arg Index | Callers |
| --- | --- | --- | --- | --- |
| sink_1:snprintf | snprintf | 0x401270 | 2 | main |
| sink_2:system | system | 0x40127f | 0 | main |

## Symbolic Evidence

- This is angr-based symbolic reachability evidence.
- Backend: `angr`
- Path status: `unsat`
- Sink reached: `false`
- Source bound: `unknown`
- Marker observed: `unknown`

### Selected Entry

- Function: `main`
- Address: `0x401196`

### Selected Sink

- Sink ID: `sink_2:system`
- Function: `system`
- Type: `command_execution`
- Address: `0x40127f`
- External address: `0x4`
- Arg index: `0`
- Callers: `main`

### Constraints Summary

- candidate_input_len: `26`
- candidate_value_truncated: `False`
- constraints_added: `32`
- symbolic_bytes: `32`

## Candidate Input Summary

- Source `ip`: input_present=`not available`, benign_marker_present=`not available`, input_len=`not available`

## Reason

selected sink callsite was not reached

## Limitations

- This is angr-based symbolic reachability evidence.
- task symbolic mode is currently scoped to local toy argv-based CGI binaries
- sink argument inspection currently supports AMD64 first-argument register rdi
- snprintf is modeled with a minimal local SimProcedure for toy source propagation
- this is source-to-sink reachability evidence, not exploit verification

## Safety Note

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- This is source-to-sink symbolic evidence, not full exploit verification.
- Candidate inputs are summarized as benign source probes, not rendered as attack payloads.
