# Dangerous Path Evidence Report

## Summary

- Task ID: `dangerous_path:toy_01_basic_cmd:toy_01`
- Candidate ID: `toy_01_cand_001`
- Verification status: `unknown`
- Verification mode: `task_adapter_dry_run`
- Executed target binary: `false`
- Oracle: `source_reaches_sink`
- Benign marker: `__NS_AEG_MARKER__`

## Binary

- Path: `/home/kali/projects/neuro-symbolic-iot-aeg/datasets/toy_cgi/build/toy_01`
- Name: `toy_01`
- Arch: `x86`

## Sources Checked

| Source ID | Name | Carrier | Symbolic | Input Present | Benign Marker Hit | Input Length |
| --- | --- | --- | --- | --- | --- | --- |
| source_1:ip | ip | argv[1] | sym_ip | true | true | 26 |

## Sinks Checked

| Sink ID | Function | Address | Arg Index | Callers |
| --- | --- | --- | --- | --- |
| sink_1:snprintf | snprintf | 0x4011ea | 2 | main |
| sink_2:system | system | 0x4011f9 | 0 | main |

## Candidate Input Summary

- Source `ip`: input_present=`true`, benign_marker_present=`true`, input_len=`26`

## Reason

task adapter dry-run completed; candidate inputs mapped to task sources

## Limitations

- This is an adapter-level dry-run result.
- The symbolic execution backend has not been fully wired for task mode yet.

## Safety Note

- No target binary was executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- This is source-to-sink symbolic evidence, not full exploit verification.
- Candidate inputs are summarized as benign source probes, not rendered as attack payloads.
