# Project Status Through Step 26

This document summarizes the current local-only research prototype status for
`neuro-symbolic-iot-aeg`.

## Timeline

| Step | Result |
|---:|---|
| 1 | Added target YAML config loading and dry-run CLI. |
| 2 | Added the first local CGI-like toy C binary. |
| 3 | Added a lightweight ELF binary inspector. |
| 4 | Added sink finding through ELF symbols and PLT parsing. |
| 5 | Added source model construction from HTTP parameters to argv bindings. |
| 6 | Added minimal angr loader metadata extraction. |
| 7 | Added concrete argv state creation. |
| 8 | Added symbolic argv state creation without exploration. |
| 9 | Added concrete sink reachability smoke test. |
| 10 | Added symbolic source-to-sink reachability and sink argument provenance observation. |
| 10.5 | Fixed claripy variable provenance matching for suffixed symbolic variable names. |
| 11 | Added source-related constraint observation at the reached sink. |
| 11.5 | Split string modeling constraints from sanitizer candidates to reduce false positives. |
| 12 | Added `toy_02_filter_chars` for fixed-byte local input checks. |
| 13 | Added JSON analysis report generation. |
| 14 | Added batch report summary generation. |
| 15 | Added `toy_03_length_limit` for length-check observation. |
| 16 | Added explicit input modeling constraint classification. |
| 17 | Added toy dataset runner and Markdown/CSV summaries. |
| 18 | Added `toy_04_branch_check` and branch-condition classification. |
| 19 | Added `toy_05_safe_case` as a safe negative source-to-sink control. |
| 20 | Added planner input/output schemas and local schema validation. |
| 21 | Added analysis report to planner input conversion. |
| 22 | Added local mock planner output generation. |
| 23 | Added symbolic verifier request/result skeleton. |
| 24 | Added end-to-end demo runner. |
| 25 | Added demo documentation. |
| 26 | Added candidate schema and contract-only verifier interface. |

## Current Completion Level

The project now has a local end-to-end toy pipeline from YAML target config to
analysis reports, planner JSON, verifier skeleton JSON, and candidate contract
JSON. It is suitable for local experiments on toy ELF binaries and for refining
structured interfaces before introducing a real planner or verifier.

## Current Demo Capabilities

The demo can show:

- Source model construction for HTTP parameter inputs.
- Sink resolution for local ELF toy binaries.
- Symbolic source-to-sink confirmation.
- Constraint observation and conservative classification.
- JSON analysis reports and dataset summaries.
- Planner input generation from reports.
- Mock planner output generation.
- Verifier skeleton request/result generation.
- Candidate contract validation without execution.

## Current Non-Capabilities

The demo does not:

- Call a real LLM.
- Generate concrete inputs.
- Generate payloads, exploits, or PoCs.
- Execute candidate inputs.
- Analyze real devices.
- Scan networks.
- Emulate full firmware.
- Perform ARM/MIPS cross-architecture experiments.

## Safety Boundary

The current scope is local toy binary analysis only. All targets live under
`datasets/toy_cgi`. Candidate examples use benign placeholders such as
`LOCAL_TEST_VALUE` and `BENIGN_MARKER_VALUE`. The contract verifier only checks
JSON safety fields and conservative token rules; it does not execute candidates
or prove safety.

## Toy Dataset

| Target | Meaning |
|---|---|
| `toy_01_basic_cmd` | Basic source-to-sink positive case. |
| `toy_02_filter_chars` | Fixed-byte local input check, expected sanitizer-like observation. |
| `toy_03_length_limit` | Length check, expected sanitizer-like observation. |
| `toy_04_branch_check` | Branch condition observation, not counted as sanitizer-like. |
| `toy_05_safe_case` | Safe negative control where `system` is reachable but source input is absent from the sink argument. |

## Current Pipeline

```text
target config
-> toy binary
-> source model
-> sink finder
-> symbolic reachability
-> constraint observation
-> analysis report
-> dataset summary
-> planner input
-> mock planner output
-> verifier skeleton
-> candidate contract
```

## Recommended Next Steps

- Step 27: candidate verifier dry-run symbolic check design.
- Step 28: real LLM planner integration strategy.
- Step 29: more toy cases.
- Step 30: ARM/MIPS toy cross-architecture dataset.
- Step 31: small-scale offline CGI analysis for authorized firmware samples.
- Step 32: paper-oriented experiment tables and ablations.
