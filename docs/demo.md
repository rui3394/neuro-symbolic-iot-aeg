# Local Toy Demo

This demo shows the current local neuro-symbolic analysis pipeline on authorized
toy ELF binaries under `datasets/toy_cgi`. It does not call a real LLM, does not
generate concrete inputs, does not generate payloads, exploits, or PoCs, and does
not analyze real devices or firmware.

## Demo Goal

The demo stitches together the current local pipeline:

- Source model construction from target YAML.
- Sink reachability and PLT discovery.
- Symbolic source-to-sink confirmation.
- Constraint observation and conservative classification.
- Planner input generation from analysis reports.
- Mock planner output generation.
- Verifier skeleton request/result generation.

The result is an end-to-end artifact trail for local toy binaries only.

## Toy Dataset

| Target | Purpose | Expected source-to-sink | Expected sanitizer observed |
|---|---|---:|---:|
| `toy_01_basic_cmd` | basic source-to-sink | yes | no |
| `toy_02_filter_chars` | fixed byte check | yes | yes |
| `toy_03_length_limit` | length check | yes | yes |
| `toy_04_branch_check` | branch condition | yes | no |
| `toy_05_safe_case` | safe negative case | no | no |

## Run The Demo

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
.venv/bin/python -m ns_aeg.cli --run-demo
```

Optional cleanup before rerunning, if you want only freshly generated planner
and verifier outputs:

```bash
rm -f examples/planner/*_planner_output.json
rm -f examples/verifier/*_verification_request.json
rm -f examples/verifier/*_verification_result.json
```

This cleanup is optional. The project does not force-delete user files. If older
Step 20 hand-written examples are present, `mock_planner` and
`verification_requests` built counts may be greater than 5. That is not a main
pipeline failure.

## Output Files

The demo writes or refreshes:

- `reports/summary.json`
- `reports/summary.md`
- `reports/summary.csv`
- `reports/demo_summary.json`
- `reports/*_analysis.json`
- `examples/planner/*_planner_input.json`
- `examples/planner/*_planner_output.json`
- `examples/verifier/*_verification_request.json`
- `examples/verifier/*_verification_result.json`

## Success Criteria

The expected `reports/demo_summary.json` core values are:

```text
status = ok
total_targets = 5
source_to_sink_confirmed_count = 4
sanitizer_like_observed_count = 2
error_count = 0
```

These values mean the current toy dataset behaved as intended.

## How To Read The Results

`toy_01_basic_cmd` demonstrates the baseline source-to-sink path from
`argv[1]` into `system`.

`toy_02_filter_chars` demonstrates that a fixed-byte local input check can be
observed and classified as sanitizer-like.

`toy_03_length_limit` demonstrates that a local length check can be observed and
classified as sanitizer-like.

`toy_04_branch_check` demonstrates that path branch conditions can be observed.
Branch conditions are tracked separately and do not count as
`sanitizer_like_observed`.

`toy_05_safe_case` is the safety negative control. It calls `system`, but the
source input does not enter the `system` argument, so `source_to_sink_confirmed`
is expected to be `false`.

## Current Limits

- Current analysis targets local toy ELF binaries only.
- The planner is a mock planner and does not call a real LLM.
- The verifier is a skeleton and does not execute candidate verification.
- No concrete inputs are generated.
- No payloads, exploits, or PoCs are generated.
- No real firmware is analyzed.
- ARM/MIPS cross-architecture validation is not implemented yet.

## Next Steps

Planned extensions include:

- Real LLM planner integration behind strict structured schemas.
- Concrete candidate schema design.
- Symbolic candidate verifier implementation.
- `toy_06` with multiple input parameters.
- ARM/MIPS cross-compiled toy dataset.
- Small-scale offline CGI analysis for authorized firmware samples.
- Experiment metrics and paper-ready result tables.
