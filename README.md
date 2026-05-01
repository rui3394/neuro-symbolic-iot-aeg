# Neuro-Symbolic Automated PoC Generation for IoT CGI Vulnerabilities

This repository is the first-stage skeleton for modeling IoT CGI analysis targets.

Current scope:

- Load a YAML target configuration.
- Validate required target fields.
- Print target metadata with a dry-run CLI.
- Inspect configured ELF binaries with a lightweight header and sink-symbol check.
- Resolve configured sinks against ELF symbols and PLT stubs.
- Normalize configured HTTP source parameters into source model entries.
- Optionally load the ELF with angr and print loader metadata.
- Optionally create a concrete angr `full_init_state` with modeled argv inputs.
- Optionally create a symbolic angr `full_init_state` with modeled argv inputs.
- Optionally run a concrete sink reachability smoke test to a PLT address.
- Optionally verify symbolic argv data reaches a sink argument.
- Optionally observe source-related constraints at a reached sink state.
- Optionally export a compact JSON report for existing local analysis results.
- Build local toy binaries for basic source-to-sink and sanitizer-observation experiments.
- Run minimal unit tests.

This stage does not implement symbolic execution, LLM reasoning, taint analysis, firmware emulation, exploit generation, or PoC generation.

## End-to-End Demo

See [docs/demo.md](docs/demo.md) for the current local toy dataset demo and
stage summary. See [docs/project_status.md](docs/project_status.md) for the
Step 1 through Step 26 project timeline and current contract boundaries.

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
.venv/bin/python -m ns_aeg.cli --run-demo
```

The demo only runs local toy binaries and writes reports, planner JSON, and
verifier skeleton JSON. It does not call a real LLM, does not generate concrete
inputs, and does not generate payloads, exploits, or PoCs.

## Candidate Contract

```bash
.venv/bin/python -m ns_aeg.cli --validate-candidate examples/candidates/toy_02_candidates.json
.venv/bin/python -m ns_aeg.cli --build-candidate-verifier-request reports/toy_02_filter_chars_analysis.json --candidates examples/candidates/toy_02_candidates.json
.venv/bin/python -m ns_aeg.cli --run-contract-verifier examples/verifier/toy_02_filter_chars_candidate_verifier_request.json
```

The candidate contract defines a safe local JSON interface for future verifier
work. It only validates benign local candidate placeholders and writes
non-executing contract results. It does not call an LLM, does not execute
candidates, and does not generate concrete inputs, payloads, exploits, or PoCs.

## Install

```bash
pip install -e .
```

## Dry Run

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --dry-run
```

## Binary Inspection

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
file datasets/toy_cgi/build/toy_01
python3 -m ns_aeg.cli --target configs/toy_01.yaml --inspect-binary
```

## Sink Finding

```bash
python3 -m ns_aeg.cli --target configs/toy_01.yaml --find-sinks
```

`find-sinks` only parses ELF symbols and PLT stubs. It does not perform taint
analysis, does not prove that a vulnerability exists, and does not generate an
exploit or PoC. Its purpose is to prepare sink symbol and address information
for later angr source-to-sink analysis.

## Source Model

```bash
python3 -m ns_aeg.cli --target configs/toy_01.yaml --show-sources
```

The Source Model only converts configured HTTP parameters into normalized input
source descriptions. The current first version supports only `http_param` to
`argv[n]` bindings. It does not perform symbolic execution, does not prove that
a vulnerability exists, and only prepares input modeling data for later angr
analysis.

## angr Loader

Create a virtual environment and install the optional angr stack when this step
is needed:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel -i https://pypi.org/simple
python -m pip install angr pytest pyyaml -i https://pypi.org/simple
```

Compile the toy binary:

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
```

Run the minimal angr loader:

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --angr-load
```

`angr-load` only loads the ELF. It does not perform symbolic execution, does
not prove that a vulnerability exists, and only checks whether angr can read
the architecture, entry point, main object, base address, and PLT information.

## argv State

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --create-argv-state
```

`create-argv-state` only creates an angr `full_init_state`. The current version
supports only concrete argv values: the configured `ip` source maps to
`argv[1]`, with a default value of `127.0.0.1`. It does not perform symbolic
execution, does not search paths, and does not prove that a vulnerability
exists. Unicorn warnings can be ignored for now as long as UNICORN is not
explicitly enabled.

## Symbolic argv State

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --create-symbolic-argv
```

`create-symbolic-argv` only creates a symbolic argv state. The configured `ip`
source maps to `argv[1]`, uses the symbolic variable `sym_ip`, and is modeled as
a null-terminated C string. It does not perform path search, does not prove that
a vulnerability exists, and does not generate an exploit or PoC.

## Sink Reachability Smoke Test

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --smoke-reach-sink
```

`smoke-reach-sink` uses concrete argv input and only checks whether execution can
reach a configured sink PLT address such as `system@plt`. It stops at the PLT
address and does not enter `system`, does not solve a symbolic vulnerability,
does not extract constraints, does not generate payloads, and does not prove
that a real device is vulnerable. It is only a reachability smoke test before
later source-to-sink analysis.

## Symbolic Sink Reachability

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --symbolic-reach-sink
```

`symbolic-reach-sink` uses symbolic argv input and checks whether the source
symbolic variable reaches a configured sink argument. For the toy target, `ip`
maps to `argv[1]` as `sym_ip`, and the check stops at `system@plt` before
entering `system`. It does not generate payloads, does not extract full
constraints, does not call an LLM, and does not prove that a real device is
vulnerable. It is only a source-to-sink validation step before later sanitizer
and constraint extraction work.

## Constraint Observation

```bash
python -m ns_aeg.cli --target configs/toy_01.yaml --observe-constraints
```

`observe-constraints` uses symbolic argv and only inspects the constraints on a
state that reaches the sink PLT address. It filters those constraints down to
ones related to the source symbolic variable. It does not generate payloads,
does not perform bypass generation, does not call an LLM, and does not prove
that a real device is vulnerable. For `toy_01`, source-related constraints may
be `0` because there is no sanitizer yet. A later `toy_02` target can add a
simple filter to validate that constraint observation detects sanitizer-like
behavior.

## Toy 02 Filter Target

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
python -m ns_aeg.cli --target configs/toy_02.yaml --observe-constraints
```

`toy_02_filter_chars` is a local-only test binary. It checks the first 32 bytes
of `argv[1]` for the fixed byte `0x3b`, prints `NS_AEG_FILTERED` if the byte is
present, and otherwise sends a harmless marker command through `snprintf` and
`system`. It is intended to validate sanitizer-candidate constraint
classification. It does not generate inputs, does not perform real device
testing, does not access the network, and only prints harmless marker output.

## Toy 03 Length-Limit Target

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
python -m ns_aeg.cli --target configs/toy_03.yaml --observe-constraints
```

`toy_03_length_limit` is a local-only test binary. It uses an explicit loop to
check that a null byte appears within the first 16 bytes of `argv[1]`, prints
`NS_AEG_LENGTH_FILTERED` if the length check rejects the input, and otherwise
sends a harmless marker command through `snprintf` and `system`. It is intended
to validate constraint observation for length-check style local input checks. It
does not generate inputs, does not perform real device testing, does not access
the network, and only prints harmless marker output.

## Toy 04 Branch-Check Target

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
python -m ns_aeg.cli --target configs/toy_04.yaml --observe-constraints
```

`toy_04_branch_check` is a local-only test binary. It requires `argv[1]` to
start with `AB` before reaching `snprintf` and `system`; otherwise it prints
`NS_AEG_BRANCH_REJECTED`. It is intended to validate path constraint observation
for source-byte equality branch conditions. It does not generate inputs, does
not perform real device testing, does not access the network, and only prints
harmless marker output.

## Toy 05 Safe-Control Target

```bash
make -C datasets/toy_cgi clean
make -C datasets/toy_cgi
python -m ns_aeg.cli --target configs/toy_05.yaml --symbolic-reach-sink
```

`toy_05_safe_case` is a local-only safe-control binary. It reads `argv[1]` and
prints it to stdout, but the `system` command uses a fixed harmless marker and
does not include the source input. It is intended to validate that the analysis
does not report source-to-sink when the source input is absent from the sink
argument. It does not generate inputs, does not perform real device testing,
does not access the network, and only prints harmless marker output.

## JSON Analysis Report

```bash
python3 -m ns_aeg.cli --target configs/toy_01.yaml --write-report
python3 -m ns_aeg.cli --target configs/toy_02.yaml --write-report
python3 -m ns_aeg.cli --target configs/toy_03.yaml --write-report
python3 -m ns_aeg.cli --target configs/toy_04.yaml --write-report
python3 -m ns_aeg.cli --target configs/toy_05.yaml --write-report
```

`write-report` only exports existing analysis results. It does not generate
inputs, does not perform bypass generation, does not call an LLM, and does not
generate an exploit or PoC. Reports are written to
`reports/<target_name>_analysis.json` by default. For the current toy targets,
`toy_01` is expected to have `sanitizer_like_observed` as `false`, while
`toy_02` and `toy_03` are expected to have `sanitizer_like_observed` as `true`
when angr is available and the local binaries are built. `toy_04` is expected
to have branch-condition constraints without setting `sanitizer_like_observed`,
and `toy_05` is expected to have `source_to_sink_confirmed` as `false`.

## Batch Report Summary

```bash
python3 -m ns_aeg.cli --batch-report configs/
python3 -m ns_aeg.cli --batch-report configs/toy_01.yaml configs/toy_02.yaml configs/toy_03.yaml configs/toy_04.yaml configs/toy_05.yaml
python3 -m ns_aeg.cli --batch-report configs/ --summary-output reports/summary.json
```

`batch-report` only generates and summarizes existing analysis reports. It does
not generate inputs, does not perform bypass generation, does not call an LLM,
and does not generate an exploit or PoC. By default, the batch summary is
written to `reports/summary.json`. For the current toy targets, `toy_01` is
expected to have `sanitizer_like_observed` as `false`, while `toy_02` and
`toy_03` are expected to have `sanitizer_like_observed` as `true` when angr is
available and the local binaries are built. `toy_04` is expected to report
branch conditions while keeping `sanitizer_like_observed` as `false`, and
`toy_05` is expected to remain a safe source-to-sink negative control.

## Toy Dataset Runner

```bash
.venv/bin/python -m ns_aeg.cli --run-toy-dataset configs/
```

`run-toy-dataset` scans `toy_*.yaml` files, generates per-target JSON analysis
reports, and exports:

- `reports/*_analysis.json`
- `reports/summary.json`
- `reports/summary.md`
- `reports/summary.csv`

It only summarizes local toy binary analysis results. It does not generate
inputs, does not perform bypass generation, does not call an LLM, and does not
generate an exploit or PoC.

## Planner JSON Schema

```bash
.venv/bin/python -m ns_aeg.cli --validate-planner-schema examples/planner/toy_02_planner_input.json --schema-kind input
.venv/bin/python -m ns_aeg.cli --validate-planner-schema examples/planner/toy_02_planner_output.json --schema-kind output
.venv/bin/python -m ns_aeg.cli --validate-planner-schema examples/planner/toy_05_planner_input.json --schema-kind input
.venv/bin/python -m ns_aeg.cli --validate-planner-schema examples/planner/toy_05_planner_output.json --schema-kind output
```

Step 20 only defines planner JSON schemas, safe examples, and local validation
helpers. It does not connect to a real LLM, does not generate concrete inputs,
does not generate a PoC, and does not execute any candidate. Planner output is
restricted to abstract candidate plans with safety flags. A later step can
convert analysis reports into planner input JSON.

## Planner Input Builder

```bash
.venv/bin/python -m ns_aeg.cli --build-planner-input reports/toy_02_filter_chars_analysis.json
.venv/bin/python -m ns_aeg.cli --build-planner-inputs reports/
```

`build-planner-input` converts an existing local analysis report into
`planner_input` JSON and writes it to `examples/planner/` by default. It only
transforms report fields into the structured planner context; it does not call
an LLM, does not generate concrete inputs, and does not generate a PoC.

## Mock Planner

```bash
.venv/bin/python -m ns_aeg.cli --mock-plan examples/planner/toy_02_filter_chars_planner_input.json
.venv/bin/python -m ns_aeg.cli --mock-plan-dir examples/planner/
```

`mock-plan` is a local-only deterministic planner for schema and pipeline
testing. It reads `planner_input` JSON and writes `planner_output` JSON with
abstract candidate plans only. It does not call a real LLM, does not generate
concrete inputs, does not generate a PoC, and every output is expected to pass
planner output schema validation.

## Symbolic Verifier Skeleton

```bash
.venv/bin/python -m ns_aeg.cli --build-verification-request examples/planner/toy_02_filter_chars_planner_output.json
.venv/bin/python -m ns_aeg.cli --run-verifier-skeleton examples/verifier/toy_02_filter_chars_verification_request.json
.venv/bin/python -m ns_aeg.cli --build-verification-requests examples/planner/
.venv/bin/python -m ns_aeg.cli --run-verifier-skeleton-dir examples/verifier/
```

The verifier skeleton converts abstract planner output into verification request
JSON and then writes a non-executing verification result. It does not execute
inputs, does not generate concrete inputs, does not generate a PoC, and only
reserves the interface for a later concrete symbolic verifier.

## End-to-End Demo Runner

```bash
.venv/bin/python -m ns_aeg.cli --run-demo
```

`run-demo` runs the current local toy pipeline end to end:

- `reports/summary.json`
- `reports/summary.md`
- `reports/summary.csv`
- `reports/demo_summary.json`
- `examples/planner/*_planner_input.json`
- `examples/planner/*_planner_output.json`
- `examples/verifier/*_verification_request.json`
- `examples/verifier/*_verification_result.json`

It does not call a real LLM, does not generate concrete inputs, does not
generate payloads or PoCs, and only stitches together the existing local
analysis/reporting skeleton.

## Test

```bash
pytest
```
