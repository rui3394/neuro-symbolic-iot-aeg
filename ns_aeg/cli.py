from __future__ import annotations

import argparse
from pathlib import Path

from ns_aeg.angr_loader import AngrLoadInfo, load_with_angr
from ns_aeg.argv_state import (
    ArgvStateInfo,
    create_argv_state,
    create_symbolic_argv_state,
)
from ns_aeg.batch_reporting import generate_batch_summary
from ns_aeg.binary_inspector import BinaryInfo, inspect_binary
from ns_aeg.candidate_contract import (
    build_verifier_request_from_candidates,
    load_json as load_contract_json,
    run_contract_only_verifier,
    validate_candidate_contract,
)
from ns_aeg.config import load_target_config
from ns_aeg.constraint_observer import (
    ConstraintObservationResult,
    observe_constraints_to_sink,
)
from ns_aeg.dataset_runner import run_toy_dataset
from ns_aeg.demo_runner import run_demo
from ns_aeg.mock_planner import (
    default_planner_output_path,
    run_mock_planner,
    run_mock_planner_dir,
)
from ns_aeg.planner_input_builder import (
    build_planner_input_from_report,
    build_planner_inputs_from_reports,
    default_planner_input_path,
)
from ns_aeg.planner_schema import (
    basic_validate_planner_input,
    basic_validate_planner_output,
    load_json,
)
from ns_aeg.reachability import (
    ReachabilityResult,
    SymbolicReachabilityResult,
    smoke_reach_sink,
    symbolic_reach_sink,
)
from ns_aeg.reporting import generate_analysis_report
from ns_aeg.sink_finder import SinkReport, find_sinks
from ns_aeg.source_model import SourceModel, build_source_model
from ns_aeg.symbolic_verifier import (
    build_verification_request,
    build_verification_requests_from_dir,
    default_verification_request_path,
    default_verification_result_path,
    run_symbolic_verifier_skeleton,
    run_symbolic_verifier_skeleton_dir,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect IoT CGI target configuration.")
    parser.add_argument("--target", help="Path to the target YAML config.")
    parser.add_argument("--dry-run", action="store_true", help="Print target metadata only.")
    parser.add_argument(
        "--inspect-binary",
        action="store_true",
        help="Inspect the configured binary without deeper analysis.",
    )
    parser.add_argument(
        "--find-sinks",
        action="store_true",
        help="Resolve configured sinks against ELF symbols and PLT stubs.",
    )
    parser.add_argument(
        "--show-sources",
        action="store_true",
        help="Show normalized input source descriptions.",
    )
    parser.add_argument(
        "--angr-load",
        action="store_true",
        help="Load the configured binary with angr and print loader metadata.",
    )
    parser.add_argument(
        "--create-argv-state",
        action="store_true",
        help="Create an angr full_init_state with concrete argv inputs.",
    )
    parser.add_argument(
        "--create-symbolic-argv",
        action="store_true",
        help="Create an angr full_init_state with symbolic argv inputs.",
    )
    parser.add_argument(
        "--smoke-reach-sink",
        action="store_true",
        help="Run a concrete argv sink reachability smoke test.",
    )
    parser.add_argument(
        "--symbolic-reach-sink",
        action="store_true",
        help="Run a symbolic argv sink reachability check.",
    )
    parser.add_argument(
        "--observe-constraints",
        action="store_true",
        help="Observe source-related constraints at the reached sink.",
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help="Write a JSON report that summarizes existing analysis results.",
    )
    parser.add_argument(
        "--report-output",
        help="Optional output path for --write-report.",
    )
    parser.add_argument(
        "--batch-report",
        nargs="+",
        help="Generate reports for config files or directories and write a summary.",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/summary.json",
        help="Optional output path for --batch-report summary JSON.",
    )
    parser.add_argument(
        "--run-toy-dataset",
        nargs="?",
        const="configs",
        help="Run all toy_*.yaml configs in a directory and export JSON/Markdown/CSV summaries.",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Output directory for per-target reports when using --run-toy-dataset.",
    )
    parser.add_argument(
        "--summary-md",
        default="reports/summary.md",
        help="Markdown summary path for --run-toy-dataset.",
    )
    parser.add_argument(
        "--summary-csv",
        default="reports/summary.csv",
        help="CSV summary path for --run-toy-dataset.",
    )
    parser.add_argument(
        "--validate-planner-schema",
        help="Validate a planner input or output JSON file with the local schema checks.",
    )
    parser.add_argument(
        "--schema-kind",
        choices=["input", "output"],
        help="Schema kind for --validate-planner-schema.",
    )
    parser.add_argument(
        "--build-planner-input",
        help="Build planner_input JSON from one analysis report.",
    )
    parser.add_argument(
        "--planner-input-output",
        help="Optional output path for --build-planner-input.",
    )
    parser.add_argument(
        "--build-planner-inputs",
        help="Build planner_input JSON files from a report file or report directory.",
    )
    parser.add_argument(
        "--mock-plan",
        help="Run the local mock planner for one planner_input JSON file.",
    )
    parser.add_argument(
        "--planner-output",
        help="Optional output path for --mock-plan.",
    )
    parser.add_argument(
        "--mock-plan-dir",
        help="Run the local mock planner for all *_planner_input.json files in a directory.",
    )
    parser.add_argument(
        "--build-verification-request",
        help="Build a verifier request JSON from one planner_output JSON file.",
    )
    parser.add_argument(
        "--verification-request-output",
        help="Optional output path for --build-verification-request.",
    )
    parser.add_argument(
        "--run-verifier-skeleton",
        help="Run the local symbolic verifier skeleton for one verification request JSON.",
    )
    parser.add_argument(
        "--verification-result-output",
        help="Optional output path for --run-verifier-skeleton.",
    )
    parser.add_argument(
        "--build-verification-requests",
        help="Build verification requests for all *_planner_output.json files in a directory.",
    )
    parser.add_argument(
        "--run-verifier-skeleton-dir",
        help="Run verifier skeleton for all *_verification_request.json files in a directory.",
    )
    parser.add_argument(
        "--run-demo",
        action="store_true",
        help="Run the local end-to-end toy demo pipeline.",
    )
    parser.add_argument(
        "--demo-output",
        default="reports/demo_summary.json",
        help="Output path for --run-demo summary JSON.",
    )
    parser.add_argument(
        "--validate-candidate",
        help="Validate a safe local candidate JSON file against the contract.",
    )
    parser.add_argument(
        "--build-candidate-verifier-request",
        help="Build a candidate verifier request from an analysis report.",
    )
    parser.add_argument(
        "--candidates",
        help="Candidate JSON file for --build-candidate-verifier-request.",
    )
    parser.add_argument(
        "--candidate-verifier-request-output",
        help="Optional output path for --build-candidate-verifier-request.",
    )
    parser.add_argument(
        "--run-contract-verifier",
        help="Run the non-executing candidate contract verifier.",
    )
    parser.add_argument(
        "--contract-verifier-result-output",
        help="Optional output path for --run-contract-verifier.",
    )
    args = parser.parse_args()

    target_actions = (
        args.dry_run
        or args.inspect_binary
        or args.find_sinks
        or args.show_sources
        or args.angr_load
        or args.create_argv_state
        or args.create_symbolic_argv
        or args.smoke_reach_sink
        or args.symbolic_reach_sink
        or args.observe_constraints
        or args.write_report
    )
    if (
        not target_actions
        and not args.batch_report
        and not args.run_toy_dataset
        and not args.validate_planner_schema
        and not args.build_planner_input
        and not args.build_planner_inputs
        and not args.mock_plan
        and not args.mock_plan_dir
        and not args.build_verification_request
        and not args.run_verifier_skeleton
        and not args.build_verification_requests
        and not args.run_verifier_skeleton_dir
        and not args.run_demo
        and not args.validate_candidate
        and not args.build_candidate_verifier_request
        and not args.run_contract_verifier
    ):
        raise SystemExit(
            "Use --dry-run, --inspect-binary, --find-sinks, --show-sources, "
            "--angr-load, --create-argv-state, --create-symbolic-argv, "
            "--smoke-reach-sink, --symbolic-reach-sink, and/or "
            "--observe-constraints, --write-report, --batch-report, or "
            "--run-toy-dataset, --validate-planner-schema, "
            "--build-planner-input, --build-planner-inputs, --mock-plan, "
            "--mock-plan-dir, --build-verification-request, "
            "--run-verifier-skeleton, --build-verification-requests, or "
            "--run-verifier-skeleton-dir, --run-demo, --validate-candidate, "
            "--build-candidate-verifier-request, or --run-contract-verifier."
        )
    if target_actions and not args.target:
        raise SystemExit("--target is required for target-specific actions.")

    if target_actions:
        config = load_target_config(args.target)
        if args.dry_run:
            _print_dry_run(config)
        if args.inspect_binary:
            info = inspect_binary(config.binary, config.sinks)
            _print_binary_inspection(info)
        if args.find_sinks:
            report = find_sinks(config.binary, config.sinks)
            _print_sink_report(report)
        if args.show_sources:
            source_model = build_source_model(config)
            _print_source_model(source_model)
        if args.angr_load:
            load_info = load_with_angr(config.binary, config.sinks)
            _print_angr_load_info(load_info, config.sinks)
        if args.create_argv_state:
            source_model = build_source_model(config)
            argv_state_info = create_argv_state(config.binary, source_model)
            _print_argv_state_info(argv_state_info)
        if args.create_symbolic_argv:
            source_model = build_source_model(config)
            symbolic_argv_info = create_symbolic_argv_state(config.binary, source_model)
            _print_symbolic_argv_info(symbolic_argv_info)
        if args.smoke_reach_sink:
            reachability_result = smoke_reach_sink(config.binary, config.sinks)
            _print_reachability_result(reachability_result)
        if args.symbolic_reach_sink:
            source_model = build_source_model(config)
            symbolic_reachability_result = symbolic_reach_sink(
                config.binary,
                config.sinks,
                source_model,
            )
            _print_symbolic_reachability_result(symbolic_reachability_result)
        if args.observe_constraints:
            source_model = build_source_model(config)
            constraint_observation = observe_constraints_to_sink(
                config.binary,
                config.sinks,
                source_model,
            )
            _print_constraint_observation(constraint_observation)
        if args.write_report:
            report = generate_analysis_report(config, args.report_output)
            _print_analysis_report(report)

    if args.batch_report:
        config_paths = _expand_batch_config_paths(args.batch_report)
        summary = generate_batch_summary(config_paths, args.summary_output)
        _print_batch_summary(summary, args.summary_output)

    if args.run_toy_dataset:
        summary = run_toy_dataset(
            config_dir=args.run_toy_dataset,
            reports_dir=args.reports_dir,
            summary_json=args.summary_output,
            summary_md=args.summary_md,
            summary_csv=args.summary_csv,
        )
        _print_toy_dataset_summary(
            summary,
            args.run_toy_dataset,
            args.reports_dir,
            args.summary_output,
            args.summary_md,
            args.summary_csv,
        )

    if args.validate_planner_schema:
        if args.schema_kind is None:
            raise SystemExit("--schema-kind is required for --validate-planner-schema.")
        data = load_json(args.validate_planner_schema)
        if args.schema_kind == "input":
            errors = basic_validate_planner_input(data)
        else:
            errors = basic_validate_planner_output(data)
        _print_planner_schema_validation(
            args.validate_planner_schema,
            args.schema_kind,
            errors,
        )

    if args.build_planner_input:
        planner_input = build_planner_input_from_report(
            args.build_planner_input,
            args.planner_input_output,
        )
        output_path = (
            Path(args.planner_input_output)
            if args.planner_input_output is not None
            else default_planner_input_path(planner_input["target_name"])
        )
        errors = basic_validate_planner_input(planner_input)
        _print_planner_input_builder(
            args.build_planner_input,
            str(output_path),
            planner_input,
            errors,
        )

    if args.build_planner_inputs:
        summary = build_planner_inputs_from_reports(args.build_planner_inputs)
        _print_planner_input_batch_builder(summary)

    if args.mock_plan:
        planner_output = run_mock_planner(args.mock_plan, args.planner_output)
        output_path = (
            Path(args.planner_output)
            if args.planner_output is not None
            else default_planner_output_path(planner_output["target_name"])
        )
        errors = basic_validate_planner_output(planner_output)
        _print_mock_planner(args.mock_plan, str(output_path), planner_output, errors)

    if args.mock_plan_dir:
        summary = run_mock_planner_dir(args.mock_plan_dir)
        _print_mock_planner_batch(summary)

    if args.build_verification_request:
        request = build_verification_request(
            args.build_verification_request,
            args.verification_request_output,
        )
        output_path = (
            Path(args.verification_request_output)
            if args.verification_request_output is not None
            else default_verification_request_path(request["target_name"])
        )
        _print_verification_request_builder(
            args.build_verification_request,
            str(output_path),
            request,
        )

    if args.run_verifier_skeleton:
        result = run_symbolic_verifier_skeleton(
            args.run_verifier_skeleton,
            args.verification_result_output,
        )
        output_path = (
            Path(args.verification_result_output)
            if args.verification_result_output is not None
            else default_verification_result_path(result["target_name"])
        )
        _print_symbolic_verifier_skeleton(
            args.run_verifier_skeleton,
            str(output_path),
            result,
        )

    if args.build_verification_requests:
        summary = build_verification_requests_from_dir(args.build_verification_requests)
        _print_verification_request_batch(summary)

    if args.run_verifier_skeleton_dir:
        summary = run_symbolic_verifier_skeleton_dir(args.run_verifier_skeleton_dir)
        _print_symbolic_verifier_skeleton_batch(summary)

    if args.run_demo:
        summary = run_demo(output_path=args.demo_output)
        _print_demo_summary(summary, args.demo_output)

    if args.validate_candidate:
        candidate_data = load_contract_json(args.validate_candidate)
        candidates = candidate_data.get("candidates")
        if candidates is None:
            candidates = [candidate_data]
        errors = _validate_candidate_list(candidates)
        _print_candidate_validation(args.validate_candidate, errors)

    if args.build_candidate_verifier_request:
        if args.candidates is None:
            raise SystemExit("--candidates is required for --build-candidate-verifier-request.")
        request = build_verifier_request_from_candidates(
            args.build_candidate_verifier_request,
            args.candidates,
            args.candidate_verifier_request_output,
        )
        output_path = (
            args.candidate_verifier_request_output
            or f"examples/verifier/{request['target_name']}_candidate_verifier_request.json"
        )
        _print_candidate_verifier_request(request, output_path)

    if args.run_contract_verifier:
        result = run_contract_only_verifier(
            args.run_contract_verifier,
            args.contract_verifier_result_output,
        )
        output_path = (
            args.contract_verifier_result_output
            or f"examples/verifier/{result['target_name']}_candidate_verifier_result.json"
        )
        _print_contract_verifier(result, output_path)


def _print_dry_run(config) -> None:
    print(f"[+] Target name: {config.name}")
    print(f"[+] Binary path: {config.binary}")
    print(f"[+] Arch: {config.arch}")
    print(f"[+] HTTP method: {config.http_method}")
    print(f"[+] HTTP path: {config.http_path}")
    for source_param in config.source_params:
        print(f"[+] Source param: {source_param.name}, max_len={source_param.max_len}")
    print(f"[+] Vulnerability type: {config.vulnerability_type}")
    print(f"[+] Sinks: {', '.join(config.sinks)}")
    print("[+] Dry run completed.")


def _print_binary_inspection(info: BinaryInfo) -> None:
    print(f"[+] Binary path: {info.path}")
    print(f"[+] Exists: {_yes_no(info.exists)}")
    print(f"[+] Format: {'ELF' if info.is_elf else 'not ELF'}")

    if info.elf_class is not None:
        print(f"[+] ELF class: {info.elf_class}")
    if info.endianness is not None:
        print(f"[+] Endianness: {info.endianness}")
    if info.machine is not None:
        print(f"[+] Machine: {info.machine}")

    for sink in info.found_sinks:
        print(f"[+] Sink symbol found: {sink}")
    for sink in info.missing_sinks:
        print(f"[+] Missing sink symbol: {sink}")
    print("[+] Binary inspection completed.")


def _print_sink_report(report: SinkReport) -> None:
    print(f"[+] Binary path: {report.binary_path}")
    print(f"[+] Configured sinks: {', '.join(report.configured_sinks)}")

    for match in report.matches:
        print()
        prefix = "[+]" if match.found else "[-]"
        print(f"{prefix} Sink: {match.name}")
        print(f"    status: {'found' if match.found else 'missing'}")
        if match.found:
            print(f"    symbol: {match.symbol_name}")
            print(f"    imported: {_yes_no(match.imported)}")
            print(f"    plt: {match.plt_address or 'none'}")
        elif match.reason is not None:
            print(f"    reason: {match.reason}")

    print()
    print("[+] Sink finding completed.")


def _print_source_model(source_model: SourceModel) -> None:
    print("[+] Source model")
    for source in source_model.sources:
        print(f"[+] Source: {source.name}")
        print(f"    type: {source.source_type}")
        print(f"    max_len: {source.max_len}")
        print(f"    runtime_binding: {source.runtime_binding}")
        print(f"    symbolic_name: {source.symbolic_name}")
    print("[+] Source model completed.")


def _print_angr_load_info(info: AngrLoadInfo, sinks: list[str]) -> None:
    print("[+] angr load result")
    print(f"[+] Binary path: {info.binary_path}")
    print(f"[+] Loaded: {_yes_no(info.loaded)}")
    if info.arch is not None:
        print(f"[+] Arch: {info.arch}")
    if info.bits is not None:
        print(f"[+] Bits: {info.bits}")
    if info.entry is not None:
        print(f"[+] Entry: {info.entry}")
    if info.base_addr is not None:
        print(f"[+] Base address: {info.base_addr}")
    if info.main_object is not None:
        print(f"[+] Main object: {info.main_object}")

    for sink in sinks:
        address = info.plt.get(sink)
        if address is None:
            print(f"[-] PLT {sink}: missing")
        else:
            print(f"[+] PLT {sink}: {address}")

    if info.error is not None:
        print(f"[-] Error: {info.error}")
    print("[+] angr loader completed.")


def _print_argv_state_info(info: ArgvStateInfo) -> None:
    print("[+] argv state result")
    print(f"[+] Binary path: {info.binary_path}")
    print(f"[+] Created: {_yes_no(info.created)}")
    print(f"[+] State kind: {info.state_kind}")
    for index, value in enumerate(info.argv):
        print(f"[+] argv[{index}]: {value}")
    for name, binding in info.source_bindings.items():
        print(f"[+] Source binding: {name} -> {binding}")
    print(f"[+] Symbolic mode: {_yes_no(info.symbolic)}")
    if info.error is not None:
        print(f"[-] Error: {info.error}")
    print("[+] angr argv state completed.")


def _print_symbolic_argv_info(info: ArgvStateInfo) -> None:
    print("[+] symbolic argv result")
    print(f"[+] Binary path: {info.binary_path}")
    print(f"[+] Created: {_yes_no(info.created)}")
    print(f"[+] State kind: {info.state_kind}")
    for index, value in enumerate(info.argv):
        print(f"[+] argv[{index}]: {value}")
    for name, binding in info.source_bindings.items():
        print(f"[+] Source binding: {name} -> {binding}")
    for name in info.source_bindings:
        symbolic_var = info.symbolic_vars.get(name)
        if symbolic_var is not None:
            print(f"[+] Symbolic variable: {symbolic_var}")
        symbolic_size = info.symbolic_sizes.get(name)
        if symbolic_size is not None:
            print(f"[+] Symbolic size: {symbolic_size} bytes")
    for constraint in info.constraints:
        print(f"[+] Constraint: {constraint}")
    print(f"[+] Symbolic mode: {_yes_no(info.symbolic)}")
    if info.error is not None:
        print(f"[-] Error: {info.error}")
    print("[+] symbolic argv state completed.")


def _print_reachability_result(result: ReachabilityResult) -> None:
    print("[+] sink reachability smoke test")
    print(f"[+] Binary path: {result.binary_path}")
    print(f"[+] Input mode: {result.input_mode}")
    if len(result.argv) > 1:
        print(f"[+] argv[1]: {result.argv[1]}")
    if result.target_sink is not None:
        print(f"[+] Target sink: {result.target_sink}")
    if result.target_addr is not None:
        print(f"[+] Target address: {result.target_addr}")
    print(f"[+] Max steps: {result.max_steps}")
    prefix = "[+]" if result.reachable else "[-]"
    print(f"{prefix} Reachable: {_yes_no(result.reachable)}")
    print(f"[+] Found states: {result.found_states}")
    if result.error is not None:
        print(f"[-] Error: {result.error}")
    print("[+] Smoke test completed.")


def _print_symbolic_reachability_result(result: SymbolicReachabilityResult) -> None:
    print("[+] symbolic sink reachability")
    print(f"[+] Binary path: {result.binary_path}")
    print(f"[+] Input mode: {result.input_mode}")
    if result.source_name is not None:
        print(f"[+] Source: {result.source_name}")
    if result.symbolic_var is not None:
        print(f"[+] Symbolic variable: {result.symbolic_var}")
    if result.runtime_binding is not None:
        print(f"[+] Runtime binding: {result.runtime_binding}")
    for constraint in result.input_constraints:
        print(f"[+] Input constraint: {constraint}")
    if result.target_sink is not None:
        print(f"[+] Target sink: {result.target_sink}")
    if result.target_addr is not None:
        print(f"[+] Target address: {result.target_addr}")
    print(f"[+] Max steps: {result.max_steps}")
    prefix = "[+]" if result.reachable else "[-]"
    print(f"{prefix} Reachable: {_yes_no(result.reachable)}")
    print(f"[+] Found states: {result.found_states}")
    if result.sink_arg_register is not None:
        print(f"[+] Sink argument register: {result.sink_arg_register}")
    print(f"[+] Sink argument symbolic: {_yes_no(result.sink_arg_symbolic)}")
    if result.sink_arg_variables:
        print(f"[+] Sink argument variables: {', '.join(result.sink_arg_variables)}")
    else:
        print("[+] Sink argument variables: none")
    print(
        "[+] Source variable in sink argument: "
        f"{_yes_no(result.source_var_in_sink_arg)}"
    )
    if result.error is not None:
        print(f"[-] Error: {result.error}")
    print("[+] Symbolic reachability completed.")


def _print_constraint_observation(result: ConstraintObservationResult) -> None:
    print("[+] constraint observation")
    print(f"[+] Binary path: {result.binary_path}")
    print("[+] Input mode: symbolic argv")
    if result.source_name is not None:
        print(f"[+] Source: {result.source_name}")
    if result.symbolic_var is not None:
        print(f"[+] Symbolic variable: {result.symbolic_var}")
    if result.runtime_binding is not None:
        print(f"[+] Runtime binding: {result.runtime_binding}")
    for constraint in result.input_constraints:
        print(f"[+] Input constraint: {constraint}")
    if result.target_sink is not None:
        print(f"[+] Target sink: {result.target_sink}")
    if result.target_addr is not None:
        print(f"[+] Target address: {result.target_addr}")
    prefix = "[+]" if result.reachable else "[-]"
    print(f"{prefix} Reachable: {_yes_no(result.reachable)}")
    print(f"[+] Total constraints: {result.total_constraints}")
    print(f"[+] Source-related constraints: {result.source_related_count}")
    for index, constraint in enumerate(result.source_related_constraints[:3]):
        print(f"[+] Constraint[{index}]: {constraint}")
    print(f"[+] String-modeling constraints: {result.string_modeling_count}")
    print(f"[+] Input-modeling constraints: {result.input_modeling_count}")
    print(f"[+] Branch condition constraints: {result.branch_condition_count}")
    print(f"[+] Sanitizer candidate constraints: {result.sanitizer_candidate_count}")
    for index, constraint in enumerate(result.sanitizer_candidate_constraints):
        print(f"[+] SanitizerCandidate[{index}]: {constraint}")
    print(f"[+] Unknown source constraints: {result.unknown_source_count}")
    for index, constraint in enumerate(result.unknown_source_constraints[:3]):
        print(f"[+] UnknownConstraint[{index}]: {constraint}")
    print(
        "[+] Sanitizer-like constraints observed: "
        f"{_yes_no(result.sanitizer_like_observed)}"
    )
    if result.error is not None:
        print(f"[-] Error: {result.error}")
    print("[+] Constraint observation completed.")


def _print_analysis_report(report: dict) -> None:
    summary = report["summary"]
    print("[+] analysis report")
    print(f"[+] Target: {report['target']['name']}")
    print(f"[+] Output: {report['report_path']}")
    print(
        "[+] Source-to-sink confirmed: "
        f"{_yes_no(summary['source_to_sink_confirmed'])}"
    )
    print(
        "[+] Sanitizer-like observed: "
        f"{_yes_no(summary['sanitizer_like_observed'])}"
    )
    print("[+] Report written.")


def _print_batch_summary(summary: dict, output_path: str) -> None:
    print("[+] batch report")
    print(f"[+] Configs: {summary['total_targets']}")
    print(f"[+] Summary output: {output_path}")
    print(f"[+] Total targets: {summary['total_targets']}")
    print(f"[+] OK targets: {summary['ok_targets']}")
    print(
        "[+] Source-to-sink confirmed: "
        f"{summary['source_to_sink_confirmed_count']}"
    )
    print(
        "[+] Sanitizer-like observed: "
        f"{summary['sanitizer_like_observed_count']}"
    )
    print(f"[+] Errors: {summary['error_count']}")
    print("[+] Batch summary written.")


def _print_toy_dataset_summary(
    summary: dict,
    config_dir: str,
    reports_dir: str,
    summary_json: str,
    summary_md: str,
    summary_csv: str,
) -> None:
    print("[+] toy dataset runner")
    print(f"[+] Config dir: {config_dir}")
    print(f"[+] Targets: {summary['total_targets']}")
    print(f"[+] Reports dir: {reports_dir}")
    print(f"[+] Summary JSON: {summary_json}")
    print(f"[+] Summary Markdown: {summary_md}")
    print(f"[+] Summary CSV: {summary_csv}")
    print(
        "[+] Source-to-sink confirmed: "
        f"{summary['source_to_sink_confirmed_count']}"
    )
    print(
        "[+] Sanitizer-like observed: "
        f"{summary['sanitizer_like_observed_count']}"
    )
    print(f"[+] Errors: {summary['error_count']}")
    print("[+] Toy dataset runner completed.")


def _print_planner_schema_validation(
    path: str,
    schema_kind: str,
    errors: list[str],
) -> None:
    print("[+] planner schema validation")
    print(f"[+] File: {path}")
    print(f"[+] Schema kind: {schema_kind}")
    print(f"[+] Valid: {_yes_no(not errors)}")
    for error in errors:
        print(f"[-] Error: {error}")


def _print_planner_input_builder(
    report_path: str,
    output_path: str,
    planner_input: dict,
    errors: list[str],
) -> None:
    observations = planner_input["observations"]
    print("[+] planner input builder")
    print(f"[+] Report: {report_path}")
    print(f"[+] Target: {planner_input['target_name']}")
    print(f"[+] Output: {output_path}")
    print(
        "[+] Source-to-sink confirmed: "
        f"{_yes_no(observations['source_to_sink_confirmed'])}"
    )
    print(
        "[+] Sanitizer-like observed: "
        f"{_yes_no(observations['sanitizer_like_observed'])}"
    )
    print(f"[+] Valid: {_yes_no(not errors)}")
    for error in errors:
        print(f"[-] Error: {error}")
    print("[+] Planner input written.")


def _print_planner_input_batch_builder(summary: dict) -> None:
    invalid_count = sum(1 for target in summary["targets"] if not target["valid"])
    print("[+] planner input batch builder")
    print(f"[+] Reports: {summary['reports']}")
    print(f"[+] Output dir: {summary['output_dir']}")
    print(f"[+] Built: {summary['built']}")
    print(f"[+] Errors: {summary['errors']}")
    if invalid_count:
        print(f"[-] Invalid planner inputs: {invalid_count}")
        for target in summary["targets"]:
            if target["valid"]:
                continue
            print(f"[-] {target['report_path']}: {', '.join(target['validation_errors'])}")


def _print_mock_planner(
    input_path: str,
    output_path: str,
    planner_output: dict,
    errors: list[str],
) -> None:
    print("[+] mock planner")
    print(f"[+] Input: {input_path}")
    print(f"[+] Target: {planner_output['target_name']}")
    print(f"[+] Decision: {planner_output['decision']}")
    print(f"[+] Candidate plans: {len(planner_output['candidate_plans'])}")
    print(f"[+] Output: {output_path}")
    print(f"[+] Valid: {_yes_no(not errors)}")
    for error in errors:
        print(f"[-] Error: {error}")


def _print_mock_planner_batch(summary: dict) -> None:
    print("[+] mock planner batch")
    print(f"[+] Inputs: {summary['inputs']}")
    print(f"[+] Output dir: {summary['output_dir']}")
    print(f"[+] Built: {summary['built']}")
    print(f"[+] Errors: {summary['errors']}")
    for target in summary["targets"]:
        if target["valid"]:
            continue
        print(f"[-] {target['input_path']}: {target['error']}")


def _print_verification_request_builder(
    input_path: str,
    output_path: str,
    request: dict,
) -> None:
    print("[+] verification request builder")
    print(f"[+] Input: {input_path}")
    print(f"[+] Target: {request['target_name']}")
    print(f"[+] Requests: {len(request['requests'])}")
    print(f"[+] Output: {output_path}")
    print("[+] Verification request written.")


def _print_symbolic_verifier_skeleton(
    input_path: str,
    output_path: str,
    result: dict,
) -> None:
    print("[+] symbolic verifier skeleton")
    print(f"[+] Input: {input_path}")
    print(f"[+] Target: {result['target_name']}")
    print(f"[+] Executed: {_yes_no(result['executed'])}")
    print(f"[+] Deferred requests: {result['summary']['deferred_requests']}")
    print(f"[+] Output: {output_path}")
    print("[+] Verifier skeleton completed.")


def _print_verification_request_batch(summary: dict) -> None:
    print("[+] verification request batch builder")
    print(f"[+] Inputs: {summary['inputs']}")
    print(f"[+] Output dir: {summary['output_dir']}")
    print(f"[+] Built: {summary['built']}")
    print(f"[+] Errors: {summary['errors']}")
    for target in summary["targets"]:
        if target["error"] is None:
            continue
        print(f"[-] {target['input_path']}: {target['error']}")


def _print_symbolic_verifier_skeleton_batch(summary: dict) -> None:
    print("[+] symbolic verifier skeleton batch")
    print(f"[+] Inputs: {summary['inputs']}")
    print(f"[+] Output dir: {summary['output_dir']}")
    print(f"[+] Built: {summary['built']}")
    print(f"[+] Errors: {summary['errors']}")
    for target in summary["targets"]:
        if target["error"] is None:
            continue
        print(f"[-] {target['input_path']}: {target['error']}")


def _print_demo_summary(summary: dict, output_path: str) -> None:
    print("[+] end-to-end demo runner")
    print("[+] Step 1/5: toy dataset")
    print("[+] Step 2/5: planner inputs")
    print("[+] Step 3/5: mock planner")
    print("[+] Step 4/5: verification requests")
    print("[+] Step 5/5: verifier skeleton")
    print(f"[+] Demo status: {summary['status']}")
    print(f"[+] Demo summary: {output_path}")
    print("[+] End-to-end demo completed.")


def _validate_candidate_list(candidates) -> list[str]:
    if not isinstance(candidates, list):
        return ["candidates must be an array"]
    errors: list[str] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            errors.append(f"candidates[{index}] must be an object")
            continue
        for error in validate_candidate_contract(candidate):
            errors.append(f"candidates[{index}]: {error}")
    return errors


def _print_candidate_validation(path: str, errors: list[str]) -> None:
    print("[+] candidate contract validation")
    print(f"[+] File: {path}")
    print(f"[+] Valid: {_yes_no(not errors)}")
    for error in errors:
        print(f"[-] Error: {error}")


def _print_candidate_verifier_request(request: dict, output_path: str) -> None:
    print("[+] candidate verifier request")
    print(f"[+] Target: {request['target_name']}")
    print(f"[+] Candidates: {len(request['candidates'])}")
    print(f"[+] Output: {output_path}")


def _print_contract_verifier(result: dict, output_path: str) -> None:
    print("[+] contract-only verifier")
    print(f"[+] Target: {result['target_name']}")
    print(f"[+] Executed: {_yes_no(result['executed'])}")
    print(f"[+] Accepted by contract: {result['summary']['accepted_by_contract']}")
    print(f"[+] Deferred: {result['summary']['deferred_count']}")
    print(f"[+] Output: {output_path}")


def _expand_batch_config_paths(paths: list[str]) -> list[str]:
    expanded: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            expanded.extend(str(candidate) for candidate in sorted(path.glob("*.yaml")))
        else:
            expanded.append(raw_path)
    return expanded


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


if __name__ == "__main__":
    main()
