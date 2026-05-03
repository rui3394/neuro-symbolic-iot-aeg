from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ns_aeg.ghidra.export_facts import load_json
from ns_aeg.verifier.symbolic_task_runner import (
    _find_states_until_addr,
    _sink_address_candidates,
    run_symbolic_task_verification,
)
from ns_aeg.verifier.task_adapter import load_candidate, task_to_verifier_config


def test_symbolic_task_runner_reaches_toy_01_system_callsite() -> None:
    _require_angr()
    if not Path("datasets/toy_cgi/build/toy_01").exists():
        pytest.skip("toy_01 binary is not built")

    task = _toy_01_symbolic_task()
    candidate = load_candidate("examples/candidates/toy_01_candidate.example.json")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate)

    assert result["mode"] == "symbolic_task"
    assert result["executed"] is False
    assert result["backend"] == "angr"
    assert result["selected_sink"]["function"] == "system"
    # Fixture-specific x86_64 toy_01 regression: recompiling toy_01 may change
    # this callsite, so cross-arch tests must not treat it as a universal value.
    assert result["selected_sink"]["address"] == "0x4011f9"
    assert result["sink_reached"] is True
    assert result["path_status"] == "sat"
    assert result["source_bound"] is True
    assert result["marker_observed"] is True
    assert result["sink_argument"]["arg_index"] == 0
    assert result["sink_argument"]["register"] == "rdi"
    assert result["sink_argument"]["contains_source"] is True
    assert result["sink_argument"]["contains_marker"] is True
    assert result["sink_policy"]["policy_status"] == "positive_evidence"
    assert result["sink_policy"]["reason"] == "source_and_marker_observed_in_system_argument"
    assert result["reachability_debug"]["matched_sink_address"] == "0x4011f9"
    assert result["reachability_debug"]["match_reason"] == "selected_sink_address"
    assert "weapon" not in json.dumps(result).lower()


def test_symbolic_task_runner_missing_candidate_input_is_unsupported() -> None:
    _require_angr()
    task = _toy_01_symbolic_task()
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(
        config,
        {"candidate_id": "missing", "inputs": {"other": "value"}},
    )

    assert result["status"] == "unsupported"
    assert result["sink_reached"] == "unknown"
    assert "missing_candidate_input: ip" in result["reason"]


def test_symbolic_task_runner_toy_02_filter_chars_reaches_system() -> None:
    _require_angr()
    _require_file("datasets/toy_cgi/build/toy_02", "toy_02 binary is not built")
    _require_file("examples/dangerous_tasks/toy_02_task.real.json", "toy_02 task is not generated")
    _require_file(
        "examples/candidates/toy_02_candidates.rule.generated.json",
        "toy_02 candidates are not generated",
    )

    task = load_json("examples/dangerous_tasks/toy_02_task.real.json")
    candidate = load_candidate("examples/candidates/toy_02_candidates.rule.generated.json")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate)

    assert result["status"] == "sat"
    assert result["selected_sink"]["function"] == "system"
    assert result["sink_reached"] is True
    assert result["source_bound"] is True
    assert result["marker_observed"] is True
    assert result["sink_argument"]["location"] == "register:rdi"
    assert result["sink_argument"]["method"] == "register_pointer_memory_string"
    assert result["sink_policy"]["policy_status"] == "positive_evidence"


def test_symbolic_task_runner_toy_05_safe_fixed_system_argument_is_negative_evidence() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_05/task.real.json",
        "x86_64 toy_05 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_05/candidates.rule.json",
        "x86_64 toy_05 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/x86_64_toy_05/task.real.json")
    candidate_set = load_json("reports/cross_arch/toy_smoke/x86_64_toy_05/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] == "unsat"
    assert result["sink_reached"] is True
    assert result["source_bound"] is False
    assert result["marker_observed"] is False
    assert result["sink_policy"]["policy_status"] == "negative_evidence"
    assert result["sink_policy"]["reason"] == "safe_fixed_sink_argument_without_source"
    assert result["sink_policy"]["fixed_safe_argument"] is True


def test_symbolic_task_runner_toy_06_format_flow_reaches_system_argument() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_06/task.real.json",
        "x86_64 toy_06 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_06/candidates.rule.json",
        "x86_64 toy_06 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/x86_64_toy_06/task.real.json")
    candidate_set = load_json("reports/cross_arch/toy_smoke/x86_64_toy_06/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] == "sat"
    assert result["sink_policy"]["policy_status"] == "positive_evidence"
    assert result["format_flow"]["observed"] is True
    assert result["format_flow"]["status"] == "positive"
    assert result["format_flow"]["flows_to_command_sink"] is True
    assert result["format_flow"]["records"][0]["format_sink"] in {"snprintf", "sprintf"}


def test_symbolic_task_runner_toy_07_format_safe_negative_does_not_count_format_as_command_evidence() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_07/task.real.json",
        "x86_64 toy_07 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/x86_64_toy_07/candidates.rule.json",
        "x86_64 toy_07 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/x86_64_toy_07/task.real.json")
    candidate_set = load_json("reports/cross_arch/toy_smoke/x86_64_toy_07/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] == "unsat"
    assert result["sink_reached"] is True
    assert result["sink_policy"]["policy_status"] == "negative_evidence"
    assert result["sink_policy"]["reason"] == "safe_fixed_sink_argument_without_source"
    assert result["format_flow"]["observed"] is True
    assert result["format_flow"]["status"] == "negative"
    assert result["format_flow"]["flows_to_command_sink"] is False


def test_symbolic_task_runner_toy_08_snprintf_truncation_is_not_positive_evidence() -> None:
    _require_angr()
    task, candidate = _cross_arch_task_and_candidate("x86_64", "toy_08")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] != "sat"
    assert result["sink_reached"] is True
    assert result["marker_observed"] is False
    assert result["sink_policy"]["policy_status"] == "inconclusive"
    assert result["format_flow"]["status"] == "truncated"
    assert result["format_flow"]["marker_truncated"] is True
    assert result["format_flow"]["truncated_write_count"] >= 1


def test_symbolic_task_runner_toy_09_snprintf_enough_size_is_positive_evidence() -> None:
    _require_angr()
    task, candidate = _cross_arch_task_and_candidate("x86_64", "toy_09")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] == "sat"
    assert result["marker_observed"] is True
    assert result["sink_policy"]["policy_status"] == "positive_evidence"
    assert result["format_flow"]["status"] == "positive"
    assert result["format_flow"]["marker_truncated"] is False


def test_symbolic_task_runner_toy_10_memcpy_flow_is_positive_evidence() -> None:
    _require_angr()
    task, candidate = _cross_arch_task_and_candidate("x86_64", "toy_10")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] == "sat"
    assert result["sink_policy"]["policy_status"] == "positive_evidence"
    assert result["format_flow"]["status"] == "positive"
    assert result["format_flow"]["memory_copy_count"] >= 1
    assert result["format_flow"]["flows_to_command_sink"] is True


def test_symbolic_task_runner_toy_11_memcpy_truncation_is_not_positive_evidence() -> None:
    _require_angr()
    task, candidate = _cross_arch_task_and_candidate("x86_64", "toy_11")
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="full-init")

    assert result["status"] != "sat"
    assert result["sink_reached"] is True
    assert result["marker_observed"] is False
    assert result["sink_policy"]["policy_status"] == "inconclusive"
    assert result["format_flow"]["status"] == "truncated"
    assert result["format_flow"]["memory_copy_count"] >= 1
    assert result["format_flow"]["marker_truncated"] is True


def test_symbolic_task_runner_toy_03_length_filter_is_unsat_for_marker_candidate() -> None:
    _require_angr()
    _require_file("datasets/toy_cgi/build/toy_03", "toy_03 binary is not built")
    _require_file("examples/dangerous_tasks/toy_03_task.real.json", "toy_03 task is not generated")

    task = load_json("examples/dangerous_tasks/toy_03_task.real.json")
    candidate = {
        "candidate_id": "toy_03_marker_incompatible",
        "inputs": {"ip": "127.0.0.1__NS_AEG_MARKER__"},
        "strategy": "marker_length_incompatible_with_window",
        "safety": {"benign": True, "weaponized": False},
    }
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate)

    assert result["status"] == "unsat"
    assert result["sink_reached"] is False
    assert "selected sink callsite was not reached" in result["reason"]
    assert result["reachability_debug"]["reason"]
    assert result["reachability_debug"]["sink_address_candidates"]


def test_symbolic_task_runner_mips_full_init_repair_reaches_sink() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json",
        "mipsel toy_01 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json",
        "mipsel toy_01 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json")
    candidate_set = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    full_init = run_symbolic_task_verification(config, candidate, startup_mode="full-init")
    auto = run_symbolic_task_verification(config, candidate, startup_mode="auto")

    assert full_init["status"] == "sat"
    assert full_init["startup_debug"]["selected_startup_mode"] == "full_init"
    assert full_init["reachability_debug"]["reached_main"] is True
    assert full_init["reachability_debug"]["full_init_repair_applied"] is True
    assert full_init["evidence_strength"]["level"] == "full_program_startup_symbolic"
    assert auto["status"] == "sat"
    assert auto["startup_debug"]["selected_startup_mode"] == "full_init"
    assert auto["startup_debug"]["full_init_status"] == "reached"
    assert auto["startup_debug"]["direct_main_status"] is None
    assert auto["sink_argument"]["location"] == "register:a0"
    assert auto["evidence_strength"]["level"] == "full_program_startup_symbolic"
    assert auto["evidence_strength"]["can_claim_full_startup_proof"] is True


def test_symbolic_task_runner_non_toy_auto_does_not_use_direct_main_without_opt_in() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json",
        "mipsel toy_01 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json",
        "mipsel toy_01 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json")
    task["scope"] = "firmware"
    task.pop("allow_direct_main", None)
    task["sinks"] = [
        {
            "sink_id": "fake_missing_sink",
            "type": "command_execution",
            "function": "missing_sink",
            "address": "0x410000",
            "arg_index": 0,
            "callers": ["main"],
            "callsites": [{"address": "0x410000", "caller": "main", "caller_entry": "0x4007a0"}],
        }
    ]
    candidate_set = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    result = run_symbolic_task_verification(config, candidate, startup_mode="auto")

    assert result["status"] == "unsat"
    assert result["startup_debug"]["selected_startup_mode"] == "full_init"
    assert result["startup_debug"]["direct_main_status"] is None
    assert "explicit opt-in" in " ".join(result["startup_debug"]["limitations"])
    assert result["evidence_strength"]["level"] == "full_program_startup_symbolic"


def test_symbolic_task_runner_non_toy_direct_main_requires_explicit_opt_in() -> None:
    _require_angr()
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json",
        "mipsel toy_01 cross-arch task is not generated",
    )
    _require_file(
        "reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json",
        "mipsel toy_01 candidates are not generated",
    )

    task = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/task.real.json")
    task["scope"] = "firmware"
    candidate_set = load_json("reports/cross_arch/toy_smoke/mipsel_toy_01/candidates.rule.json")
    candidate = candidate_set["candidates"][0]
    config = task_to_verifier_config(task)

    blocked = run_symbolic_task_verification(config, candidate, startup_mode="direct-main")
    allowed = run_symbolic_task_verification(
        config,
        candidate,
        startup_mode="direct-main",
        allow_direct_main_for_non_toy=True,
    )

    assert blocked["status"] == "unsupported"
    assert "direct_main startup disabled" in blocked["reason"]
    assert allowed["status"] == "sat"
    assert allowed["startup_debug"]["selected_startup_mode"] == "direct_main"
    assert allowed["evidence_strength"]["requires_explicit_opt_in"] is True


def test_find_states_until_addr_returns_unsat_when_no_active_states() -> None:
    class EmptySimgr:
        active: list = []

        def step(self, num_inst: int = 1) -> None:
            raise AssertionError("step should not be called when active states are empty")

    found, steps, timed_out = _find_states_until_addr(EmptySimgr(), 0x401000, 10)

    assert found == []
    assert steps == 0
    assert timed_out is False


def test_sink_address_candidates_include_arm_thumb_and_mips_delay_slot() -> None:
    class Project:
        class Arch:
            name = "ARMEL"

        arch = Arch()

    arm = _sink_address_candidates(Project(), {"address": "0x1054c"}, 0x1054C)
    assert arm[0x1054C]["reason"] == "selected_sink_address"
    assert arm[0x1054D]["reason"] == "thumb_bit_candidate"
    assert arm[0x1054E]["reason"] == "thumb_next_halfword_candidate"

    class MipsProject:
        class Arch:
            name = "MIPS32"

        arch = Arch()

    mips = _sink_address_candidates(MipsProject(), {"address": "0x400834"}, 0x400834)
    assert mips[0x400838]["reason"] == "mips_delay_slot_candidate"
    assert mips[0x40083C]["reason"] == "mips_after_delay_slot_candidate"


def _toy_01_symbolic_task() -> dict:
    task = load_json("examples/dangerous_tasks/toy_01_task.example.json")
    task["sinks"] = [
        {
            "sink_id": "sink_1:snprintf",
            "type": "string_formatting",
            "function": "snprintf",
            "address": "0x4011ea",
            "arg_index": 2,
            "callers": ["main"],
            "external_address": "0x4",
        },
        {
            "sink_id": "sink_2:system",
            "type": "command_execution",
            "function": "system",
            "address": "0x4011f9",
            "arg_index": 0,
            "callers": ["main"],
            "external_address": "0x3",
        },
    ]
    return task


def _cross_arch_task_and_candidate(arch: str, toy_id: str) -> tuple[dict, dict]:
    base = Path("reports/cross_arch/toy_smoke") / f"{arch}_{toy_id}"
    _require_file(str(base / "task.real.json"), f"{arch} {toy_id} cross-arch task is not generated")
    _require_file(str(base / "candidates.rule.json"), f"{arch} {toy_id} candidates are not generated")
    task = load_json(str(base / "task.real.json"))
    candidate_set = load_json(str(base / "candidates.rule.json"))
    return task, candidate_set["candidates"][0]


def _require_angr() -> None:
    if importlib.util.find_spec("angr") is None or importlib.util.find_spec("claripy") is None:
        pytest.skip("angr/claripy are not installed")


def _require_file(path: str, reason: str) -> None:
    if not Path(path).exists():
        pytest.skip(reason)
