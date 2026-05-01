from __future__ import annotations

import json
from pathlib import Path

from ns_aeg.candidate_contract import (
    build_verifier_request_from_candidates,
    run_contract_only_verifier,
    validate_candidate_contract,
    validate_verifier_request_contract,
    validate_verifier_result_contract,
)


def test_valid_candidate_passes_contract() -> None:
    assert validate_candidate_contract(_candidate()) == []


def test_candidate_value_with_semicolon_fails() -> None:
    errors = validate_candidate_contract(_candidate(candidate_value="LOCAL;TEST"))

    assert any("disallowed token: ;" in error for error in errors)


def test_candidate_value_with_dangerous_keywords_fails() -> None:
    for keyword in ("curl ", "wget ", "rm ", "bash "):
        errors = validate_candidate_contract(_candidate(candidate_value=f"{keyword}marker"))
        assert errors
        assert any("disallowed keyword" in error for error in errors)


def test_executable_code_safety_flag_true_fails() -> None:
    candidate = _candidate()
    candidate["safety"]["contains_executable_code"] = True

    errors = validate_candidate_contract(candidate)

    assert "safety.contains_executable_code must be false" in errors


def test_shell_metacharacter_safety_flag_true_fails() -> None:
    candidate = _candidate()
    candidate["safety"]["contains_shell_metacharacters"] = True

    errors = validate_candidate_contract(candidate)

    assert "safety.contains_shell_metacharacters must be false" in errors


def test_local_toy_only_false_fails() -> None:
    candidate = _candidate()
    candidate["safety"]["local_toy_only"] = False

    errors = validate_candidate_contract(candidate)

    assert "safety.local_toy_only must be true" in errors


def test_verifier_request_executes_candidate_true_fails() -> None:
    request = _request([_candidate()])
    request["safety"]["executes_candidate"] = True

    errors = validate_verifier_request_contract(request)

    assert "safety.executes_candidate must be false" in errors


def test_contract_verifier_does_not_execute_candidate(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "request.json", _request([_candidate()]))

    result = run_contract_only_verifier(str(request_path))

    assert result["executed"] is False
    assert result["safety"]["executed_input"] is False
    assert result["results"][0]["status"] == "deferred"
    assert validate_verifier_result_contract(result) == []


def test_contract_verifier_handles_empty_candidates(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "request.json", _request([]))

    result = run_contract_only_verifier(str(request_path))

    assert result["executed"] is False
    assert result["summary"] == {
        "total_candidates": 0,
        "accepted_by_contract": 0,
        "verified_count": 0,
        "deferred_count": 0,
        "rejected_count": 0,
        "status": "no_candidates",
    }


def test_build_verifier_request_from_fake_report_and_candidates(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_json(tmp_path, "report.json", _report())
    candidates_path = _write_json(tmp_path, "candidates.json", {"candidates": [_candidate()]})

    request = build_verifier_request_from_candidates(
        str(report_path),
        str(candidates_path),
    )

    assert request["target_name"] == "toy_02_filter_chars"
    assert request["binary"] == "datasets/toy_cgi/build/toy_02"
    assert request["source"] == {
        "name": "ip",
        "runtime_binding": "argv[1]",
        "max_len": 32,
    }
    assert request["sink"] == {"name": "system", "address": "0x401090"}
    assert request["verification_mode"] == "local_toy_candidate_check"
    assert len(request["candidates"]) == 1
    assert validate_verifier_request_contract(request) == []
    assert (
        tmp_path
        / "examples"
        / "verifier"
        / "toy_02_filter_chars_candidate_verifier_request.json"
    ).exists()


def test_build_verifier_request_with_empty_candidates_is_abstract_contract_only(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_json(tmp_path, "report.json", _report())
    candidates_path = _write_json(tmp_path, "candidates.json", {"candidates": []})

    request = build_verifier_request_from_candidates(str(report_path), str(candidates_path))

    assert request["candidates"] == []
    assert request["verification_mode"] == "abstract_contract_only"


def test_contract_result_rejects_invalid_candidate_without_execution(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    bad_candidate = _candidate(candidate_value="LOCAL;TEST")
    request_path = _write_json(tmp_path, "request.json", _request([bad_candidate]))

    result = run_contract_only_verifier(str(request_path))

    assert result["executed"] is False
    assert result["summary"]["rejected_count"] == 1
    assert result["results"][0]["status"] == "rejected_by_contract"


def test_no_llm_solver_payload_or_poc_terms_in_candidate_contract_output(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    request_path = _write_json(tmp_path, "request.json", _request([_candidate()]))

    result = run_contract_only_verifier(str(request_path))
    serialized = json.dumps(result).lower()

    assert "llm" not in serialized
    assert "solver.eval" not in serialized


def _candidate(candidate_value: str = "LOCAL_TEST_VALUE") -> dict:
    return {
        "candidate_id": "cand_001",
        "target_name": "toy_02_filter_chars",
        "target_source": "ip",
        "candidate_kind": "benign_local_test_value",
        "candidate_value": candidate_value,
        "encoding": "plain",
        "max_len": 32,
        "constraints_claimed": {
            "respects_max_len": True,
            "avoids_observed_sanitizer_candidates": True,
            "satisfies_branch_conditions": False,
        },
        "safety": {
            "local_toy_only": True,
            "contains_shell_metacharacters": False,
            "contains_network_target": False,
            "contains_file_operation": False,
            "contains_executable_code": False,
        },
        "requires_symbolic_verification": True,
    }


def _request(candidates: list[dict]) -> dict:
    return {
        "target_name": "toy_02_filter_chars",
        "binary": "datasets/toy_cgi/build/toy_02",
        "source": {
            "name": "ip",
            "runtime_binding": "argv[1]",
            "max_len": 32,
        },
        "sink": {"name": "system", "address": "0x401090"},
        "verification_mode": "local_toy_candidate_check",
        "candidates": candidates,
        "safety": {
            "local_toy_only": True,
            "executes_candidate": False,
            "generates_payload": False,
            "generates_poc": False,
        },
    }


def _report() -> dict:
    return {
        "target": {
            "name": "toy_02_filter_chars",
            "binary": "datasets/toy_cgi/build/toy_02",
        },
        "source_model": {
            "sources": [
                {
                    "name": "ip",
                    "runtime_binding": "argv[1]",
                    "max_len": 32,
                }
            ]
        },
        "symbolic_reachability": {
            "target_sink": "system",
            "target_addr": "0x401090",
        },
    }


def _write_json(directory: Path, filename: str, data: dict) -> Path:
    path = directory / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
