import json
from types import SimpleNamespace

from ns_aeg.config import TargetConfig
from ns_aeg.reporting import generate_analysis_report


def test_default_output_path_creates_reports_dir_and_writes_json(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch)

    report = generate_analysis_report(_config())
    output = tmp_path / "reports" / "toy_report_analysis.json"

    assert output.exists()
    assert report["report_path"] == "reports/toy_report_analysis.json"
    written = json.loads(output.read_text(encoding="utf-8"))
    assert set(written) >= {
        "target",
        "source_model",
        "angr_loader",
        "symbolic_reachability",
        "constraint_observation",
        "summary",
    }


def test_report_contains_expected_sections_and_summary_values(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch, sanitizer_like=True)

    report = generate_analysis_report(_config())

    assert report["target"]["name"] == "toy_report"
    assert report["target"]["configured_sinks"] == ["system", "snprintf"]
    assert report["source_model"]["sources"] == [
        {
            "name": "ip",
            "source_type": "http_param",
            "max_len": 32,
            "symbolic_name": "sym_ip",
            "runtime_binding": "argv[1]",
        }
    ]
    assert report["angr_loader"]["plt"] == {"system": "0x401050"}
    assert report["symbolic_reachability"]["source_var_in_sink_arg"] is True
    assert report["constraint_observation"]["sanitizer_like_observed"] is True
    assert report["constraint_observation"]["input_modeling_count"] == 2
    assert report["constraint_observation"]["input_modeling_constraints"] == [
        "<Bool !(sym_ip_0_248[247:240] == 0)>",
        "<Bool !(sym_ip_0_248[239:232] == 0)>",
    ]
    assert report["constraint_observation"]["branch_condition_count"] == 2
    assert report["constraint_observation"]["branch_condition_constraints"] == [
        "<Bool sym_ip_0_248[247:240] == 65>",
        "<Bool sym_ip_0_248[239:232] == 66>",
    ]
    assert report["summary"] == {
        "source_to_sink_confirmed": True,
        "sanitizer_like_observed": True,
        "status": "ok",
    }


def test_source_to_sink_confirmed_requires_reachable_and_source_in_sink_arg(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch, reachable=True, source_in_sink=False)

    report = generate_analysis_report(_config())

    assert report["summary"]["source_to_sink_confirmed"] is False
    assert report["summary"]["status"] == "not_source_to_sink"


def test_custom_output_path_is_used(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch)
    output = tmp_path / "custom" / "report.json"

    report = generate_analysis_report(_config(), str(output))

    assert output.exists()
    assert report["report_path"] == str(output)


def test_failed_step_error_is_written_without_traceback(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch, raise_reachability=True)

    report = generate_analysis_report(_config())

    assert report["symbolic_reachability"]["error"].startswith(
        "failed to run symbolic reachability:"
    )
    assert report["summary"]["status"] == "error"
    written = json.loads((tmp_path / "reports" / "toy_report_analysis.json").read_text())
    assert written["symbolic_reachability"]["error"] == report["symbolic_reachability"]["error"]


def test_report_limits_sanitizer_candidate_constraints_to_first_three(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(
        monkeypatch,
        sanitizer_like=True,
        sanitizer_candidates=["c0", "c1", "c2", "c3"],
    )

    report = generate_analysis_report(_config())

    assert report["constraint_observation"]["sanitizer_candidate_constraints"] == [
        "c0",
        "c1",
        "c2",
    ]


def test_report_does_not_include_payload_poc_or_input_samples(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _install_fake_analysis(monkeypatch)

    report = generate_analysis_report(_config())
    serialized = json.dumps(report)

    assert "payload" not in serialized.lower()
    assert "poc" not in serialized.lower()
    assert "solver.eval" not in serialized


def _config() -> TargetConfig:
    return TargetConfig(
        name="toy_report",
        binary="datasets/toy_cgi/build/toy_report",
        arch="auto",
        http_method="GET",
        http_path="/cgi-bin/ping",
        params={"ip": {"source": True, "max_len": 32}},
        source_params=[],
        vulnerability_type="command_path_observation",
        sinks=["system", "snprintf"],
        dry_run=True,
    )


def _install_fake_analysis(
    monkeypatch,
    *,
    reachable: bool = True,
    source_in_sink: bool = True,
    sanitizer_like: bool = False,
    sanitizer_candidates: list[str] | None = None,
    raise_reachability: bool = False,
) -> None:
    import ns_aeg.reporting as reporting

    def fake_load_with_angr(binary, sinks):
        return SimpleNamespace(
            loaded=True,
            arch="AMD64",
            bits=64,
            entry="0x401080",
            base_addr="0x400000",
            main_object="toy_report",
            plt={"system": "0x401050"},
            missing_plt=["snprintf"],
            error=None,
        )

    def fake_symbolic_reach_sink(binary, sinks, source_model):
        if raise_reachability:
            raise RuntimeError("boom")
        return SimpleNamespace(
            created=True,
            reachable=reachable,
            source_name="ip",
            symbolic_var="sym_ip",
            runtime_binding="argv[1]",
            input_constraints=["first 4 symbolic bytes are non-null"],
            target_sink="system",
            target_addr="0x401050",
            sink_arg_symbolic=True,
            source_var_in_sink_arg=source_in_sink,
            sink_arg_variables=["sym_ip_0_248"],
            error=None if reachable else "target sink was not reached",
        )

    def fake_observe_constraints_to_sink(binary, sinks, source_model):
        candidates = sanitizer_candidates or (["sym_ip[7:0] != 0x3b"] if sanitizer_like else [])
        return SimpleNamespace(
            created=True,
            reachable=reachable,
            source_name="ip",
            symbolic_var="sym_ip",
            runtime_binding="argv[1]",
            target_sink="system",
            target_addr="0x401050",
            total_constraints=5,
            source_related_count=len(candidates) + 2,
            string_modeling_count=0,
            input_modeling_count=2,
            input_modeling_constraints=[
                "<Bool !(sym_ip_0_248[247:240] == 0)>",
                "<Bool !(sym_ip_0_248[239:232] == 0)>",
            ],
            branch_condition_count=2,
            branch_condition_constraints=[
                "<Bool sym_ip_0_248[247:240] == 65>",
                "<Bool sym_ip_0_248[239:232] == 66>",
            ],
            sanitizer_candidate_count=len(candidates),
            unknown_source_count=0,
            sanitizer_like_observed=bool(candidates),
            input_constraints=["first 4 symbolic bytes are non-null"],
            sanitizer_candidate_constraints=candidates,
            error=None,
        )

    monkeypatch.setattr(reporting, "load_with_angr", fake_load_with_angr)
    monkeypatch.setattr(reporting, "symbolic_reach_sink", fake_symbolic_reach_sink)
    monkeypatch.setattr(
        reporting,
        "observe_constraints_to_sink",
        fake_observe_constraints_to_sink,
    )
