import json
import sys

from ns_aeg.batch_reporting import generate_batch_summary


def test_generate_batch_summary_handles_multiple_configs(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_a = _write_config(tmp_path, "a.yaml", "toy_a", "build/a")
    config_b = _write_config(tmp_path, "b.yaml", "toy_b", "build/b")
    _install_fake_reporter(monkeypatch, sanitizer_by_name={"toy_b": True})

    summary = generate_batch_summary([str(config_a), str(config_b)])

    assert summary["total_targets"] == 2
    assert summary["ok_targets"] == 2
    assert summary["source_to_sink_confirmed_count"] == 2
    assert summary["sanitizer_like_observed_count"] == 1
    assert summary["error_count"] == 0
    assert [target["name"] for target in summary["targets"]] == ["toy_a", "toy_b"]


def test_summary_json_is_written_to_default_path(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = _write_config(tmp_path, "toy.yaml", "toy", "build/toy")
    _install_fake_reporter(monkeypatch)

    generate_batch_summary([str(config)])
    output = tmp_path / "reports" / "summary.json"

    assert output.exists()
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["total_targets"] == 1
    assert written["targets"][0]["report_path"] == "reports/toy_analysis.json"


def test_custom_summary_output_path_is_supported(tmp_path, monkeypatch) -> None:
    config = _write_config(tmp_path, "toy.yaml", "toy", "build/toy")
    _install_fake_reporter(monkeypatch)
    output = tmp_path / "custom" / "summary.json"

    summary = generate_batch_summary([str(config)], str(output))

    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == summary


def test_failed_target_does_not_interrupt_batch(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    ok_config = _write_config(tmp_path, "ok.yaml", "ok_target", "build/ok")
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("name: bad\n", encoding="utf-8")
    _install_fake_reporter(monkeypatch)

    summary = generate_batch_summary([str(ok_config), str(bad_config)])

    assert summary["total_targets"] == 2
    assert summary["ok_targets"] == 1
    assert summary["error_count"] == 1
    failed = summary["targets"][1]
    assert failed["name"] == "bad"
    assert failed["status"] == "error"
    assert "error" in failed


def test_reporter_exception_marks_target_error(tmp_path, monkeypatch) -> None:
    config = _write_config(tmp_path, "toy.yaml", "toy", "build/toy")
    _install_fake_reporter(monkeypatch, raise_for={"toy"})

    summary = generate_batch_summary([str(config)], str(tmp_path / "summary.json"))

    assert summary["error_count"] == 1
    assert summary["targets"][0]["status"] == "error"
    assert "boom" in summary["targets"][0]["error"]


def test_batch_report_directory_is_expanded_by_filename_order(tmp_path, monkeypatch, capsys) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    z_config = _write_config(config_dir, "z.yaml", "toy_z", "build/z")
    a_config = _write_config(config_dir, "a.yaml", "toy_a", "build/a")
    calls = {}

    import ns_aeg.cli as cli

    def fake_generate_batch_summary(config_paths, output_path):
        calls["config_paths"] = config_paths
        calls["output_path"] = output_path
        return {
            "total_targets": len(config_paths),
            "ok_targets": 2,
            "source_to_sink_confirmed_count": 2,
            "sanitizer_like_observed_count": 1,
            "error_count": 0,
            "targets": [],
        }

    monkeypatch.setattr(cli, "generate_batch_summary", fake_generate_batch_summary)
    monkeypatch.setattr(
        sys,
        "argv",
        ["ns-aeg", "--batch-report", str(config_dir)],
    )

    cli.main()

    assert calls["config_paths"] == [str(a_config), str(z_config)]
    assert calls["output_path"] == "reports/summary.json"
    assert "[+] Batch summary written." in capsys.readouterr().out


def test_batch_report_configs_directory_includes_toy_05(monkeypatch) -> None:
    calls = {}

    import ns_aeg.cli as cli

    def fake_generate_batch_summary(config_paths, output_path):
        calls["config_paths"] = config_paths
        calls["output_path"] = output_path
        return {
            "total_targets": len(config_paths),
            "ok_targets": 4,
            "source_to_sink_confirmed_count": 4,
            "sanitizer_like_observed_count": 2,
            "error_count": 0,
            "targets": [],
        }

    monkeypatch.setattr(cli, "generate_batch_summary", fake_generate_batch_summary)
    monkeypatch.setattr(sys, "argv", ["ns-aeg", "--batch-report", "configs/"])

    cli.main()

    assert "configs/toy_05.yaml" in calls["config_paths"]
    assert calls["config_paths"] == sorted(calls["config_paths"])


def test_batch_summary_expected_toy_sanitizer_counts(monkeypatch) -> None:
    _install_fake_reporter(
        monkeypatch,
        sanitizer_by_name={
            "toy_01_basic_cmd": False,
            "toy_02_filter_chars": True,
            "toy_03_length_limit": True,
            "toy_04_branch_check": False,
            "toy_05_safe_case": False,
        },
        source_to_sink_by_name={"toy_05_safe_case": False},
        status_by_name={"toy_05_safe_case": "not_source_to_sink"},
    )

    summary = generate_batch_summary(
        [
            "configs/toy_01.yaml",
            "configs/toy_02.yaml",
            "configs/toy_03.yaml",
            "configs/toy_04.yaml",
            "configs/toy_05.yaml",
        ]
    )

    assert summary["total_targets"] == 5
    assert summary["source_to_sink_confirmed_count"] == 4
    assert summary["sanitizer_like_observed_count"] == 2
    assert summary["error_count"] == 0
    assert [
        target["sanitizer_like_observed"] for target in summary["targets"]
    ] == [False, True, True, False, False]
    assert summary["targets"][-1]["source_to_sink_confirmed"] is False
    assert summary["targets"][-1]["status"] == "not_source_to_sink"


def test_batch_report_custom_summary_output_is_passed_to_cli(tmp_path, monkeypatch) -> None:
    config = _write_config(tmp_path, "toy.yaml", "toy", "build/toy")
    output = tmp_path / "summary.json"
    calls = {}

    import ns_aeg.cli as cli

    def fake_generate_batch_summary(config_paths, output_path):
        calls["config_paths"] = config_paths
        calls["output_path"] = output_path
        return {
            "total_targets": 1,
            "ok_targets": 1,
            "source_to_sink_confirmed_count": 1,
            "sanitizer_like_observed_count": 0,
            "error_count": 0,
            "targets": [],
        }

    monkeypatch.setattr(cli, "generate_batch_summary", fake_generate_batch_summary)
    monkeypatch.setattr(
        sys,
        "argv",
        ["ns-aeg", "--batch-report", str(config), "--summary-output", str(output)],
    )

    cli.main()

    assert calls["config_paths"] == [str(config)]
    assert calls["output_path"] == str(output)


def test_batch_summary_does_not_include_payload_poc_or_input_samples(
    tmp_path,
    monkeypatch,
) -> None:
    config = _write_config(tmp_path, "toy.yaml", "toy", "build/toy")
    _install_fake_reporter(monkeypatch)

    summary = generate_batch_summary([str(config)], str(tmp_path / "summary.json"))
    serialized = json.dumps(summary)

    assert "payload" not in serialized.lower()
    assert "poc" not in serialized.lower()
    assert "solver.eval" not in serialized


def _write_config(directory, filename: str, name: str, binary: str):
    path = directory / filename
    path.write_text(
        "\n".join(
            [
                f"name: {name}",
                f"binary: {binary}",
                "arch: auto",
                "http:",
                "  method: GET",
                "  path: /cgi-bin/ping",
                "  params:",
                "    ip:",
                "      source: true",
                "      max_len: 32",
                "analysis:",
                "  vulnerability_type: command_path_observation",
                "  sinks:",
                "    - system",
                "mode:",
                "  dry_run: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _install_fake_reporter(
    monkeypatch,
    *,
    sanitizer_by_name: dict[str, bool] | None = None,
    source_to_sink_by_name: dict[str, bool] | None = None,
    status_by_name: dict[str, str] | None = None,
    raise_for: set[str] | None = None,
) -> None:
    import ns_aeg.batch_reporting as batch_reporting

    sanitizer_by_name = sanitizer_by_name or {}
    source_to_sink_by_name = source_to_sink_by_name or {}
    status_by_name = status_by_name or {}
    raise_for = raise_for or set()

    def fake_generate_analysis_report(config):
        if config.name in raise_for:
            raise RuntimeError(f"boom for {config.name}")
        sanitizer_like = sanitizer_by_name.get(config.name, False)
        source_to_sink = source_to_sink_by_name.get(config.name, True)
        return {
            "report_path": f"reports/{config.name}_analysis.json",
            "target": {
                "name": config.name,
                "binary": config.binary,
            },
            "summary": {
                "source_to_sink_confirmed": source_to_sink,
                "sanitizer_like_observed": sanitizer_like,
                "status": status_by_name.get(config.name, "ok"),
            },
        }

    monkeypatch.setattr(
        batch_reporting,
        "generate_analysis_report",
        fake_generate_analysis_report,
    )
