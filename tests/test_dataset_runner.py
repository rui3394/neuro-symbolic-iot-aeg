import csv
import json
from pathlib import Path
import sys

from ns_aeg.dataset_runner import run_toy_dataset


def test_run_toy_dataset_scans_toy_yaml_and_ignores_non_toy(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    toy_a = _write_config(config_dir, "toy_a.yaml", "toy_a", "build/a")
    toy_b = _write_config(config_dir, "toy_b.yaml", "toy_b", "build/b")
    _write_config(config_dir, "other.yaml", "other", "build/other")
    calls: list[tuple[str, str]] = []
    _install_fake_reporter(monkeypatch, calls=calls)

    summary = run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(tmp_path / "reports"),
        summary_json=str(tmp_path / "reports" / "summary.json"),
        summary_md=str(tmp_path / "reports" / "summary.md"),
        summary_csv=str(tmp_path / "reports" / "summary.csv"),
    )

    assert summary["total_targets"] == 2
    assert [path for path, _output in calls] == [str(toy_a), str(toy_b)]


def test_run_toy_dataset_writes_summary_json_md_and_csv(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    _write_config(config_dir, "toy_a.yaml", "toy_a", "build/a")
    _install_fake_reporter(monkeypatch, sanitizer_by_name={"toy_a": True})
    reports_dir = tmp_path / "reports"

    summary = run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(reports_dir),
        summary_json=str(reports_dir / "summary.json"),
        summary_md=str(reports_dir / "summary.md"),
        summary_csv=str(reports_dir / "summary.csv"),
    )

    assert (reports_dir / "summary.json").exists()
    assert (reports_dir / "summary.md").exists()
    assert (reports_dir / "summary.csv").exists()
    assert json.loads((reports_dir / "summary.json").read_text()) == summary
    assert "toy_a" in (reports_dir / "summary.md").read_text(encoding="utf-8")
    csv_text = (reports_dir / "summary.csv").read_text(encoding="utf-8")
    assert "target,binary,source_to_sink_confirmed" in csv_text
    assert "branch_condition_count" in csv_text


def test_summary_md_contains_expected_table_fields(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    _write_config(config_dir, "toy_a.yaml", "toy_a", "build/a")
    _install_fake_reporter(monkeypatch, sanitizer_by_name={"toy_a": True})
    reports_dir = tmp_path / "reports"

    run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(reports_dir),
        summary_json=str(reports_dir / "summary.json"),
        summary_md=str(reports_dir / "summary.md"),
        summary_csv=str(reports_dir / "summary.csv"),
    )

    text = (reports_dir / "summary.md").read_text(encoding="utf-8")
    assert "| Target | Source-to-Sink | Sanitizer Observed |" in text
    assert "Branch Conditions" in text
    assert "| toy_a | yes | yes | 1 | 2 | 2 | ok |" in text


def test_summary_csv_contains_expected_rows(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    _write_config(config_dir, "toy_a.yaml", "toy_a", "build/a")
    _install_fake_reporter(monkeypatch, sanitizer_by_name={"toy_a": True})
    reports_dir = tmp_path / "reports"

    run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(reports_dir),
        summary_json=str(reports_dir / "summary.json"),
        summary_md=str(reports_dir / "summary.md"),
        summary_csv=str(reports_dir / "summary.csv"),
    )

    with (reports_dir / "summary.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert rows[0]["target"] == "toy_a"
    assert rows[0]["sanitizer_candidate_count"] == "1"
    assert rows[0]["input_modeling_count"] == "2"
    assert rows[0]["branch_condition_count"] == "2"


def test_failed_target_does_not_interrupt_runner(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    _write_config(config_dir, "toy_ok.yaml", "toy_ok", "build/ok")
    _write_config(config_dir, "toy_bad.yaml", "toy_bad", "build/bad")
    _install_fake_reporter(monkeypatch, raise_for={"toy_bad"})
    reports_dir = tmp_path / "reports"

    summary = run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(reports_dir),
        summary_json=str(reports_dir / "summary.json"),
        summary_md=str(reports_dir / "summary.md"),
        summary_csv=str(reports_dir / "summary.csv"),
    )

    assert summary["total_targets"] == 2
    assert summary["error_count"] == 1
    failed = [target for target in summary["targets"] if target["status"] == "error"][0]
    assert failed["name"] == "toy_bad"
    assert "boom" in failed["error"]


def test_runner_does_not_include_payload_poc_or_input_samples(tmp_path, monkeypatch) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    _write_config(config_dir, "toy_a.yaml", "toy_a", "build/a")
    _install_fake_reporter(monkeypatch)
    reports_dir = tmp_path / "reports"

    summary = run_toy_dataset(
        config_dir=str(config_dir),
        reports_dir=str(reports_dir),
        summary_json=str(reports_dir / "summary.json"),
        summary_md=str(reports_dir / "summary.md"),
        summary_csv=str(reports_dir / "summary.csv"),
    )
    serialized = json.dumps(summary) + (reports_dir / "summary.md").read_text()

    assert "payload" not in serialized.lower()
    assert "poc" not in serialized.lower()
    assert "solver.eval" not in serialized


def test_cli_run_toy_dataset_passes_paths(tmp_path, monkeypatch, capsys) -> None:
    calls = {}

    import ns_aeg.cli as cli

    def fake_run_toy_dataset(
        config_dir,
        reports_dir,
        summary_json,
        summary_md,
        summary_csv,
    ):
        calls["args"] = (config_dir, reports_dir, summary_json, summary_md, summary_csv)
        return {
            "total_targets": 3,
            "ok_targets": 3,
            "source_to_sink_confirmed_count": 3,
            "sanitizer_like_observed_count": 2,
            "error_count": 0,
            "targets": [],
        }

    monkeypatch.setattr(cli, "run_toy_dataset", fake_run_toy_dataset)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ns-aeg",
            "--run-toy-dataset",
            "configs/",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--summary-output",
            str(tmp_path / "summary.json"),
            "--summary-md",
            str(tmp_path / "summary.md"),
            "--summary-csv",
            str(tmp_path / "summary.csv"),
        ],
    )

    cli.main()

    assert calls["args"] == (
        "configs/",
        str(tmp_path / "reports"),
        str(tmp_path / "summary.json"),
        str(tmp_path / "summary.md"),
        str(tmp_path / "summary.csv"),
    )
    assert "[+] Toy dataset runner completed." in capsys.readouterr().out


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
    calls: list[tuple[str, str]] | None = None,
    sanitizer_by_name: dict[str, bool] | None = None,
    raise_for: set[str] | None = None,
) -> None:
    import ns_aeg.dataset_runner as dataset_runner

    sanitizer_by_name = sanitizer_by_name or {}
    raise_for = raise_for or set()

    def fake_generate_analysis_report(config, output_path=None):
        if calls is not None:
            calls.append((config.path if hasattr(config, "path") else "", output_path))
        if config.name in raise_for:
            raise RuntimeError(f"boom for {config.name}")
        sanitizer_like = sanitizer_by_name.get(config.name, False)
        report_path = output_path or f"reports/{config.name}_analysis.json"
        report = {
            "report_path": report_path,
            "target": {
                "name": config.name,
                "binary": config.binary,
            },
            "constraint_observation": {
                "sanitizer_candidate_count": 1 if sanitizer_like else 0,
                "input_modeling_count": 2,
                "branch_condition_count": 2,
            },
            "summary": {
                "source_to_sink_confirmed": True,
                "sanitizer_like_observed": sanitizer_like,
                "status": "ok",
            },
        }
        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report), encoding="utf-8")
        return report

    def fake_load_target_config(path):
        from ns_aeg.config import load_target_config

        config = load_target_config(path)
        object.__setattr__(config, "path", path)
        return config

    monkeypatch.setattr(dataset_runner, "generate_analysis_report", fake_generate_analysis_report)
    monkeypatch.setattr(dataset_runner, "load_target_config", fake_load_target_config)
