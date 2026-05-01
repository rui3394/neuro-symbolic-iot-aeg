from pathlib import Path

import pytest
import yaml

from ns_aeg.config import load_target_config


def test_loads_toy_config() -> None:
    config = load_target_config("configs/toy_01.yaml")

    assert config.binary == "datasets/toy_cgi/build/toy_01"


def test_reads_target_name() -> None:
    config = load_target_config("configs/toy_01.yaml")

    assert config.name == "toy_01_basic_cmd"


def test_reads_source_param_ip() -> None:
    config = load_target_config("configs/toy_01.yaml")

    assert config.source_params[0].name == "ip"
    assert config.source_params[0].max_len == 64


def test_loads_toy_02_config() -> None:
    config = load_target_config("configs/toy_02.yaml")

    assert config.name == "toy_02_filter_chars"
    assert config.binary == "datasets/toy_cgi/build/toy_02"
    assert config.source_params[0].name == "ip"
    assert config.source_params[0].max_len == 32
    assert config.sinks == ["system", "snprintf"]


def test_loads_toy_03_config() -> None:
    config = load_target_config("configs/toy_03.yaml")

    assert config.name == "toy_03_length_limit"
    assert config.binary == "datasets/toy_cgi/build/toy_03"
    assert config.source_params[0].name == "ip"
    assert config.source_params[0].max_len == 32
    assert config.sinks == ["system", "snprintf"]


def test_loads_toy_04_config() -> None:
    config = load_target_config("configs/toy_04.yaml")

    assert config.name == "toy_04_branch_check"
    assert config.binary == "datasets/toy_cgi/build/toy_04"
    assert config.source_params[0].name == "ip"
    assert config.source_params[0].max_len == 32
    assert config.sinks == ["system", "snprintf"]


def test_loads_toy_05_config() -> None:
    config = load_target_config("configs/toy_05.yaml")

    assert config.name == "toy_05_safe_case"
    assert config.binary == "datasets/toy_cgi/build/toy_05"
    assert config.source_params[0].name == "ip"
    assert config.source_params[0].max_len == 32
    assert config.sinks == ["system", "snprintf"]


def test_missing_sinks_raises_value_error(tmp_path: Path) -> None:
    raw_config = yaml.safe_load(Path("configs/toy_01.yaml").read_text(encoding="utf-8"))
    del raw_config["analysis"]["sinks"]
    broken_config = tmp_path / "missing_sinks.yaml"
    broken_config.write_text(yaml.safe_dump(raw_config), encoding="utf-8")

    with pytest.raises(ValueError, match="analysis.sinks"):
        load_target_config(str(broken_config))
