from typing import Any

from ns_aeg.config import TargetConfig, load_target_config
from ns_aeg.source_model import build_source_model


def test_builds_source_from_toy_config() -> None:
    config = load_target_config("configs/toy_01.yaml")

    model = build_source_model(config)
    source = model.sources[0]

    assert source.name == "ip"
    assert source.source_type == "http_param"
    assert source.max_len == 64
    assert source.runtime_binding == "argv[1]"
    assert source.symbolic_name == "sym_ip"
    assert source.required is True


def test_no_source_params_returns_empty_model() -> None:
    config = _config({"ip": {"source": False, "max_len": 32}})

    model = build_source_model(config)

    assert model.sources == []


def test_missing_max_len_defaults_to_64() -> None:
    config = _config({"host": {"source": True}})

    model = build_source_model(config)

    assert model.sources[0].max_len == 64


def test_multiple_sources_map_to_argv_in_order() -> None:
    config = _config(
        {
            "ip": {"source": True, "max_len": 64},
            "host": {"source": True, "max_len": 32},
        }
    )

    model = build_source_model(config)

    assert [source.name for source in model.sources] == ["ip", "host"]
    assert [source.runtime_binding for source in model.sources] == ["argv[1]", "argv[2]"]


def test_illegal_param_chars_are_sanitized_in_symbolic_name() -> None:
    config = _config({"ip-address!": {"source": True, "max_len": 64}})

    model = build_source_model(config)

    assert model.sources[0].symbolic_name == "sym_ip_address_"
    assert model.sources[0].symbolic_name.replace("_", "").isalnum()


def _config(params: dict[str, Any]) -> TargetConfig:
    return TargetConfig(
        name="test",
        binary="dummy",
        arch="auto",
        http_method="GET",
        http_path="/cgi-bin/test",
        params=params,
        source_params=[],
        vulnerability_type="command_injection",
        sinks=["system"],
        dry_run=True,
    )
