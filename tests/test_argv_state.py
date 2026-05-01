import builtins
import sys
from types import SimpleNamespace

from ns_aeg.argv_state import create_argv_state
from ns_aeg.source_model import SourceModel, SourceSpec


def test_missing_binary_returns_created_false(tmp_path) -> None:
    info = create_argv_state(str(tmp_path / "missing"), _source_model(["ip"]))

    assert info.created is False
    assert "does not exist" in (info.error or "")


def test_missing_angr_returns_clear_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "angr":
            raise ImportError("no angr")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    info = create_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is False
    assert info.error == "angr is not installed"
    assert info.argv == [str(binary), "127.0.0.1"]


def test_default_ip_value_is_used_for_argv_1(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls)

    info = create_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is True
    assert info.argv == [str(binary), "127.0.0.1"]
    assert calls["project_args"] == (str(binary), False)
    assert calls["full_init_args"] == [str(binary), "127.0.0.1"]
    assert "simgr_called" not in calls
    assert "unicorn_accessed" not in calls


def test_concrete_value_overrides_default(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls)

    info = create_argv_state(
        str(binary),
        _source_model(["ip"]),
        concrete_values={"ip": "1.2.3.4"},
    )

    assert info.created is True
    assert info.argv == [str(binary), "1.2.3.4"]
    assert calls["full_init_args"] == [str(binary), "1.2.3.4"]


def test_multiple_sources_map_to_argv_in_order(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls)

    info = create_argv_state(
        str(binary),
        _source_model(["ip", "host"]),
        concrete_values={"ip": "1.2.3.4", "host": "example.test"},
    )

    assert info.created is True
    assert info.argv == [str(binary), "1.2.3.4", "example.test"]
    assert info.source_bindings == {"ip": "argv[1]", "host": "argv[2]"}


def test_unsupported_runtime_binding_returns_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls)
    source_model = SourceModel(
        sources=[
            SourceSpec(
                name="ip",
                source_type="http_param",
                max_len=64,
                symbolic_name="sym_ip",
                runtime_binding="env[IP]",
                required=True,
            )
        ]
    )

    info = create_argv_state(str(binary), source_model)

    assert info.created is False
    assert info.error == "unsupported runtime binding: env[IP]"
    assert "project_args" not in calls


def test_does_not_create_simulation_manager_or_enable_unicorn(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls)

    info = create_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is True
    assert "simgr_called" not in calls
    assert "unicorn_accessed" not in calls


def _source_model(names: list[str]) -> SourceModel:
    return SourceModel(
        sources=[
            SourceSpec(
                name=name,
                source_type="http_param",
                max_len=64,
                symbolic_name=f"sym_{name}",
                runtime_binding=f"argv[{index}]",
                required=True,
            )
            for index, name in enumerate(names, start=1)
        ]
    )


def _install_fake_angr(monkeypatch, calls: dict[str, object]) -> None:
    class FakeFactory:
        def full_init_state(self, args):
            calls["full_init_args"] = list(args)
            return SimpleNamespace(kind="state")

        def simgr(self, *args, **kwargs):
            calls["simgr_called"] = True
            raise AssertionError("SimulationManager must not be created")

    class FakeProject:
        def __init__(self, path, auto_load_libs=False):
            calls["project_args"] = (path, auto_load_libs)
            self.factory = FakeFactory()

    class FakeOptions:
        def __getattr__(self, name):
            if name == "UNICORN":
                calls["unicorn_accessed"] = True
                raise AssertionError("UNICORN must not be accessed")
            raise AttributeError(name)

    class FakeAngr:
        options = FakeOptions()

        @staticmethod
        def Project(path, auto_load_libs=False):
            return FakeProject(path, auto_load_libs=auto_load_libs)

        def __getattr__(self, name):
            if name == "SimulationManager":
                calls["simgr_called"] = True
                raise AssertionError("SimulationManager must not be created")
            raise AttributeError(name)

    monkeypatch.setitem(sys.modules, "angr", FakeAngr())
