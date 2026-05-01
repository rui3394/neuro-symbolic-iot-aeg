import builtins
import sys
from types import SimpleNamespace

from ns_aeg.argv_state import create_symbolic_argv_state
from ns_aeg.source_model import SourceModel, SourceSpec


def test_missing_binary_returns_created_false(tmp_path) -> None:
    info = create_symbolic_argv_state(str(tmp_path / "missing"), _source_model(["ip"]))

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

    info = create_symbolic_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is False
    assert info.error == "angr is not installed"


def test_missing_claripy_returns_clear_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setitem(sys.modules, "angr", SimpleNamespace(Project=lambda *a, **k: None))
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "claripy":
            raise ImportError("no claripy")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    info = create_symbolic_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is False
    assert info.error == "claripy is not installed"


def test_symbolic_ip_maps_to_argv_1(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls)

    info = create_symbolic_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is True
    assert info.argv == [str(binary), "sym_ip"]
    assert info.source_bindings == {"ip": "argv[1]"}
    assert info.symbolic is True
    assert info.symbolic_vars["ip"] == "sym_ip"
    assert info.symbolic_sizes["ip"] == 64
    assert "sym_ip is null-terminated" in info.constraints
    assert calls["bvs"] == [("sym_ip", 504)]
    assert calls["bvv"] == [(0, 8)]
    assert calls["full_init_args"] == [
        str(binary),
        "concat(BVS(sym_ip,504),BVV(0,8))",
    ]


def test_max_len_less_than_or_equal_to_one_returns_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls)

    info = create_symbolic_argv_state(str(binary), _source_model(["ip"], max_len=1))

    assert info.created is False
    assert info.error == "source max_len must be greater than 1: ip"
    assert "project_args" not in calls


def test_multiple_sources_map_to_configured_argv_slots(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls)

    info = create_symbolic_argv_state(str(binary), _source_model(["ip", "host"]))

    assert info.created is True
    assert info.argv == [str(binary), "sym_ip", "sym_host"]
    assert info.source_bindings == {"ip": "argv[1]", "host": "argv[2]"}
    assert info.symbolic_vars == {"ip": "sym_ip", "host": "sym_host"}
    assert info.symbolic_sizes == {"ip": 64, "host": 64}
    assert calls["full_init_args"] == [
        str(binary),
        "concat(BVS(sym_ip,504),BVV(0,8))",
        "concat(BVS(sym_host,504),BVV(0,8))",
    ]


def test_unsupported_runtime_binding_returns_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls)
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

    info = create_symbolic_argv_state(str(binary), source_model)

    assert info.created is False
    assert info.error == "unsupported runtime binding: env[IP]"
    assert "project_args" not in calls


def test_does_not_create_simulation_manager_or_enable_unicorn(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls)

    info = create_symbolic_argv_state(str(binary), _source_model(["ip"]))

    assert info.created is True
    assert "simgr_called" not in calls
    assert "unicorn_accessed" not in calls


def _source_model(names: list[str], max_len: int = 64) -> SourceModel:
    return SourceModel(
        sources=[
            SourceSpec(
                name=name,
                source_type="http_param",
                max_len=max_len,
                symbolic_name=f"sym_{name}",
                runtime_binding=f"argv[{index}]",
                required=True,
            )
            for index, name in enumerate(names, start=1)
        ]
    )


def _install_fake_angr_and_claripy(monkeypatch, calls: dict[str, object]) -> None:
    class FakeAst:
        def __init__(self, text: str):
            self.text = text

        def concat(self, other):
            return FakeAst(f"concat({self.text},{other.text})")

        def __repr__(self) -> str:
            return self.text

        def __eq__(self, other) -> bool:
            return self.text == other

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

    class FakeClaripy:
        @staticmethod
        def BVS(name, bits):
            calls.setdefault("bvs", []).append((name, bits))
            return FakeAst(f"BVS({name},{bits})")

        @staticmethod
        def BVV(value, bits):
            calls.setdefault("bvv", []).append((value, bits))
            return FakeAst(f"BVV({value},{bits})")

    monkeypatch.setitem(sys.modules, "angr", FakeAngr())
    monkeypatch.setitem(sys.modules, "claripy", FakeClaripy())
