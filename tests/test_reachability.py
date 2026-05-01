import builtins
import sys
from types import SimpleNamespace

from ns_aeg.reachability import smoke_reach_sink


def test_missing_binary_returns_created_false(tmp_path) -> None:
    info = smoke_reach_sink(str(tmp_path / "missing"), ["system"])

    assert info.created is False
    assert info.reachable is False
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

    info = smoke_reach_sink(str(binary), ["system"])

    assert info.created is False
    assert info.error == "angr is not installed"


def test_no_available_plt_sink_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(monkeypatch, calls, plt={})

    info = smoke_reach_sink(str(binary), ["system", "snprintf"])

    assert info.created is True
    assert info.reachable is False
    assert info.error == "no configured sink PLT found"
    assert "full_init_args" not in calls


def test_sink_priority_is_system_then_popen_then_snprintf(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(
        monkeypatch,
        calls,
        plt={"snprintf": 0x401080, "popen": 0x401060, "system": 0x401050},
        active_sequences=[[0x401050]],
    )

    info = smoke_reach_sink(str(binary), ["snprintf", "system", "popen"])

    assert info.target_sink == "system"
    assert info.target_addr == "0x401050"
    assert info.reachable is True


def test_reachable_when_active_state_addr_matches_target(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(
        monkeypatch,
        calls,
        plt={"system@plt": 0x401050},
        active_sequences=[[0x400000], [0x401050]],
    )

    info = smoke_reach_sink(str(binary), ["system"])

    assert info.created is True
    assert info.reachable is True
    assert info.steps == 1
    assert info.found_states == 1
    assert calls["full_init_args"] == [str(binary), "127.0.0.1"]
    assert calls["state_args"] == [str(binary), "127.0.0.1"]
    assert "bvs_called" not in calls


def test_max_steps_without_reaching_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x400000], [0x400010], [0x400020]],
    )

    info = smoke_reach_sink(str(binary), ["system"], max_steps=2)

    assert info.created is True
    assert info.reachable is False
    assert info.steps == 2
    assert info.found_states == 0
    assert info.error == "target sink was not reached"


def test_argv_uses_binary_path_and_default_concrete_value(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(
        monkeypatch,
        calls,
        plt={"snprintf": 0x401080},
        active_sequences=[[0x401080]],
    )

    info = smoke_reach_sink(str(binary), ["snprintf"])

    assert info.argv == [str(binary), "127.0.0.1"]
    assert calls["full_init_args"] == [str(binary), "127.0.0.1"]
    assert info.input_mode == "concrete argv"


def test_does_not_enable_unicorn(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
    )

    info = smoke_reach_sink(str(binary), ["system"])

    assert info.reachable is True
    assert "unicorn_accessed" not in calls


def _install_fake_angr(
    monkeypatch,
    calls: dict[str, object],
    *,
    plt: dict[str, int],
    active_sequences: list[list[int]] | None = None,
) -> None:
    active_sequences = active_sequences or [[]]

    class FakeSimgr:
        def __init__(self):
            self.step_index = 0

        @property
        def active(self):
            index = min(self.step_index, len(active_sequences) - 1)
            return [SimpleNamespace(addr=addr) for addr in active_sequences[index]]

        def step(self):
            calls["steps"] = calls.get("steps", 0) + 1
            self.step_index += 1
            return self

    class FakeFactory:
        def full_init_state(self, args):
            calls["full_init_args"] = list(args)
            for arg in args:
                if not isinstance(arg, str):
                    calls["symbolic_arg_seen"] = True
            return SimpleNamespace(args=list(args))

        def simulation_manager(self, state):
            calls["state_args"] = state.args
            return FakeSimgr()

    class FakeProject:
        def __init__(self, path, auto_load_libs=False):
            calls["project_args"] = (path, auto_load_libs)
            self.loader = SimpleNamespace(main_object=SimpleNamespace(plt=plt))
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

    class FakeClaripy:
        @staticmethod
        def BVS(*args, **kwargs):
            calls["bvs_called"] = True
            raise AssertionError("symbolic argv must not be used")

    monkeypatch.setitem(sys.modules, "angr", FakeAngr())
    monkeypatch.setitem(sys.modules, "claripy", FakeClaripy())
