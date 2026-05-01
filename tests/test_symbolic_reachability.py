import builtins
import sys
from types import SimpleNamespace

from ns_aeg.reachability import symbolic_reach_sink, variable_matches_symbolic_name
from ns_aeg.source_model import SourceModel, SourceSpec


def test_variable_matches_symbolic_name_exact_and_suffixed() -> None:
    assert variable_matches_symbolic_name("sym_ip", "sym_ip") is True
    assert variable_matches_symbolic_name("sym_ip_0_504", "sym_ip") is True
    assert variable_matches_symbolic_name("sym_ip_extra", "sym_ip") is True
    assert variable_matches_symbolic_name("other_sym_ip_0_504", "sym_ip") is False


def test_missing_binary_returns_created_false(tmp_path) -> None:
    info = symbolic_reach_sink(str(tmp_path / "missing"), ["system"], _source_model())

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

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

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

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.created is False
    assert info.error == "claripy is not installed"


def test_no_source_returns_clear_error(tmp_path) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")

    info = symbolic_reach_sink(str(binary), ["system"], SourceModel(sources=[]))

    assert info.created is False
    assert info.reachable is False
    assert info.error == "no source configured"


def test_no_available_plt_sink_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls, plt={})

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.created is True
    assert info.reachable is False
    assert info.error == "no configured sink PLT found"
    assert "full_init_args" not in calls


def test_sink_priority_is_system_then_popen_then_snprintf(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"snprintf": 0x401080, "popen": 0x401060, "system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip"},
    )

    info = symbolic_reach_sink(str(binary), ["snprintf", "system", "popen"], _source_model())

    assert info.target_sink == "system"
    assert info.target_addr == "0x401050"
    assert info.reachable is True


def test_max_len_less_than_or_equal_to_one_returns_error(tmp_path) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")

    info = symbolic_reach_sink(str(binary), ["system"], _source_model(max_len=1))

    assert info.created is False
    assert info.error == "source max_len must be greater than 1: ip"


def test_non_argv_runtime_binding_returns_error(tmp_path) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
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

    info = symbolic_reach_sink(str(binary), ["system"], source_model)

    assert info.created is False
    assert info.error == "unsupported runtime binding: env[IP]"


def test_reachable_and_source_var_in_sink_arg(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system@plt": 0x401050},
        active_sequences=[[0x400000], [0x401050]],
        variables={"sym_ip"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.created is True
    assert info.reachable is True
    assert info.steps == 1
    assert info.found_states == 1
    assert info.source_name == "ip"
    assert info.symbolic_var == "sym_ip"
    assert info.runtime_binding == "argv[1]"
    assert info.sink_arg_register == "rdi"
    assert info.sink_arg_symbolic is True
    assert info.source_var_in_sink_arg is True
    assert info.sink_arg_variables == ["sym_ip"]
    assert calls["bvs"] == [("sym_ip", 504)]
    assert calls["bvv"] == [(0, 8)]
    assert calls["solver_add"] == [
        "BVS(sym_ip,504)[503:496] != 0",
        "BVS(sym_ip,504)[495:488] != 0",
        "BVS(sym_ip,504)[487:480] != 0",
        "BVS(sym_ip,504)[479:472] != 0",
    ]
    assert calls["full_init_args"] == [
        str(binary),
        "concat(BVS(sym_ip,504),BVV(0,8))",
    ]
    assert calls["memory_load"] == [("rdi_ptr", 128)]
    assert "solver_eval_called" not in calls


def test_source_var_not_in_sink_arg_returns_false(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"other_sym"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.sink_arg_symbolic is True
    assert info.source_var_in_sink_arg is False
    assert info.sink_arg_variables == ["other_sym"]


def test_suffixed_source_var_in_sink_arg_returns_true(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip_0_504"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.sink_arg_variables == ["sym_ip_0_504"]
    assert info.source_var_in_sink_arg is True


def test_unrelated_suffixed_var_in_sink_arg_returns_false(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"other_0_64"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.sink_arg_variables == ["other_0_64"]
    assert info.source_var_in_sink_arg is False


def test_max_steps_without_reaching_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x400000], [0x400010], [0x400020]],
        variables={"sym_ip"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model(), max_steps=2)

    assert info.created is True
    assert info.reachable is False
    assert info.steps == 2
    assert info.error == "target sink was not reached"


def test_multiple_argv_slots_fill_missing_with_empty_string(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip"},
    )
    source_model = SourceModel(
        sources=[
            SourceSpec(
                name="ip",
                source_type="http_param",
                max_len=64,
                symbolic_name="sym_ip",
                runtime_binding="argv[3]",
                required=True,
            )
        ]
    )

    info = symbolic_reach_sink(str(binary), ["system"], source_model)

    assert info.reachable is True
    assert calls["full_init_args"] == [
        str(binary),
        "",
        "",
        "concat(BVS(sym_ip,504),BVV(0,8))",
    ]


def test_does_not_enable_unicorn(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert "unicorn_accessed" not in calls


def test_unsupported_arch_reports_argument_inspection_error(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip"},
        arch_name="ARMEL",
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.source_var_in_sink_arg is False
    assert info.error == "unsupported arch for sink argument inspection: ARMEL"


def test_non_null_prefix_constraints_respect_small_max_len(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        variables={"sym_ip"},
    )

    info = symbolic_reach_sink(str(binary), ["system"], _source_model(max_len=3))

    assert info.input_constraints == ["first 2 symbolic bytes are non-null"]
    assert calls["solver_add"] == [
        "BVS(sym_ip,16)[15:8] != 0",
        "BVS(sym_ip,16)[7:0] != 0",
    ]


def _source_model(max_len: int = 64) -> SourceModel:
    return SourceModel(
        sources=[
            SourceSpec(
                name="ip",
                source_type="http_param",
                max_len=max_len,
                symbolic_name="sym_ip",
                runtime_binding="argv[1]",
                required=True,
            )
        ]
    )


def _install_fake_angr_and_claripy(
    monkeypatch,
    calls: dict[str, object],
    *,
    plt: dict[str, int],
    active_sequences: list[list[int]] | None = None,
    variables: set[str] | None = None,
    arch_name: str = "AMD64",
) -> None:
    active_sequences = active_sequences or [[]]
    variables = variables or set()

    class FakeAst:
        def __init__(self, text: str, ast_variables: set[str] | None = None):
            self.text = text
            self.variables = ast_variables or set()

        def __getitem__(self, key):
            return FakeAst(f"{self.text}[{key.start}:{key.stop}]", set(self.variables))

        def __ne__(self, other) -> str:
            return f"{self.text} != {other}"

        def concat(self, other):
            return FakeAst(f"concat({self.text},{other.text})", set(self.variables))

        def __repr__(self) -> str:
            return self.text

        def __eq__(self, other) -> bool:
            return self.text == other

    class FakeMemory:
        def load(self, ptr, size):
            calls.setdefault("memory_load", []).append((ptr, size))
            return FakeAst("cmd_expr", set(variables))

    class FakeSolver:
        def add(self, constraint):
            calls.setdefault("solver_add", []).append(constraint)

        def symbolic(self, expr):
            calls["solver_symbolic"] = expr
            return bool(getattr(expr, "variables", set()))

        def eval(self, *args, **kwargs):
            calls["solver_eval_called"] = True
            raise AssertionError("solver.eval must not be called")

    class FakeState:
        def __init__(self, addr):
            self.addr = addr
            self.regs = SimpleNamespace(rdi="rdi_ptr")
            self.memory = FakeMemory()
            self.solver = FakeSolver()

    class FakeSimgr:
        def __init__(self):
            self.step_index = 0

        @property
        def active(self):
            index = min(self.step_index, len(active_sequences) - 1)
            return [FakeState(addr) for addr in active_sequences[index]]

        def step(self):
            calls["steps"] = calls.get("steps", 0) + 1
            self.step_index += 1
            return self

    class FakeFactory:
        def full_init_state(self, args):
            calls["full_init_args"] = list(args)
            return SimpleNamespace(args=list(args), solver=FakeSolver())

        def simulation_manager(self, state):
            calls["state_args"] = state.args
            return FakeSimgr()

    class FakeProject:
        def __init__(self, path, auto_load_libs=False):
            calls["project_args"] = (path, auto_load_libs)
            self.arch = SimpleNamespace(name=arch_name)
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
        def BVS(name, bits):
            calls.setdefault("bvs", []).append((name, bits))
            return FakeAst(f"BVS({name},{bits})", {name})

        @staticmethod
        def BVV(value, bits):
            calls.setdefault("bvv", []).append((value, bits))
            return FakeAst(f"BVV({value},{bits})")

    monkeypatch.setitem(sys.modules, "angr", FakeAngr())
    monkeypatch.setitem(sys.modules, "claripy", FakeClaripy())
