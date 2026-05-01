import builtins
import sys
from types import SimpleNamespace

from ns_aeg.constraint_observer import (
    classify_source_constraint_text,
    observe_constraints_to_sink,
)
from ns_aeg.source_model import SourceModel, SourceSpec


def test_null_terminator_byte_slices_classify_as_string_modeling() -> None:
    text = "sym_ip[31:24] == 0 || sym_ip[39:32] == 0 || sym_ip[47:40] == 0"

    assert classify_source_constraint_text(text, "sym_ip") == "string_modeling"


def test_nested_if_null_check_classifies_as_string_modeling() -> None:
    text = "if sym_ip[31:24] == 0 then 3 else if sym_ip[39:32] == 0 then 4 else 5"

    assert classify_source_constraint_text(text, "sym_ip") == "string_modeling"


def test_bad_char_semicolon_compare_classifies_as_sanitizer_candidate() -> None:
    text = "sym_ip[7:0] != 0x3b"

    assert classify_source_constraint_text(text, "sym_ip") == "sanitizer_candidate"


def test_bad_char_ampersand_compare_classifies_as_sanitizer_candidate() -> None:
    text = "sym_ip[15:8] != 0x26"

    assert classify_source_constraint_text(text, "sym_ip") == "sanitizer_candidate"


def test_non_null_prefix_negated_equality_classifies_as_input_modeling() -> None:
    text = "!(sym_ip_0_248[247:240] == 0)"

    assert classify_source_constraint_text(text, "sym_ip") == "input_modeling"


def test_non_null_prefix_inequality_classifies_as_input_modeling() -> None:
    text = "<Bool sym_ip_0_248[247:240] != 0>"

    assert classify_source_constraint_text(text, "sym_ip") == "input_modeling"


def test_branch_equal_decimal_classifies_as_branch_condition() -> None:
    assert (
        classify_source_constraint_text("<Bool sym_ip_0_248[247:240] == 65>", "sym_ip")
        == "branch_condition"
    )
    assert (
        classify_source_constraint_text("<Bool sym_ip_0_248[239:232] == 66>", "sym_ip")
        == "branch_condition"
    )


def test_branch_equal_hex_classifies_as_branch_condition() -> None:
    assert (
        classify_source_constraint_text("<Bool sym_ip_0_248[247:240] == 0x41>", "sym_ip")
        == "branch_condition"
    )
    assert (
        classify_source_constraint_text("<Bool sym_ip_0_248[239:232] == 0x42>", "sym_ip")
        == "branch_condition"
    )


def test_single_null_byte_check_classifies_as_unknown() -> None:
    text = "sym_ip_0_248[215:208] == 0"

    assert classify_source_constraint_text(text, "sym_ip") == "unknown"


def test_fixed_range_null_or_classifies_as_string_modeling() -> None:
    text = " || ".join(f"sym_ip[{index * 8 + 7}:{index * 8}] == 0" for index in range(16))

    assert classify_source_constraint_text(text, "sym_ip") == "string_modeling"


def test_unknown_source_constraint_classifies_as_unknown() -> None:
    text = "sym_ip[7:0] + sym_ip[15:8] == checksum"

    assert classify_source_constraint_text(text, "sym_ip") == "unknown"


def test_missing_binary_returns_created_false(tmp_path) -> None:
    info = observe_constraints_to_sink(str(tmp_path / "missing"), ["system"], _source_model())

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

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

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

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.created is False
    assert info.error == "claripy is not installed"


def test_no_source_returns_clear_error(tmp_path) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")

    info = observe_constraints_to_sink(str(binary), ["system"], SourceModel(sources=[]))

    assert info.created is False
    assert info.error == "no source configured"


def test_source_max_len_less_than_or_equal_to_one_returns_error(tmp_path) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(max_len=1))

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

    info = observe_constraints_to_sink(str(binary), ["system"], source_model)

    assert info.created is False
    assert info.error == "unsupported runtime binding: env[IP]"


def test_no_available_plt_sink_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(monkeypatch, calls, plt={}, constraints=[])

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

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
        constraints=[],
    )

    info = observe_constraints_to_sink(str(binary), ["snprintf", "system", "popen"], _source_model())

    assert info.reachable is True
    assert info.target_sink == "system"
    assert info.target_addr == "0x401050"


def test_max_steps_without_reaching_returns_not_reachable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x400000], [0x400010], [0x400020]],
        constraints=[],
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(), max_steps=2)

    assert info.created is True
    assert info.reachable is False
    assert info.steps == 2
    assert info.error == "target sink was not reached"


def test_source_related_unknown_constraints_do_not_imply_sanitizer(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("sym constraint", {"sym_ip_0_504"}),
        FakeConstraint("other constraint", {"other_0_64"}),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.total_constraints == 2
    assert info.source_related_count == 1
    assert info.source_related_constraints == ["sym constraint"]
    assert info.unknown_source_constraints == ["sym constraint"]
    assert info.unknown_source_count == 1
    assert info.sanitizer_candidate_count == 0
    assert info.input_modeling_count == 0
    assert info.branch_condition_count == 0
    assert info.source_related_count == (
        info.string_modeling_count
        + info.input_modeling_count
        + info.branch_condition_count
        + info.sanitizer_candidate_count
        + info.unknown_source_count
    )
    assert info.sanitizer_like_observed is False
    assert "solver_eval_called" not in calls


def test_non_source_constraints_are_ignored(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [FakeConstraint("other constraint", {"other_0_64"})]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert info.total_constraints == 1
    assert info.source_related_count == 0
    assert info.source_related_constraints == []
    assert info.sanitizer_like_observed is False


def test_long_constraint_is_truncated(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    long_text = "X" * 300
    constraints = [FakeConstraint(long_text, {"sym_ip_0_504"})]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(
        str(binary),
        ["system"],
        _source_model(),
        max_constraint_text_len=20,
    )

    assert info.source_related_count == 1
    assert info.source_related_constraints == ["XXXXXXXXXXXXXXXXXXXX...<truncated>"]


def test_sanitizer_candidate_constraint_sets_sanitizer_like(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [FakeConstraint("sym_ip[7:0] != 0x3b", {"sym_ip_0_504"})]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.source_related_count == 1
    assert info.sanitizer_candidate_constraints == ["sym_ip[7:0] != 0x3b"]
    assert info.sanitizer_candidate_count == 1
    assert info.sanitizer_like_observed is True
    assert info.input_constraints == ["first 4 symbolic bytes are non-null"]
    assert calls["solver_add"] == [
        "BVS(sym_ip,504)[503:496] != 0",
        "BVS(sym_ip,504)[495:488] != 0",
        "BVS(sym_ip,504)[487:480] != 0",
        "BVS(sym_ip,504)[479:472] != 0",
    ]


def test_only_string_modeling_constraints_do_not_set_sanitizer_like(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("sym_ip[31:24] == 0 || sym_ip[39:32] == 0", {"sym_ip_0_504"}),
        FakeConstraint(
            "if sym_ip[47:40] == 0 then 5 else if sym_ip[55:48] == 0 then 6",
            {"sym_ip_0_504"},
        ),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.source_related_count == 2
    assert info.string_modeling_count == 2
    assert info.sanitizer_candidate_count == 0
    assert info.input_modeling_count == 0
    assert info.branch_condition_count == 0
    assert info.unknown_source_count == 0
    assert info.source_related_count == (
        info.string_modeling_count
        + info.input_modeling_count
        + info.branch_condition_count
        + info.sanitizer_candidate_count
        + info.unknown_source_count
    )
    assert info.sanitizer_like_observed is False


def test_branch_condition_constraints_do_not_set_sanitizer_like(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("<Bool sym_ip_0_248[247:240] == 65>", {"sym_ip_0_248"}),
        FakeConstraint("<Bool sym_ip_0_248[239:232] == 66>", {"sym_ip_0_248"}),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(max_len=32))

    assert info.source_related_count == 2
    assert info.branch_condition_constraints == [
        "<Bool sym_ip_0_248[247:240] == 65>",
        "<Bool sym_ip_0_248[239:232] == 66>",
    ]
    assert info.branch_condition_count == 2
    assert info.sanitizer_candidate_count == 0
    assert info.sanitizer_like_observed is False


def test_input_modeling_constraints_do_not_set_sanitizer_like(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("<Bool !(sym_ip_0_248[247:240] == 0)>", {"sym_ip_0_248"}),
        FakeConstraint("<Bool sym_ip_0_248[239:232] != 0>", {"sym_ip_0_248"}),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(max_len=32))

    assert info.source_related_count == 2
    assert info.input_modeling_constraints == [
        "<Bool !(sym_ip_0_248[247:240] == 0)>",
        "<Bool sym_ip_0_248[239:232] != 0>",
    ]
    assert info.input_modeling_count == 2
    assert info.sanitizer_candidate_count == 0
    assert info.unknown_source_count == 0
    assert info.sanitizer_like_observed is False


def test_length_check_constraint_sets_sanitizer_like(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("<Bool !(sym_ip_0_248[247:240] == 0)>", {"sym_ip_0_248"}),
        FakeConstraint("<Bool sym_ip_0_248[215:208] == 0>", {"sym_ip_0_248"}),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(max_len=32))

    assert info.source_related_count == 2
    assert info.input_modeling_count == 1
    assert info.sanitizer_candidate_constraints == [
        "<Bool sym_ip_0_248[215:208] == 0>"
    ]
    assert info.sanitizer_candidate_count == 1
    assert info.unknown_source_count == 0
    assert info.sanitizer_like_observed is True


def test_string_modeling_prevents_null_byte_length_check_promotion(
    tmp_path,
    monkeypatch,
) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    constraints = [
        FakeConstraint("<Bool !(sym_ip_0_504[503:496] == 0)>", {"sym_ip_0_504"}),
        FakeConstraint("sym_ip_0_504[31:24] == 0 || sym_ip_0_504[39:32] == 0", {"sym_ip_0_504"}),
        FakeConstraint("<Bool sym_ip_0_504[215:208] == 0>", {"sym_ip_0_504"}),
    ]
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=constraints,
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.input_modeling_count == 1
    assert info.string_modeling_count == 1
    assert info.sanitizer_candidate_count == 0
    assert info.unknown_source_constraints == ["<Bool sym_ip_0_504[215:208] == 0>"]
    assert info.sanitizer_like_observed is False


def test_does_not_enable_unicorn(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=[],
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model())

    assert info.reachable is True
    assert "unicorn_accessed" not in calls


def test_non_null_prefix_constraints_respect_small_max_len(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    calls: dict[str, object] = {}
    _install_fake_angr_and_claripy(
        monkeypatch,
        calls,
        plt={"system": 0x401050},
        active_sequences=[[0x401050]],
        constraints=[],
    )

    info = observe_constraints_to_sink(str(binary), ["system"], _source_model(max_len=3))

    assert info.input_constraints == ["first 2 symbolic bytes are non-null"]
    assert calls["solver_add"] == [
        "BVS(sym_ip,16)[15:8] != 0",
        "BVS(sym_ip,16)[7:0] != 0",
    ]


class FakeConstraint:
    def __init__(self, text: str, variables: set[str]):
        self.text = text
        self.variables = variables

    def __str__(self) -> str:
        return self.text


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
    constraints: list[FakeConstraint] | None = None,
) -> None:
    active_sequences = active_sequences or [[]]
    constraints = constraints or []

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

    class FakeSolver:
        def __init__(self):
            self.constraints = list(constraints)

        def add(self, constraint):
            calls.setdefault("solver_add", []).append(constraint)

        def eval(self, *args, **kwargs):
            calls["solver_eval_called"] = True
            raise AssertionError("solver.eval must not be called")

    class FakeState:
        def __init__(self, addr):
            self.addr = addr
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
