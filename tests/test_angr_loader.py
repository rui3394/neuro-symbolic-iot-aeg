import builtins
from types import SimpleNamespace

from ns_aeg.angr_loader import load_with_angr


def test_missing_binary_returns_loaded_false(tmp_path) -> None:
    missing = tmp_path / "missing"

    info = load_with_angr(str(missing), ["system"])

    assert info.loaded is False
    assert info.missing_plt == ["system"]
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

    info = load_with_angr(str(binary), ["system"])

    assert info.loaded is False
    assert info.error == "angr is not installed"
    assert info.missing_plt == ["system"]


def test_load_reads_project_metadata_and_plt(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")

    main_object = SimpleNamespace(
        binary_basename="toy",
        mapped_base=0x400000,
        plt={
            "system": 0x401050,
            "snprintf@plt": 0x401040,
        },
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="AMD64", bits=64),
        entry=0x401080,
        loader=SimpleNamespace(main_object=main_object),
    )

    def fake_project(path, auto_load_libs=False):
        assert path == str(binary)
        assert auto_load_libs is False
        return project

    monkeypatch.setitem(
        __import__("sys").modules,
        "angr",
        SimpleNamespace(Project=fake_project),
    )

    info = load_with_angr(str(binary), ["system", "snprintf", "popen"])

    assert info.loaded is True
    assert info.arch == "AMD64"
    assert info.bits == 64
    assert info.entry == "0x401080"
    assert info.base_addr == "0x400000"
    assert info.main_object == "toy"
    assert info.plt == {"system": "0x401050", "snprintf": "0x401040"}
    assert info.missing_plt == ["popen"]
    assert info.error is None


def test_missing_plt_is_reported(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "toy"
    binary.write_bytes(b"\x7fELF")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="AMD64", bits=64),
        entry=0x401080,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary_basename="toy", mapped_base=0x400000, plt={})
        ),
    )

    monkeypatch.setitem(
        __import__("sys").modules,
        "angr",
        SimpleNamespace(Project=lambda *args, **kwargs: project),
    )

    info = load_with_angr(str(binary), ["system", "snprintf"])

    assert info.loaded is True
    assert info.plt == {}
    assert info.missing_plt == ["system", "snprintf"]
