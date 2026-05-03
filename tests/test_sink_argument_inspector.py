from __future__ import annotations

from ns_aeg.verifier.sink_argument_inspector import (
    argument_register_for_arch,
    inspect_sink_argument,
    normalize_arch_name,
)


def test_amd64_sysv_argument_register_mapping() -> None:
    assert argument_register_for_arch("AMD64", 0) == "rdi"
    assert argument_register_for_arch("AMD64", 1) == "rsi"
    assert argument_register_for_arch("AMD64", 2) == "rdx"
    assert argument_register_for_arch("x86_64", 3) == "rcx"
    assert argument_register_for_arch("x86:LE:64:default", 4) == "r8"
    assert argument_register_for_arch("AMD64", 5) == "r9"


def test_arm_aarch64_and_mips_argument_register_mapping() -> None:
    assert argument_register_for_arch("ARM32", 0) == "r0"
    assert argument_register_for_arch("ARM", 1) == "r1"
    assert argument_register_for_arch("AArch64", 0) == "x0"
    assert argument_register_for_arch("arm64", 7) == "x7"
    assert argument_register_for_arch("MIPS32", 0) == "a0"
    assert argument_register_for_arch("mipsel", 3) == "a3"


def test_unsupported_architecture_returns_graceful_result() -> None:
    result = inspect_sink_argument(
        object(),
        object(),
        {"function": "system", "arg_index": 0},
        arch="PowerPC",
    )

    assert result["arch"] == "POWERPC"
    assert result["contains_marker"] == "unknown"
    assert result["contains_source"] == "unknown"
    assert result["method"] == "unsupported_abi_argument_mapping"
    assert result["limitations"]


def test_i386_stack_arguments_are_explicitly_partial() -> None:
    result = inspect_sink_argument(
        object(),
        object(),
        {"function": "system", "arg_index": 0},
        arch="i386",
    )

    assert result["arch"] == "X86"
    assert result["location"] == "stack:arg0"
    assert result["method"] == "unsupported_stack_argument_inspection"
    assert "i386" in " ".join(result["limitations"])


def test_missing_arg_index_falls_back_to_sink_catalog_default() -> None:
    result = inspect_sink_argument(
        object(),
        object(),
        {"function": "system"},
        arch="AMD64",
    )

    assert result["arg_index"] == 0
    assert result["register"] == "rdi"
    assert "sink catalog default" in " ".join(result["limitations"])


def test_arch_normalization_handles_ghidra_language_ids() -> None:
    assert normalize_arch_name("x86:LE:64:default") == "AMD64"
    assert normalize_arch_name("x86:LE:32:default") == "X86"
    assert normalize_arch_name("AARCH64:LE:64:v8A") == "AARCH64"
    assert normalize_arch_name("MIPS:LE:32:default") == "MIPS32"
