"""M5 #27 — the backend contract + the non-Ghidra IL extractor + auto-selection.

These tests are engine-free: they exercise the ``DecompilerBackend`` Protocol, the
``cdecomp`` pseudo-C → IL extractor (which both rizin and angr backends use), and
the ``$ZEROVERSE_BACKEND`` selector — without invoking r2/angr/Ghidra. A separate
``test_rizin_fallback`` runs the real fallback when r2 is installed.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from zeroverse.analyze import scan
from zeroverse.backends import contract
from zeroverse.backends.cdecomp import build_il, normalize_c, normalize_name
from zeroverse.backends.contract import ProgramAdapter, ProgramMeta
from zeroverse.backends.ghidra import GhidraBackend
from zeroverse.il import ILAdapter, Kind
from zeroverse.taint import load_model


def _install_pyghidra_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the ``pyghidra`` bridge look importable without installing Ghidra."""
    monkeypatch.setitem(sys.modules, "pyghidra", types.SimpleNamespace())


def _remove_pyghidra_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the bridge unimportable even where it is genuinely installed (the
    Docker image), so these tests assert behaviour rather than the host."""
    monkeypatch.delitem(sys.modules, "pyghidra", raising=False)
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, package=None: (
            None if name == "pyghidra" else real_find_spec(name, package)
        ),
    )


def test_program_adapter_conforms_to_iladapter() -> None:
    a = ProgramAdapter([], {}, {}, {}, {}, meta=ProgramMeta())
    assert isinstance(a, ILAdapter)
    assert hasattr(a, "all_insts") and hasattr(a, "meta")


def test_backend_classes_conform_to_protocol() -> None:
    from zeroverse.backends.angr_backend import AngrBackend
    from zeroverse.backends.ghidra import GhidraBackend
    from zeroverse.backends.rizin import RizinBackend

    for b in (GhidraBackend(), RizinBackend(), AngrBackend()):
        assert isinstance(b, contract.DecompilerBackend)
        assert isinstance(b.name, str) and b.name
        assert isinstance(b.available(), bool)


def test_normalize_strips_decompiler_prefixes() -> None:
    assert normalize_name("sym.imp.read") == "read"
    assert normalize_name("strcpy") == "strcpy"
    assert "read" in normalize_c("iVar = sym.imp.read(0,&buf,0x10);")
    assert "sym.imp." not in normalize_c("sym.imp.strcpy(&dst,&buf);")


def test_build_il_recovers_calls_and_argvars() -> None:
    # The read/strcpy shape r2ghidra's pdg emits for benchmarks/overflow.c.
    code = {
        "main": (
            "ulong main(void){\n"
            "  char *dest;\n"
            "  size_t fildes;\n"
            "  int iVar1;\n"
            "  iVar1 = sym.imp.read(0,&fildes,0x1ff);\n"
            "  sym.imp.strcpy(&dest,&fildes);\n"
            "  return 0;\n"
            "}"
        )
    }
    insts, _defs, callgraph = build_il(code)
    calls = {i.dest: i for i in insts if i.kind is Kind.CALL}
    assert "read" in calls and "strcpy" in calls
    # read(fd, buf, n): buffer is arg index 1; strcpy(dst, src): src is arg index 1.
    assert calls["read"].arg_vars[1] == "fildes"
    assert calls["strcpy"].arg_vars[1] == "fildes"
    assert "read" in callgraph["main"] and "strcpy" in callgraph["main"]


def test_build_il_value_flow_def_map() -> None:
    # p = getenv("X"); system(p);  -> system's arg resolves to the getenv call.
    code = {"main": 'char *p; p = getenv("X"); system(p);'}
    insts, defs, _ = build_il(code)
    calls = {i.dest: i for i in insts if i.kind is Kind.CALL}
    getenv_id = calls["getenv"].id
    assert defs.get(("p", "main")) == getenv_id


def test_extracted_il_slices_source_to_sink() -> None:
    # The non-Ghidra IL drives the real analyze.scan: read->strcpy memory flow.
    code = {
        "main": (
            "int iVar1; char *dest; size_t fildes;\n"
            "iVar1 = read(0,&fildes,0x1ff);\n"
            "strcpy(&dest,&fildes);\n"
        )
    }
    insts, defs, _ = build_il(code)
    adapter = ProgramAdapter(insts, defs, {}, {}, {}, meta=ProgramMeta())
    findings = scan(adapter, load_model(Path("conf")), insts)
    pairs = {(f.source, f.sink) for f in findings}
    assert ("read", "strcpy") in pairs


def test_select_explicit_unavailable_is_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Ghidra pinned but its toolchain absent -> select resolves to None.
    monkeypatch.setenv("ZEROVERSE_BACKEND", "ghidra")
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    assert contract.select() is None
    # a bogus name resolves to nothing.
    assert contract.select("nope") is None
    # the selection note mentions Ghidra when ghidra is pinned but absent.
    assert "Ghidra" in contract.selection_note("ghidra")


def test_select_auto_prefers_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZEROVERSE_BACKEND", "auto")
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _install_pyghidra_bridge(monkeypatch)
    b = contract.select()
    assert b is not None and b.name == "ghidra"  # ghidra preferred when available


# --- #296/#297: a Ghidra install without its bridge is UNAVAILABLE, not degraded


def test_ghidra_install_without_bridge_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The exact bench-box shape: Ghidra unpacked, GHIDRA_HOME exported, pyghidra
    # missing. Nothing can be decompiled, so the backend must not claim it can.
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _remove_pyghidra_bridge(monkeypatch)
    assert GhidraBackend().available() is False
    assert contract.select("ghidra") is None
    # The note has to name the missing half — "install Ghidra" is the wrong fix here.
    note = contract.selection_note("ghidra")
    assert "pyghidra" in note and "/opt/ghidra" in note


def test_auto_falls_through_a_bridgeless_ghidra(monkeypatch: pytest.MonkeyPatch) -> None:
    # auto must not pin itself to an engine it cannot start.
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _remove_pyghidra_bridge(monkeypatch)
    selected = contract.select("auto")
    assert selected is None or selected.name != "ghidra"


def test_explicit_backend_demand_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _remove_pyghidra_bridge(monkeypatch)
    with pytest.raises(contract.BackendUnavailableError):
        contract.ensure_explicit_backend("ghidra")
    # ...including when the demand arrives through the environment.
    monkeypatch.setenv("ZEROVERSE_BACKEND", "ghidra")
    with pytest.raises(contract.BackendUnavailableError):
        contract.ensure_explicit_backend(None)


def test_auto_is_a_preference_and_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Degradation stays legal for auto — that is what the fallback chain is for.
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("ZEROVERSE_BACKEND", "auto")
    contract.ensure_explicit_backend(None)
    contract.ensure_explicit_backend("auto")


def test_satisfied_demand_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _install_pyghidra_bridge(monkeypatch)
    contract.ensure_explicit_backend("ghidra")


def test_resolve_choice_normalizes_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZEROVERSE_BACKEND", raising=False)
    assert contract.resolve_choice(None) == "auto"
    assert contract.resolve_choice("  Ghidra ") == "ghidra"
    monkeypatch.setenv("ZEROVERSE_BACKEND", "RIZIN")
    assert contract.resolve_choice(None) == "rizin"
    assert contract.resolve_choice("angr") == "angr"  # an argument beats the env


def test_cli_scan_exits_nonzero_when_the_demanded_backend_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from zeroverse.cli import main

    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setenv("GHIDRA_HOME", "/opt/ghidra")
    _remove_pyghidra_bridge(monkeypatch)
    assert main(["scan", str(binary), "--backend", "ghidra"]) != 0
    assert "pyghidra" in capsys.readouterr().err


def test_cli_run_exits_nonzero_when_the_env_demand_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from zeroverse.cli import main

    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setenv("ZEROVERSE_BACKEND", "rizin")
    monkeypatch.setattr(
        "zeroverse.backends.rizin.RizinBackend.available", lambda self: False
    )
    assert main(["run", str(binary)]) != 0
    assert "rizin" in capsys.readouterr().err
