"""Taint model + par_slice DSL — engine-agnostic, no Ghidra needed."""

from pathlib import Path

import pytest

from zeroverse.taint import (
    Synopsis,
    compile_par_slice,
    load_model,
    tainted_arg_indices,
)

CONF = Path(__file__).resolve().parents[1] / "conf"


# --- par_slice DSL ---------------------------------------------------------

def test_par_slice_basic():
    assert compile_par_slice("i == 2")(2) is True
    assert compile_par_slice("i == 2")(1) is False
    assert compile_par_slice("True")(99) is True
    p = compile_par_slice("i >= 2")
    assert [p(i) for i in range(4)] == [False, False, True, True]


def test_par_slice_rejects_arbitrary_code():
    # No calls, no foreign names, no dunder access — these must all raise.
    for bad in ["__import__('os')", "open('x')", "i.__class__", "j == 1", "exit()"]:
        with pytest.raises(ValueError):
            compile_par_slice(bad)


# --- synopsis --------------------------------------------------------------

def test_synopsis_parse():
    s = Synopsis.parse("ssize_t read (int filedes, void *buffer, size_t size)")
    assert s.name == "read" and s.arg_count == 3 and s.varargs is False
    v = Synopsis.parse("int printf (const char *template, ...)")
    assert v.name == "printf" and v.arg_count == 1 and v.varargs is True
    z = Synopsis.parse("char * gets (char *s)")
    assert z.arg_count == 1


# --- model load ------------------------------------------------------------

def test_load_seed_model():
    m = load_model(CONF)
    syms = {f.name for f in m.functions}
    assert {"read", "recv", "gets", "memcpy", "system", "sprintf"} <= syms

    src_names = {f.name for f in m.sources()}
    snk_names = {f.name for f in m.sinks()}
    assert "read" in src_names and "memcpy" in snk_names
    # snprintf is shipped disabled.
    assert "snprintf" not in snk_names

    # read's tainted arg is the buffer (index 2).
    read = m.by_symbol("read")
    assert list(tainted_arg_indices(read.source, read.synopsis)) == [2]

    # gets is reachable by alias.
    assert m.by_symbol("__builtin_gets").name == "gets"
