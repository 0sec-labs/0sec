"""First-pass indirect / virtual-call resolver (M1 #1) — mock-only unit tests.

Synthetic ProgramMeta fixtures (no Ghidra): assert the resolver adds speculative
edges from indirect call sites to address-taken functions and to fn-pointer-table
members, and that ``propagate_taint`` then delivers non-zero taint to a node only
reachable via a recovered indirect edge (the 0.00 regression this closes)."""

from zeroverse.backends.ghidra import GhidraAdapter, ProgramMeta
from zeroverse.indirect_calls import (
    ADDR_TAKEN_WEIGHT,
    PTR_TABLE_WEIGHT,
    IndirectEdge,
    address_taken,
    augmented_callgraph,
    indirect_call_sites,
    propagate_taint,
    resolve_indirect_edges,
)

# --- inputs ----------------------------------------------------------------

def test_indirect_call_sites_from_unresolved_edges() -> None:
    meta = ProgramMeta(unresolved_edges=[
        {"func": "dispatch", "addr": "0x1000", "op": "CALLIND", "arity": 2},
        {"func": "loader", "addr": "0x2000", "op": "CALLOTHER"},
        {"func": "direct", "addr": "0x3000", "op": "CALL"},  # resolved: ignored
    ])
    sites = indirect_call_sites(meta)
    assert set(sites) == {"dispatch", "loader"}
    assert sites["dispatch"][0]["arity"] == 2


def test_address_taken_prefers_explicit_then_falls_back_to_text() -> None:
    explicit = ProgramMeta(address_taken=["on_tag", "on_row"])
    assert address_taken(explicit) == {"on_tag", "on_row"}

    # No explicit list -> textual scan of decompiled C: a name used as a *value*.
    textual = ProgramMeta(decompiled_c={
        "register": "set_handler(parse_row);",   # parse_row taken (no call parens)
        "parse_row": "int parse_row(void){ return 0; }",
    })
    assert "parse_row" in address_taken(textual)


# --- heuristic 1: address-taken --------------------------------------------

def test_resolver_adds_addr_taken_edge_from_indirect_site() -> None:
    # dispatch() has an indirect call; handle_row is address-taken (a callback).
    meta = ProgramMeta(
        callgraph={"dispatch": ["helper"]},   # helper already direct — not re-added
        unresolved_edges=[{"func": "dispatch", "addr": "0x10", "op": "CALLIND"}],
        address_taken=["handle_row", "helper"],
    )
    edges = resolve_indirect_edges(meta)
    pairs = {(e.caller, e.callee, e.kind) for e in edges}
    assert ("dispatch", "handle_row", "addr-taken") in pairs
    assert ("dispatch", "helper", "addr-taken") not in pairs   # already direct
    assert all(e.weight == ADDR_TAKEN_WEIGHT for e in edges if e.kind == "addr-taken")


def test_resolver_only_wires_from_functions_with_indirect_sites() -> None:
    # 'clean' has no indirect site -> it must not sprout speculative edges (FP bound).
    meta = ProgramMeta(
        callgraph={"clean": [], "dispatch": []},
        unresolved_edges=[{"func": "dispatch", "addr": "0x10", "op": "CALLIND"}],
        address_taken=["cb"],
    )
    callers = {e.caller for e in resolve_indirect_edges(meta)}
    assert callers == {"dispatch"}


def test_resolver_arity_filter_when_known() -> None:
    meta = ProgramMeta(
        unresolved_edges=[{"func": "dispatch", "addr": "0x10", "op": "CALLIND", "arity": 2}],
        address_taken=["two_arg", "three_arg"],
    )
    edges = resolve_indirect_edges(meta, func_arity={"two_arg": 2, "three_arg": 3})
    callees = {e.callee for e in edges}
    assert callees == {"two_arg"}   # arity 3 candidate filtered out


def test_resolver_fanout_cap() -> None:
    meta = ProgramMeta(
        unresolved_edges=[{"func": "d", "addr": "0x10", "op": "CALLIND"}],
        address_taken=[f"cb{i}" for i in range(50)],
    )
    edges = resolve_indirect_edges(meta, max_targets_per_site=5)
    assert len(edges) == 5


# --- heuristic 2: fn-pointer / vtable table --------------------------------

def test_resolver_wires_ptr_table_members() -> None:
    # A recovered vtable in .data.rel.ro; loader() dispatches through it.
    meta = ProgramMeta(
        unresolved_edges=[{"func": "loader", "addr": "0x10", "op": "CALLIND"}],
        ptr_tables=[{"section": ".data.rel.ro", "addr": "0x4000",
                     "members": ["vfunc_a", "vfunc_b"], "loaders": ["loader"]}],
    )
    edges = resolve_indirect_edges(meta)
    ptr = {(e.caller, e.callee) for e in edges if e.kind == "ptr-table"}
    assert ptr == {("loader", "vfunc_a"), ("loader", "vfunc_b")}
    assert all(e.weight == PTR_TABLE_WEIGHT for e in edges if e.kind == "ptr-table")


def test_ptr_table_without_loaders_falls_back_to_indirect_callers() -> None:
    meta = ProgramMeta(
        unresolved_edges=[{"func": "dispatch", "addr": "0x10", "op": "CALLIND"}],
        ptr_tables=[{"members": ["vfunc_a"]}],   # no loaders
    )
    edges = resolve_indirect_edges(meta)
    assert ("dispatch", "vfunc_a") in {(e.caller, e.callee) for e in edges}


# --- augmented call graph ---------------------------------------------------

def test_augmented_callgraph_is_nonmutating_union() -> None:
    meta = ProgramMeta(
        callgraph={"dispatch": ["helper"]},
        unresolved_edges=[{"func": "dispatch", "addr": "0x10", "op": "CALLIND"}],
        address_taken=["handle_row"],
    )
    aug = augmented_callgraph(meta)
    assert set(aug["dispatch"]) == {"helper", "handle_row"}
    assert meta.callgraph == {"dispatch": ["helper"]}   # original untouched


# --- taint propagation ------------------------------------------------------

def test_propagate_taint_zero_without_indirect_edges() -> None:
    # THE REGRESSION: the bug function is only reachable via an indirect dispatch,
    # so over the direct-only graph it gets 0.00 taint.
    direct = {"LLVMFuzzerTestOneInput": ["parse"], "parse": []}  # dispatch is indirect
    taint = propagate_taint(direct, sources=["LLVMFuzzerTestOneInput"])
    assert taint.get("vuln_handler", 0.0) == 0.0


def test_propagate_taint_reaches_node_via_indirect_edge() -> None:
    # parse() dispatches indirectly into vuln_handler (address-taken). With the
    # recovered edge, taint now flows to vuln_handler — non-zero, below direct.
    meta = ProgramMeta(
        callgraph={"LLVMFuzzerTestOneInput": ["parse"], "parse": []},
        unresolved_edges=[{"func": "parse", "addr": "0x10", "op": "CALLIND"}],
        address_taken=["vuln_handler"],
    )
    edges = resolve_indirect_edges(meta)
    taint = propagate_taint(
        meta.callgraph, sources=["LLVMFuzzerTestOneInput"], indirect_edges=edges)
    assert taint["vuln_handler"] > 0.0
    # Depth-2 direct hop + 1 indirect hop: 1.0 * 1.0 * ADDR_TAKEN_WEIGHT.
    assert taint["vuln_handler"] == ADDR_TAKEN_WEIGHT
    # And strictly below the fully-direct node at the same depth.
    assert taint["vuln_handler"] < taint["parse"]


def test_propagate_taint_prefers_stronger_edge_and_terminates_on_cycle() -> None:
    # Cycle a->b->a plus two edges into 'target': a weak addr-taken and a stronger
    # ptr-table. Max-product must pick the stronger and still terminate.
    cg = {"src": ["a"], "a": ["b"], "b": ["a"]}
    edges = [
        IndirectEdge("a", "target", "addr-taken", ADDR_TAKEN_WEIGHT),
        IndirectEdge("b", "target", "ptr-table", PTR_TABLE_WEIGHT),
    ]
    taint = propagate_taint(cg, sources=["src"], indirect_edges=edges)
    # via a: 1.0(src->a) * 0.35 ; via b: 1.0 *1.0(a->b) * 0.55 -> stronger wins.
    assert taint["target"] == PTR_TABLE_WEIGHT


# --- ProgramMeta roundtrip for the new fields -------------------------------

def test_new_meta_fields_roundtrip_through_json() -> None:
    meta = ProgramMeta(
        address_taken=["cb_a", "cb_b"],
        ptr_tables=[{"section": ".rodata", "addr": "0x4000",
                     "members": ["v0", "v1"], "loaders": []}],
    )
    a = GhidraAdapter([], {}, {}, {}, {}, meta=meta)
    import json

    back = GhidraAdapter.from_json(json.loads(a.to_json()))
    assert back.meta.address_taken == ["cb_a", "cb_b"]
    assert back.meta.ptr_tables[0]["members"] == ["v0", "v1"]
