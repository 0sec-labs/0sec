"""Recovered struct-layout context for the pseudo-C LLM scan (the missing ingredient).

Compilation strips the source-level types: a field access ``params->nInputs`` becomes
raw offset arithmetic ``*(uint *)(iVar1 + 8)`` in the decompiler output, and an array
member ``params->nSamples[i]`` becomes ``*(char **)(iVar1 + 0x10 + i*4)``. The model
can reason about memory safety perfectly well (feeding it the recovered struct made it
flag the lcms ``WriteCLUT`` OOB read that it MISSED on the raw offsets alone) — it just
cannot know that ``+8`` is a length and ``+0x10`` is a **fixed 15-element array** unless
we hand it the layout.

When the binary carries type info (DWARF imported into Ghidra's ``DataTypeManager``, or
any format Ghidra recovers), we harvest the struct definitions and, for a given
function body, select the structs whose field offsets match the raw offset constants the
body dereferences — reattaching ``+8 -> nInputs`` / ``+0x10 -> nSamples[15]`` so an OOB
index against the array bound is legible again.

Everything here is generic (offset-driven, never keyed to a particular library) and a
strict no-op when no type info is available — a stripped/toy binary yields an empty
struct list and the scan prompt is unchanged.
"""

from __future__ import annotations

import re
from typing import Any

# Additive offset constants the decompiler emits in pointer arithmetic:
# ``(cVar2 + 0x10 + uVar5 * 4)``, ``*(uint *)(iVar1 + 8)``. We take the constant that
# immediately follows a ``+`` — the base+displacement of a struct field access. A leading
# ``*`` (multiply) is excluded by anchoring on ``+``; ``-`` displacements are ignored
# (they are stack-frame temporaries like ``gridPoints[uVar5 - 4]``, not struct fields).
_OFFSET = re.compile(r"\+\s*(0x[0-9a-fA-F]+|\d+)\b")

# ``BASE + OFF`` where BASE is a recovered pointer temporary — captures which pointer an
# offset is applied to, so offsets belonging to *different* structs a function touches
# (``cVar2 + 8`` vs ``_Precision + 0x20``) are not pooled into one bogus match. A base
# token starting with a digit (``0xff01 + 0x800000`` — a pure arithmetic constant) is
# excluded by requiring a leading letter/underscore.
_BASE_OFFSET = re.compile(r"([A-Za-z_]\w*)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\b")

# A cap so an over-broad match can never blow the prompt budget.
_MAX_STRUCTS = 5
_MAX_CHARS = 2400
# Offsets that hit almost every struct carry little discriminative signal on their own.
_MIN_MATCHES = 2


def harvest_structs(program: Any) -> list[dict[str, Any]]:
    """Pull every composite (struct) layout out of Ghidra's ``DataTypeManager`` into a
    JSON-serializable form: ``{name, size, fields:[{offset,type,name,is_array,count}]}``.

    Ghidra populates the DTM from DWARF (``.debug_info``) during analysis, so this is
    available for any not-stripped / debug binary. Best-effort per struct — a datatype
    that fails to introspect is skipped, never fatal. Returns ``[]`` when the program
    has no recovered composites (stripped binary) so the caller degrades to a no-op."""
    out: list[dict[str, Any]] = []
    try:
        dtm = program.getDataTypeManager()
        structs = list(dtm.getAllStructures())
    except Exception:  # Ghidra interop / no DTM
        return out
    for s in structs:
        try:
            fields: list[dict[str, Any]] = []
            for i in range(s.getNumComponents()):
                c = s.getComponent(i)
                dt = c.getDataType()
                tname = str(dt.getName())
                # Ghidra renders arrays as ``type[N]`` in getName(); detect + size them
                # so we can flag a matched offset that lands on a fixed-size array (the
                # exact OOB-target shape).
                is_array = False
                count = 0
                try:
                    from ghidra.program.model.data import Array

                    if isinstance(dt, Array):
                        is_array = True
                        count = int(dt.getNumElements())
                except Exception:
                    is_array = bool(re.search(r"\[\d+\]", tname))
                fields.append({
                    "offset": int(c.getOffset()),
                    "type": tname,
                    "name": str(c.getFieldName() or f"field_{c.getOffset():#x}"),
                    "is_array": is_array,
                    "count": count,
                    "len": int(c.getLength()),
                })
            if fields:
                out.append({
                    "name": str(s.getName()),
                    "size": int(s.getLength()),
                    "fields": fields,
                })
        except Exception:  # one bad datatype must not sink the harvest
            continue
    return out


def _to_int(tok: str) -> int | None:
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except ValueError:
        return None


def body_offsets(body: str) -> set[int]:
    """The set of additive offset constants dereferenced in a decompiled body — the raw
    ``+ N`` displacements that (before compilation) were named struct-field accesses."""
    offs: set[int] = set()
    for m in _OFFSET.finditer(body):
        v = _to_int(m.group(1))
        if v is not None:
            offs.add(v)
    return offs


def base_offset_groups(body: str) -> dict[str, set[int]]:
    """Group offsets by the pointer variable they are added to: ``{'cVar2': {8, 0x10},
    '_Precision': {0x20}}``. A single function dereferences several distinct structs;
    grouping keeps each struct's offsets separate so a coherent multi-field match
    against one base is not diluted (or faked) by offsets that belong to a different
    pointer — the precision fix that makes the real struct out-rank incidental decoys."""
    groups: dict[str, set[int]] = {}
    for m in _BASE_OFFSET.finditer(body):
        base = m.group(1)
        v = _to_int(m.group(2))
        if v is not None:
            groups.setdefault(base, set()).add(v)
    return groups


def _field_offsets(struct: dict[str, Any]) -> set[int]:
    return {int(f["offset"]) for f in struct.get("fields", [])}


def _names_in_body(body: str) -> set[str]:
    """Identifiers appearing verbatim in the body (types Ghidra *did* keep, e.g. a
    typedef'd pointer ``cmsIOHANDLER *io``). Lets a struct named in the recovered
    signature be included even if its offsets don't match."""
    return set(re.findall(r"[A-Za-z_]\w+", body))


def _best_match(
    struct: dict[str, Any], groups: dict[str, set[int]]
) -> tuple[int, int, int]:
    """The struct's best coherent match against any single base pointer's offset set.
    Returns (matched non-zero offsets, array-on-matched-offset bonus, max matched
    offset). Evaluating per base (not against a pooled set) is what stops an incidental
    decoy — a struct that happens to have fields at offsets which, across *different*
    pointers, cover the body — from beating the struct actually behind one pointer.

    Offset 0 is excluded — every pointer dereferences its own base, so +0 carries no
    signal. A matched offset landing on a fixed-size **array** field is the OOB-target
    signature (``nSamples[15]`` at +0x10) and adds a point. ``max matched offset`` is a
    deterministic tiebreak favoring matches on deeper (rarer, more specific) fields."""
    foffs = _field_offsets(struct)
    array_offsets = {int(f["offset"]) for f in struct.get("fields", []) if f.get("is_array")}
    best = (0, 0, 0)
    for offs in groups.values():
        matched = {o for o in offs if o in foffs and o != 0}
        if not matched:
            continue
        array_hit = len(matched & array_offsets)
        cand = (len(matched), array_hit, max(matched))
        if cand > best:
            best = cand
    return best


def select_structs(
    body: str,
    structs: list[dict[str, Any]],
    *,
    max_structs: int = _MAX_STRUCTS,
    min_matches: int = _MIN_MATCHES,
    max_chars: int = _MAX_CHARS,
) -> list[dict[str, Any]]:
    """Pick the structs most likely to explain a function's raw offset accesses.

    A struct qualifies if at least ``min_matches`` of the offsets applied to a *single*
    pointer in ``body`` are non-zero fields of the struct (offset-driven, per-base,
    library-agnostic), OR it is named verbatim in the body. Qualifiers are ranked by
    match quality (matched-count, array-on-match, deepest offset) and capped at
    ``max_structs`` / ``max_chars`` to keep the added prompt context bounded.

    Returns ``[]`` when nothing qualifies (toy/stripped binary, or a function that does
    no struct access) — the caller then emits the original, unchanged prompt."""
    if not structs:
        return []
    groups = base_offset_groups(body)
    names = _names_in_body(body)
    scored: list[tuple[tuple[int, int, int], str, dict[str, Any]]] = []
    for s in structs:
        match = _best_match(s, groups)
        named = str(s.get("name", "")) in names
        if match[0] < min_matches and not named:
            continue
        # A name-only match ranks at low priority (its offset match count may be 0).
        key = (max(match[0], 1 if named else 0), match[1], match[2])
        scored.append((key, str(s.get("name", "")), s))
    # Best score first; name asc as the final deterministic tiebreak.
    scored.sort(key=lambda t: (-t[0][0], -t[0][1], -t[0][2], t[1]))

    picked: list[dict[str, Any]] = []
    budget = max_chars
    for _score_t, _name, s in scored[: max_structs * 2]:
        text = format_struct(s)
        if len(picked) >= max_structs:
            break
        if budget - len(text) < 0 and picked:
            break
        picked.append(s)
        budget -= len(text)
    return picked


def format_struct(struct: dict[str, Any]) -> str:
    """Render one struct as a C-like definition annotated with byte offsets, so the model
    can map a raw ``+ N`` access to a named field (and see array bounds)."""
    lines = [f"struct {struct.get('name', 'anon')} {{  // size {struct.get('size', 0)} bytes"]
    for f in struct.get("fields", []):
        off = int(f["offset"])
        arr = "  [FIXED-SIZE ARRAY]" if f.get("is_array") else ""
        lines.append(f"    {f['type']} {f['name']};  // +{off:#x}{arr}")
    lines.append("};")
    return "\n".join(lines)


def struct_context(
    body: str, structs: list[dict[str, Any]] | None, **kw: Any
) -> str:
    """The prompt fragment to append for a function, or ``""`` when no type info applies.

    Selects the relevant structs (offset/name match) and formats them under a header that
    tells the model these map raw offset accesses to fields. Empty string is the no-op
    path (no structs harvested, or none relevant) — appending it changes nothing."""
    if not structs:
        return ""
    picked = select_structs(body, structs, **kw)
    if not picked:
        return ""
    defs = "\n\n".join(format_struct(s) for s in picked)
    return (
        "\n--- RECOVERED STRUCT TYPES (map the raw offset accesses above to fields) ---\n"
        "The decompiler lowered field accesses to raw pointer arithmetic. These are the\n"
        "recovered layouts for the structs this function dereferences: a `*(T *)(p + N)`\n"
        "in the body is the field at offset +N below. A loop bound read from one field\n"
        "used to index a FIXED-SIZE ARRAY field is an out-of-bounds access when the bound\n"
        "can exceed the array's element count.\n\n"
        f"{defs}\n"
    )
