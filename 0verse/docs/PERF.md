# Performance: the optional Rust/PyO3 fast-path (#31)

0verse's CPU-bound stages (ingest/triage, the bug-class lens scan, NDJSON
emission) are pure-Python and work everywhere with zero native dependencies. #31
adds an **optional** Rust extension (`zeroverse._native`) that accelerates the one
stage where Rust measurably wins, and an **algorithmic** fix to the lens scan that
is the single biggest speedup — in pure Python.

This document is deliberately honest: it reports what was actually slow, what Rust
did and did **not** help, and the real end-to-end effect (which is small, because
in a production run Ghidra/angr dominate wall-time).

## TL;DR

| Stage | Before | After | Speedup | How |
|---|---|---|---|---|
| `bugclasses.prime_bugclasses` (all 5 lenses) | 3695 ms | 577 ms | **6.4×** | pure-Python keyword **prefilter** (skip doomed regex) |
| └ `fmtstring_lens` | 1647 ms | 88 ms | 18.7× | prefilter |
| └ `cmdi_lens` | 1546 ms | 69 ms | 22.4× | prefilter |
| `ingest.triage` (150 MB ELF) | 205 ms | 102 ms | **2.0×** | Rust Aho-Corasick multi-marker scan |
| `serialize.to_ndjson` (20k findings) | 150 ms | 150 ms | 1.0× | **not ported** (`json` is already C) |

**Rust helps the ingest byte-scan (2×). The headline lens speedup (6.4×) is
algorithmic and pure Python — it does not need the extension at all.**

## Methodology

- Box: `bench` (Ryzen 3900, 62 GB). Python 3.12, rustc 1.75, pyo3 0.22 (abi3),
  aho-corasick 1.1, release build (`lto`, `opt-level=3`).
- Inputs (large, synthetic, in-memory): a **157 MB ELF** (valid header + filler +
  buried `__stack_chk_fail` / `.symtab` markers, worst case for whole-file
  substring search); a **6000-function / 10 MB decompiled-C corpus** (1/8 of
  functions carry real alloc/free/printf/system shapes, the rest benign — the
  realistic case where most functions have no sink); **20 000 findings** for the
  NDJSON path.
- Timing: best of 5 runs per stage (`time.perf_counter`).
- Native vs Python: the same code path, toggling the extension on/off at the
  `_fastpath` seam, asserting the two produce **byte-for-byte identical** results
  on the large inputs every time.
- Reproduce: `python .bench_native.py` from a worktree with the extension built
  (`./rust/build.sh`).

## What the profiler actually showed

cProfile over `triage + prime_bugclasses + to_ndjson` on the inputs above:

```
prime_bugclasses        3.919 s   (95% of CPU)
  fmtstring_lens        1.647 s
  cmdi_lens             1.546 s
  intoverflow_lens      0.240 s
  uaf_lens              0.206 s
  logic_lens            0.279 s
ingest.triage           0.196 s   (read 0.085 + _triage_elf 0.111)
to_ndjson               0.217 s
```

The lens scan dominated. The reason was structural, not algorithmic complexity:
`fmtstring_lens` / `cmdi_lens` run `re.finditer(r"\bNAME\s*\(", body)` for **every**
keyword name (10–11 of them) against **every** function body — including the 7/8
of bodies that contain no such keyword at all.

## The lens fix — pure-Python prefilter (the 6.4× win)

A `\bNAME\s*\(` match can only occur where `NAME` literally appears as a
substring. So before running the expensive regex, `bugclasses._presence` does one
cheap substring presence test per body and **skips** any keyword that is absent.
This cannot change a lens's output — it only avoids a regex pass that was
guaranteed to find nothing. (Note `execlp` contains `execl` and `fprintf` contains
`printf`: the prefilter is *conservative*, it only ever skips when the substring
is truly absent, so overlapping names just fall through to the regex, which then
correctly matches nothing.)

This is the single biggest speedup in #31, and it is **pure Python** — no Rust
required. A keyword parity test asserts the prefiltered lenses produce identical
findings to the original unconditional scan.

### Why this part is *not* in Rust

We tried. A native Aho-Corasick corpus sweep (`scan_corpus`, then a bitmask
variant `scan_masks`, then zero-copy `PyBackedStr` inputs) was consistently
**slower** than CPython's built-in `in` for this shape:

```
fmtstring_lens   python(prefilter)= 88 ms   native(aho-corasick)= 127 ms   0.69×
prime_bugclasses python(prefilter)=577 ms   native              = 653 ms   0.91×
```

The haystacks are thousands of *tiny* (~1.7 KB) function bodies. The cost of
crossing the Python↔Rust boundary 6000 times — and building Python result objects
back — exceeds the work itself, where CPython's SIMD `memmem` is already optimal
and short-circuits. **Shipping a native lens path would make extension-installed
users slower**, so the lens prefilter is intentionally pure Python.

## The ingest fix — Rust where it earns its keep (2×)

`triage` probes the *whole* file for marker strings (`__stack_chk_fail`,
`.symtab`, `__security_cookie`, `.debug`, `PDB`, …) to decide canary/stripped —
several independent full-file scans over a 100 MB+ blob. Here the haystack is one
**large contiguous** buffer, exactly where Aho-Corasick + one boundary crossing
wins: `_fastpath.contains_any_bytes` finds all markers in a single GIL-released
pass.

```
ingest.triage (157 MB ELF)   python=205 ms   native=102 ms   2.01×   [identical]
```

When the extension is absent, `contains_any_bytes` falls back to `[n in data for n
in needles]` — identical booleans, just N passes instead of one.

## NDJSON (`serialize` / `dataset`) — not ported, on purpose

`to_ndjson` is `json.dumps` per finding; `json` is already a C extension and the
Python part (`finding_dict`) is light dict construction. A Rust port would mean
re-implementing the exact (nested, optional `angr`/`pov`) record shape with high
parity risk for ~150 ms. Not worth it — left as pure Python.

## End-to-end honesty

These stages are CPU-bound microbenchmarks. In a **real** 0verse run the
wall-time is dominated by Ghidra decompilation and angr symbolic execution
(seconds to minutes per binary), against which a ~100 ms ingest saving and a
~3 s → 0.6 s lens saving are real but small in the total. The lens prefilter is
the change you'd actually feel on a large decompiled corpus; the Rust extension is
a clean 2× on ingest of very large blobs and a no-op everywhere else. The OSS
install never requires a Rust toolchain.

## Building the optional extension

```
pip install maturin
./rust/build.sh          # builds zeroverse._native and drops it into the package
```

`zeroverse._fastpath.NATIVE` reports whether the native path is active;
everything degrades transparently to pure Python when it is not.
