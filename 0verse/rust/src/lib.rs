//! Optional Rust/PyO3 fast-path for 0verse (module ``zeroverse._native``).
//!
//! The pure-Python engine works everywhere; this extension accelerates the one
//! place the profiler showed Rust genuinely wins — scanning a **large, contiguous
//! blob** (a 100MB+ binary) for several byte markers at once. ingest/triage
//! probes the whole file for canary / `.symtab` / `.debug` / `PDB` strings; today
//! that is N separate full-file scans, and this collapses them into ONE
//! multi-pattern Aho-Corasick sweep (~2x on a 150MB ELF, byte-for-byte identical).
//!
//! NOTE (honesty): this is *not* used for the bug-class lens prefilter. There the
//! haystacks are thousands of tiny function bodies, and crossing the Python↔Rust
//! boundary per body costs more than CPython's built-in ``in`` (memmem) — measured
//! repeatedly. The lens speedup is a pure-Python algorithmic skip (see
//! ``bugclasses._presence`` and docs/PERF.md). Rust earns its keep on big blobs.
//!
//! Every function answers one question — "does this needle occur as a substring of
//! this haystack?" — identically to Python's ``needle in haystack``, so the native
//! path is a drop-in that must stay in parity with the fallback (see the test).

use aho_corasick::{AhoCorasick, MatchKind};
use pyo3::prelude::*;

/// Mark which `needles` occur at least once in `haystack` using one overlapping
/// Aho-Corasick sweep. `present[i]` is true iff `needles[i]` is a substring.
fn presence(haystack: &[u8], needles: &[Vec<u8>]) -> Vec<bool> {
    let mut present = vec![false; needles.len()];
    if needles.is_empty() {
        return present;
    }
    // An empty needle is a substring of everything (matches Python `"" in x`).
    let mut remaining = 0usize;
    for (i, n) in needles.iter().enumerate() {
        if n.is_empty() {
            present[i] = true;
        } else {
            remaining += 1;
        }
    }
    if remaining == 0 || haystack.is_empty() {
        // With an empty haystack only empty needles match (already set above).
        return present;
    }
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .build(needles)
        .expect("aho-corasick build over needle set");
    for m in ac.find_overlapping_iter(haystack) {
        let pid = m.pattern().as_usize();
        if !present[pid] {
            present[pid] = true;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
    }
    present
}

/// `contains_any(haystack: str, needles: list[str]) -> list[bool]`.
#[pyfunction]
fn contains_any(haystack: &str, needles: Vec<String>) -> Vec<bool> {
    let nb: Vec<Vec<u8>> = needles.into_iter().map(String::into_bytes).collect();
    presence(haystack.as_bytes(), &nb)
}

/// `contains_any_bytes(haystack: bytes, needles: list[bytes]) -> list[bool]`.
///
/// The ingest/triage hot path: one sweep of the whole file for every marker. The
/// GIL is released for the scan (a 100MB+ haystack is pure byte work).
#[pyfunction]
fn contains_any_bytes(py: Python<'_>, haystack: &[u8], needles: Vec<Vec<u8>>) -> Vec<bool> {
    py.allow_threads(|| presence(haystack, &needles))
}

/// Tiny self-identifying probe so Python can confirm the native path is live.
#[pyfunction]
fn backend() -> &'static str {
    "rust-aho-corasick"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(contains_any, m)?)?;
    m.add_function(wrap_pyfunction!(contains_any_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(backend, m)?)?;
    m.add("__doc__", "0verse native fast-path (Aho-Corasick substring presence).")?;
    Ok(())
}
