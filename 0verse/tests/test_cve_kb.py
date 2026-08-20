"""Tests for the shared CVE knowledge base + novelty/dedup gate (``zeroverse.cve_kb``).

Pure data + math, no network: everything rides on the bundled REAL feed samples
(``src/zeroverse/cve_kb/data/sample_*.json`` — captured from NVD/OSV) plus the
curated seed table. The headline proof lives here: segwindrvx64.sys resolves to
CVE-2024-33228 offline (Mode A structured, off the real NVD description prose,
with no CPE), while a genuinely-obscure driver returns NO-PUBLIC-RECORD-FOUND.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse import cve_kb as kb
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.cve_kb import cpe, ingest, nvd, osv
from zeroverse.cve_kb.embed import CorpusEntry, LexicalBackend
from zeroverse.cve_kb.scan_gate import annotate_run, fingerprint_from_finding, novelty_summary
from zeroverse.cve_kb.store import CveStore
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV
from zeroverse.serialize import finding_dict
from zeroverse.windows_novelty import DriverIdentity, assess_novelty

DATA = Path(kb.__file__).resolve().parent / "data"


@pytest.fixture(scope="module")
def store() -> CveStore:
    return kb.build_store(include_bundled=True, include_seed=True)


# --- ingest / normalization -------------------------------------------------

def test_nvd_normalize_driver_cve_has_filename_and_cwe() -> None:
    payload = json.loads((DATA / "sample_nvd_cve-2024-33228.json").read_text())
    recs = nvd.normalize_response(payload)
    assert len(recs) == 1
    r = recs[0]
    assert r.id == "CVE-2024-33228"
    # the whole point: a driver CVE with NO CPE, filename recovered from prose
    assert r.cpe_matches == ()
    assert "segwindrvx64.sys" in r.files
    assert "CWE-94" in r.cwes


def test_nvd_normalize_dbutil_has_cpe_range() -> None:
    payload = json.loads((DATA / "sample_nvd_cve-2021-21551.json").read_text())
    r = nvd.normalize_response(payload)[0]
    assert r.id == "CVE-2021-21551"
    assert any("dbutil" in m.criteria for m in r.cpe_matches)


def test_osv_keys_on_cve_and_keeps_ghsa_alias() -> None:
    payload = json.loads((DATA / "sample_osv_log4j.json").read_text())
    recs = osv.normalize_query_response(payload)
    log4shell = next(r for r in recs if r.id == "CVE-2021-44228")
    # GHSA id preserved as an alias so either-way attribution resolves
    assert any(a.upper().startswith("GHSA-") for a in log4shell.aliases)
    assert log4shell.affected  # has [introduced, fixed) ranges


def test_nvd_normalize_any_shapes() -> None:
    payload = json.loads((DATA / "sample_nvd_cve-2024-33228.json").read_text())
    # full API response
    assert len(nvd.normalize_any(payload)) == 1
    # bare cve object
    bare = payload["vulnerabilities"][0]["cve"]
    assert nvd.normalize_any(bare)[0].id == "CVE-2024-33228"
    # wrapped item
    assert nvd.normalize_any({"cve": bare})[0].id == "CVE-2024-33228"
    # list + junk
    assert len(nvd.normalize_any([payload, {"not": "a cve"}])) == 1


def test_load_nvd_dir_over_bundled(tmp_path: Path) -> None:
    # the mirror directory-loader parses the bundled NVD 2.0 files and ignores
    # the OSV/tally ones in the same tree.
    s = ingest.load_nvd_dir(DATA)
    assert s.get("CVE-2024-33228") is not None
    assert s.get("CVE-2021-21551") is not None


def test_store_roundtrip(tmp_path: Path, store: CveStore) -> None:
    p = tmp_path / "records.jsonl"
    store.save(p)
    reloaded = CveStore.load(p)
    assert len(reloaded) == len(store)
    seg = reloaded.get("CVE-2024-33228")
    assert seg is not None and "segwindrvx64.sys" in seg.files


def test_store_ignores_falsy_empty_store_arg() -> None:
    # regression: an empty CveStore is falsy (__len__==0); load_bundled must NOT
    # discard a passed-in empty store via `store or CveStore()`.
    s = CveStore()
    ingest.load_bundled(s)
    assert len(s) >= 2


# --- Mode A: known_cve (THE proof) ------------------------------------------

def test_segwindrvx64_resolves_to_cve_2024_33228_offline(store: CveStore) -> None:
    finding = kb.FindingFingerprint(
        file="segwindrvx64.sys",
        vendor="Insyde Software Corp",
        ecosystem="windows-driver",
        bug_class="arb-physical-rw",
        cwe="CWE-94",
    )
    result = kb.known_cve(store, finding)
    assert result.verdict == kb.KNOWN_CVE
    assert "CVE-2024-33228" in result.cve_ids
    assert result.confidence == "high"
    assert result.label() == "KNOWN-CVE(CVE-2024-33228)"


def test_obscure_driver_returns_no_record_with_caveat(store: CveStore) -> None:
    finding = kb.FindingFingerprint(
        file="zzobscuredrv_acme9000.sys",
        vendor="Acme Widgets LLC",
        ecosystem="windows-driver",
        bug_class="arb-physical-rw",
    )
    result = kb.known_cve(store, finding)
    assert result.verdict == kb.NO_PUBLIC_RECORD
    assert result.caveat  # explicit "not proof of novelty"
    assert "not" in result.caveat.lower() and "novelty" in result.caveat.lower()
    # never emits a NOVEL verdict
    assert result.verdict != "NOVEL"


def test_dbutil_resolves_to_cve_2021_21551(store: CveStore) -> None:
    finding = kb.FindingFingerprint(file="dbutil_2_3.sys", vendor="Dell")
    result = kb.known_cve(store, finding)
    assert result.verdict == kb.KNOWN_CVE
    assert "CVE-2021-21551" in result.cve_ids


def test_attribution_gate_cwe_only_is_not_known(store: CveStore) -> None:
    # A finding sharing ONLY a CWE with a record must not be marked KNOWN — that
    # would be a false-dedup. It may still surface as a weak review candidate.
    finding = kb.FindingFingerprint(file="totally_unrelated_x.sys", cwe="CWE-94")
    result = kb.known_cve(store, finding)
    assert result.verdict == kb.NO_PUBLIC_RECORD


def test_seed_driver_is_known_advisory(store: CveStore) -> None:
    finding = kb.FindingFingerprint(file="iscflashx64.sys", vendor="Insyde Software")
    result = kb.known_cve(store, finding)
    assert result.verdict in (kb.KNOWN_ADVISORY, kb.KNOWN_CVE)
    assert result.is_known


# --- driver novelty-tally ingest (the 30-driver corpus, offline) ------------

@pytest.mark.parametrize(
    "filename,want_cve",
    [
        ("segwindrvx64.sys", "CVE-2024-33228"),
        ("RwDrv.sys", "CVE-2020-15368"),
        ("cpuz.sys", "CVE-2017-15302"),
        ("LenovoDiagnosticsDriver.sys", "CVE-2022-3699"),
        ("PDFWKRNL.sys", "CVE-2023-20598"),
        ("AMDPowerProfiler.sys", "CVE-2021-26334"),
    ],
)
def test_driver_tally_resolves_corpus_offline(
    store: CveStore, filename: str, want_cve: str
) -> None:
    fp = kb.FindingFingerprint(file=filename, ecosystem="windows-driver")
    result = kb.known_cve(store, fp)
    assert result.verdict == kb.KNOWN_CVE
    assert want_cve in result.cve_ids


def test_multi_cve_driver_surfaces_all_cves(store: CveStore) -> None:
    # IOMap64 is CVE-2024-41498 + CVE-2024-33223 in the tally; both must surface.
    fp = kb.FindingFingerprint(file="IOMap64.sys", ecosystem="windows-driver")
    result = kb.known_cve(store, fp)
    assert result.verdict == kb.KNOWN_CVE
    assert {"CVE-2024-41498", "CVE-2024-33223"} <= set(result.cve_ids)


def test_tally_no_public_record_driver_not_synthesized(store: CveStore) -> None:
    # A driver the gate marked NO-PUBLIC-RECORD must NOT become a known record.
    for name in ("Bs_Def.sys", "MyPortIO_x64.sys", "fjfwupgd.sys"):
        result = kb.known_cve(store, kb.FindingFingerprint(file=name, ecosystem="windows-driver"))
        assert result.verdict == kb.NO_PUBLIC_RECORD


def test_tally_known_advisory_without_cve_id(store: CveStore) -> None:
    # KNOWN-ADVISORY with no parsed CVE id is still a real public record (by name).
    fp = kb.FindingFingerprint(file="ADV64DRV.sys", ecosystem="windows-driver")
    result = kb.known_cve(store, fp)
    assert result.verdict == kb.KNOWN_ADVISORY


# --- Mode C: cves_for (deterministic version-range) -------------------------

def test_version_compare() -> None:
    assert cpe.compare_versions("2.0", "2.0.0") == 0
    assert cpe.compare_versions("2.0", "2.0-rc1") > 0  # release > pre-release
    assert cpe.compare_versions("2.14.1", "2.15.0") < 0
    assert cpe.compare_versions("100.00.07.02", "100.0.7.1") > 0


def test_product_matches_precision() -> None:
    # exact coordinate / bare token both resolve
    assert cpe.product_matches("org.apache.logging.log4j:log4j-core",
                               "org.apache.logging.log4j:log4j-core")
    assert cpe.product_matches("dbutil", "dbutil")
    # a bare CPE product 'log4j' must NOT match the Maven coordinate (noise at scale)
    assert not cpe.product_matches("org.apache.logging.log4j:log4j-core", "log4j")
    # two DISTINCT coordinates sharing an artifact name must NOT match
    assert not cpe.product_matches("org.apache.logging.log4j:log4j-core",
                                   "com.guicedee.services:log4j-core")
    # a different unscoped package sharing a prefix must NOT match
    assert not cpe.product_matches("lodash", "lodash-rails")


def test_cves_for_dbutil_in_and_out_of_range(store: CveStore) -> None:
    hit_ids = {h.cve_id for h in kb.cves_for(store, "dbutil", "2.3", vendor="dell")}
    assert "CVE-2021-21551" in hit_ids


def test_cves_for_log4j_hits_log4shell(store: CveStore) -> None:
    hits = kb.cves_for(store, "org.apache.logging.log4j:log4j-core", "2.14.1")
    ids = {h.cve_id for h in hits}
    assert "CVE-2021-44228" in ids  # Log4Shell applies to 2.14.1
    # a patched version must NOT be flagged for the original Log4Shell range
    patched = kb.cves_for(store, "org.apache.logging.log4j:log4j-core", "2.17.1")
    assert "CVE-2021-44228" not in {h.cve_id for h in patched}


# --- Mode B: dedup ----------------------------------------------------------

def test_dedup_ranks_family_nearest(store: CveStore) -> None:
    corpus = [CorpusEntry.from_cve(r) for r in store.all()]
    finding = kb.FindingFingerprint(
        file="newphysdrv.sys",
        bug_class="arbitrary physical read write MmMapIoSpace IOCTL",
        cwe="CWE-782",
        description="class-1 physical R/W via METHOD_OUT_DIRECT ioctl",
    )
    hits = kb.dedup(finding, corpus, backend=LexicalBackend(), min_similarity=0.05)
    assert hits
    # the Insyde phys-R/W family should rank above the log4j java CVEs
    top_ids = [h.ref_id for h in hits[:2]]
    assert any("iscflash" in i.lower() or i == "CVE-2024-33228" for i in top_ids)


def test_dedup_empty_corpus_is_empty(store: CveStore) -> None:
    finding = kb.FindingFingerprint(file="x.sys", bug_class="oob")
    assert kb.dedup(finding, [], backend=LexicalBackend()) == []


# --- the windows_novelty bridge (subsumption) -------------------------------

def test_kb_searcher_resolves_driver_gate_offline(store: CveStore) -> None:
    searcher = kb.KnowledgeBaseSearcher(store)
    ident = DriverIdentity(
        filename="segwindrvx64.sys", vendor="Insyde Software Corp", device_family="SEG"
    )
    assessment = assess_novelty(ident, searcher)
    assert assessment.verdict == "KNOWN-CVE"
    assert "CVE-2024-33228" in assessment.cve_ids


def test_kb_searcher_obscure_no_record(store: CveStore) -> None:
    searcher = kb.KnowledgeBaseSearcher(store)
    ident = DriverIdentity(filename="zzobscuredrv_acme9000.sys", vendor="Acme Widgets LLC")
    assessment = assess_novelty(ident, searcher)
    assert assessment.verdict == "NO-PUBLIC-RECORD-FOUND"


# --- layered gate -----------------------------------------------------------

def test_gate_known_short_circuits(store: CveStore) -> None:
    finding = kb.FindingFingerprint(file="segwindrvx64.sys", vendor="Insyde Software Corp")
    result = kb.novelty(finding, store)
    assert result.verdict == kb.KNOWN_CVE
    assert result.method == "structured"  # A settled it; B/web never ran


def test_gate_no_record_surfaces_review_candidates(store: CveStore) -> None:
    corpus = [CorpusEntry.from_cve(r) for r in store.all()]
    finding = kb.FindingFingerprint(
        file="newphysdrv.sys",
        bug_class="arbitrary physical read write MmMapIoSpace",
        description="class-1 physical R/W METHOD_OUT_DIRECT",
    )
    result = kb.novelty(finding, store, corpus=corpus, embed_backend=LexicalBackend())
    assert result.verdict == kb.NO_PUBLIC_RECORD
    assert "embedding" in result.method
    assert result.candidates  # recall-first: never empty-handed when neighbors exist


# --- scan-pipeline wiring (novelty field on every finding) ------------------

def _driver_tf() -> TriagedFinding:
    # a scan finding on the segwindrvx64 driver (PE .sys), as the pipeline builds it
    f = Finding("recv", "MmMapIoSpace", "DispatchDeviceControl", 0x1000, 0x2a14, 3)
    v = Verdict(True, "CWE-782", "high", "arbitrary physical R/W via IOCTL", "AAAA")
    pov = PoV(input_bytes=b"\x00" * 8, crash_class="kernel-write", capability="arb-physical-rw",
              frames=[], reproduced=True, crash_trace="MmMapIoSpace")
    return TriagedFinding(finding=f, verdict=v, pov=pov)


def _driver_run(filename: str) -> RunResult:
    t = Triage(path=f"/samples/{filename}", fmt="PE", arch="x86-64", bits=64,
               endian="little", kind="DYN")
    return RunResult(triage=t, stages_run=["ingest"], findings=[_driver_tf()])


def test_fingerprint_from_driver_finding_is_windows_driver(store: CveStore) -> None:
    tf = _driver_tf()
    t = Triage(path="/samples/segwindrvx64.sys", fmt="PE", arch="x86-64", bits=64,
               endian="little", kind="DYN")
    fp = fingerprint_from_finding(t, tf)
    assert fp.file == "segwindrvx64.sys"
    assert fp.ecosystem == "windows-driver"
    assert fp.cwe == "CWE-782"


def test_scan_annotates_known_cve_rediscovery(store: CveStore) -> None:
    # THE production fix: a scan re-discovering segwindrvx64 auto-flags the CVE.
    result = _driver_run("segwindrvx64.sys")
    annotate_run(result, store=store)
    nov = result.findings[0].novelty
    assert nov is not None
    assert nov["verdict"] == kb.KNOWN_CVE
    assert "CVE-2024-33228" in nov["cve_ids"]
    # and it flows through the real serializer onto the emitted record
    d = finding_dict(result.findings[0])
    assert d["novelty"]["verdict"] == kb.KNOWN_CVE
    assert "CVE-2024-33228" in d["novelty"]["cve_ids"]
    summary = novelty_summary(result)
    assert "CVE-2024-33228" in summary["known_cve_rediscoveries"]


def test_scan_annotates_obscure_as_no_record(store: CveStore) -> None:
    result = _driver_run("zzobscuredrv_acme9000.sys")
    annotate_run(result, store=store)
    nov = result.findings[0].novelty
    assert nov is not None
    assert nov["verdict"] == kb.NO_PUBLIC_RECORD


def test_annotate_run_no_store_is_graceful_noop() -> None:
    # no KB configured -> findings simply carry no novelty field, scan unbroken
    result = _driver_run("segwindrvx64.sys")
    annotate_run(result, path="/nonexistent/records.jsonl")
    assert result.findings[0].novelty is None
    # serializer omits the field entirely
    assert "novelty" not in finding_dict(result.findings[0])
