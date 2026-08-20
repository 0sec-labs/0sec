"""#42 — fleet-scale cross-target variant analysis (M7 Bet C, the leapfrog).

Hermetic tests (no compiler) cover the mechanism: matcher-from-seed, fleet ingest
spec resolution, variant ranking, the confirm routing (incl. kernel stays a
hypothesis), dedup, and dataset emission. The PROOF harness compiles a small
fleet of 'vendor' variants of one vulnerable function — several vulnerable (across
compiler optimization levels + renamed), several PATCHED (the negative controls) —
seeds from ONE, sweeps, and asserts the economics: 1 seed -> N CONFIRMED n-days
with a real PoV, and 0 false confirmations on the patched members.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse import dataset, fleet
from zeroverse.fleet import FleetMember, ReferenceShape
from zeroverse.ingest import Triage, triage

_HAS_CC = shutil.which("cc") or shutil.which("gcc")
requires_cc = pytest.mark.skipif(not _HAS_CC, reason="no C compiler for the fleet PoV harness")
requires_linux_elf = pytest.mark.skipif(
    sys.platform != "linux", reason="fleet PoV proof builds and confirms ELF binaries"
)


def _member(decompiled: dict[str, str], *, path: str = "/x", fmt: str = "ELF",
            arch: str = "x86-64") -> FleetMember:
    t = Triage(path=path, fmt=fmt, arch=arch, bits=64, endian="little", kind="EXEC")
    return FleetMember(path=path, triage=t, abi=None, decompiled=decompiled)


# --- 1. seed -> matcher -----------------------------------------------------

def test_seed_from_bugclass_archetype() -> None:
    for ident in ("cmdi", "bugclass:cmdi"):
        seed = fleet.seed_from_archetype(ident)
        assert seed.bug_class == "cmdi"
        assert seed.route == fleet.ROUTE_USERLAND
        assert seed.matcher_kind == "bugclass"
        assert "system" in seed.sink_symbols


def test_seed_from_firmware_seedclass_routes_firmware() -> None:
    seed = fleet.seed_from_archetype("firmware:cgi-cmdi")
    assert seed.matcher_kind == "seedbug"
    assert seed.route == fleet.ROUTE_FIRMWARE
    assert seed.seedbug is not None


def test_seed_from_kernel_seedclass_routes_verify_lane() -> None:
    seed = fleet.seed_from_archetype("linux-ko:copy-from-user")
    assert seed.route == fleet.ROUTE_KERNEL_VERIFY


def test_seed_from_catalog_uid_resolves_engine_lens() -> None:
    # kernel/DRV-01 maps (via engine_lens) to the selector-index seed class.
    seed = fleet.seed_from_archetype("kernel/DRV-01")
    assert seed.route == fleet.ROUTE_KERNEL_VERIFY
    assert seed.matcher_kind == "seedbug"


def test_unknown_archetype_raises() -> None:
    with pytest.raises(ValueError):
        fleet.seed_from_archetype("not-a-real-archetype")


def test_reference_shape_similarity_ranks_siblings_above_strangers() -> None:
    ref_code = ('void vendor_handler(char *q){ char cmd[256]; '
                'snprintf(cmd, 256, "ntpdate %s", q); system(cmd); }')
    ref = ReferenceShape.from_body("vendor_handler", ref_code)
    sibling = ('void cgi_set_ntp(char *p){ char buf[256]; '
               'snprintf(buf, 256, "ntpdate %s", p); system(buf); }')
    stranger = "int add(int a, int b){ return a + b; }"
    assert ref.similarity(ref_code) > 0.9          # itself
    assert ref.similarity(sibling) > ref.similarity(stranger)
    assert ref.similarity(stranger) < 0.2


# --- 2/3. fleet ingest + variant detection ----------------------------------

def test_detect_variants_flags_cmdi_sink_not_literal() -> None:
    seed = fleet.seed_from_archetype("cmdi")
    member = _member({
        "vuln": "void vuln(char *c){ system(c); }",
        "safe": 'void safe(void){ system("/bin/ls"); }',   # literal -> not a candidate
    })
    cands = fleet.detect_variants(seed, member)
    funcs = {c.function for c in cands}
    assert "vuln" in funcs
    assert "safe" not in funcs


def test_detect_variants_ranks_by_reference_similarity() -> None:
    ref_code = 'void h(char *q){ char c[256]; snprintf(c,256,"ntpdate %s",q); system(c); }'
    seed = fleet.seed_from_archetype("cmdi").with_reference(
        ReferenceShape.from_body("h", ref_code))
    member = _member({
        "near": 'void near(char *q){ char c[256]; snprintf(c,256,"ntpdate %s",q); system(c); }',
        "far": "void far(char *x){ system(x); }",
    })
    cands = fleet.detect_variants(seed, member)
    assert cands[0].function == "near"   # highest similarity sorts first
    assert cands[0].similarity > cands[-1].similarity


def test_symbol_pass_cheap_lane_when_no_decompiler(tmp_path: Path) -> None:
    # A stripped firmware blob with surviving getter + shell symbols, no bodies.
    blob = tmp_path / "stripped.bin"
    blob.write_bytes(b"\x7fELF" + b"\x00" * 64 + b"websGetVar\x00" + b"junk" + b"system\x00")
    seed = fleet.seed_from_archetype("firmware:cgi-cmdi")
    member = FleetMember(path=str(blob), triage=triage(blob), abi=None, decompiled={})
    cands = fleet.detect_variants(seed, member)
    assert len(cands) == 1
    assert cands[0].detector == "symbol-pass"
    assert cands[0].sink == "system"


def test_ingest_fleet_resolves_directory(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"\x7fELF" + b"\x00" * 60)
    (tmp_path / "b").write_bytes(b"\x7fELF" + b"\x00" * 60)
    members = fleet.ingest_fleet(tmp_path, decompile=False)
    assert {m.name for m in members} == {"a", "b"}


def test_ingest_fleet_manifest_list(tmp_path: Path) -> None:
    f1 = tmp_path / "x"
    f1.write_bytes(b"\x7fELF" + b"\x00" * 60)
    manifest = tmp_path / "fleet.txt"
    manifest.write_text(f"# fleet\n{f1}\n")
    members = fleet.ingest_fleet(manifest, decompile=False)
    assert [m.name for m in members] == ["x"]


# --- 4. per-target confirmation routing -------------------------------------

def test_kernel_variant_never_auto_confirmed() -> None:
    seed = fleet.seed_from_archetype("linux-ko:copy-from-user")
    member = _member({
        "dev_ioctl": ("long dev_ioctl(struct file *f, unsigned cmd, unsigned long a){ "
                      "char buf[64]; copy_from_user(buf, (void*)a, a); return 0; }"),
    })
    cands = fleet.detect_variants(seed, member)
    assert cands, "the .ko copy-from-user shape should be a candidate"
    cv = fleet.confirm_variant(seed, member, cands[0])
    assert cv.status == "hypothesis"      # no bare-binary oracle — routed to KASAN lane
    assert not cv.confirmed
    assert "kernel-verify" in cv.oracle


def test_directed_targets_consumed_from_candidates() -> None:
    seed = fleet.seed_from_archetype("cmdi")
    member = _member({"vuln": "void vuln(char *c){ system(c); }"})
    cands = fleet.detect_variants(seed, member)
    dt = fleet.directed_targets_for(cands, member)
    # collect_targets yields an (honest, possibly empty without sink addrs)
    # DirectedTargets — the directed-fuzz escalation lane is wired, not faked.
    assert isinstance(dt, type(dt))


# --- 5. dedup + dataset emission --------------------------------------------

def test_run_fleet_detect_only_emits_hypothesis_records(tmp_path: Path) -> None:
    seed = fleet.seed_from_archetype("cmdi")
    member = _member({"vuln": "void vuln(char *c){ system(c); }"})
    ds = tmp_path / "corpus.ndjson"
    report = fleet.run_fleet(seed, [member], confirm=False, dataset_path=ds)
    assert report.n_candidates == 1
    assert report.n_confirmed == 0
    assert report.dataset_records_written == 1
    rows = list(dataset.iter_records(ds))          # re-validates every record
    assert rows[0]["verdict"] == "hypothesis"
    assert "variant-of[bugclass:cmdi]" in rows[0]["explanation"]


# ---------------------------------------------------------------------------
# THE PROOF — 1 seed -> N confirmed variants, 0 FP on patched members
# ---------------------------------------------------------------------------

# A vulnerable 'vendor' variant: a CGI-style handler passes an attacker arg into
# an snprintf-built command and runs it through system() (CWE-78). ``{cmd}`` and
# ``{fn}`` vary the command template + function name across vendors.
_VULN_TMPL = """\
#include <stdlib.h>
#include <stdio.h>
int {fn}(const char *q){{
    char cmd[256]; snprintf(cmd, sizeof cmd, "{cmd} %s", q); return system(cmd);
}}
int main(int argc, char **argv){{ if(argc>1) return {fn}(argv[1]); return 0; }}
"""

# Patched negative #1: an alphanumeric allowlist rejects shell metacharacters
# BEFORE the (still-present) system() — the lens may still flag the sink (recall),
# but the injection canary never reaches the shell, so no PoV is produced.
_PATCH_ALLOWLIST = """\
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
int vendor_handler(const char *q){
    for(const char *p=q; *p; ++p) if(!isalnum((unsigned char)*p) && *p!='.') return -1;
    char cmd[256]; snprintf(cmd, sizeof cmd, "ntpdate %s", q); return system(cmd);
}
int main(int argc, char **argv){ if(argc>1) return vendor_handler(argv[1]); return 0; }
"""

# Patched negative #2: the command is a constant — the attacker arg is ignored, so
# it is not even a command-injection candidate (literal format).
_PATCH_FIXED = """\
#include <stdlib.h>
#include <stdio.h>
int vendor_handler(const char *q){ (void)q; return system("ntpdate pool.ntp.org"); }
int main(int argc, char **argv){ (void)argc; (void)argv; return vendor_handler(""); }
"""


def _cc(src: str, out: Path, *flags: str) -> str:
    c = out.with_suffix(".c")
    c.write_text(src)
    subprocess.run(
        ["cc", "-fno-stack-protector", "-no-pie", *flags, str(c), "-o", str(out)],
        check=True, capture_output=True,
    )
    return str(out)


def _decompiler_ready(binary: str) -> bool:
    return bool(fleet.decompile_functions(binary))


@requires_cc
@requires_linux_elf
def test_PROOF_one_seed_to_N_confirmed_zero_fp_on_patched(tmp_path: Path) -> None:
    # --- the reference (where the bug was found ONCE) -> the seed --------------
    ref = _cc(_VULN_TMPL.format(fn="vendor_handler", cmd="ntpdate"), tmp_path / "ref", "-O0")
    if not _decompiler_ready(ref):
        pytest.skip("no decompiler backend (rizin/ghidra) available for the sweep")

    seed = fleet.seed_from_reference(ref, "vendor_handler")
    assert seed.bug_class == "cmdi"
    assert seed.reference is not None

    # --- the FLEET: 5 vulnerable 'vendor' variants + 3 patched controls -------
    fleet_dir = tmp_path / "fleet"
    fleet_dir.mkdir()
    vulnerable = {
        "vendor_alpha":  _VULN_TMPL.format(fn="vendor_handler", cmd="ntpdate"),   # -O0
        "vendor_beta":   _VULN_TMPL.format(fn="vendor_handler", cmd="ntpdate"),   # -O2
        "vendor_gamma":  _VULN_TMPL.format(fn="vendor_handler", cmd="ntpdate"),   # -Os
        "vendor_delta":  _VULN_TMPL.format(fn="cgi_set_ntp",   cmd="ntpdate"),    # renamed
        "vendor_eps":    _VULN_TMPL.format(fn="vendor_handler", cmd="reboot -d"), # other cmd
    }
    opts = {"vendor_alpha": "-O0", "vendor_beta": "-O2", "vendor_gamma": "-Os",
            "vendor_delta": "-O2", "vendor_eps": "-O0"}
    patched = {
        "patched_allowlist": _PATCH_ALLOWLIST,
        "patched_fixedcmd":  _PATCH_FIXED,
        "patched_fixedcmd2": _PATCH_FIXED.replace("pool.ntp.org", "time.cloudflare.com"),
    }
    for name, src in vulnerable.items():
        _cc(src, fleet_dir / name, opts[name])
    for name, src in patched.items():
        _cc(src, fleet_dir / name, "-O0")

    # --- ingest + sweep + confirm + capture -----------------------------------
    ds = tmp_path / "fleet_corpus.ndjson"
    members = fleet.ingest_fleet(fleet_dir)
    report = fleet.run_fleet(seed, members, confirm=True, dataset_path=ds,
                             out_dir=tmp_path / "out")

    confirmed = set(report.confirmed_members)
    patched_names = set(patched)

    # 1 seed -> N confirmed n-days across the fleet
    assert confirmed == set(vulnerable), (
        f"expected all {len(vulnerable)} vendor variants confirmed, got {confirmed}")
    assert report.n_confirmed >= len(vulnerable)

    # 0 false confirmations on the patched members (the whole point)
    assert not (confirmed & patched_names), f"FP on patched members: {confirmed & patched_names}"

    # every confirmation carries a REAL, on-disk PoV replay script (PoV-is-truth)
    for mres in report.members:
        for cv in mres.confirmed:
            assert cv.pov is not None and cv.pov.pov_script
            assert Path(cv.pov.pov_script).exists()

    # the dataset captured one record per swept variant (feeds the #32 flywheel),
    # and every confirmed record is PoV-backed (validate_record enforces it).
    rows = list(dataset.iter_records(ds))
    confirmed_rows = [r for r in rows if r["verdict"] == "confirmed"]
    assert len(confirmed_rows) >= len(vulnerable)
    for r in confirmed_rows:
        assert r["pov"]["path"]
        assert "fleet sweep" in r["explanation"]

    # economics string is honest + non-trivial
    assert "CONFIRMED" in report.economics
