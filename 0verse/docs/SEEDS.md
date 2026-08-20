# 0verse Seed Catalog — provenance & engine cross-reference

This documents the **data-driven seed registry**: 90 bug archetypes mined from the
last ~3 years (2023–2025) of CVE-grounded vulnerability research across three
domains — **kernel** (34), **userland** (30), **firmware** (26) — consolidated into
a single auditable, vendored data file and cross-referenced to the 0verse engine
lens / seed-class that implements each one.

- **Data:** [`src/zeroverse/data/archetypes.json`](../src/zeroverse/data/archetypes.json)
  — generalized patterns only (id, name, CWE, pattern, `detection_signature`,
  `grounding`, `confirmable`, `engine_lens`, `route`). **No specific exploit code.**
  The kernel `weaponization_note` field is intentionally excluded; `grounding`
  lists public CVE/advisory identifiers as *witnesses*, not the pattern itself.
- **Loader / audit queries:** [`src/zeroverse/seedcatalog.py`](../src/zeroverse/seedcatalog.py)
  — typed `Archetype` records plus `by_lens`, `implemented`, `hypothesis_only`,
  `for_route`, `summary`.

```python
from zeroverse import seedcatalog
seedcatalog.summary()                       # {'total': 90, 'implemented': 71, ...}
seedcatalog.by_lens("seed:linux-ko:selector-index")   # archetypes behind DRV-01
seedcatalog.hypothesis_only()               # route-to-verify-lane / not-detectable
```

## How a seed becomes detection (honesty over volume)

Each archetype carries a `route` saying *how* (or whether) 0verse acts on it:

| route | meaning | confirmed by |
|---|---|---|
| `kernel-static` | statically-strong `.ko` seed-class; ranked **hypothesis** | bench KASAN verify lane |
| `kernel-verify` | kernel **hypothesis-only** (deferred-free / RCU / refcount / race) | bench KASAN verify lane |
| `not-binary-detectable` | needs source / live oracle (BPF verifier, core-mm, cred) | source analysis (hand-off) |
| `userland-confirmable` | static lens → **PoV** | diff-allocator + CASR + canary / exec-trap |
| `userland-med` | confirmable once a specific path/state is driven | same, with protocol stepping |
| `userland-hypothesis` | race/signal-gated (e.g. regreSSHion) | static hint is the deliverable |
| `firmware-lane` | per-handler Qiling oracle | cmdi-canary / crash oracle |
| `firmware-lane-partial` | needs socket/daemon or rootfs scaffolding | partial Qiling + nvram model |
| `firmware-static` | static-only (backdoor, hardcoded key, update crypto) | constant extraction / call-graph |
| `firmware-detect-only` | baseband — detect, hand off to specialist emulator | FirmWire/ShannonEmu (hand-off) |

`engine_lens` names the implementing component, e.g. `bugclass:cmdi`,
`bugclass:overflow`, `seed:linux-ko:selector-index`, `seed:firmware:cgi-cmdi`, or
`null` (catalogued but no binary lens — an honest hand-off).

## Kernel — statically-strong seed-classes (the binary `.ko` lane)

11 of 34 kernel archetypes are statically strong on a stripped `.ko` and now ship
as `seedbugs.py` seed-classes (ranked hypotheses; a `.ko` finding is never
upgraded to *confirmed* without a PoV on a live kernel):

| archetype | seed-class |
|---|---|
| DRV-01 ioctl selector-index OOB | `seed:linux-ko:selector-index` (indexed indirect call) |
| DRV-02 / SOCK-03 / FS-01 user-len copy | `seed:linux-ko:copy-from-user` |
| DRV-03 alloc-size int-overflow | `seed:linux-ko:kmalloc-overflow` |
| DRV-04 missing `capable()` gate | `seed:linux-ko:missing-capable` |
| DRV-07 ioctl double-fetch | `seed:linux-ko:double-fetch` |
| DRV-08 mmap `vm_pgoff`/`remap_pfn_range` | `seed:linux-ko:mmap-pgoff` |
| MM-03 / SCH-04 uninit copy-to-user infoleak | `seed:linux-ko:uninit-infoleak` (missing memset) |
| NF-03 netlink length/range OOB | `seed:linux-ko:netlink-oob` |

The remaining ~21 kernel families (deferred-free / RCU / GC / refcount /
concurrency UAFs — NF-01/02/04/05, SCH-01/02/03, SOCK-01/02/04, DRV-05/06,
MISC-01/02, IOU-*, BPF-*, MM-01/02, FS-02/03) are **`kernel-verify` hypotheses**:
they can NOT be bare-binary-confirmed (the free happens in a different
callback/worker than the use). Three representative matchers ship tagged
`route="kernel-verify"` (`seed:linux-ko:deferred-free-uaf`, `…:refcount-uaf`,
`…:errpath-double-free`) so the funnel surfaces them and routes them to the KASAN
lane — **never auto-confirmed**. BPF/core-mm are `not-binary-detectable`.

## Userland — mechanical lens upgrades (the confirmable set)

The 30 userland archetypes sharpened the five userland lenses. Highlights now in
`bugclasses.py`:

- **uaf**: `realloc` added to the free-set (frees + moves; UAF-03); `*_put` /
  `*_release` / `*_unref` / `kref_put` treated as conditional frees (UAF-04).
- **intoverflow**: signed-check/unsigned-use detector (IO-03, CWE-839); additive
  `hdr+len1+len2` sums (IO-02); `calloc(a,b)` downgraded (self-guarded, IO-01).
- **overflow** (new lens): `stpcpy` / `sprintf("…%s…")` / ignored-`strlcat` sinks
  (OF-04/09), and a loop-writer sub-lens (cursor-vs-alloc-end across a back-edge,
  OF-02/06). `getenv` + `argv[]` are first-class taint sources.
- **fmtstring**: per-function format-arg position fixed (printf=0, fprintf=1,
  snprintf=2, syslog=1, **warn=0 / err=1**); `syslog` / `err*` / `warn*` / `v*`
  family added; `.rodata`-literal formats FP-suppressed.
- **cmdi**: `popen` / shell-`execl*` + **argv-injection (CWE-88)** — a tainted
  argv element to `execv*`/`posix_spawn` (no shell). `getenv`/config taint sources.

**New oracle — exec-trap (cmdi).** The memory oracle is blind to command
injection. `oracle.build_exectrap_shim()` builds an LD_PRELOAD shim that intercepts
`system`/`popen`/`exec*`/`posix_spawn`; when a per-run sentinel token reaches an
exec argument it emits a token-bound capability marker and `_exit`s **before**
running the command — confirming injection (including CWE-88, where nothing is
echoed) without executing anything harmful. Wired as the `cmdi` class's confirming
oracle (`bugclasses._confirm_cmdi`), with the `echo`-canary as a no-compiler
fallback.

## Firmware — priming the MIPS/ARM lane

The firmware cmdi (unauth CGI/config getter → `system`) and stack-overflow
archetypes prime the firmware lane via two seed-classes
(`seed:firmware:cgi-cmdi`, `seed:firmware:stack-overflow`) keyed on the vendor
getter symbols that survive stripping (`websGetVar` / `nvram_get` / `get_cgi` /
`getenv` / `recv`). They are primed by arch — `seedbugs.firmware_seeds_for_arch()`
— for MIPS/ARM/AArch64 targets and are confirmable in the Qiling firmware lane
(cmdi-canary / crash oracle). Backdoors, hardcoded keys and update-crypto logic are
catalogued as `firmware-static` (static-only, high-confidence) hand-offs.

## Maintaining the catalog

Add or revise an archetype by editing `data/archetypes.json` (data, not code) and
— if it becomes detectable — pointing `engine_lens` at the implementing lens/seed.
`seedcatalog.summary()` and the `tests/test_seedcatalog.py` invariants keep the
data and the engine in sync.
