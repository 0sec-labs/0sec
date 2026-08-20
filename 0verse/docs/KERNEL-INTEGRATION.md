# 0verse — the binary-only kernel lane

> Status: 2026-06-28. Living document.

0verse is 0sec's **binary-only** vulnerability-research engine. For kernel work it
is the tool you reach for when there is **no source**:

| Surface | Tool | Why |
|---|---|---|
| Upstream Linux **with source** | **syzkaller / source analysis** (CodeQL, Semgrep, coverage-guided fuzzing) | You have the tree. Source-level taint + KCOV/KASAN feedback beats decompiling. |
| Closed / out-of-tree `.ko` drivers | **0verse** | No source — only a relocatable ELF. |
| Firmware kernel blobs, vendor BSPs | **0verse** | Shipped as binaries; often stripped. |
| Vendor / Android kernels & modules | **0verse** | Source unavailable or diverged from upstream; modules ship as `.ko`. |
| macOS / XNU kexts | **0verse** | Closed Mach-O kernel extensions (IOKit). |
| n-day binary diffing | **0verse** | Diff a patched vs unpatched blob; no source needed. |

The rule of thumb: **if you have the source, 0verse is the wrong tool** — use the
source lane. 0verse earns its keep precisely where source-analysis can't run.

## What 0verse does on a kernel binary

0verse classifies the target, decompiles it (Ghidra by default), and primes a
**seed-bug-class** — a directed, Big-Sleep-style variant-analysis hypothesis set
keyed to the surface. Two kernel families ship today (`src/zeroverse/seedbugs.py`):

- **Linux `.ko`** (`origin seed:linux-ko:*`) — five kernel-module LPE classes:
  - `linux-ko:copy-from-user` — `copy_from_user`/`copy_to_user` with a
    user-controlled size into a fixed buffer → OOB (CWE-787 / CWE-125). *Flagship.*
  - `linux-ko:ioctl-dispatch` — `unlocked_ioctl`/`compat_ioctl` cmd dispatch where
    a user selector/size reaches a copy/alloc with no bound (CWE-129).
  - `linux-ko:kmalloc-overflow` — `kmalloc`/`kvmalloc`/`vmalloc` size **arithmetic**
    (`a*b`, `a<<n`, `a+len`) that wraps → undersized alloc (CWE-190 → CWE-122).
  - `linux-ko:user-deref` — unchecked `__user` pointer deref / `get_user`/`put_user`
    misuse (CWE-822).
  - `linux-ko:missing-capable` — privileged op with **no** `capable()`/`ns_capable()`
    gate (CWE-862, **hypothesis-only**, no generic oracle).
- **macOS / XNU kext** (`origin seed:iokit.*`) — IOKit user-client `externalMethod`
  dispatch OOB / missing input-count check.

### Why detection survives stripping

The detection hook is the same trick for both families: **kernel-exported symbols
survive stripping.** A `.ko` references `copy_from_user`, `__kmalloc_noprof`,
`__get_user_8`, … as *undefined* symbols the module loader resolves at load time —
so they stay in the symbol table (and the relocations) even when the driver's own
function names are stripped to `FUN_xxx`. The decompiler renders the call by name,
and the seed class keys off that surviving name, not the (gone) handler name. The
module-identity markers (`.modinfo`, `module_layout`, `__this_module`) survive for
the same reason (the loader needs them), so a stripped vendor/Android `.ko` still
classifies as `KMOD`. (XNU's equivalent surviving symbols are `IOMalloc`/`copyin`.)

### Honest degrade — `.ko` findings stay hypotheses

A bare `.ko` has **no dynamic oracle**. 0verse's confirmable bug-classes
(int-overflow, fmtstring, UAF, cmdi) prove themselves with a reproducing PoV under
a differential/quarantine allocator — that requires *running* the target. You
cannot run a `.ko` without a live kernel / VM, which is out of scope for a static
binary scan. Therefore every `.ko` seed finding is a **hypothesis** (`confirmed =
false`, `hypothesis = true`) and is **never** upgraded to confirmed without a PoV
on a live kernel. This is the PoV-is-truth gate (`docs`/`api.py`) holding for the
kernel lane. To confirm, hand the ranked hypothesis to a kernel PoV harness
(kernelCTF / a KASAN VM) — that lives outside 0verse.

## How a kernel-hunt agent calls 0verse

0verse exposes the engine over the **MCP bridge** (`src/zeroverse/mcp.py`), so an
agent that hits a binary-only kernel surface calls it as a tool — same engine,
one versioned contract (`api.CONTRACT_VERSION`):

```
scan_binary(path)            # run the pipeline on a .ko / kext / firmware blob
list_findings()              # the hypotheses (origin seed:linux-ko:* etc.)
get_pov(finding_id)          # a reproducing PoV, when a confirmable class produced one
get_report(format=sarif)     # full report (json | ndjson | sarif)
```

Routing decision for the hunt agent:

1. **Do I have the kernel/module source?** → yes: syzkaller / source analysis. Stop.
2. **No source, binary-only kernel surface** (closed `.ko`, firmware, vendor/Android,
   XNU kext, n-day diff)? → call `scan_binary(path)`.
3. Read `list_findings()`; the `seed:linux-ko:*` / `seed:iokit.*` origins are the
   directed kernel hypotheses. Treat them as **leads**, not bugs.
4. Confirmation needs a live kernel — route the lead to a kernelCTF/KASAN PoV
   harness. 0verse will not (and must not) report a `.ko` finding as confirmed.

### MCP smoke test

Point the bridge at a real compiled `.ko` and confirm it classifies + routes:

```python
from zeroverse.mcp import Engine
out = Engine().scan_binary("/path/to/driver.ko")
assert out["format"] == "ELF"        # classified + routed as an ELF kernel module
assert out["confirmed"] == 0          # honest degrade — hypotheses only on a bare .ko
# list_findings() then carries the seed:linux-ko:* hypotheses (Ghidra present).
```

With Ghidra available, `list_findings()` surfaces the `seed:linux-ko:*` hypotheses
(e.g. `copy-from-user`, `kmalloc-overflow`, `user-deref`, `missing-capable` on a
vulnerable ioctl handler). Without Ghidra the bridge still classifies the `.ko`
and degrades to ingest-only — it never fabricates a finding.
