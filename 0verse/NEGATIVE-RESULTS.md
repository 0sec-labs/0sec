# 0verse negative-results log

> The auditable honesty record. PoV-is-truth cuts both ways: a run that confirms
> *nothing* is still a result, and recording it is what keeps the project honest.
> This is the **human-curated** half (the seeded residuals from M1–M6); the
> **machine** half is the append-only NDJSON written by `zeroverse.negative` (one
> record per negative run — see "Machine log" below).
>
> A finding without a reproducing PoV is a *hypothesis*, not a win. Everything in
> this file is a place where 0verse honestly does **not** confirm a bug, by design
> or by current limitation.

## Linux 6.12.94 KMSAN raw corpus: reclaim/block false signal

**Status:** negative triage; preserved evidence, no disclosure candidate.

The paused 18-bucket KMSAN corpus was reviewed on 2026-07-12. Its sanitizer
labels include `dma_direct_unmap_sg`, `__blk_rq_map_sg`,
`__end_swap_bio_write`, and `xas_create`, but their origin and consuming stacks
cross unrelated reclaim, swap, ATA/SCSI, TTY, and networking activity. Reports
occur in UID 0 background workers after severe memory pressure, have no
minimized reproducer, and do not show bytes returned across a user/kernel
boundary. Other buckets are hangs, corrupted stacks, suppressed reports, or VM
loss. This is consistent with KMSAN metadata/state corruption in the
memory-starved test environment, not evidence of an unprivileged information
disclosure or exploitable UAF. The historical workdir remains unchanged.

## Fidelity gaps & honest degrades (carried from M1–M5)

These are documented in `ROADMAP.md` / `docs/INTEGRATION.md` and re-stated here as
the standing negative-results baseline:

- **Mach-O dynamic confirmation needs a Mac/XNU host (#18).** Mach-O ingest, the
  Ghidra static slice, foxguard, and LLM triage all run on Linux, but dynamic
  confirmation (oracle/fuzz) of arm64 Mach-O needs a macOS/XNU host or emulator.
  On Linux, Mach-O findings stay **hypotheses** — we never fake a crash. The
  IOKit/externalMethod seed-bug-class primes high-value *leads*, not confirmations.
- **rizin / angr decompiler backends are lower-fidelity (#27).** The non-Ghidra
  fallbacks mine a pseudo-C IL: they recover call sites + argument names + return
  def-use, but **not** SSA-grade def-use and **no per-instruction addresses**. The
  slice + differential oracle still confirm, but recall is lower and the note says
  so.
- **angr reachability (#5) is disabled on the fallback backends.** The concolic
  prune stage keys on real sink VAs + the function entry, which only the Ghidra
  backend recovers. On rizin/angr-pseudo-C backends the stage is **skipped** — no
  UNSAT pruning, so more hypotheses survive to (or past) the oracle.
- **The logic / auth-bypass class is hypothesis-only (#26).** There is no generic
  binary oracle for "missing check / off-by-one / auth bypass", so these are
  surfaced as high-value funnel leads and **never** marked confirmed without a PoV.
  An honest, permanent confirmation gap for this class.
- **PE is static-only unless a real Windows worker is configured (#20).** Slice +
  foxguard + LLM triage (+ angr where CLE loads the PE) run locally. SSH dispatch is
  live-accepted through PageHeap+cdb; Dr. Memory 2.6.0 fails on the current lab build.
  Full discovery still needs WinAFL on Windows. Without the real worker, PE findings
  remain hypotheses; wine is never treated as confirmation.
- **MIPS/ARM firmware uses the Qiling lane, not native execution (#21).** A genuine
  router image is out of scope on the bench; the lane is proven on a committed MIPS
  ELF and the real-image rootfs carve is documented, never faked.
- **foxguard pre-pass: no C++ grammar; Ghidra noise costs recall.** Indirect calls,
  SSA-ish temporaries, and gotos in Ghidra pseudo-C reduce foxguard's recall and add
  some false positives; normalization mitigates but does not eliminate this.

## Benchmark negatives (M6 #33)

From `docs/BENCHMARKS.md` (60 s budget, 2026-06-28):

- **`ungated` target: 0verse ties — and baseline AFL++ was marginally *faster*
  (0.5 s vs 0.8 s).** On a target with no structural gate, 0verse's
  dictionary/CMPLOG machinery is pure overhead and adds no value over plain AFL++.
  Reported as a tie inside the noise floor — not spun as a win.
- **Harness synthesis has no plain-AFL++ baseline.** The comparison holds the
  synthesized harness constant, so it measures the seed/dictionary/CMPLOG
  contribution only — *not* the value of harness synthesis itself. We do not claim a
  measured win for harness-synth.

## Harness / comparison artifacts found & fixed (M6)

Recorded so the next contributor doesn't re-derive them:

- **Mining string literals from a target's *comments* poisoned the seed corpus.**
  An early version of the benchmark mined a quoted string out of a C **comment**,
  producing a seed that itself crashed; AFL++ aborts on a crashing start seed →
  the lane falsely showed "no crash". Fixed by holding the seed corpus identical
  (single `\x00`) across lanes and varying only {dictionary + CMPLOG}. (Real
  decompiled code has no comments, so this was a benchmark-harness artifact, not an
  engine bug — but worth logging.)
- **Stack-buffer overflow targets confirm flakily under the differential-allocator
  oracle.** The guard-page oracle instruments the **heap**; a stack OOB caught by
  ASAN during fuzzing did not reproduce deterministically under the stock-vs-guard
  allocator replay. Benchmark targets were switched to `malloc`'d buffers (matching
  the rest of the corpus). The standing limitation: **the differential-allocator
  oracle is heap-shaped** — stack-only corruption needs a different confirmer.

## Campaign architecture negatives

- **2026-07-13 vmSwitch packet-parser family:** PDB-mapped comparison of GA
  26100.1 and serviced 26100.8655 reviewed IPv4, IPv6, IPv6 extensions, GRE,
  VXLAN, DHCP, and first-packet ingress. Actual packet-length checks dominate
  every subtraction and variable header consumption. The apparent unchecked
  IPv6 extension callback uses `NdisGetDataBuffer_exref` with matching length
  gates and caller-owned scratch storage, so fragmentation does not make the
  result nullable. Verdict: static negative; no trigger justified. Evidence is
  in `benchmarks/windows_negative/vmswitch-packet-parser-validation-26100.8655/`.

- **2026-07-13 exact-LTS POSIX mqueue disposable pilot:** a one-VM setuid smoke
  reached all intended mqueue syscalls plus signalfd/epoll interactions and
  exited cleanly with zero crashes. Generated timed waits reduced throughput to
  about 62 executions/minute; after 179 executions the manager retained zero
  corpus and zero aggregate coverage despite raw per-call KCOV output. Verdict:
  unhealthy config, not promoted. An attempted nonblocking lifecycle seed improved
  throughput to ~230/min over 662 executions, but triage still retained zero
  corpus/coverage. Debug then proved successful mqueue calls produce four-digit
  raw KCOV and non-empty manager signal. Repacking the accidentally version-0
  corpus as current version 5 still admitted nothing over 676 executions. The
  remaining failure is post-signal stability/admission, not KCOV transport.
  Candidate-only replay then found and fixed a raw-ABI error (the libc-style
  leading slash) and two output-pointer encodings. The corrected setuid seed
  genuinely created, sent to, notified, unlinked, and closed a queue, but an
  isolated admission run still retained nothing after 401 executions. The lane
  design is retired rather than extended. Evidence is in
  `benchmarks/kernel_negative/mqueue-exact94-pilot-2026-07-13.md`.

- **2026-07-13 vmSwitch short-checksum hypothesis:** PDB-backed analysis found
  unsigned `packet_len - 14` arithmetic and a possible checksum-field store at
  output offset 24 in both GA 26100.1 and serviced 26100.8655. Caller tracing
  tied the output allocation to packet length, but the guest ingress chain
  supplies a dominating guard: `VmsVmNicPvtConvertRndisPacketToNbl` compares
  the parsed RNDIS data length with 14 and returns `STATUS_INVALID_PARAMETER`
  when it is smaller, before NBL allocation. Verdict: falsified for the
  investigated guest RNDIS path, no vulnerability claim. Prepared trigger
  modules were never loaded or invoked and were retired. Exact assembly and
  disposition are in
  `benchmarks/windows_candidates/vmswitch-short-checksum-underflow-26100.1/NEGATIVE-RESULT.md`.
- **2026-07-13 current vmSwitch RNDIS scalar validators:** a broader bounded
  review covered packet/PPI validation, MDL parsing, NBL conversion, PD-buffer
  conversion, and version-1 send-buffer handling in build 26100.8655. The code
  uses subtract-before-compare region checks, validates fixed structure sizes
  and reserved fields, enforces the Ethernet minimum in both conversion
  backends, and bounds send-buffer indices/sizes. No scalar offset/length or
  short-frame candidate survived. This does not clear stateful lifetime paths;
  it redirects future work toward batching, completion/cancellation,
  suballocation reuse, and teardown. Evidence is in
  `benchmarks/windows_negative/vmswitch-rndis-ingress-validation-26100.8655/`.
  A follow-up on the stateful suballocation helpers found an apparent exact-end
  fragment-walk hazard in isolation, but every reviewed RNDIS caller supplies
  internal offsets and pairs variable offset 24 with an
  `allocation >= payload + 24` check; zero-length copies return before walking.
  Allocation classes/free lists are internal metadata and completion is
  reference-counted. No guest-controlled caller invariant violation was found.
  A teardown follow-up found the primary channel disables servicing and waits
  for rundown to drain before checking outstanding packet/control/send counters
  and resetting state. Acquire/release pairs rundown protection with an
  interlocked operation pool, and completion clears backing state before VMBus
  completion. No close-versus-complete UAF or double completion survived the
  reviewed ordering.

- **2026-07-11 Mozilla Nightly JS-shell monolith:** explicit Ghidra analysis of the
  current official shell exposed ~43k symbols. Even after attack-surface ordering and
  a 1,600-function cap, the external 30-minute deadline terminated PyGhidra during
  export (`JVMNotRunning` during forced shutdown), leaving no result artifact. This
  is neither a vulnerability miss nor a clean scan. Verdict: whole-browser/engine
  monolithic decompilation is not an operational campaign; use component-native fuzz
  targets and browser-level replay.
- **2026-07-11 Linux `cleanup_prefix_route` bucket:** the 6.12.93 KASAN
  null-pointer write exactly matches CVE-2026-53214 and upstream fix
  `b70c687b7cf267fb08586667a3946c8851cad672`, shipped in 6.12.94. Syzkaller
  could not minimize the historical crash, and the current campaign kernel
  already contains the sentinel check. Verdict: known/fixed duplicate, not a
  0sec finding and not a bounty candidate.
- **2026-07-12 KCSAN AF_ALG revalidation background reports:** the temporary
  one-VM setuid manager recorded one report each for
  `d_lru_del / proc_sys_compare`, `process_one_work`, and
  `__call_rcu_common / mas_walk`. None names the AF_ALG target functions, none
  has a syzkaller reproducer, and unrelated races repeatedly recycled the only
  VM. They are quarantined as non-evidence for the AF_ALG candidate, not claimed
  as globally disproven bugs. The noisy manager is disabled; the bounded
  standalone guest attempted a KCSAN whitelist for only `af_alg_pull_tsgl` and
  `af_alg_sendmsg`, but this upstream 6.12.94 build exposes no writable runtime
  whitelist. Its exact-seed run is therefore explicitly unfiltered and all
  non-AF_ALG reports remain quarantined.
- **2026-07-12 AF_ALG `ctx->used` race impact gate:** the exact recovered seed
  reproduced `af_alg_pull_tsgl / af_alg_sendmsg` as UID 65534 on isolated KCSAN
  6.12.94 and 6.12.95 builds. The unlocked read is the first condition evaluation
  inside `sk_wait_event()`; the macro reacquires the socket lock and rechecks it
  before proceeding, while the wait entry is installed before unlock and the
  receive path wakes it after decrementing `ctx->used`. Bounded runs showed no
  hang, memory error, corruption, or privilege effect. Verdict: real data race
  and possible `READ_ONCE()` cleanup, but no present security impact and not a
  bounty candidate. Evidence is retained in
  `benchmarks/kernel_candidates/afalg_ctx_used_kcsan_6.12.95/`.
- **2026-07-11 GPIO `WARNING in __proc_create`:** repairing the KernelGPT GPIO
  resource model exposed a deterministic path from
  `GPIO_GET_LINEEVENT_IOCTL` through `lineevent_create` and
  `register_handler_proc` to `__proc_create` when the consumer label is `"."`.
  A 29-line C reproducer succeeds (`ioctl=0`, event fd returned) and emits the
  warning on 6.12.95 KASAN. The default lab `/dev/gpiochip0` is root-only, the
  trace contains no KASAN/KMSAN memory corruption, and no privilege boundary or
  durable denial of service is demonstrated. Syzkaller's generic minimizer did
  not produce a repro, but the direct reproducer is retained at
  `benchmarks/kernel_negative/gpio_proc_name_warning.c`; remote serial evidence
  and hashes are under
  `/root/repro/gpio-proc-name-warning-20260711/` on `fuzzer`. Verdict: genuine
  low-impact kernel warning/regression lead, not an LPE or bounty candidate.
- **2026-07-03 TLS-lane `WARNING in __tcp_retransmit_skb`:** the warning arose
  in timer softirq context after `tcp_send_synack: wrong queue state` while the
  historical manager used `sandbox: none` and syzkaller network-device setup.
  A 58-minute extraction tried 36 multi-program candidates but produced no
  deterministic reproducer (`repro0` is an extraction transcript, not a syz
  program). There is no memory-safety report or unprivileged reachability proof.
  Verdict: root/network-emulation state-machine noise, not a candidate. The TLS
  lane now runs with `sandbox: setuid`; preserve the old bucket for deduplication
  but do not promote it unless it recurs there with a minimal reproducer.
- **2026-07-12 pipe-lane `kernel BUG in ext4_mb_use_inode_pa`:** the immutable
  UID 65534 report reaches `ext4_mb_use_inode_pa` through direct-I/O writeback,
  but it matches syzbot's still-open `d79019213609e7056a19` ext4 bucket, which
  has a public C reproducer and hundreds of upstream occurrences dating from
  2024. The report also depends on an ext4 filesystem state outside the pipe
  lane's intended attack surface. Verdict: known public duplicate, not a novel
  0sec finding or bounty candidate. Preserve the snapshot on `fuzzer` for local
  deduplication.
- **Historical pipe/driver `INFO: rcu detected stall in corrupted`:** the trace
  is from the older root/sandbox campaign and stalls in `vga_put()` while
  releasing the VGA-arbitration device. It has no memory-safety diagnostic,
  unprivileged reachability proof, or current setuid recurrence. Verdict: old
  privileged device-emulation stall, not an LPE or bounty candidate.
- **Historical AF_ALG `unregister_netdevice: waiting for DEV to become free`:**
  the artifact contains only a network-namespace cleanup wait on `lo`, with no
  kernel stack, sanitizer finding, reproducer, or demonstrated security impact.
  Verdict: infrastructure cleanup noise, not a candidate.
- **2026-07-13 serviced `vmswitch.sys` generic scan alerts:** identity-gated PDB
  enrichment mapped all 22 informational alerts to real function names. The six
  rundown patterns did not identify a competing lifetime path, and the 16
  off-by-one patterns either operated on internal state or retained explicit
  packet/MDL and descriptor bounds. No concrete guest-controlled memory-safety
  sink survived static review. The complete mapping and scope limits are in
  `benchmarks/windows_negative/vmswitch-packet-parser-validation-26100.8655/SERVICED-SCAN-TRIAGE.md`.
  Verdict: static negative; no trigger run and no claim.
- **2026-07-13 serviced `vid.sys` MMIO stack-copy lead:** the consumer uses a
  hypervisor-provided 32-bit field to size operations on 64-byte stack buffers,
  and its deferred message stores only the low byte. An isolated,
  network-disabled Windows guest was serviced through KB5094126 to obtain the
  exact 26100.8655 `hvix64.exe` producer. Its three direct call sites admit only
  `1..64` or powers of two no greater than 8. The producer payload `+0x30`,
  16-byte dispatch wrapper, copied-buffer `+0x40`, and `vid.sys` per-VP `+0x70`
  map to the same checked field. Verdict: exact-build upstream invariant;
  resolved negative, no trigger or vulnerability claim. Evidence and verifiers
  are in
  `benchmarks/windows_candidates/vid-mmio-stack-copy-26100.8328/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` generic scan:** the isolated,
  offline-serviced hypervisor image decompiled into 5,157 functions and
  produced 32 informational heuristics: 16 `memset` observations and 16
  off-by-one observations, with zero confirmed findings. Constant-size clears
  match their objects; the two variable clears remain coupled to bitmap or
  page-rounded allocation capacity. The only literal `array[index + 1]`
  stores write a 32-word host logical-processor bitmap after its header, with
  exact-image processor indexes bounded below `0x800`. Verdict: the generic
  alert set is a static negative, not proof that the hypervisor has no bugs.
  Hash-pinned evidence is in
  `benchmarks/windows_negative/hvix-generic-scan-triage-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` port-I/O intercept:** targeted
  tracing mapped VM-exit reason `0x1e` through VMCS exit qualification
  `0x6400`, decoded the 16-bit port and one-to-four-byte width, and followed
  the operands through partition policy, string/REP routing, scalar emulation,
  and register update. Both halves of the 65,536-port bitmap retain half-open
  interval and wrap bounds; string I/O returns through an intercept message
  before scalar direct-port execution. Verdict: targeted static negative; no
  trigger or vulnerability claim. The exact-build proof is in
  `benchmarks/windows_negative/hvix-io-intercept-validation-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` shared hypercall marshalling:**
  VMCALL exit reason `0x12` maps to a 306-entry descriptor table at RVA
  `0x2000`. A reusable extractor recovered all fixed/repeated input and output
  sizes. Standard marshalling bounds page offset plus total size to 4,096;
  fast marshalling bounds aligned input and output to its 112-byte register
  buffer; repeat-start validation prevents the later output adjustment from
  underflowing. Verdict: core marshalling negative only. The 306 individual
  handlers remain under targeted review. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-marshalling-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` variable-input handlers:** a
  descriptor-to-handler offset pass isolated four apparent fixed-input
  overreads (`0xa9`, `0xab`, `0xbd`, and `0x10a`). All use descriptor flag bit
  1, whose recovered ABI admits a control-word-sized variable input segment.
  Standard and fast marshalling include that segment in their page/register
  bounds, and the dispatch thunks pass its byte count to the handlers. Each of
  the four extra accesses is gated to remain within fixed plus validated
  variable bytes. Verdict: these four size mismatches are targeted negatives;
  nested pointers and the remaining individual handler semantics are still
  open. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-variable-input-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` call `0x64` output array:** the
  handler writes one qword per object page into a 4 KiB fixed output. Its local
  loop bound comes from the call-`0x60` creator, which admits only 1..512 pages
  and stores the checked value unchanged in the shared object. The maximum
  footprint is therefore exactly `512 * 8 = 4096` bytes; the creator's largest
  compound allocation also cannot wrap. Verdict: targeted object-pair negative.
  Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-output-page-array-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` call `0x105` output list:** two
  internal enumerators append eight-byte records after an eight-byte output
  header. The first receives a capacity of 511 and returns its consumption;
  the second receives exactly the remainder, with both helpers checking their
  running count before writes. The combined maximum is
  `8 + 511 * 8 = 4096` bytes. Verdict: targeted fixed-output negative; object
  lifetime semantics remain outside this result. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-105-output-list-26100.8655/`.

- **2026-07-13 exact 26100.8655 `hvix64.exe` call `0x9c` subcommand 0:** the
  handler contains a real unbounded 24-byte-record to 32-byte-stride stack copy;
  count 17 stays inside its fixed 536-byte input and overwrites the `/GS`
  cookie. Ordinary created L1 partitions cannot receive the required
  `CpuManagement` privilege. The exact installed `ntoskrnl.exe` has one
  536-byte call-`0x9c` wrapper and exactly six direct callers, but their fixed
  subcommands are only `1,2,3,5,6,7`; exact `winhvr.sys` has no direct wrapper.
  Verdict: real static memory corruption, but targeted bounty negative on the
  exact stock reachability boundary. Do not manufacture privilege or patch a
  caller to trigger it. Hash-pinned evidence and two root verifiers are in
  `benchmarks/windows_candidates/hvix-hypercall-9c-stack-overflow-26100.8655/`.

- **2026-07-13 exact 26100.8655 port hypercalls `0x95` and `0x96`:** targeted
  tracing covered the embedded GPAs in `HvCallCreatePort` and
  `HvCallConnectPort`. The create-port path bounds the guest page against the
  partition GPA range and requires page alignment before mapping. The
  connect-port doorbell path additionally validates reserved fields, allowed
  flag bits, trigger width, and that the selected access cannot cross the 4 KiB
  page. Downstream object copies preserve the checked GPA and map it through
  guest-page helpers rather than dereferencing it as a host pointer. Verdict:
  targeted embedded-address negative; port teardown and notification races are
  outside this result. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-port-embedded-gpa-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xc2` DispatchVp:** its 32-byte input
  contains a scalar time slice and speculation-control value, not embedded
  pointers. Exact tracing shows the time slice is stored in the current VP
  dispatch record, while speculation control must be a subset of the
  platform-supported mask. A per-VP interlocked bit serializes the state
  transition, internal object references are released, and the eight-byte
  output comes from two 32-bit dispatch state/event fields. The handler also
  requires `CpuManagement`. Verdict: embedded-address ranker false positive and
  basic state-transition negative; deeper scheduler cross-path races remain a
  separate lane. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-c2-dispatch-vp-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x62` object-page mapping:** paired
  analysis with its call-`0x60` creator proves the stored dimensions are capped
  at 512 pages and 640 slots. The consumer validates an empty in-range slot and
  indexes `(slot * page_count + page) * 0x88`; the final possible descriptor
  ends exactly at the creator's 44,564,480-byte allocation. Backing pages are
  hypervisor allocated, the per-slot allocation is at most 2 MiB, and zeroed
  arrays plus zero-before-init descriptors make partial cleanup safe. Both
  paths require the root/internal partition bit. Verdict: targeted arithmetic,
  embedded-address, and partial-cleanup negative; cross-call teardown races are
  not closed by this result. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-62-object-page-map-26100.8655/`.

- **2026-07-13 exact 26100.8655 EventLogBuffer map/delete lifetime:** call
  `0x63` drops its object lock while unmapping descriptors, and call `0x64`
  bypasses the nonzero teardown-state check in the hypervisor's special
  allocation mode. This preserves a real latent descriptor/PFN lifetime race.
  Both calls require the internal/root partition bit, however, and a read-only
  scan of the serviced Windows root found only one stock consumer:
  `hvservice.sys`. Its exact lifecycle holds one shared mutex across group
  creation and teardown, drains group and per-buffer rundown protection, and
  orders release, unmap, MDL unmap, then delete. The IOCTL dispatcher does not
  expose these lifecycle APIs, and its type-2 path never invokes delete.
  Verdict: real static cross-call defect, targeted bounty negative on exact
  stock reachability. Evidence is in
  `benchmarks/windows_candidates/hvix-hypercall-64-eventlog-map-delete-race-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x18` image-loader-shaped path:** its
  40-byte input carries a two-level PFN list, page count, flags, and optional
  callback. The count is capped at `512 * 512` and at the selected internal
  destination's page-rounded size; both table indices are nine bits, table and
  leaf PFNs are ownership-validated, and the callback must remain inside the
  destination region. Although validation and copy are separate PFN-list
  walks, the handler holds the hypervisor's global logical-processor rendezvous
  across both, excluding a CPU-driven leaf rewrite. The call requires the
  internal/root partition bit and has no output. Verdict: targeted nested-PFN,
  control-flow, and CPU double-fetch negative; malicious DMA is not generalized
  away but supplies no ordinary L1 or LPE boundary. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-18-image-loader-26100.8655/`.

- **2026-07-13 exact 26100.8655 calls `0x53`/`0x54` GPA read/write:** both
  handlers limit transfers to 1..16 bytes, reject page crossing, validate the
  target GPA start and inclusive end against the selected partition's physical
  limit, and retain the target VP for a synchronous request. A non-root caller
  can select only itself or its direct child, not an unrelated or host
  partition. Read places at most 16 bytes after an eight-byte result in its
  24-byte output; write carries exactly 16 inline input bytes and has an
  eight-byte result. Exact `winhvr.sys` wrappers independently enforce the same
  16-byte maximum. Verdict: targeted range, transfer-size, and partition-
  selection negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-53-54-gpa-access-26100.8655/`.

- **2026-07-13 exact 26100.8655 repeated calls `0xbc`/`0xf7`:** both root-only
  handlers compute `repeat_count - repeat_start`, optionally scale the range by
  512, and pass it to internal root-memory range operations. Standard and fast
  dispatchers require `start < count`, so remaining is 1..4095 and the scaled
  maximum is 2,096,640. The downstream range checker uses
  `start <= limit && length <= limit - start`. The unchecked base-plus-start
  addition can canonicalize through wrap, but supplies no new address because
  the resulting start can be requested directly with repeat start zero, and
  the interface already requires the internal/root bit. Verdict: targeted
  subtraction, scaling, and range negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-bc-f7-root-ranges-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x1b`:** the apparent wide pointer fields
  describe a processor-local MSR or I/O-port operation. The handler requires
  privilege bit 44 (`CpuManagement`), validates an active LP index below
  `0x800`, policy-checks MSR read/write access or every byte of a 1/2/4-byte
  port range, and atomically reserves a fixed per-LP request slot. The worker
  performs the validated operation and clears that slot; no input value is
  dereferenced as a host address. Verdict: embedded-address false positive and
  targeted operation/lifetime negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-1b-processor-hardware-access-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x40` `HvCallCreatePartition`:** the
  56-byte documented AMD64 input contains scalar creation flags, NUMA and
  compatibility values, and disabled processor/XSAVE masks—not pointers. The
  handler requires `CreatePartitions`, validates a fixed compatibility table
  and creation/isolation flags, serializes child creation, establishes the
  parent reference before publication, and cleans a partially allocated child
  on failure. The only output is one eight-byte partition ID. Verdict:
  embedded-address false positive and targeted basic creation-lifetime
  negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-40-create-partition-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x8c` synthetic machine-check
  injection:** the 128-byte input selects a permitted direct-child partition,
  a retained VP below `0x800`, and a 112-byte scalar machine-check record. The
  handler rejects the reserved tail and invalid status bits, copies the record
  into a fixed internal message, and releases all target/sibling references.
  No field is dereferenced as a host pointer. Verdict: embedded-address false
  positive and targeted target/lifetime negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-8c-synthetic-machine-check-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xb2` root device-context operation:**
  the fixed 32-byte input carries a root/self partition selector, validated
  VTL and mode, and a three-form tagged hardware selector. The tag parser
  rejects reserved bits and never treats the scalar as an address. Alternate
  mode resolves a keyed internal per-VTL object under a reference, uses its
  internal descriptor, and releases it on exit. The call has no output.
  Verdict: embedded-address false positive and targeted authority/lifetime
  negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-b2-root-device-context-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x10a` partition-property update:** the
  variable-input handler accepts exactly eight tail bytes for ordinary
  properties or 48 for three extended properties. The extended path copies
  six qwords into fixed internal fields without exceeding the tail; ordinary
  helpers constrain the wide value as scalar policy/state. Target objects are
  ownership-scoped and retained, while property updates use internal locks or
  interlocked gates. No input value is dereferenced or mapped as a GPA.
  Verdict: embedded-address false positive and targeted variable-input
  geometry negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-10a-partition-property-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x5` platform configuration:** the
  16-byte call is gated by `CpuManagement`; its reserved dword must be zero and
  its qword is restricted per operation to a boolean, one, or a bounded scalar.
  Fixed callback targets load only a byte/dword into global scalar state,
  refresh platform features, invoke a fixed helper with the low dword, or do
  nothing. No value is dereferenced or used for memory geometry. Verdict:
  embedded-address false positive and targeted fixed-callback negative.
  Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-05-platform-configuration-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xb8` root keyed configuration:** the
  first qword is a key into a hypervisor-owned list, not an address, and lookup
  retains the selected object. The other qword is restricted to a bounded
  dword or byte scalar. Mutations take the object gate, reject teardown, and
  bound internal pointer-array and bitmap operations using stored dimensions.
  The handler requires internal/root bit zero and exposes no output. Verdict:
  embedded-address false positive and targeted bounds/lifetime negative.
  Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-b8-root-keyed-configuration-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x7b` privileged system query:** the
  shared marshaller zeroes the validated 1,032-byte output before dispatch.
  The largest list is capped at 64 16-byte records after its eight-byte header;
  array counts are capped at 128 and 64, and smaller helpers write at most 32
  bytes. Subcommand `0x26`'s internal record count is zero-initialized with no
  later writer in the exact cache. The call also requires `CpuManagement`.
  Verdict: targeted output disclosure/overwrite and embedded-address negative.
  Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-7b-system-query-output-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xac` translate virtual address:** the
  32-byte input is four fixed scalars and the apparent page operation is a
  guest-virtual-page shift, not an embedded host address. The handler retains
  a permitted self-or-child partition and a VP below `0x800`, rejects reserved
  and conflicting control bits, and builds a zeroed fixed `0x90`-byte internal
  request. The shared marshaller zeroes all 64 output bytes; direct and helper
  writes stay inside that result. The exact `winhvr.sys` wrapper confirms the
  fixed ABI. Verdict: address-arithmetic, disclosure, lifetime, and embedded-
  pointer negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-ac-translate-virtual-address-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xb3` privileged root page list:** this
  private repeated call has a 40-byte fixed input and eight-byte list records.
  Its target must carry the internal/root bit, its fixed controls have narrow
  masks, and the selected internal object is retained. Shared marshalling
  proves `start < count` and bounds the full list inside one input page; the
  worker separately bounds the sequential page span to the target address
  width, advances exactly one record per iteration, and validates every page
  before table selection. Verdict: repeated-input bounds, lifetime, and
  embedded-address negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-b3-root-page-list-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xb4` privileged root page range:** this
  adjacent private call uses repeated-call control fields as a contiguous range
  count, with no record bytes. Shared validation proves start is below count;
  the handler passes only their difference after adding start to an aligned
  base page. Its worker independently requires start plus count to fit the
  target physical-address width. Verdict: repeat-count arithmetic, page-range,
  lifetime, and embedded-address negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-b4-root-page-range-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0xe1` `HvCallMapVpStatePage`:** the
  handler retains the permitted partition and VP, serializes mapping on the VP,
  and bounds type/VTL selectors before selecting a fixed `0xa8`-byte VP-owned
  slot. Layered-host extended call `0x800a` validates the requested GPA before
  storing it page-aligned in that slot, and `0x800b` releases it. The simple
  handler maps only that stored GPA; its eight-byte output is pre-zeroed and
  written only after success. Verdict: GPA provenance, selector bounds,
  lifetime, disclosure, and embedded-address negative. Evidence is in
  `benchmarks/windows_negative/hvix-hypercall-e1-map-vp-state-page-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x4e` virtual-processor creation:** the
  fixed 40-byte input contains scalar partition, VP, topology, and affinity
  identifiers rather than embedded host pointers. The target partition is
  retained and its conditional lock is balanced. The internal topology index
  is required below `0x800` before a 32-byte-stride lookup; ordinary topology
  and affinity forms are accepted only after bounded helper validation. The
  allocation paths receive a local 16-byte descriptor assembled from those
  checked values. No hypercall was issued. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-4e-create-vp-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x7c` `HvCallMapDeviceInterrupt`:** the
  variable processor-set parser requires an exact
  `16 + popcount(mask) * 8` bytes, caps the expanded bitmap at 32 groups, and
  writes into a zeroed local allocation sized for exactly those groups. Device
  IDs become reserved-bit-checked tagged locals; interrupt type, count, vector,
  flags, and target masks are validated before the retained core mapping. The
  fixed 56-byte output is pre-zeroed and only a 16-byte identity is written on
  the reviewed success path. No hypercall was issued. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-7c-map-device-interrupt-26100.8655/`.

- **2026-07-13 exact 26100.8655 private call `0x82`:** its fixed 40-byte input
  carries a tagged device identifier, a selector capped at two, narrow
  flags/configuration fields, and a scalar key for a target-owned object list.
  The handler retains the partition and optional selector object, converts the
  device identifier into a checked 24-byte local descriptor, and balances both
  lifetimes. The core caps flags below `0x100`, caps and aligns configuration
  below `0x1000`, and checks optional-field consistency. Exact assembly proves
  that the offset-`0x18` qword is passed by value; the core only compares it
  with locked list keys and never dereferences it. No output exists and no
  hypercall was issued. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-82-private-device-object-26100.8655/`.

- **2026-07-13 exact 26100.8655 private call `0x94`:** the handler retains its
  target and selector, caps the selector at two, and passes four fixed scalar
  fields to an operation dispatcher. Direct VP lookup is capped below `0x800`.
  The strongest apparent issue, a 16-bit target-map load without a local
  comparison, is dominated by an eight-bit source mask in legacy mode. Target
  construction forces the alternate mode whenever feature bit `0x4000` is
  set, and that full-width path checks the index against its initialized
  dynamic-map capacity. No embedded address, guest-controlled out-of-range map
  index, output, or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-94-private-vp-operation-26100.8655/`.

- **2026-07-13 exact 26100.8655 private call `0xd9`:** shared repeated-call
  validation proves start below count, and the handler checks base plus start
  before passing only count minus start to its range worker. That worker clips
  processed progress to a target-owned address-space limit. Consequently the
  continuation's base plus start plus progress cannot wrap. Encoded selectors
  are restricted to values zero through two, retained, and released with the
  target reference. No repeat underflow, embedded pointer, stale object,
  output, or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-d9-private-range-operation-26100.8655/`.

- **2026-07-13 exact 26100.8655 private root-only call `0xeb`:** the handler
  requires an internal/root caller at its highest active selector and retains
  the selected target. A tagged device identity becomes a checked local
  descriptor; the other wide qword is a scalar key into a gated target-owned
  object list. Lookup retains the matched object. The core restricts flags
  below `0x100`, restricts aligned configuration below `0x1000`, matches all
  supplied identity/mode fields against stored state, and performs activation
  under object and global gates with rollback and balanced releases. No
  embedded address, stale object, output, or hypercall invocation survived
  review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-eb-root-device-activation-26100.8655/`.

- **2026-07-13 exact 26100.8655 private root-only call `0x16`:** the shared
  marshaller pre-zeroes its fixed 4 KiB output. The operation selector is
  restricted to three forms that write only a 32-bit boot-list count, three
  fixed 24-byte records, or one qword per requested page. The page count is at
  most 512, its base is aligned, and both the first and final page must lie in
  the selected immutable boot range. Exact cross-references show the traversed
  list is constructed during initialization with no runtime mutation path. No
  overrun, disclosure, mutable-list race, child reachability, embedded pointer,
  or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-16-root-boot-metadata-query-26100.8655/`.

- **2026-07-13 exact 26100.8655 private partition-control call `0x4d`:** the
  retained target receives only a narrow operation value, a private subcommand
  through `0x11`, and a final qword split into scalar ushorts/dwords. Inclusive
  ranges require end at least start; direct bit indices are below 32; masks are
  confined to five bits. The widest dword key is decomposed into a sparse-tree
  key, masked ten-bit bitmap index, and five-bit bit selector under dedicated
  target gates. No guest value is dereferenced. No unchecked flat index,
  unsynchronized bitmap mutation, stale target, output, or hypercall invocation
  survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-4d-private-partition-controls-26100.8655/`.

- **2026-07-13 exact 26100.8655 `HvCallSetVpRegisters` (`0x51`):** shared
  repeated-call validation proves start below count and bounds the fixed
  16-byte header plus 32-byte records inside the mapped input page. Exact
  assembly computes the source as `input + 16 + start*32` and the copy size as
  `(count-start)*32`; 12-bit repeat fields also exclude arithmetic overflow.
  The request uses copied environment scratch or fixed local storage. Direct
  and queued paths complete before the handler releases its retained VP and
  partition references. No repeated-input overrun, scratch UAF, embedded
  pointer, output, or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-51-set-vp-registers-26100.8655/`.

- **2026-07-13 exact 26100.8655 private call `0xa9`:** operation zero requires
  no variable bytes; operation one requires exactly eight, restricts its only
  meaningful byte to a boolean, and rejects all seven reserved bytes. The
  32-bit object ID selects an active internal registry object under registry
  rundown and takes its reference. Object deletion refuses a nonzero reference
  count. Both state paths serialize on the object's interlocked gate and the
  handler releases the reference synchronously. No extension overread,
  embedded pointer, stale object, unlocked mutation, output, or hypercall
  invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-a9-private-object-control-26100.8655/`.

- **2026-07-13 exact 26100.8655 `WinHvUnacceptGpaPages` call `0xda`:** the
  handler accepts only even masks below eight and retains at most three
  selected per-VTL state objects. Shared repeat validation proves start below
  count; base plus start is checked before addition. The synchronous page-state
  worker clamps progress to the lesser of requested remaining pages and
  `address_limit - checked_base`, then reports exactly current minus base.
  Continuation arithmetic therefore cannot underflow or wrap, and all
  stack-backed state and retained references are released before return. No
  range overrun, escaping stack pointer, output, or hypercall invocation
  survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-da-unaccept-gpa-pages-26100.8655/`.

- **2026-07-13 exact 26100.8655 private VTL/VP bitmap query call `0xe5`:** the
  handler clears 264 bytes of a 272-byte local, but the uncleared final qword
  lies beyond its one-qword header plus 32-qword bitmap format. Object creation
  rejects identifiers at the active limit, which is never above `0x800`, so
  the largest bitmap group is 31. The converter reads only those 32 groups,
  emits at most 32 group records into the exact 272-byte output, and zero-fills
  the remainder. The target and selected VTL state are retained, and the
  handler ignores any flag-two variable extension. No stack overrun, disclosure,
  stale reference, embedded pointer, or hypercall invocation survived review.
  Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-e5-vtl-vp-bitmap-query-26100.8655/`.

- **2026-07-13 exact 26100.8655 private partition-property query call
  `0x101`:** the standard marshaller validates and zeroes its complete
  4,072-byte output. Ordinary properties write one qword, property `0x90005`
  writes 24 bytes through a retained VP, and property `0x90000` writes a fixed
  72-byte bitmap while scanning exactly 512 entries. The page-shaped `0x90005`
  values require an internal/root target selected under mode-three ownership,
  so an ordinary child cannot use the branch to query root state. No overwrite,
  stale-output or child-visible address disclosure, stale reference, embedded
  pointer, or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-101-partition-property-query-26100.8655/`.

- **2026-07-13 exact 26100.8655 `HvlMapGpaPages` call `0x4b`:** shared
  marshalling bounds the 24-byte header plus 8-byte records to 509 entries,
  matching the exact kernel wrapper's `0x1fd` chunk cap. The handler checks
  `base + stride*repeat_start` before addition for both one-page and 512-page
  modes. The worker requires 512-page alignment for the large form, clamps the
  requested page span to the target limit, converts progress back to records,
  and reports no more than the remaining count. Target/rundown references and
  synchronous stack request state are balanced. No overread, arithmetic wrap,
  progress overrun, escaping stack pointer, output, or hypercall invocation
  survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-4b-map-gpa-pages-26100.8655/`.

- **2026-07-13 exact 26100.8655 `WinHvPostMessage` call `0x5c`:** both the
  serviced wrapper and hypervisor handler cap payloads at 240 bytes. The
  wrapper zero-pads the unused payload tail. The resolved connection owns 16
  interlocked slots, each with a 256-byte request buffer; the hypervisor writes
  a 16-byte header plus at most 240 payload bytes. Successful requests are
  linked through the selected VP queue gate, failures restore slot state, and
  connection teardown drains claimed slots before releasing the backing block.
  No overread, overwrite, stale-input disclosure, queued-buffer UAF, embedded
  pointer, output, or hypercall invocation survived review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-5c-post-message-26100.8655/`.

- **2026-07-13 exact 26100.8655 call `0x70` operation-9 stock reachability:**
  the internal type-2 association-list deletion path does leave a stale node,
  but operation 9 rejects every hypervisor global mode except initialization
  mode 1. The only exact writers set that mode during initialization and later
  transition it through mode 2 to runtime mode 0. Complete exact serviced
  `vid.sys` disassembly has two `WinHvSetPortProperty` references: a dominating
  filter restricts one to operations 1 or 5, and the other loads constant
  operation 3. No stock operation-9 call, ordinary-child phase control, or
  runtime bounty boundary survived review. The structural defect remains a
  preserved variant/phase candidate, but no dynamic test or hypercall was
  issued. Evidence is under
  `benchmarks/windows_candidates/hvix-hypercall-70-port-association-list-uaf-26100.8655/`.

- **2026-07-13 exact 26100.8655 calls `0xd0`/`0xd1` stock callback
  reachability:** the
  global 24-byte DMA-flush scratch reuse remains an exact internal concurrency
  structure, but `HvlDmaFlushDeviceDomain` and
  `HvlDmaFlushDeviceDomainVaList` have no direct kernel callers. The exact
  kernel publishes them only through the PDB-typed
  `HalPrivateDispatchTable+0x240` and `+0x248` fields. An IAT-aware, manifest-
  and image-hash-pinned scan found zero consumers of either slot among all 426
  serviced drivers and all 403 DriverStore images; the 11 and seven table
  importers use other fields, and no additional dynamic-name-only resolver is
  present. Call `0xd0` also rejects nonzero reserved input, requires a retained
  internal/root target at the current VTL, retains its keyed domain object, and
  balances both lifetimes around the synchronous shared worker. No installed
  stock call chain, lock-scope question, hardware-test justification, or
  hypercall invocation survived review. Preserve the structure for variant
  comparison, but do not claim or dynamically test it absent a new supported
  consumer. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-d0-dma-flush-device-domain-26100.8655/`
  and
  `benchmarks/windows_candidates/hvix-hypercall-d1-dma-flush-global-scratch-race-26100.8655/`.

- **2026-07-13 exact 26100.8655 `WinHvQueryVtlProtectionMaskRange` call
  `0xcc`:** its fixed input's six reserved bytes must be zero, and the handler
  checks base plus repeat start before addition. Shared repeat validation
  bounds each four-byte output record and proves start below count. The
  selector admits only bits one and two; both selected VTL-state references
  fit a fixed three-slot local and are balanced. Work is clamped to the lesser
  of remaining records and `target_limit - checked_base`. Each output dword is
  cleared before its selected ushort halves are written, and reported progress
  cannot exceed the clamp. No output overwrite, stale-byte disclosure, range
  wrap, stale reference, embedded pointer, or hypercall invocation survived
  review. Evidence is under
  `benchmarks/windows_negative/hvix-hypercall-cc-vtl-protection-query-26100.8655/`.

- **2026-07-13 exact 26100.8655 `HvCallGetVpRegisters` call `0x50`:** shared
  repeated-call validation maps the fixed header, four-byte register names,
  and 16-byte output values within their admitted pages and proves start below
  count. The handler uses start-scaled name/value pointers, subtracts start from
  count, and clamps reported progress before copying `progress * 16` bytes.
  Queued/non-self requests zero internal output scratch before dispatch and
  copy back only completed records; the direct self path writes into the
  guest-owned mapped output rather than exposing internal uninitialized data.
  Target partition and VP references remain held through synchronous queue or
  direct completion. No geometry, stale-output, embedded-pointer, lifetime, or
  authority candidate—and no hypercall invocation—survived review. Evidence is
  under
  `benchmarks/windows_negative/hvix-hypercall-50-get-vp-registers-26100.8655/`.

- **2026-07-13 exact-LTS seccomp-notify pilot:** a bounded setuid manager
  executed 408 programs but retained zero aggregate coverage; listener create,
  notification receive/send, and add-fd all remained dormant. It produced zero
  crash buckets and was stopped early. The displaced keyrings lane was restored
  without a restart. Verdict: failed promotion; do not repeat the same seed and
  configuration. See
  `benchmarks/kernel_negative/seccomp-notify-exact94-pilot-2026-07-13.md`.

## Machine log

`zeroverse.negative` appends one NDJSON record per **negative run** (zero confirmed
PoVs) when `ZEROVERSE_NEGATIVE_LOG` points at a file — so clean/empty scans are
captured too, not just findings. Each record carries the classified `reason`:

| reason | meaning |
|--------|---------|
| `unsupported-format`     | ingest could not route the container |
| `no-backend`             | no decompiler backend available on this host |
| `no-candidates`          | pipeline ran; slice/lenses found no hypothesis |
| `static-only-degrade`    | host cannot run/emulate the target — hypotheses only |
| `all-pruned`             | every hypothesis proven unreachable (angr UNSAT) |
| `unconfirmed-hypotheses` | leads surfaced, none reproduced a PoV |

```sh
ZEROVERSE_NEGATIVE_LOG=negatives.ndjson  0verse scan ./target --format ndjson
```

The log is append-only and operator-local (git-ignored). This file is its
human-curated companion: when a recurring negative reveals a real fidelity gap,
promote it into the sections above.
