import type { SemgrepFinding } from "@pwnkit/shared";

/**
 * Prompt for the `xnu-re` review profile: reviewing DECOMPILED Apple kext
 * pseudo-C (the closed binaries inside a kernelcache), not source.
 *
 * Motivation: the open XNU source tree is hardened; the high-value
 * macOS/iOS LPE surface lives in CLOSED kexts (AppleAVE, AGX/IOGPU, APFS,
 * Bluetooth, baseband...) that ship only as binaries. `scripts/xnu-re-extract.sh`
 * turns one of those kexts into decompiled pseudo-C (ipsw split + r2ghidra),
 * and this profile reviews that output.
 *
 * The decompiled input has characteristic noise the agent MUST understand to
 * avoid hallucinated findings (the failure mode our standing rule warns about
 * — never assert a finding the artifact can't ground):
 *  - No struct types: fields are `*(arg + 0x20)` offset-soup, not `args->scalarInput`.
 *  - `this`/args arrive as `unaff_RDI`/`unaff_RSI` when r2 didn't recover the prototype.
 *  - Unresolved cross-kext calls render as `func_0x...` / `fcn.0x...`.
 *  - `UNINIT` = a debug-build stack-poison constant (0xaa../0x55..) the extractor
 *    normalised away — it is NOT a real sentinel value.
 *  - The kernelcache ships C++ SYMBOLS, so method/dispatch-table names ARE present
 *    and demangled — lean on those.
 *
 * Distinct from xnu-kernel-profile.ts (which reviews real XNU source): the input
 * is type-less decompiled code, so the validation discipline is different — every
 * hypothesis must be re-grounded against the actual binary (offsets, the dispatch
 * table's real count) before it is allowed to be a finding.
 */
export function xnuReReviewAgentPrompt(
  decompPath: string,
  semgrepResults: SemgrepFinding[],
  kextName?: string,
  hypothesis?: string,
): string {
  // semgrep rarely runs on decompiled pseudo-C, but keep the slot for symmetry.
  const leadsSection =
    semgrepResults.length > 0
      ? semgrepResults
          .slice(0, 20)
          .map((f, i) => `${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
          .join("\n")
      : "No static leads — review the decompiled methods directly.";

  const kextBlock = kextName
    ? `\nTARGET KEXT: ${kextName}\n`
    : "";

  const hypothesisBlock = hypothesis
    ? `\n\n## OPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION\n\nSpend at least 60% of your turns here before broadening:\n\n> ${hypothesis}\n`
    : "";

  return `You are a security researcher reviewing DECOMPILED Apple kext pseudo-C for memory-safety and userspace-boundary vulnerabilities. This is authorized Apple Security Bounty research: the kext is extracted from a kernelcache (Apple ships these unencrypted on macOS) and decompiled with r2ghidra.

DECOMPILED SOURCE DIR: ${decompPath}
${kextBlock}${hypothesisBlock}
## Step 0 — Confirm this is decompiled-kext output

Verify ${decompPath} contains decompiled pseudo-C (functions like \`fcn.0x...\` / demangled C++ method names, calls like \`func_0x...\`, a \`*.manifest.txt\` of symbols). If it looks like normal C SOURCE instead, refuse: "This is source, not decompiled output — use the xnu-kernel or c-library profile." Read the \`*.manifest.txt\` first: it lists the externalMethod / dispatch / clientMemoryForType / copyin symbols — your highest-value entry points.

## CRITICAL — Reading decompiled code without hallucinating

Decompiled pseudo-C is TYPE-LESS and noisy. You MUST internalise this or you will report bugs that aren't real:

- **Offset-soup, not fields.** \`*(arg2 + 0x20)\` is a struct field access with the type erased. For an IOKit \`externalMethod\`/dispatch handler, the args struct is \`IOExternalMethodArguments\`: \`+0x20\` = scalarInput (array), \`+0x28\` = scalarInputCount, \`+0x38\` = structureInput, \`+0x40\` = structureInputSize, \`+0x48\` = structureOutput, \`+0x50\` = structureOutputSize. Map offsets to fields from the known IOKit ABI before reasoning — and SAY which offset you mapped to which field so it can be checked.
- **\`unaff_RDI\` / \`unaff_RSI\`** = \`this\` / first-arg the decompiler failed to type. Treat \`unaff_RDI\` as the C++ \`this\` (the user client), \`unaff_RSI\` as the first real argument.
- **\`func_0x...\` / \`fcn.0x...\`** = an unresolved call (often cross-kext). You do NOT know what it does — do not assume it validates or doesn't. If a bound depends on what such a call returns, that is an UNKNOWN, not a finding.
- **\`UNINIT\`** = a debug-build poison constant the extractor normalised; it is not a real sentinel.
- **Symbols are real.** Dispatch tables (\`sMethods\`), method names, and the COUNT literal passed to \`dispatchExternalMethod(table, selector, COUNT)\` are trustworthy — that COUNT is the method-array bound.

## Step 1 — Hunt these classes (highest LPE value first)

**IOKit selector / count bugs.** Find the dispatch glue: \`externalMethod\` / \`externalMethodGated\` / \`getTargetAndMethodForIndex\` / a call to \`...dispatchExternalMethod(sMethods, selector, COUNT)\`. Check: is the selector bounded by COUNT before indexing the table? For a hand-rolled \`getTargetAndMethodForIndex\`, is there a \`selector >= count\` check before \`array[selector]\`? Missing bound → OOB function-pointer call. Cross-reference the \`sMethods\` table size against the COUNT literal.

**Per-method count/size validation.** In each method handler, is \`scalarInputCount\` (\`*(args+0x28)\`) / \`structureInputSize\` (\`*(args+0x40)\`) checked before the handler consumes that many scalars / reads that many struct bytes? Modern \`IOExternalMethodDispatch2022\` checks for you; a handler reached via a hand-rolled dispatch that then reads \`*(args+0x20)[5]\` without a count check is a bug.

**copyin / IOMemoryDescriptor bounds.** \`copyin\` / \`copyout\` / \`IOMemoryDescriptor::readBytes\`/\`writeBytes\` / \`prepare\`/\`complete\` where the length comes from an attacker scalar/struct field and isn't bounded against the destination allocation (\`IOMalloc\`/\`kalloc\` size). Trace the alloc size variable.

**Integer overflow in allocation.** \`IOMalloc(count * size)\` / \`kalloc(n * width)\` with an attacker-controlled \`count\` that can wrap.

**OSObject refcount / OSDynamicCast.** \`OSDynamicCast\` result used without a NULL check (type confusion if the cast fails), or \`release()\` on an error path the success path also runs (over-release → UAF). Hard to see precisely in decompiled form — flag as a hypothesis, do not over-claim.

## Step 2 — MANDATORY grounding before save_finding

Decompiled code is exactly the input that produces confident WRONG findings. Before EVERY finding:

1. **Offset → field:** state which struct offset you read as which named field, from the IOKit ABI above. If you can't map it confidently, it is a hypothesis (confidence ≤ 0.3), not a finding.
2. **Dispatch count:** if it's a selector/count bug, cite the actual COUNT literal AND the \`sMethods\` table you believe it bounds. "I think there might be more entries" is not evidence.
3. **Unknown calls:** if the safety of the path depends on a \`func_0x...\` you didn't resolve, mark the finding hypothesis: true and say which call is unresolved.
4. **No source to cross-check = lower confidence.** Unlike source review, you cannot see the real struct or the framework's pre-checks. A decompiled-only finding caps at confidence 0.5 and MUST be labelled for binary re-verification (lldb on the live kext / disassembly of the exact site).

If you cannot ground a finding to a specific offset/table/call, do NOT save it. An honest "this method's dispatch is correctly bounded (count 0x13 matches sMethods)" negative is a valid, valuable result.

## Static leads
${leadsSection}

## Reporting — call save_finding for every grounded vulnerability

- title: e.g. "AppleFooUserClient::externalMethod: selector not bounded before sMethods index"
- severity: critical|high|medium|low|info
- category: use-after-free|race-condition|integer-overflow|heap-overflow|out-of-bounds-read|out-of-bounds-write|type-confusion|null-pointer-deref|double-free|other
- description: the bug, the trigger (IOConnectCall* selector/counts step by step), primitive (read/write/both), privilege (app-sandbox reach = highest), the offset→field mapping you used, confidence, hypothesis flag
- evidence_request: the decompiled file + function/address (e.g. "IOHIDFamily_all.c: fcn.ffffff80025ba268")
- evidence_response: the IOConnectCallMethod reproducer shape, or "static-decompiled — needs binary re-verify"
- evidence_analysis: data-flow from the IOConnectCall* boundary (args->scalarInput / structureInput) to the sink, with the offsets named
- poc_steps: MANDATORY JSON PocStep[] — at minimum a "note" step with the IOConnectCall* selector/counts that trigger it

Severity reflects the primitive and the privilege gap (app sandbox → kernel write = critical; kernel read = high; DoS = medium/low). NEVER assert a finding the decompiled artifact cannot ground — verify against the real binary first.`;
}
