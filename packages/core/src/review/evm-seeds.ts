import { execFileSync } from "node:child_process";
import type { SemgrepFinding } from "@0sec/shared";

/**
 * Solidity/EVM static-analysis SEED layer for the `evm-onchain` review profile
 * ("0contract").
 *
 * Fallback layer for when the configured static scanner does not return
 * Solidity leads (Semgrep's Solidity coverage is thin and Slither is not on
 * PATH in the engine image). This gives the review concrete seeds (file:line +
 * rule + snippet + why) to hunt from, in the exact `SemgrepFinding` shape the
 * review prompt already consumes (`evmOnchainReviewAgentPrompt`).
 *
 * MVP SCOPE (honest): this is a ripgrep/regex seed layer. It is a LEAD
 * generator, not a verifier — every seed is "this token appears here, look at
 * it", and the review agent still does the reachability + guard-present +
 * value-impact analysis the profile mandates. Regex cannot prove a
 * `.call{value:}` is re-enterable or that a price read is manipulable; it can
 * only point the agent at the candidate sink. A `slither --json` pass is a
 * deliberate FOLLOW-UP (needs solc + the Slither toolchain in the sandbox,
 * which isn't present today). The regex layer ships now and needs only
 * ripgrep, which the engine already depends on.
 *
 * The bug classes mirror the `evm-onchain` profile's "Hypothesis classes"
 * section, so the seeds and the prompt speak the same language.
 */

/** A single regex rule within a bug class. */
interface EvmRule {
  /** Sub-rule id (becomes the suffix of the SemgrepFinding ruleId). */
  id: string;
  /** Source-text regex. Matched against the whole line. */
  re: RegExp;
  /** Short "why this matters" shown to the review agent. */
  why: string;
}

/** A bug class = a group of rules sharing a severity bucket. */
interface EvmBugClass {
  /** Class id (prefixes the ruleId, e.g. `reentrancy`). */
  klass: string;
  /** Default severity bucket for seeds in this class. */
  severity: "high" | "medium" | "low" | "info";
  rules: EvmRule[];
}

/**
 * Bug classes the `evm-onchain` profile cares about. These are LEADS, not
 * findings — severity reflects "how often this token is the actual bug", not a
 * confirmed impact. External-call reentrancy and cross-chain message handlers
 * are the highest-value drains, so they rank highest.
 */
const BUG_CLASSES: EvmBugClass[] = [
  {
    klass: "external-call",
    severity: "high",
    rules: [
      { id: "call-value", re: /\.call\s*\{[^}]*value\s*:/, why: "Low-level ETH-sending call — classic reentrancy sink. Confirm state is settled (Checks-Effects-Interactions) BEFORE this call and/or a nonReentrant guard covers the re-entrant path." },
      { id: "low-level-call", re: /\.\s*call\s*\(/, why: "Low-level `call` into an external address — re-enterable and its return value is easy to ignore. Check the callee cannot re-enter unsettled state and that success is checked." },
      { id: "send-transfer", re: /\.\s*(send|transfer)\s*\(/, why: "ETH `send`/`transfer` — a callback surface (and `transfer`'s 2300-gas assumption is fragile). Confirm reentrancy ordering and that a failed `send` return is handled." },
      { id: "erc20-transfer", re: /\.\s*(transfer|transferFrom)\s*\(/, why: "ERC20 transfer/transferFrom NOT via SafeERC20 — a no-return or false-returning token silently fails; check the return value and fee-on-transfer/rebasing accounting." },
      { id: "erc721-callback", re: /\b(onERC721Received|onERC1155Received|tokensReceived|_safeMint|safeTransferFrom)\b/, why: "Token-receive hook / safeMint — hands control to a user-controlled receiver mid-call (ERC777/721/1155 reentrancy). Confirm state is settled before the hook fires." },
      { id: "flashloan-callback", re: /\b(flashLoan|onFlashLoan|executeOperation|uniswapV2Call|uniswapV3(Swap|FlashCallback)|receiveFlashLoan)\b/, why: "Flash-loan callback — attacker code runs inside your call with borrowed capital (oracle-manipulation + reentrancy enabler). Verify the callback authenticates the initiator and prices are not spot-read here." },
    ],
  },
  {
    klass: "delegatecall-proxy",
    severity: "high",
    rules: [
      { id: "delegatecall", re: /\bdelegatecall\s*\(/, why: "delegatecall executes foreign code in THIS contract's storage — storage-layout collision (owner/impl slot clobber) or attacker-controlled `target` = full takeover. Verify the target is trusted and the layout matches." },
      { id: "upgrade-to", re: /\b(upgradeTo|upgradeToAndCall|_authorizeUpgrade|_upgradeTo)\b/, why: "Proxy upgrade entrypoint — if `_authorizeUpgrade`/`onlyOwner` gating is missing or the impl is uninitialized, anyone upgrades or bricks the proxy." },
      { id: "selfdestruct", re: /\b(selfdestruct|suicide)\s*\(/, why: "selfdestruct — on an implementation reachable via an unprotected initializer this bricks a UUPS proxy; also breaks `address(this).balance` assumptions." },
      { id: "storage-slot", re: /\b(sstore|sload)\s*\(|\.slot\b|assembly\s*\{/, why: "Inline-assembly storage access / unstructured storage — check the slot cannot collide with proxy admin/impl slots or be attacker-clobbered." },
    ],
  },
  {
    klass: "cross-chain",
    severity: "high",
    rules: [
      { id: "lz-receive", re: /\b(lzReceive|_nonblockingLzReceive|_blockingLzReceive|nonblockingLzReceive)\b/, why: "LayerZero inbound handler — MUST verify msg.sender is the trusted endpoint AND the (srcChainId, srcAddress) trusted-remote AND a per-nonce replay guard. Missing any = forged/replayed bridge mint." },
      { id: "ccip-receive", re: /\b(ccipReceive|_ccipReceive)\b/, why: "Chainlink CCIP inbound handler — verify the router caller, the source chain selector, the sender, and replay protection before crediting bridged value." },
      { id: "wormhole", re: /\b(receiveWormholeMessages|parseAndVerifyVM|completeTransfer|verifyVM)\b/, why: "Wormhole message intake — verify the guardian-set signature (parseAndVerifyVM), the emitter chain+address, and that the VAA hash cannot be replayed (the Wormhole signature-verification class)." },
      { id: "generic-execute", re: /\b(_execute|processMessage|handle|onMessageReceived|receiveMessage)\b/, why: "Generic cross-chain message handler — check source-chain-id, source/sender address, mailbox/endpoint authenticity, and nonce/replay binding are ALL enforced." },
      { id: "merkle-root", re: /\b(merkleProof|MerkleProof|verifyProof|processMessage|_root|confirmAt|acceptableRoot)\b/, why: "Merkle-root / commitment claim — verify the proof is checked against the RIGHT root and an UNINITIALIZED/zero root is NOT trusted (the Nomad zero-root class); guard against re-claiming the same leaf." },
    ],
  },
  {
    klass: "access-control",
    severity: "high",
    rules: [
      { id: "tx-origin", re: /\btx\.origin\b/, why: "tx.origin authentication is phishable — any contract the victim calls can relay. Use msg.sender." },
      { id: "initializer", re: /\b(initialize|__init|_disableInitializers)\b/, why: "Initializer — an unprotected `initialize()` can be front-run to seize ownership; a UUPS implementation missing `_disableInitializers()` in its constructor can be initialized+selfdestructed. Confirm the initializer modifier and one-time guard." },
      { id: "owner-setter", re: /\b(_setOwner|transferOwnership|_transferOwnership|setOwner|setAdmin|grantRole|_setupRole)\b/, why: "Ownership/role mutation — confirm it is gated (onlyOwner/onlyRole) and the granted role cannot be self-assigned by an attacker." },
      { id: "unprotected-modifier", re: /\bmsg\.sender\s*==/, why: "Manual sender check — confirm it pins the RIGHT privileged address and that every value-moving sibling function has an equivalent gate (missing-auth is the #1 access-control drain)." },
    ],
  },
  {
    klass: "oracle-price",
    severity: "medium",
    rules: [
      { id: "get-reserves", re: /\b(getReserves|getAmountOut|getAmountsOut|token0|token1)\b/, why: "AMM spot-price read — flash-loan-manipulable. If a price/exchange-rate is derived from these reserves within one tx, it is spot-manipulable; require a robust TWAP or an external oracle." },
      { id: "balance-price", re: /\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)|\.balanceOf\s*\([^)]*pair|\.balanceOf\s*\([^)]*pool/, why: "Price/share derived from a pool's `balanceOf` — donation-inflatable (first-depositor share inflation) and flash-loan-manipulable. Check the accounting cannot be skewed by a direct transfer in." },
      { id: "chainlink", re: /\b(latestRoundData|latestAnswer|getRoundData)\b/, why: "Chainlink read — `latestAnswer` is deprecated; `latestRoundData` MUST check `updatedAt` (staleness), `answeredInRound >= roundId`, and min/max bounds. Missing = stale/negative-price acceptance." },
      { id: "price-getter", re: /\b(getPrice|getUnderlyingPrice|price\s*\()/, why: "Custom price getter — trace its source: a spot ratio is manipulable, an unvalidated feed is stale-able. Confirm the source is not attacker-movable in one tx." },
    ],
  },
  {
    klass: "signature-replay",
    severity: "medium",
    rules: [
      { id: "ecrecover", re: /\becrecover\s*\(/, why: "Raw ecrecover — check for signature malleability (constrain `s`, `v`), that `address(0)` on bad input is rejected, and that a nonce+deadline+domain bind each signature to one use/chain/contract." },
      { id: "permit", re: /\b(permit|DOMAIN_SEPARATOR|_hashTypedDataV4|EIP712|_domainSeparatorV4)\b/, why: "EIP-712 / permit — verify the domain separator binds `block.chainid` AND `address(this)` (else cross-chain / cross-deploy replay) and that a per-signer nonce is consumed." },
      { id: "nonce", re: /\b(nonce|nonces|usedSignatures|_used|processed)\b/, why: "Replay bookkeeping — confirm the nonce/used-map is actually incremented/marked BEFORE the authorized action and keyed so a signature cannot be replayed." },
    ],
  },
  {
    klass: "arithmetic-precision",
    severity: "medium",
    rules: [
      { id: "unchecked-block", re: /\bunchecked\s*\{/, why: "unchecked{} disables Solidity 0.8 overflow/underflow traps — verify every op inside cannot wrap for attacker-influenced inputs." },
      { id: "downcast", re: /\buint(8|16|32|64|96|128|160)\s*\(/, why: "Explicit narrowing downcast silently truncates (0.8 does NOT trap this) — a value truncated here can desync a later balance/amount check. Use SafeCast." },
      { id: "mul-div", re: /\bmulDiv\b|\*\s*[A-Za-z_][\w.]*\s*\/|\/\s*[A-Za-z_][\w.]*\s*\*/, why: "Multiply/divide share/fee math — check rounding DIRECTION (should round against the user) and multiply-before-divide ordering to avoid precision loss the attacker captures." },
      { id: "solidity-pragma-old", re: /pragma\s+solidity\s+[\^>=~ ]*0\.[0-7]\b/, why: "Pre-0.8 pragma — arithmetic does NOT trap on overflow/underflow. Every +,-,* on attacker-influenced values is a classic overflow candidate unless SafeMath-wrapped." },
      { id: "first-deposit", re: /\b(totalSupply|totalAssets|convertToShares|convertToAssets|previewDeposit)\b/, why: "ERC4626-style share math — check the first-depositor inflation guard (virtual shares / dead shares / minimum deposit); without it a 1-wei mint + direct donation steals the next depositor." },
    ],
  },
  {
    klass: "mev-dos",
    severity: "low",
    rules: [
      { id: "no-slippage", re: /\b(swap|swapExactTokensFor|addLiquidity|removeLiquidity)\b/, why: "Swap/LP action — confirm a caller-supplied `minAmountOut`/`amountOutMin` and a real `deadline` (not block.timestamp) exist, else it is sandwichable." },
      { id: "block-randomness", re: /\b(block\.timestamp|block\.number|blockhash|block\.prevrandao|block\.difficulty)\b/, why: "Block value used as randomness or a hard deadline — miner/validator-influenceable; not a safe entropy or fairness source." },
      { id: "unbounded-loop", re: /\bfor\s*\(|\bwhile\s*\(/, why: "Loop — if it iterates an attacker-growable array (holders, queue, per-user list) it can be pushed past the block gas limit to brick the function (griefing DoS). Confirm the bound." },
      { id: "approve-race", re: /\.\s*approve\s*\(/, why: "approve() — the classic allowance front-run race; prefer increase/decreaseAllowance or a set-to-zero-first pattern." },
    ],
  },
];

/** Per-class cap so the seed list stays useful, not enormous. */
const PER_CLASS_CAP = 25;
/** Global cap across all classes (the prompt only renders the first 30 anyway). */
const GLOBAL_CAP = 120;
/** ripgrep wall-clock guard. */
const RG_TIMEOUT_MS = 60_000;

interface RgMatch {
  path: string;
  lineNumber: number;
  line: string;
  column: number;
}

/**
 * Strip lookbehind/lookahead groups from a regex source so it is accepted by
 * ripgrep's default (Rust regex) engine, which rejects lookaround. The rule's
 * lookarounds never contain a nested `)`, so a flat removal is safe. The
 * resulting pattern OVER-matches; `classifyLine` re-applies the precise rule
 * regex in JS to drop those.
 */
function toRgSource(source: string): string {
  return source
    .replace(/\(\?<[=!][^)]*\)/g, "") // lookbehind (?<=...) / (?<!...)
    .replace(/\(\?[=!][^)]*\)/g, ""); // lookahead  (?=...)  / (?!...)
}

/**
 * Run ripgrep for one bug class (all its rules OR-ed via -e) and return raw
 * line matches. We OR the class's patterns into ONE ripgrep invocation (~8
 * processes total, not one-per-rule) and re-classify each hit in JS against the
 * rule table — fast over big trees, precise per-rule labelling.
 */
function rgClass(targetPath: string, klass: EvmBugClass): RgMatch[] {
  const combined = klass.rules.map((r) => `(?:${toRgSource(r.re.source)})`).join("|");
  const args = [
    "--json",
    "-g",
    "*.sol",
    // Skip dependency + build artifacts that survive in a tree.
    "-g",
    "!node_modules/**",
    "-g",
    "!lib/**",
    "-g",
    "!out/**",
    "-g",
    "!artifacts/**",
    "-g",
    "!cache/**",
    "-e",
    combined,
    targetPath,
  ];

  let raw = "";
  try {
    raw = execFileSync("rg", args, {
      timeout: RG_TIMEOUT_MS,
      stdio: "pipe",
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    // ripgrep exits 1 when there are no matches — that is not an error for us.
    const code = err && typeof err === "object" && "status" in err ? (err as { status: number }).status : undefined;
    const stdout = err && typeof err === "object" && "stdout" in err ? (err as { stdout?: Buffer | string }).stdout : undefined;
    if (code === 1 && !stdout) return [];
    raw = typeof stdout === "string" ? stdout : stdout ? stdout.toString("utf-8") : "";
    if (!raw) return [];
  }

  const matches: RgMatch[] = [];
  for (const rawLine of raw.split("\n")) {
    if (!rawLine.trim()) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(rawLine);
    } catch {
      continue;
    }
    if (!obj || typeof obj !== "object") continue;
    const rec = obj as { type?: string; data?: any };
    if (rec.type !== "match" || !rec.data) continue;
    const path: string | undefined = rec.data.path?.text;
    const lineNumber: number | undefined = rec.data.line_number;
    const lineText: string | undefined = rec.data.lines?.text;
    const column: number = rec.data.submatches?.[0]?.start ?? 0;
    if (!path || !lineNumber || lineText === undefined) continue;
    matches.push({ path, lineNumber, line: lineText.replace(/\n$/, ""), column });
  }
  return matches;
}

/**
 * Decide whether a matched line should be dropped as obvious noise:
 * - pure comment lines (`// ...`, `/* ... *​/`, `* ...`), where a token is
 *   documented not used;
 * - import lines (the symbol is imported, not a call site).
 */
function isNoiseLine(line: string): boolean {
  const trimmed = line.trimStart();
  if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) return true;
  if (/^import(\s|$)/.test(trimmed)) return true;
  return false;
}

/**
 * Classify a matched line to the first rule in the class whose regex matches.
 * Returns undefined if none re-match (can happen when the combined alternation
 * matched via a different rule's overlap — rare; we just skip).
 */
function classifyLine(line: string, klass: EvmBugClass): EvmRule | undefined {
  for (const rule of klass.rules) {
    // Rebuild a global-free copy to avoid lastIndex state across calls.
    const re = new RegExp(rule.re.source, rule.re.flags.replace("g", ""));
    if (re.test(line)) return rule;
  }
  return undefined;
}

/**
 * Generate Solidity/EVM seeds for a source tree, as `SemgrepFinding[]` ready to
 * push into the review pipeline's `semgrepFindings` list. Paths are made
 * tree-relative so they match the rest of the pipeline's conventions.
 */
export function generateEvmSeeds(targetPath: string): SemgrepFinding[] {
  const base = targetPath.endsWith("/") ? targetPath : `${targetPath}/`;
  const seeds: SemgrepFinding[] = [];

  for (const klass of BUG_CLASSES) {
    let kept = 0;
    let raw: RgMatch[];
    try {
      raw = rgClass(targetPath, klass);
    } catch {
      // ripgrep missing or failed for this class — skip it, keep the others.
      continue;
    }
    for (const m of raw) {
      if (kept >= PER_CLASS_CAP) break;
      if (isNoiseLine(m.line)) continue;
      const rule = classifyLine(m.line, klass);
      if (!rule) continue;
      const relPath = m.path.startsWith(base) ? m.path.slice(base.length) : m.path;
      seeds.push({
        ruleId: `evm-seed.${klass.klass}.${rule.id}`,
        message: rule.why,
        severity: klass.severity,
        path: relPath,
        startLine: m.lineNumber,
        endLine: m.lineNumber,
        snippet: m.line.trim().slice(0, 300),
        metadata: {
          source: "evm-seed",
          bugClass: klass.klass,
          rule: rule.id,
          // Honest provenance: this is a regex lead, not a verified finding.
          seedKind: "regex",
        },
      });
      kept++;
    }
  }

  // Stable, useful ordering: highest-severity classes first (external-call /
  // delegatecall / cross-chain), and hard-cap the total so the prompt sees the
  // most promising leads.
  const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };
  seeds.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  return seeds.slice(0, GLOBAL_CAP);
}
