# Related Work Notes for 0sec Paper Draft

This file captures comparable systems and references already discussed in the
0sec docs, reformatted for paper writing.

## 1) Agentic Pentesting Systems

Primary source for this section:
`docs/src/content/docs/research/competitive-landscape.md`.

| System | Reported score/context | Notable trait |
|---|---|---|
| BoxPwnr | 97.1% XBOW headline | Shell-first orchestration and broad benchmark coverage |
| Shannon | 96.15% XBOW (white-box) | Multi-agent workflow with source-first analysis |
| KinoSec | 92.3% XBOW (black-box) | Tight black-box execution constraints |
| MAPTA | 76.9% XBOW (paper) | Evidence-gated branching and role decomposition |
| deadend-cli | 77.55% (reported subset context) | Single-agent recursive decomposition |

Use this table as context, not as a strict apples-to-apples leaderboard. The
methodology page should always clarify protocol differences.

## 2) FP Reduction and Triage Architectures

Primary sources:

- `docs/src/content/docs/research/fp-reduction-moat.md`
- `docs/src/content/docs/research/finding-triage-ml.md`

Patterns that recur across disclosed systems:

1. deterministic/rule filters,
2. reachability or execution realism checks,
3. LLM-assisted or model-assisted triage,
4. memory/feedback loops from prior analyst decisions.

Within 0sec docs, Endor Labs and Semgrep Assistant are used as reference
points for this shape (with caveats that the exact commercial internals are
not fully open).

## 3) Hybrid Feature + Model Signals

0sec docs cite VulnBERT-style hybrid thinking (handcrafted features plus
model features) as motivation for triage routing and classifier design.

Important writing constraint: frame this as architectural inspiration rather
than claiming direct equivalence in task/domain (kernel commit classification
vs agent-generated finding triage).

## 4) Debate, PoV, and Evidence-Gated Verification

The triage docs reference:

- MAPTA-style evidence-gated branching,
- PoV-first verification logic,
- adversarial/debate verification structures.

For the paper, anchor these as "design influences" unless a one-to-one
implementation and benchmark comparison is shown.

## 5) Positioning Statement (Draft)

Suggested concise positioning for 0sec:

"Relative to prior open and closed systems, 0sec's primary contribution is
not a novel single triage primitive but an open, end-to-end integration of
shell-first exploitation, layered verification, and methodology-explicit
benchmark accounting with retained artifact lineage."

## 6) Citation Hygiene Checklist

Before submission, verify each related-work claim has:

1. a primary source link,
2. a date/context qualifier if benchmark numbers are used,
3. explicit protocol caveats when comparing across systems,
4. no implication that non-open systems expose internals they do not publish.
