# Windows link-following (CWE-59) lens contract fixture

This is a synthetic, non-executable capability contract for the CWE-59
link-following lens in `windows-variant-rank`. It models the public
RoguePlanet/ShieldBreak class: a service resolves an attacker-influenced path
more than once (scan-then-purge) without a reparse/link check, while a hardened
sibling performs the check and must be suppressed. It contains no real Windows
code and no real vulnerability.

What it pins:

- the `file-open` / `file-mutate` path-sink families and the `reparse-check`
  guard transfer;
- the double-resolution (TOCTOU) window ranking signal — `ScanThenPurge`
  re-resolves one path through two sinks and must outrank the single-use
  `QuarantineMove`;
- patched-control suppression of `HardenedQuarantine`;
- the candidate-only output contract (`weaponization=false`,
  `automatic_disclosure=false`).

Run from the repository root:

```bash
0verse windows-variant-rank benchmarks/windows_linkfollow_contract/campaign.json
0verse windows-variant-eval \
  benchmarks/windows_linkfollow_contract/campaign.json \
  benchmarks/windows_linkfollow_contract/labels.json
```

A passing run is a contract regression result only. Real capability claims need
the hash-pinned corpus gate in `docs/WINDOWS-VARIANT-RANK.md` evaluated per lens
family, then independent reachability and dynamic proof for every candidate.
