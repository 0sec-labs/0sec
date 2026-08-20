# Windows variant ranker contract fixture

This is a synthetic, non-executable regression fixture. It proves the manifest,
hash, guard-transfer, reachability-annotation, patched-control suppression, and
evaluation contracts. It is explicitly **not** a capability benchmark and
contains no real Windows code or vulnerability.

Run from the repository root:

```bash
0verse windows-variant-rank benchmarks/windows_variant_contract/campaign.json
0verse windows-variant-eval \
  benchmarks/windows_variant_contract/campaign.json \
  benchmarks/windows_variant_contract/labels.json
```

`windows-discover` is the label-blind producer path for real semantic High-P-Code
v3 bundles. The legacy fixtures in this directory intentionally remain variant-rank
fixtures; `tests/test_windows_discovery.py` constructs validated v3 facts and proves
the discovery boundary without reading a seed or labels. It accepts either the
minimal v3 campaign or the exact bound audit output from
`windows_driver_pair_intake`; neither form establishes servicing lineage or
adjacency. `--output` uses an atomic no-replace, no-follow mode-0600 file boundary.
