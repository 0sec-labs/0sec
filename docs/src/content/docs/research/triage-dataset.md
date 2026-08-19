---
title: Triage Dataset
description: How 0sec turns benchmark runs and verified findings into labeled JSONL for triage-model training.
---

`packages/benchmark/src/triage-data-collector.ts` converts benchmark artifacts
and local verified findings into a single JSONL dataset for training
true-positive / false-positive classifiers.

The output is designed to be useful for two families of models:

- pure text classifiers over finding title / description / request / response
- hybrid models that fuse text embeddings with 0sec's handcrafted
  45-feature vector

This is the data pipeline behind the paper-plan tracked in
[issue #67](https://github.com/0sec-labs/0sec/issues/67).

## Inputs

The collector supports four input surfaces:

| Input | Flag | Ground truth source |
|------|------|---------------------|
| XBOW / Cybench-style results JSON | `--results <file>` | Flag extraction |
| npm-bench results JSON | `--npm-bench <file>` | Package verdict |
| 0sec SQLite DB | `--db <file>` | Blind verify status |
| Directory of scan DBs | `--scan-dir <dir>` | Blind verify status |

If you run the collector with no explicit `--results` or `--npm-bench`
flag, it will also auto-scan `packages/benchmark/results/*.json` and route
files by filename:

- `*npm-bench*.json` -> npm-bench path
- every other `.json` -> XBOW-style path

## Quick start

Run against a specific benchmark artifact:

```bash
pnpm --filter @0sec/benchmark exec tsx src/triage-data-collector.ts \
  --npm-bench packages/benchmark/results/npm-bench-latest.json \
  --output packages/benchmark/results/triage-dataset.jsonl
```

Combine npm-bench with local verified findings from the SQLite DB:

```bash
pnpm --filter @0sec/benchmark exec tsx src/triage-data-collector.ts \
  --npm-bench packages/benchmark/results/npm-bench-latest.json \
  --db ~/.0sec/0sec.db \
  --output packages/benchmark/results/triage-dataset-mixed.jsonl
```

Pull labels from a whole directory of scan databases:

```bash
pnpm --filter @0sec/benchmark exec tsx src/triage-data-collector.ts \
  --scan-dir ./.0sec/scans \
  --output packages/benchmark/results/triage-dataset-from-db.jsonl
```

## Output schema

Each line is one JSON object with this shape:

| Field | Type | Meaning |
|------|------|---------|
| `text` | `string` | Flattened training text: title, category, severity, description, request, response, optional analysis |
| `features` | `number[45]` | Handcrafted feature vector from `extractFeatures()` |
| `label` | `0 \| 1` | Numeric classification target |
| `label_text` | `"true_positive" \| "false_positive"` | Human-readable target |
| `source` | `string` | Provenance string identifying the benchmark case or verified scan |
| `label_source` | `string` | How the ground truth was assigned |
| `confidence` | `number` | Agent-reported confidence copied from the finding when available |

## `label_source` values

The current `TriageSample` type exposes these values:

| `label_source` | Meaning | Emitted by current collector? |
|----------------|---------|-------------------------------|
| `flag_extraction` | The agent got the real benchmark flag, so the finding is treated as a true positive | Yes |
| `package_verdict` | The benchmark labels the package as `malicious`, `vulnerable`, or `safe` | Yes |
| `blind_verify` | The finding status in the SQLite DB says it was verified / confirmed vs false-positive / rejected | Yes |
| `manual` | Reserved for future hand-curated rows or external labels | Not by the built-in collector today |

## Ground truth by source

| Source | Positive label | Negative label | Notes |
|--------|----------------|----------------|-------|
| XBOW / Cybench results | `flagFound = true` | `flagFound = false` | One benchmark result can yield many finding rows |
| npm-bench | package verdict is `malicious` or `vulnerable` | package verdict is `safe` | Coarse package-level labeling, not per-finding labeling |
| SQLite DB | finding status is `verified` or `confirmed` | finding status is `false_positive` or `rejected` | Skips rows with unknown status |

## Provenance strings

`source` is deliberately simple and human-readable:

| Source family | Format | Example |
|---------------|--------|---------|
| XBOW / Cybench-style JSON | `<challenge-id>` | `XBEN-001` |
| npm-bench | `npm-bench:<pkg>:<verdict>` | `npm-bench:event-stream:malicious` |
| SQLite DB | `<target>-<scan_id>` | `https://example.com-scan_01HXYZ...` |

The row `id` is stricter and used only for deduplication. It is built from
the benchmark case / scan id plus the finding id when available.

## Example row

Pretty-printed example, abbreviated for readability. The real `features`
array always has 45 numeric entries.

```json
{
  "text": "Title: Prototype pollution\nCategory: prototype_pollution\nSeverity: high\nDescription: Vulnerable merge path reachable from user input\nRequest: GET /api/search?q=__proto__\nResponse: HTTP/1.1 500 Internal Server Error\nAnalysis: Confirmed by benchmark ground truth",
  "features": [500, 0, 0, 1, 0, 0, 0, 0, 0, 33, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 3, 0.9, 1, 1, 0, 1, 0, 0, 58, 1, 1, 0, 1, 42, 0, 1, 1, 1, 1, 2.7, 1.5, 1],
  "label": 1,
  "label_text": "true_positive",
  "source": "npm-bench:lodash@4.17.20:vulnerable",
  "label_source": "package_verdict",
  "confidence": 0.9
}
```

## Dedup, balance, split

- Dedup by `id` first. The collector already does this before writing.
- Stratify by both `label_text` and `label_source`, not just the binary label.
- Keep benchmark families separated when you can. For example, don't let
  all rows from the same benchmark case leak across train and test.
- For mixed datasets, report metrics per source family as well as global
  averages. A model that performs well on web findings may do poorly on
  npm supply-chain findings.

Recommended split policy:

1. Hold out one whole source family if you want a domain-transfer test.
2. Otherwise split within each `label_source` bucket.
3. Preserve class balance after deduplication, not before.

## Label-noise caveat

`package_verdict` is intentionally coarse. If a package is labeled `safe`,
then every finding emitted against it becomes a `false_positive` row. That
is useful because it gives us cheap negative labels at scale, but it is not
the same thing as hand-labeling each finding individually.

That trade-off is acceptable for baseline training and ablation work, but
any paper or benchmark should call out the noise floor explicitly.

## Related

- [Feature Extractor](/research/feature-extractor/) — the 45-element vector carried in every row
- [FP Reduction Moat](/research/fp-reduction-moat/) — where the dataset fits into the broader triage stack
- [Finding Triage ML](/research/finding-triage-ml/) — the design doc for the full hybrid model direction
