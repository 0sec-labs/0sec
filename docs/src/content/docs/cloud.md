---
title: 0sec cloud
description: How the managed 0sec cloud layer relates to the OSS agent and docs site.
---

:::note
**Managed offering — separate from the open-source CLI.** Everything below is the
paid managed layer, not the OSS `0sec` engine documented in the rest of this site.
:::

`0sec cloud` is the managed recurring-run surface built on top of the public
`0sec` engine. It uses no private fork — the scanner, benchmarks, and
verification logic all stay in the OSS repo.

**OSS (`0sec`):** CLI scanning, benchmarks and methodology, blind verification,
triage and reporting primitives, and these docs.

**Managed (`0sec cloud`) adds:** recurring scans, orchestration across
protected/authenticated targets, an operator triage workflow, customer-facing
evidence bundles, and managed storage and scheduling.

This split is why the marketing site cites public benchmark receipts while the
managed layer sells reliability, continuity, and operations.

## Read next

- [Architecture](/architecture/) — the public execution model
- [Benchmark](/benchmark/) — public performance and methodology
- [Adversarial Evals](/adversarial-evals/) — category framing
