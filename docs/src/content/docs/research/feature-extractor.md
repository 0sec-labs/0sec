---
title: Feature Extractor
description: Reference for the 45 handcrafted finding-triage features exposed by extractFeatures() and FEATURE_NAMES.
---

`packages/core/src/triage/feature-extractor.ts` exports a 45-element numeric
vector used as a fast first-pass triage signal:

- `extractFeatures(finding): number[]`
- `FEATURE_NAMES: string[]`

The extractor is intentionally cheap:

- pure regex and string operations
- no LLM calls
- no network requests
- no external scanners

It is the handcrafted half of pwnkit's VulnBERT-inspired hybrid direction.

## Why it exists

VulnBERT's reported ablations are the key reference point:

| Model family | Recall | False positive rate |
|--------------|--------|---------------------|
| Handcrafted features alone | 76.8% | 15.9% |
| CodeBERT alone | 84.3% | 4.2% |
| Hybrid features + neural fusion | 92.2% | 1.2% |

pwnkit uses the handcrafted layer today because it is deterministic,
explainable, and cheap enough to run before any paid verification.

## Group breakdown

| Group | Count | Indices |
|------|-------|---------|
| Response features | 13 | `0-12` |
| Request features | 10 | `13-22` |
| Metadata features | 8 | `23-30` |
| Text quality features | 10 | `31-40` |
| Cross-field features | 4 | `41-44` |

## Full reference

### Response features

| Idx | Name | Type | Range | Rationale |
|-----|------|------|-------|-----------|
| 0 | `resp_http_status` | int | `0+` | Raw HTTP status extracted from evidence response |
| 1 | `resp_sql_error` | bool | `0/1` | SQL error strings are strong exploit evidence for SQLi |
| 2 | `resp_stack_trace` | bool | `0/1` | Stack traces often indicate unexpected execution paths |
| 3 | `resp_error_message` | bool | `0/1` | Generic error responses raise exploit plausibility |
| 4 | `resp_payload_exact_reflection` | bool | `0/1` | Exact reflection is strong for reflected XSS / echo-driven bugs |
| 5 | `resp_payload_partial_reflection` | bool | `0/1` | Partial reflection catches normalized or truncated echoes |
| 6 | `resp_sensitive_data` | bool | `0/1` | Leaked credentials / tokens / PII are high-signal evidence |
| 7 | `resp_flag_pattern` | bool | `0/1` | CTF-style flag markers are direct benchmark proof |
| 8 | `resp_content_type_match` | bool | `0/1` | Matching content type helps align evidence with the claimed category |
| 9 | `resp_length` | int | `0+` | Response size often distinguishes empty errors from real leakage |
| 10 | `resp_waf_signature` | bool | `0/1` | WAF blocks can explain false negatives and noisy probes |
| 11 | `resp_redirect` | bool | `0/1` | Redirect behavior matters for auth and route-confusion findings |
| 12 | `resp_5xx_status` | bool | `0/1` | Server errors are noisy but still useful exploit context |

### Request features

| Idx | Name | Type | Range | Rationale |
|-----|------|------|-------|-----------|
| 13 | `req_sql_syntax` | bool | `0/1` | SQL syntax in the request aligns with SQLi claims |
| 14 | `req_xss_payload` | bool | `0/1` | Script / event-handler patterns align with XSS claims |
| 15 | `req_ssti_syntax` | bool | `0/1` | Template delimiters align with SSTI claims |
| 16 | `req_path_traversal` | bool | `0/1` | Traversal markers align with file-read claims |
| 17 | `req_command_injection` | bool | `0/1` | Shell metacharacters align with command-injection claims |
| 18 | `req_encoding_detected` | bool | `0/1` | Encoded payloads often show intentional bypass attempts |
| 19 | `req_http_method` | int | small ordinal | Request-method encoding lets the model distinguish GET/POST/etc. |
| 20 | `req_auth_header` | bool | `0/1` | Auth-bearing requests matter for IDOR / auth-boundary findings |
| 21 | `req_param_count` | int | `0+` | Parameter fanout helps characterize probe complexity |
| 22 | `req_body_length` | int | `0+` | Body size separates tiny probes from full exploit payloads |

### Metadata features

| Idx | Name | Type | Range | Rationale |
|-----|------|------|-------|-----------|
| 23 | `meta_severity_ordinal` | int | `0-4` | Encodes severity as an ordinal prior |
| 24 | `meta_confidence` | float | `0-1` typical | Carries the agent's own confidence into triage |
| 25 | `meta_high_confidence_category` | bool | `0/1` | Some categories are more reliable than others in practice |
| 26 | `meta_injection_class` | bool | `0/1` | Injection bugs share structural traits worth flagging |
| 27 | `meta_access_control_class` | bool | `0/1` | Access-control bugs differ materially from injection bugs |
| 28 | `meta_has_template_id` | bool | `0/1` | Template-backed findings tend to be more structured |
| 29 | `meta_has_cwe` | bool | `0/1` | CWE references correlate with more mature analysis text |
| 30 | `meta_has_cve` | bool | `0/1` | CVE references often indicate external corroboration |

### Text quality features

| Idx | Name | Type | Range | Rationale |
|-----|------|------|-------|-----------|
| 31 | `text_description_length` | int | `0+` | Very short descriptions often correlate with low-quality findings |
| 32 | `text_repro_steps` | bool | `0/1` | Reproduction steps are a strong signal of finding quality |
| 33 | `text_impact_statement` | bool | `0/1` | Explicit impact reasoning raises trust in the finding |
| 34 | `text_hedging_language` | bool | `0/1` | Hedging often correlates with weak or speculative findings |
| 35 | `text_verification_language` | bool | `0/1` | "confirmed", "verified", "reproduced" are strong positive cues |
| 36 | `text_analysis_length` | int | `0+` | Richer analysis text often means a more grounded claim |
| 37 | `text_code_blocks` | bool | `0/1` | Embedded code or PoC snippets raise exploit credibility |
| 38 | `text_evidence_request_nonempty` | bool | `0/1` | Missing request evidence is a major weakness |
| 39 | `text_evidence_response_nonempty` | bool | `0/1` | Missing response evidence is a major weakness |
| 40 | `text_evidence_analysis_nonempty` | bool | `0/1` | Missing analyst context weakens triage quality |

### Cross-field features

| Idx | Name | Type | Range | Rationale |
|-----|------|------|-------|-----------|
| 41 | `cross_payload_category_consistent` | bool | `0/1` | Checks that the request payload matches the claimed bug class |
| 42 | `cross_severity_confidence_interaction` | float | `0+` | Multiplies severity prior by agent confidence |
| 43 | `cross_response_request_length_ratio` | float | `0+` | Large response / request ratios can indicate leakage or reflected amplification |
| 44 | `cross_evidence_completeness` | float | `0-1` | Non-empty request / response / analysis count divided by 3 |

## How features are chosen

The features deliberately mix five signal families:

- response evidence
- request payload shape
- metadata priors
- text-quality heuristics
- cross-field consistency

That split reflects how triage actually works in practice: a finding is not
credible because any one field looks good, but because several independent
signals line up.

## Fusion with neural models

The extractor is meant to pair with text embeddings, not replace them.

The natural hybrid shape is:

1. `text` -> encoder embedding
2. `features` -> linear projection
3. fusion head over both representations
4. binary TP/FP classifier

That is the same broad architecture family referenced from
[Finding Triage ML](/research/finding-triage-ml/).

## Domain-transfer caveat

These features are strongest on web and exploit-style findings because many
of them look for:

- reflected payloads
- status codes
- stack traces
- SQL errors
- request / response evidence density

On npm supply-chain findings, many of those fields are sparse or zero. That
is not a bug in the extractor; it is a real domain-transfer limitation and
exactly the kind of thing a paper should report honestly.

## Reproducibility

- deterministic
- source available
- pure local computation
- no model calls
- no network dependence

That makes the feature vector suitable for ablations, baselines, and
air-gapped experimentation.

## Related

- [Triage Dataset](/research/triage-dataset/) — where this vector is emitted into JSONL
- [Finding Triage ML](/research/finding-triage-ml/) — broader design and hybrid-model direction
- [FP Reduction Moat](/research/fp-reduction-moat/) — how the feature layer fits into the overall stack
