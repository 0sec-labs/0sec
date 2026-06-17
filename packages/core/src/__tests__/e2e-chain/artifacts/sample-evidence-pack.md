# CodeWall chain — evidence pack

> Self-test against a LOCAL vulnerable fixture (127.0.0.1 only). All
> findings below were planted; this demonstrates the chained tools firing
> end-to-end. No external target was contacted.

- **Target:** `http://127.0.0.1:PORT`
- **Generated:** 2026-06-17T00:00:00Z

## Stage 2 — JS recon (`js_recon`)

Discovered 4 endpoint(s) from the public JS bundle:

- `GET /api/public/users` (source: http://127.0.0.1:PORT/static/app.js)
- `POST /api/reports` (source: http://127.0.0.1:PORT/static/app.js)
- `GET /api/admin/config` (source: http://127.0.0.1:PORT/static/app.js)
- `GET /api` (source: http://127.0.0.1:PORT/static/app.js)

Leaked secrets (redacted):

- aws_access_key_id [REDACTED, high confidence] — found in `http://127.0.0.1:PORT/static/app.js`

## Stage 3 — Auth-boundary probe (`auth_boundary_probe`)

2 of 4 probed endpoint(s) reachable WITHOUT credentials.

- LEAK [high] — `GET http://127.0.0.1:PORT/api/public/users` → unauth-reachable (unauthenticated request retrieved the SAME resource as the authenticated baseline (body similarity 1.00) — protected endpoint exposed to anonymous callers)
- LEAK [high] — `POST http://127.0.0.1:PORT/api/reports` → unauth-reachable (unauthenticated request retrieved the SAME resource as the authenticated baseline (body similarity 1.00) — protected endpoint exposed to anonymous callers)
- holds — `GET http://127.0.0.1:PORT/api/admin/config` → auth-required (unauthenticated request was denied (HTTP 401); auth boundary holds)
- holds — `GET http://127.0.0.1:PORT/api` → not-found (endpoint returned HTTP 404 unauthenticated; nothing to gate)

## Stage 4 — Structural SQLi probe (`structural_sqli_probe`)

- **Injected key:** `sort`
- **Verdict:** `confirmed`
- **Dialect:** `sqlite`

Iteration trail:

  1. payload=`sort'` balanced=false → error_signal (broken key triggered a sqlite SQL error — key reaches the parser)
  2. payload=`sort'--` balanced=true → confirmed (balanced sqlite key parsed cleanly while broken key errored — structural SQLi confirmed)

## Stage 5 — Cloud surface probe (`cloud_probe_s3`)

- **Bucket:** `acme-reports-export-fixture`
- **Endpoint:** `https://acme-reports-export-fixture.s3.amazonaws.com`
- **Access verdict:** `public` [high] — Anonymous GET / returned 200 — bucket contents are publicly listable. ACL is also publicly readable.
- **Takeover:** `no` [info] — Bucket "acme-reports-export-fixture" exists (verdict: public) — not takeover-able.

## Chain summary

recon → js_recon → auth_boundary_probe → structural_sqli → cloud_probe

The endpoints js_recon pulled out of the public JS fed directly into the
auth-boundary probe and the SQLi probe; the bucket name js_recon found fed
the cloud probe. Each stage consumed the previous stage's output.
