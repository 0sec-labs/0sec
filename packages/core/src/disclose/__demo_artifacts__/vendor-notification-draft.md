# Vulnerability report: Unauthenticated SQL injection in CodeWall /api/reports org filter

> **DRAFT — NOT SENT.** Auto-assembled vendor-notification draft. An operator must review, fill in any `to be filled in` fields, and send it manually. Nothing here is transmitted to a vendor by 0sec. Embargo rules in `disclosure/AGENTS.md` apply.

**Severity (estimate):** critical

## What

The `/api/reports` endpoint interpolates the `org` query parameter directly into a SQL WHERE clause with no authentication and no parameterisation. An unauthenticated attacker can read arbitrary rows across all tenants (cross-tenant data exposure) and enumerate the schema.

## Where

`codewall` (ref `v3.4.0`)

## Impact

Critical — full compromise / unauthenticated remote impact is plausible.

## Reproduction

1. **Stand up the CodeWall demo target** _(setup)_

```sh
docker compose -f codewall/docker-compose.yml up -d
```

2. **Inject a boolean-based SQL payload into the unauthenticated /api/reports filter** _(exploit)_

```http
GET https://demo.codewall.example/api/reports?org=1%27%20OR%20%271%27%3D%271
Authorization: <REDACTED-Authorization>
Cookie: <REDACTED-Cookie>
X-Api-Key: <REDACTED-X-Api-Key>
```

3. **Confirm the response leaks rows from a table the org should not see** _(verify)_

Response returns rows for every org, not just org=1 — confirms unauthenticated cross-tenant SQLi.

## Suggested remediation

Use parameterised queries and require authentication on /api/reports.

1. Replace string concatenation with a parameterised query / prepared statement.
2. Require an authenticated, org-scoped session before serving /api/reports.
3. Add an org-scoping predicate so a session can only read its own org's rows.
