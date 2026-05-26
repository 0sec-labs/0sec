# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in pwnkit, please report it via email to **security@0sec.ai** or via [GitHub Security Advisories](https://github.com/0sec-labs/pwnkit/security/advisories/new).

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x+  | Yes       |

## Binary integrity (supply-chain)

Every release publishes a `checksums.txt` manifest alongside the
per-platform standalone binaries. Both supported install paths refuse
to run an unverified binary:

- **`install.sh`** (curl-pipe-bash and direct invocation) downloads
  `checksums.txt` from the same release tag as the binary, computes the
  SHA-256 of the downloaded binary with `sha256sum` (Linux) or
  `shasum -a 256` (macOS), and compares against the manifest entry. A
  mismatch — or a missing manifest entry — aborts the install **before**
  the binary is made executable.
- **`pwnkit-cli` npm launcher** (`scripts/npm-launcher/launcher.cjs`)
  does the same in Node: fetches `checksums.txt` first, streams the
  binary to a temp file with mode `0600`, verifies SHA-256, and only
  then `chmod +x`'s and atomically renames into
  `~/.pwnkit/cache/v<version>/`.

A tampered binary in flight (compromised CDN, hostile network) cannot
pass either check. A compromised release that re-published binaries
without re-uploading the manifest also fails closed.

### Out of scope today (tracked follow-ups)

- Sigstore / cosign signing of release binaries
- Signed Git tags on release commits
- SBOMs / SLSA provenance attestations
- Migration to a "bootstrap binary" pattern (current curl + chmod is
  acceptable once verified)

If you find a way around the verification above — or a regression in
either install path — please report it via the security advisory link
at the top of this file.
