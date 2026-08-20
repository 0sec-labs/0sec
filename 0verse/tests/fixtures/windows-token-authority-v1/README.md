# Native authority-chain interop vector

These compact JSON files are a fixed Python/OpenSSH-produced vector for the
Windows native capture broker. The raw bytes, including the final LF, are part
of the SHA-256 bindings in `expected.json`; `.gitattributes` therefore pins LF
line endings.

The directory name is historical: the chain intentionally mixes campaign and
grant v1, scope and worker-acceptance v2. The current acceptance wire contract
is v2 and older acceptance documents are rejected.

The three signed documents use the public test-only key in
`../windows-token-sshsig/allowed_signers`. The corresponding private key is a
committed test fixture only and must never be accepted by a deployed broker.
The verifier injects `2026-07-15T00:00:00Z` so freshness checks are
deterministic and do not weaken production operation-time validation.
