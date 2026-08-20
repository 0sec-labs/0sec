# Foxguard baseline

This baseline contains only feature-resolution false positives for the native
Windows SSHSIG dependency. Cargo records `ssh-key` 0.6.7's disabled optional
ECDSA/RSA packages in `Cargo.lock` even though the crate enables only `std` and
`ed25519`. `cargo tree -e normal` excludes `p521` and `rsa`, and Windows CI fails
if RSA enters the compiled graph.

The three fingerprints are intentionally lockfile-specific. Any lockfile change
invalidates them and requires a fresh dependency/security review; do not broaden
the baseline to source findings or enabled dependencies.
