# Test-only SSHSIG interoperability vector

These deterministic Ed25519 materials exist only to prove byte compatibility
between OpenSSH `ssh-keygen -Y` and the native Rust broker. The private key is
public test data and must never be used for authorization or production signing.
