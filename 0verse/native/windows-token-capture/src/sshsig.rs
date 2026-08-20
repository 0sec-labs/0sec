use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use zeroize::Zeroizing;

const MAX_MATERIAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;

fn safe_label(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
    {
        return Err(format!("SSHSIG {name} is empty, oversized, or unsafe"));
    }
    Ok(())
}

fn validate_material(material: &[u8]) -> Result<(), String> {
    if material.is_empty() || material.len() > MAX_MATERIAL_BYTES {
        return Err("SSHSIG material is empty or oversized".to_owned());
    }
    Ok(())
}

fn exact_ed25519_signer(policy: &str, identity: &str) -> Result<PublicKey, String> {
    if policy.len() > MAX_POLICY_BYTES || policy.contains('\0') {
        return Err("allowed-signers policy is oversized or unsafe".to_owned());
    }
    let mut matched = None;
    for (index, raw_line) in policy.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let principals = fields
            .next()
            .ok_or_else(|| format!("allowed-signers line {} is malformed", index + 1))?;
        let key_type = fields
            .next()
            .ok_or_else(|| format!("allowed-signers line {} is malformed", index + 1))?;
        let key_body = fields
            .next()
            .ok_or_else(|| format!("allowed-signers line {} is malformed", index + 1))?;
        if key_type != "ssh-ed25519" {
            return Err(format!(
                "allowed-signers line {} is not an exact Ed25519 key",
                index + 1
            ));
        }
        if principals.contains(',') {
            return Err("allowed-signers principal lists are unsupported".to_owned());
        }
        safe_label(principals, "policy principal")?;
        if principals
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'!'))
        {
            return Err("allowed-signers wildcard principals are unsupported".to_owned());
        }
        if principals != identity {
            continue;
        }
        if matched.is_some() {
            return Err("allowed-signers identity matches more than one key".to_owned());
        }
        let public = PublicKey::from_openssh(&format!("{key_type} {key_body}"))
            .map_err(|_| "allowed-signers Ed25519 key is invalid".to_owned())?;
        if public.algorithm() != Algorithm::Ed25519 {
            return Err("allowed-signers key algorithm is not Ed25519".to_owned());
        }
        matched = Some(public);
    }
    matched.ok_or_else(|| "allowed-signers identity has no exact key".to_owned())
}

fn public_key_sha256(public: &PublicKey) -> Result<String, String> {
    let canonical = public
        .to_bytes()
        .map_err(|_| "cannot canonicalize SSHSIG Ed25519 public key".to_owned())?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

pub(crate) fn ed25519_policy_key_sha256(policy: &str, identity: &str) -> Result<String, String> {
    public_key_sha256(&exact_ed25519_signer(policy, identity)?)
}

#[cfg(any(windows, test))]
pub(crate) fn ed25519_private_key_public_sha256(private_key_pem: &[u8]) -> Result<String, String> {
    if private_key_pem.is_empty()
        || private_key_pem.len() > MAX_PRIVATE_KEY_BYTES
        || private_key_pem.contains(&0)
    {
        return Err("SSHSIG private key is empty, oversized, or unsafe".to_owned());
    }
    let private = PrivateKey::from_openssh(private_key_pem)
        .map_err(|_| "SSHSIG private key is encrypted, malformed, or unsupported".to_owned())?;
    if private.algorithm() != Algorithm::Ed25519 {
        return Err("SSHSIG private key is not Ed25519".to_owned());
    }
    public_key_sha256(private.public_key())
}

/// Verify one OpenSSH SSHSIG using a deliberately strict allowed-signers subset.
///
/// The policy accepts exact, non-wildcard principals and Ed25519 public keys only.
/// Options, certificates, wildcard principals, and multiple matching keys fail
/// closed so service authorization cannot drift from a single reviewed identity.
///
/// # Errors
///
/// Returns an error for unsafe inputs, unsupported policy syntax or algorithms,
/// namespace/key mismatch, or a cryptographically invalid signature.
pub fn verify_ed25519(
    material: &[u8],
    signature_pem: &str,
    identity: &str,
    namespace: &str,
    allowed_signers: &str,
) -> Result<(), String> {
    validate_material(material)?;
    safe_label(identity, "identity")?;
    safe_label(namespace, "namespace")?;
    if signature_pem.len() > MAX_SIGNATURE_BYTES
        || !signature_pem.starts_with("-----BEGIN SSH SIGNATURE-----\n")
        || !signature_pem
            .trim_end()
            .ends_with("-----END SSH SIGNATURE-----")
        || signature_pem.contains('\0')
    {
        return Err("SSHSIG armor is malformed or oversized".to_owned());
    }
    let public = exact_ed25519_signer(allowed_signers, identity)?;
    let signature = SshSig::from_pem(signature_pem)
        .map_err(|_| "SSHSIG armor or payload is invalid".to_owned())?;
    if signature.version() != SshSig::VERSION
        || signature.algorithm() != Algorithm::Ed25519
        || signature.hash_alg() != HashAlg::Sha512
        || !signature.reserved().is_empty()
    {
        return Err("SSHSIG uses an unsupported version, algorithm, hash, or extension".to_owned());
    }
    public
        .verify(namespace, material, &signature)
        .map_err(|_| "SSHSIG signature, key, or namespace is invalid".to_owned())
}

/// Prove that an OpenSSH private key corresponds to the one exact Ed25519
/// identity selected from an allowed-signers policy.
///
/// This performs no signing and accepts no path. Callers retain ownership of
/// the source buffer so a service can keep it in a zeroizing allocation.
///
/// # Errors
///
/// Returns an error for an unsafe/ambiguous policy, an encrypted or unsupported
/// private key, or a public-key mismatch.
pub fn verify_private_key_identity(
    private_key_pem: &[u8],
    identity: &str,
    allowed_signers: &str,
) -> Result<(), String> {
    if private_key_pem.is_empty()
        || private_key_pem.len() > MAX_PRIVATE_KEY_BYTES
        || private_key_pem.contains(&0)
    {
        return Err("SSHSIG private key is empty, oversized, or unsafe".to_owned());
    }
    let expected = exact_ed25519_signer(allowed_signers, identity)?;
    let private = PrivateKey::from_openssh(private_key_pem)
        .map_err(|_| "SSHSIG private key is encrypted, malformed, or unsupported".to_owned())?;
    if private.algorithm() != Algorithm::Ed25519
        || private.public_key().key_data() != expected.key_data()
    {
        return Err("SSHSIG private key does not match the configured identity".to_owned());
    }
    Ok(())
}

/// Require two OpenSSH Ed25519 private keys to have different public keys.
///
/// This is a custody-domain separation check, not a byte-encoding comparison:
/// alternate encodings of the same key are still rejected.
///
/// # Errors
///
/// Returns an error when either key is unsafe, encrypted, malformed, not
/// Ed25519, or resolves to the same public key.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "key separation is enforced by the Windows-only device store"
    )
)]
pub(crate) fn require_distinct_ed25519_private_keys(
    first: &[u8],
    second: &[u8],
) -> Result<(), String> {
    let parse = |bytes: &[u8], label: &str| -> Result<PrivateKey, String> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_KEY_BYTES || bytes.contains(&0) {
            return Err(format!(
                "SSHSIG {label} private key is empty, oversized, or unsafe"
            ));
        }
        let key = PrivateKey::from_openssh(bytes).map_err(|_| {
            format!("SSHSIG {label} private key is encrypted, malformed, or unsupported")
        })?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(format!("SSHSIG {label} private key is not Ed25519"));
        }
        Ok(key)
    };
    let first = parse(first, "first")?;
    let second = parse(second, "second")?;
    if first.public_key().key_data() == second.public_key().key_data() {
        return Err("SSHSIG private keys reuse the same Ed25519 public key".to_owned());
    }
    Ok(())
}

/// Sign bounded material as an OpenSSH-compatible Ed25519 SSHSIG using SHA-512.
///
/// This cryptographic primitive does not read a path or establish that the key
/// is service-owned. A2 must pass bytes loaded through its LocalSystem-only,
/// handle-validated key store and zeroize the source buffer after parsing.
///
/// # Errors
///
/// Returns an error for unsafe inputs, an encrypted/malformed/non-Ed25519 key,
/// signing failure, or PEM encoding failure.
pub fn sign_ed25519(
    material: &[u8],
    private_key_pem: Zeroizing<Vec<u8>>,
    namespace: &str,
) -> Result<String, String> {
    validate_material(material)?;
    safe_label(namespace, "namespace")?;
    if private_key_pem.len() > MAX_PRIVATE_KEY_BYTES || private_key_pem.contains(&0) {
        return Err("SSHSIG private key is oversized or unsafe".to_owned());
    }
    let private = PrivateKey::from_openssh(private_key_pem.as_slice())
        .map_err(|_| "SSHSIG private key is encrypted, malformed, or unsupported".to_owned())?;
    if private.algorithm() != Algorithm::Ed25519 {
        return Err("SSHSIG private key is not Ed25519".to_owned());
    }
    let result = private
        .sign(namespace, HashAlg::Sha512, material)
        .and_then(|signature| signature.to_pem(LineEnding::LF))
        .map_err(|_| "SSHSIG signing or PEM encoding failed".to_owned());
    drop(private);
    drop(private_key_pem);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATERIAL: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/material.json");
    const SIGNATURE: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/material.json.sig");
    const PRIVATE_KEY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");
    const IDENTITY: &str = "capture@example.test";
    const NAMESPACE: &str = "0verse-windows-token-capture";
    const DISTINCT_PRIVATE_KEY: &str =
        include_str!("../../../tests/fixtures/windows-device-open-sshsig/test-only-key");

    #[test]
    fn verifies_openssh_signature_and_reproduces_it_byte_for_byte() {
        verify_ed25519(MATERIAL, SIGNATURE, IDENTITY, NAMESPACE, POLICY).unwrap();
        assert_eq!(
            sign_ed25519(
                MATERIAL,
                Zeroizing::new(PRIVATE_KEY.as_bytes().to_vec()),
                NAMESPACE,
            )
            .unwrap(),
            SIGNATURE
        );
    }

    #[test]
    fn rejects_wrong_role_namespace_material_and_policy_ambiguity() {
        assert!(
            verify_ed25519(MATERIAL, SIGNATURE, "other@example.test", NAMESPACE, POLICY).is_err()
        );
        assert!(verify_ed25519(MATERIAL, SIGNATURE, IDENTITY, "other-namespace", POLICY).is_err());
        assert!(verify_ed25519(b"tampered", SIGNATURE, IDENTITY, NAMESPACE, POLICY).is_err());
        assert!(
            verify_ed25519(
                MATERIAL,
                SIGNATURE,
                IDENTITY,
                NAMESPACE,
                &format!("{POLICY}{POLICY}")
            )
            .is_err()
        );
        assert!(
            verify_ed25519(
                MATERIAL,
                SIGNATURE,
                IDENTITY,
                NAMESPACE,
                &POLICY.replace(IDENTITY, "*@example.test")
            )
            .is_err()
        );
    }

    #[test]
    fn private_key_is_bound_to_exact_policy_identity() {
        verify_private_key_identity(PRIVATE_KEY.as_bytes(), IDENTITY, POLICY).unwrap();
        assert!(
            verify_private_key_identity(PRIVATE_KEY.as_bytes(), "other@example.test", POLICY)
                .is_err()
        );
        assert!(
            verify_private_key_identity(
                PRIVATE_KEY.as_bytes(),
                IDENTITY,
                &POLICY.replace(IDENTITY, "other@example.test"),
            )
            .is_err()
        );
    }

    #[test]
    fn private_key_custody_domains_require_distinct_public_keys() {
        require_distinct_ed25519_private_keys(
            PRIVATE_KEY.as_bytes(),
            DISTINCT_PRIVATE_KEY.as_bytes(),
        )
        .unwrap();
        assert!(
            require_distinct_ed25519_private_keys(PRIVATE_KEY.as_bytes(), PRIVATE_KEY.as_bytes())
                .is_err()
        );
        assert!(
            require_distinct_ed25519_private_keys(PRIVATE_KEY.as_bytes(), b"not a key").is_err()
        );
    }

    #[test]
    fn public_key_fingerprint_ignores_principal_aliases_but_not_keys() {
        let private = ed25519_private_key_public_sha256(PRIVATE_KEY.as_bytes()).unwrap();
        let policy = ed25519_policy_key_sha256(POLICY, IDENTITY).unwrap();
        let aliased_policy = POLICY.replace(IDENTITY, "alias@example.test");
        let alias = ed25519_policy_key_sha256(&aliased_policy, "alias@example.test").unwrap();
        let distinct = ed25519_private_key_public_sha256(DISTINCT_PRIVATE_KEY.as_bytes()).unwrap();
        assert_eq!(private, policy);
        assert_eq!(private, alias);
        assert_ne!(private, distinct);
    }
}
