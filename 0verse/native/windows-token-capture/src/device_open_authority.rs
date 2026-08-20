#![allow(
    dead_code,
    reason = "the authority capability remains unreachable until broker request v2 lands"
)]

//! Signed authority for the fixed, query-only device-open boundary.
//!
//! The SHA-256 of the exact signed manifest bytes is the campaign operation
//! digest.  The existing campaign -> grant -> acceptance chain therefore
//! authorizes one exact manifest rather than a broad class of device opens.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "0verse.windows-device-open-boundary-manifest/v1";
const SIGNATURE_NAMESPACE: &str = "0verse-windows-device-open-boundary-manifest-v1";
const MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryManifest {
    schema_version: String,
    campaign_id: String,
    collector_id: String,
    collector_sha256: String,
    collector_registry_sha256: String,
    target_id: String,
    driver_id: String,
    driver_service_name: String,
    expected_installed_driver_image_sha256: String,
    interface_class_guid: String,
    interface_instance_id: String,
    receipt_signer: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    authorized_by: String,
    signature_ssh: String,
}

/// Exact signed boundary capability. Fields are deliberately private: only a
/// successful raw-byte signature and fixed-registry verification can mint it.
pub(crate) struct VerifiedDeviceOpenBoundary {
    manifest_sha256: String,
    campaign_id: String,
    collector_id: String,
    collector_sha256: String,
    receipt_signer: String,
    authorized_by: String,
    authorization_policy_sha256: String,
    authorizer_key_sha256: String,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

impl VerifiedDeviceOpenBoundary {
    pub(crate) fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub(crate) fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub(crate) fn collector_id(&self) -> &str {
        &self.collector_id
    }

    pub(crate) fn collector_sha256(&self) -> &str {
        &self.collector_sha256
    }

    pub(crate) fn receipt_signer(&self) -> &str {
        &self.receipt_signer
    }

    pub(crate) fn authorized_by(&self) -> &str {
        &self.authorized_by
    }

    pub(crate) fn authorization_policy_sha256(&self) -> &str {
        &self.authorization_policy_sha256
    }

    pub(crate) fn authorizer_key_sha256(&self) -> &str {
        &self.authorizer_key_sha256
    }

    pub(crate) const fn issued_at_unix_seconds(&self) -> i64 {
        self.issued_at_unix_seconds
    }

    pub(crate) const fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }

    #[cfg(test)]
    pub(crate) fn test_only(manifest_sha256: &str, campaign_id: &str) -> Self {
        Self {
            manifest_sha256: manifest_sha256.to_owned(),
            campaign_id: campaign_id.to_owned(),
            collector_id: "device-open-test-collector".to_owned(),
            collector_sha256: "11".repeat(32),
            receipt_signer: "device-open@example.test".to_owned(),
            authorized_by: "boundary-authorizer@example.test".to_owned(),
            authorization_policy_sha256: "22".repeat(32),
            authorizer_key_sha256: "33".repeat(32),
            issued_at_unix_seconds: 0,
            expires_at_unix_seconds: i64::MAX,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_with_receipt_signer(
        manifest_sha256: &str,
        campaign_id: &str,
        receipt_signer: &str,
    ) -> Self {
        let mut boundary = Self::test_only(manifest_sha256, campaign_id);
        boundary.receipt_signer = receipt_signer.to_owned();
        boundary
    }
}

/// Verify one exact signed manifest against the compiled one-entry registry.
///
/// The returned digest is over the raw signed bytes. Callers must bind that
/// digest as the selected campaign operation before any child is launched.
pub(crate) fn verify_device_open_boundary(
    source: &[u8],
    allowed_signers: &str,
    now_unix_seconds: i64,
) -> Result<VerifiedDeviceOpenBoundary, String> {
    if source.is_empty() || source.len() > crate::broker_protocol::MAX_FRAME_BYTES {
        return Err("device-open boundary manifest exceeds its bound".to_owned());
    }
    if !(0..=253_402_300_799).contains(&now_unix_seconds) {
        return Err("live UTC time is outside the supported range".to_owned());
    }
    let value =
        crate::broker_protocol::parse_strict_json_object(source, "device-open boundary manifest")?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize device-open boundary manifest: {error}"))?;
    if canonical != source {
        return Err("device-open boundary manifest source is not canonical JSON".to_owned());
    }
    let manifest: BoundaryManifest = serde_json::from_value(value.clone())
        .map_err(|error| format!("device-open boundary manifest schema is invalid: {error}"))?;
    validate_manifest(&manifest, now_unix_seconds)?;
    let issued_at_unix_seconds = timestamp(&manifest.issued_at, "device-open boundary issued_at")?;
    let expires_at_unix_seconds =
        timestamp(&manifest.expires_at, "device-open boundary expires_at")?;

    let material = canonical_signed_material(value)?;
    crate::sshsig::verify_ed25519(
        &material,
        &manifest.signature_ssh,
        &manifest.authorized_by,
        SIGNATURE_NAMESPACE,
        allowed_signers,
    )?;
    let authorization_policy_sha256 = format!("{:x}", Sha256::digest(allowed_signers.as_bytes()));
    let authorizer_key_sha256 =
        crate::sshsig::ed25519_policy_key_sha256(allowed_signers, &manifest.authorized_by)?;

    Ok(VerifiedDeviceOpenBoundary {
        manifest_sha256: format!("{:x}", Sha256::digest(source)),
        campaign_id: manifest.campaign_id,
        collector_id: manifest.collector_id,
        collector_sha256: manifest.collector_sha256,
        receipt_signer: manifest.receipt_signer,
        authorized_by: manifest.authorized_by,
        authorization_policy_sha256,
        authorizer_key_sha256,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
    })
}

fn validate_manifest(manifest: &BoundaryManifest, now: i64) -> Result<(), String> {
    let target = crate::device_open_protocol::fixed_target();
    if manifest.schema_version != SCHEMA_VERSION {
        return Err("device-open boundary manifest schema is unsupported".to_owned());
    }
    for (value, label) in [
        (&manifest.campaign_id, "campaign_id"),
        (&manifest.collector_id, "collector_id"),
        (&manifest.receipt_signer, "receipt_signer"),
        (&manifest.authorized_by, "authorized_by"),
    ] {
        validate_text(value, label)?;
    }
    for (value, label) in [
        (&manifest.collector_sha256, "collector SHA-256"),
        (
            &manifest.collector_registry_sha256,
            "collector registry SHA-256",
        ),
        (
            &manifest.expected_installed_driver_image_sha256,
            "installed driver SHA-256",
        ),
    ] {
        validate_sha256(value, label)?;
    }
    validate_nonce(&manifest.nonce)?;
    validate_window(&manifest.issued_at, &manifest.expires_at, now)?;
    if manifest.collector_registry_sha256 != crate::device_open_protocol::registry_sha256()?
        || manifest.target_id != target.target_id
        || manifest.driver_id != target.driver_id
        || manifest.driver_service_name != target.driver_service_name
        || manifest.expected_installed_driver_image_sha256
            != target.expected_installed_driver_image_sha256
        || manifest.interface_class_guid != target.interface_class_guid
        || manifest.interface_instance_id != target.interface_instance_id
    {
        return Err(
            "device-open boundary manifest differs from the compiled fixed target".to_owned(),
        );
    }
    Ok(())
}

fn canonical_signed_material(mut value: Value) -> Result<Vec<u8>, String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "device-open boundary manifest must be an object".to_owned())?;
    if object.remove("signature_ssh").is_none() {
        return Err("device-open boundary manifest has no detached signature".to_owned());
    }
    serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize device-open boundary manifest: {error}"))
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character < ' ' || character == '\u{7f}')
    {
        return Err(format!("device-open boundary manifest {label} is invalid"));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("device-open boundary manifest {label} is invalid"));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), String> {
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("device-open boundary manifest nonce is invalid".to_owned());
    }
    Ok(())
}

fn timestamp(value: &str, label: &str) -> Result<i64, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(format!("{label} must be exact UTC RFC3339 seconds"));
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        bytes[range].iter().try_fold(0_i64, |value, byte| {
            if !byte.is_ascii_digit() {
                return None;
            }
            value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))
        })
    };
    let year = number(0..4).ok_or_else(|| format!("{label} year is invalid"))?;
    let month = number(5..7).ok_or_else(|| format!("{label} month is invalid"))?;
    let day = number(8..10).ok_or_else(|| format!("{label} day is invalid"))?;
    let hour = number(11..13).ok_or_else(|| format!("{label} hour is invalid"))?;
    let minute = number(14..16).ok_or_else(|| format!("{label} minute is invalid"))?;
    let second = number(17..19).ok_or_else(|| format!("{label} second is invalid"))?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > month_days[usize::try_from(month - 1).map_err(|_| "invalid month")?]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(format!("{label} timestamp fields are invalid"));
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn validate_window(issued_at: &str, expires_at: &str, now: i64) -> Result<(), String> {
    let issued = timestamp(issued_at, "device-open boundary issued_at")?;
    let expires = timestamp(expires_at, "device-open boundary expires_at")?;
    if issued > now + CLOCK_SKEW_SECONDS || now - issued > MAX_AGE_SECONDS {
        return Err("device-open boundary issued_at is outside the 24-hour window".to_owned());
    }
    if expires <= now || expires <= issued || expires - issued > MAX_AGE_SECONDS {
        return Err("device-open boundary expiry interval is invalid".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");
    const IDENTITY: &str = "capture@example.test";
    const NOW: i64 = 1_784_112_313;

    fn unsigned() -> Value {
        let target = crate::device_open_protocol::fixed_target();
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "campaign_id": "device-open-synthetic-fixture",
            "collector_id": "zeroverse-windows-token-capture/v1",
            "collector_sha256": "11".repeat(32),
            "collector_registry_sha256": crate::device_open_protocol::registry_sha256().unwrap(),
            "target_id": target.target_id,
            "driver_id": target.driver_id,
            "driver_service_name": target.driver_service_name,
            "expected_installed_driver_image_sha256": target.expected_installed_driver_image_sha256,
            "interface_class_guid": target.interface_class_guid,
            "interface_instance_id": target.interface_instance_id,
            "receipt_signer": "device-open@example.test",
            "issued_at": "2026-07-15T10:40:00Z",
            "expires_at": "2026-07-15T11:40:00Z",
            "nonce": "device_open_manifest_nonce_000000000001",
            "authorized_by": IDENTITY,
        })
    }

    fn signed_source() -> Vec<u8> {
        let mut value = unsigned();
        let material = serde_json::to_vec(&value).unwrap();
        let signature = crate::sshsig::sign_ed25519(
            &material,
            Zeroizing::new(PRIVATE_KEY.to_vec()),
            SIGNATURE_NAMESPACE,
        )
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("signature_ssh".to_owned(), Value::String(signature));
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn verifies_exact_signed_fixed_boundary_and_raw_digest() {
        let source = signed_source();
        let verified = verify_device_open_boundary(&source, POLICY, NOW).unwrap();
        assert_eq!(
            verified.manifest_sha256(),
            format!("{:x}", Sha256::digest(&source))
        );
        assert_eq!(verified.campaign_id(), "device-open-synthetic-fixture");
        assert_eq!(verified.receipt_signer(), "device-open@example.test");
        assert_eq!(
            verified.authorization_policy_sha256(),
            format!("{:x}", Sha256::digest(POLICY.as_bytes()))
        );
        assert_eq!(
            verified.authorizer_key_sha256(),
            crate::sshsig::ed25519_policy_key_sha256(POLICY, IDENTITY).unwrap()
        );
    }

    #[test]
    fn rejects_unsigned_duplicate_stale_and_registry_drift() {
        assert!(
            verify_device_open_boundary(&serde_json::to_vec(&unsigned()).unwrap(), POLICY, NOW)
                .is_err()
        );
        let duplicate = br#"{"schema_version":"x","schema_version":"y"}"#;
        assert!(verify_device_open_boundary(duplicate, POLICY, NOW).is_err());
        assert!(
            verify_device_open_boundary(&signed_source(), POLICY, NOW + MAX_AGE_SECONDS + 1)
                .is_err()
        );

        let mut value: Value = serde_json::from_slice(&signed_source()).unwrap();
        value["collector_registry_sha256"] = Value::String("22".repeat(32));
        assert!(
            verify_device_open_boundary(&serde_json::to_vec(&value).unwrap(), POLICY, NOW).is_err()
        );

        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&signed_source()).unwrap())
                .unwrap();
        assert!(verify_device_open_boundary(&pretty, POLICY, NOW).is_err());
    }
}
