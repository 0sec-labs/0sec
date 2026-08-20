#![allow(
    dead_code,
    reason = "device-open ledger remains unreachable until SYSTEM broker activation is atomic"
)]

//! Platform-neutral durable-ledger records for device-open receipts.
//!
//! This module owns no paths, keys, handles, or Windows APIs. Its reservation
//! identities deliberately match the Python verifier byte for byte. A future
//! SYSTEM-only store may persist the canonical records produced here, but must
//! independently enforce protected storage and signature verification.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const RESERVATION_SCHEMA: &str = "0verse.windows-device-open-reservation/v1";
const RESERVATION_RECORD_SCHEMA: &str = "0verse.windows-device-open-reservation-record/v1";
const COMPLETION_RECORD_SCHEMA: &str = "0verse.windows-device-open-completion-record/v1";
const RECEIPT_SCHEMA: &str = "0verse.windows-device-open-boundary-receipt/v2";
const RECEIPT_SIGNATURE_NAMESPACE: &str = "0verse-windows-device-open-boundary-receipt-v2";

// These domains are an external cross-language contract. Do not rename them.
const RECEIPT_ONCE_DOMAIN: &[u8] = b"0verse-windows-device-open-receipt-once-v1\0";
const BOUNDARY_ONCE_DOMAIN: &[u8] = b"0verse-windows-device-open-boundary-once-v1\0";
const TRANSCRIPT_ONCE_DOMAIN: &[u8] = b"0verse-windows-device-open-transcript-once-v1\0";

const RESERVATION_MAX_BYTES: usize = 4096;
const RECEIPT_MAX_BYTES: usize = 1024 * 1024;
const COMPLETION_MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayIdentities {
    receipt: String,
    boundary: String,
    transcript: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    schema_version: String,
    worker_machine_id: String,
    receipt_nonce: String,
    boot_id: String,
    interface_path_sha256: String,
    observation_transcript_sha256: String,
    unsigned_receipt_sha256: String,
    receipt_once_id: String,
    boundary_once_id: String,
    transcript_once_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationRecord {
    schema_version: String,
    reservation: Reservation,
    reservation_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionRecord {
    schema_version: String,
    reservation_record_sha256: String,
    receipt_sha256: String,
    receipt: Value,
}

#[derive(Debug, PartialEq, Eq)]
struct ValidatedCompletion {
    reservation: Reservation,
    receipt_bytes: Vec<u8>,
}

impl ReplayIdentities {
    fn derive(
        worker_machine_id: &str,
        receipt_nonce: &str,
        boot_id: &str,
        interface_path_sha256: &str,
        observation_transcript_sha256: &str,
    ) -> Self {
        Self {
            receipt: digest_parts(
                RECEIPT_ONCE_DOMAIN,
                &[worker_machine_id.as_bytes(), receipt_nonce.as_bytes()],
            ),
            boundary: digest_parts(
                BOUNDARY_ONCE_DOMAIN,
                &[
                    worker_machine_id.as_bytes(),
                    boot_id.as_bytes(),
                    interface_path_sha256.as_bytes(),
                ],
            ),
            transcript: digest_parts(
                TRANSCRIPT_ONCE_DOMAIN,
                &[observation_transcript_sha256.as_bytes()],
            ),
        }
    }
}

impl Reservation {
    #[allow(
        clippy::too_many_arguments,
        reason = "exact replay binding is intentionally explicit"
    )]
    pub(crate) fn new(
        worker_machine_id: &str,
        receipt_nonce: &str,
        boot_id: &str,
        interface_path_sha256: &str,
        observation_transcript_sha256: &str,
        unsigned_receipt_sha256: &str,
    ) -> Result<Self, String> {
        validate_sha256(worker_machine_id, "worker machine ID")?;
        validate_nonce(receipt_nonce)?;
        validate_uuid(boot_id)?;
        validate_sha256(interface_path_sha256, "interface path SHA-256")?;
        validate_sha256(
            observation_transcript_sha256,
            "observation transcript SHA-256",
        )?;
        validate_sha256(unsigned_receipt_sha256, "unsigned receipt SHA-256")?;
        let identities = ReplayIdentities::derive(
            worker_machine_id,
            receipt_nonce,
            boot_id,
            interface_path_sha256,
            observation_transcript_sha256,
        );
        if identities.receipt == identities.boundary
            || identities.receipt == identities.transcript
            || identities.boundary == identities.transcript
        {
            return Err("device-open replay identity domains collide".to_owned());
        }
        Ok(Self {
            schema_version: RESERVATION_SCHEMA.to_owned(),
            worker_machine_id: worker_machine_id.to_owned(),
            receipt_nonce: receipt_nonce.to_owned(),
            boot_id: boot_id.to_owned(),
            interface_path_sha256: interface_path_sha256.to_owned(),
            observation_transcript_sha256: observation_transcript_sha256.to_owned(),
            unsigned_receipt_sha256: unsigned_receipt_sha256.to_owned(),
            receipt_once_id: identities.receipt,
            boundary_once_id: identities.boundary,
            transcript_once_id: identities.transcript,
        })
    }

    fn validated(&self) -> Result<Self, String> {
        if self.schema_version != RESERVATION_SCHEMA {
            return Err("device-open reservation schema is unsupported".to_owned());
        }
        let expected = Self::new(
            &self.worker_machine_id,
            &self.receipt_nonce,
            &self.boot_id,
            &self.interface_path_sha256,
            &self.observation_transcript_sha256,
            &self.unsigned_receipt_sha256,
        )?;
        if *self != expected {
            return Err("device-open reservation replay identities are invalid".to_owned());
        }
        Ok(expected)
    }

    fn marker_names(&self) -> [String; 3] {
        [
            format!("receipt-{}.reserved", self.receipt_once_id),
            format!("boundary-{}.reserved", self.boundary_once_id),
            format!("transcript-{}.reserved", self.transcript_once_id),
        ]
    }

    fn completion_name(&self) -> String {
        format!("completion-{}.json", self.receipt_once_id)
    }

    fn record_bytes(&self) -> Result<Vec<u8>, String> {
        self.validated()?;
        let payload = canonical_value_bytes(self)?;
        let record = ReservationRecord {
            schema_version: RESERVATION_RECORD_SCHEMA.to_owned(),
            reservation: self.clone(),
            reservation_sha256: sha256(&payload),
        };
        canonical_line(
            &record,
            RESERVATION_MAX_BYTES,
            "device-open reservation record",
        )
    }
}

fn completion_record_bytes(
    reservation: &Reservation,
    signed_receipt: &[u8],
) -> Result<Vec<u8>, String> {
    reservation.validated()?;
    let (receipt, canonical_receipt, recovered) = validate_receipt(signed_receipt)?;
    if recovered != *reservation {
        return Err("device-open receipt conflicts with its reservation".to_owned());
    }
    let reservation_record = reservation.record_bytes()?;
    let completion = CompletionRecord {
        schema_version: COMPLETION_RECORD_SCHEMA.to_owned(),
        reservation_record_sha256: sha256(&reservation_record),
        receipt_sha256: sha256(&canonical_receipt),
        receipt,
    };
    canonical_line(
        &completion,
        COMPLETION_MAX_BYTES,
        "device-open completion record",
    )
}

fn validate_reservation_record(bytes: &[u8]) -> Result<Reservation, String> {
    let value = validate_canonical_line(
        bytes,
        RESERVATION_MAX_BYTES,
        "device-open reservation record",
    )?;
    let record: ReservationRecord = serde_json::from_value(value)
        .map_err(|error| format!("device-open reservation record schema is invalid: {error}"))?;
    if record.schema_version != RESERVATION_RECORD_SCHEMA {
        return Err("device-open reservation record schema is unsupported".to_owned());
    }
    let reservation = record.reservation.validated()?;
    let payload = canonical_value_bytes(&reservation)?;
    validate_sha256(&record.reservation_sha256, "reservation payload SHA-256")?;
    if record.reservation_sha256 != sha256(&payload) {
        return Err("device-open reservation payload hash is invalid".to_owned());
    }
    Ok(reservation)
}

fn validate_reservation_record_for_name(bytes: &[u8], name: &str) -> Result<Reservation, String> {
    let reservation = validate_reservation_record(bytes)?;
    if !reservation
        .marker_names()
        .iter()
        .any(|expected| expected == name)
    {
        return Err("device-open reservation does not bind its marker filename".to_owned());
    }
    Ok(reservation)
}

fn is_reservation_marker_name(name: &str) -> bool {
    let digest = ["receipt-", "boundary-", "transcript-"]
        .into_iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .and_then(|rest| rest.strip_suffix(".reserved"));
    digest.is_some_and(valid_sha256)
}

fn is_completion_name(name: &str) -> bool {
    name.strip_prefix("completion-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(valid_sha256)
}

fn validate_completion_record(bytes: &[u8], name: &str) -> Result<ValidatedCompletion, String> {
    let value =
        validate_canonical_line(bytes, COMPLETION_MAX_BYTES, "device-open completion record")?;
    let record: CompletionRecord = serde_json::from_value(value)
        .map_err(|error| format!("device-open completion record schema is invalid: {error}"))?;
    if record.schema_version != COMPLETION_RECORD_SCHEMA {
        return Err("device-open completion record schema is unsupported".to_owned());
    }
    validate_sha256(
        &record.reservation_record_sha256,
        "completion reservation record SHA-256",
    )?;
    validate_sha256(&record.receipt_sha256, "completion receipt SHA-256")?;

    let receipt_bytes = canonical_line(
        &record.receipt,
        RECEIPT_MAX_BYTES,
        "device-open signed receipt",
    )?;
    let (_, canonical_receipt, reservation) = validate_receipt(&receipt_bytes)?;
    if name != reservation.completion_name() {
        return Err("device-open completion does not bind its filename".to_owned());
    }
    if record.reservation_record_sha256 != sha256(&reservation.record_bytes()?) {
        return Err("device-open completion reservation hash is invalid".to_owned());
    }
    if record.receipt_sha256 != sha256(&canonical_receipt) {
        return Err("device-open completion receipt hash is invalid".to_owned());
    }
    Ok(ValidatedCompletion {
        reservation,
        receipt_bytes: canonical_receipt,
    })
}

fn validate_receipt(bytes: &[u8]) -> Result<(Value, Vec<u8>, Reservation), String> {
    let mut value =
        validate_canonical_line(bytes, RECEIPT_MAX_BYTES, "device-open signed receipt")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "device-open signed receipt must be an object".to_owned())?;
    require_string(object, "schema_version", Some(RECEIPT_SCHEMA))?;
    let worker_machine_id = require_string(object, "worker_machine_id", None)?.to_owned();
    let receipt_nonce = require_string(object, "receipt_nonce", None)?.to_owned();
    let boot_id = require_string(object, "boot_id", None)?.to_owned();
    let interface_path_sha256 = require_string(object, "interface_path_sha256", None)?.to_owned();
    let observation_transcript_sha256 =
        require_string(object, "observation_transcript_sha256", None)?.to_owned();
    let signature = require_string(object, "signature_ssh", None)?;
    if signature.is_empty() {
        return Err("device-open signed receipt signature is empty".to_owned());
    }
    object
        .remove("signature_ssh")
        .ok_or_else(|| "device-open signed receipt lacks signature_ssh".to_owned())?;
    let unsigned = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize unsigned device-open receipt: {error}"))?;
    let reservation = Reservation::new(
        &worker_machine_id,
        &receipt_nonce,
        &boot_id,
        &interface_path_sha256,
        &observation_transcript_sha256,
        &sha256(&unsigned),
    )?;

    let canonical_receipt =
        validate_canonical_source(bytes, RECEIPT_MAX_BYTES, "device-open signed receipt")?;
    let receipt: Value = serde_json::from_slice(&canonical_receipt)
        .map_err(|error| format!("device-open signed receipt JSON is invalid: {error}"))?;
    Ok((receipt, canonical_receipt, reservation))
}

fn verify_receipt_signature(bytes: &[u8], allowed_signers: &str) -> Result<(), String> {
    let (mut value, _, _) = validate_receipt(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "device-open signed receipt must be an object".to_owned())?;
    let signed_by = require_string(object, "signed_by", None)?.to_owned();
    let signature = require_string(object, "signature_ssh", None)?.to_owned();
    object
        .remove("signature_ssh")
        .ok_or_else(|| "device-open signed receipt lacks signature_ssh".to_owned())?;
    let material = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize signed device-open material: {error}"))?;
    crate::sshsig::verify_ed25519(
        &material,
        &signature,
        &signed_by,
        RECEIPT_SIGNATURE_NAMESPACE,
        allowed_signers,
    )
}

fn require_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
    expected: Option<&str>,
) -> Result<&'a str, String> {
    let value = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("device-open signed receipt {name} must be a string"))?;
    if expected.is_some_and(|expected| value != expected) {
        return Err(format!("device-open signed receipt {name} is unsupported"));
    }
    Ok(value)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            digest.update(b"\0");
        }
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_value_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("cannot construct canonical device-open JSON: {error}"))?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("cannot serialize canonical device-open JSON: {error}"))
}

fn canonical_line<T: Serialize>(value: &T, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = canonical_value_bytes(value)?;
    bytes.push(b'\n');
    if bytes.len() > maximum {
        return Err(format!("{label} exceeds its size bound"));
    }
    Ok(bytes)
}

fn validate_canonical_source(bytes: &[u8], maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > maximum || bytes.last() != Some(&b'\n') {
        return Err(format!("{label} is oversized or has no final LF"));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("{label} JSON is invalid: {error}"))?;
    let canonical = canonical_line(&value, maximum, label)?;
    if canonical != bytes {
        return Err(format!("{label} is not byte-canonical"));
    }
    Ok(canonical)
}

fn validate_canonical_line(bytes: &[u8], maximum: usize, label: &str) -> Result<Value, String> {
    let canonical = validate_canonical_source(bytes, maximum, label)?;
    serde_json::from_slice(&canonical).map_err(|error| format!("{label} JSON is invalid: {error}"))
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if !valid_sha256(value) {
        return Err(format!("device-open {label} is not a canonical SHA-256"));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_nonce(value: &str) -> Result<(), String> {
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("device-open receipt nonce is invalid".to_owned());
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<(), String> {
    let widths = [8, 4, 4, 4, 12];
    let groups = value.split('-').collect::<Vec<_>>();
    if groups.len() != widths.len()
        || groups.iter().zip(widths).any(|(group, width)| {
            group.len() != width
                || !group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err("device-open boot ID is not a canonical UUID".to_owned());
    }
    Ok(())
}

fn require_pairwise_distinct_role_keys(
    boundary_key_sha256: &str,
    capture_key_sha256: &str,
    device_key_sha256: &str,
) -> Result<(), String> {
    for (value, label) in [
        (boundary_key_sha256, "boundary authorizer key SHA-256"),
        (capture_key_sha256, "capture key SHA-256"),
        (device_key_sha256, "device-open key SHA-256"),
    ] {
        validate_sha256(value, label)?;
    }
    if boundary_key_sha256 == capture_key_sha256
        || boundary_key_sha256 == device_key_sha256
        || capture_key_sha256 == device_key_sha256
    {
        return Err(
            "boundary, capture, and device-open roles must use distinct Ed25519 keys".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
mod windows_backend {
    use std::collections::{BTreeMap, BTreeSet};

    #[cfg(feature = "ci-system-test")]
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::{
        COMPLETION_MAX_BYTES, RESERVATION_MAX_BYTES, Reservation, ValidatedCompletion,
        completion_record_bytes, is_completion_name, is_reservation_marker_name,
        require_pairwise_distinct_role_keys, sha256, validate_completion_record,
        validate_reservation_record_for_name, validate_sha256, verify_receipt_signature,
    };
    #[cfg(feature = "ci-system-test")]
    use super::{
        RECEIPT_MAX_BYTES, RECEIPT_SCHEMA, RECEIPT_SIGNATURE_NAMESPACE, Value, canonical_line,
    };
    use crate::windows::protected_store::ProtectedStore;
    #[cfg(feature = "ci-system-test")]
    use crate::windows::protected_store::{DeviceOpenCiFixture, DeviceOpenCiOwner};

    const DEVICE_ROOT: &str = "windows-device-open-broker";
    const CAPTURE_ROOT: &str = "windows-token-broker";
    const POLICY_LEAF: &str = "device_open.allowed_signers";
    const PRIVATE_KEY_LEAF: &str = "device_open_ed25519";
    const CAPTURE_PRIVATE_KEY_LEAF: &str = "capture_ed25519";
    const AUTHORIZATION_POLICY_LEAF: &str = "authorization.allowed_signers";
    const LEDGER_LOCK_LEAF: &str = "ledger.lock";
    const POLICY_MAX_BYTES: u64 = 1024 * 1024;
    const PRIVATE_KEY_MAX_BYTES: u64 = 64 * 1024;
    #[cfg(feature = "ci-system-test")]
    const CI_DEVICE_POLICY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-device-open-sshsig/allowed_signers");
    #[cfg(feature = "ci-system-test")]
    const CI_DEVICE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-device-open-sshsig/test-only-key");
    #[cfg(feature = "ci-system-test")]
    const CI_CAPTURE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    #[cfg(feature = "ci-system-test")]
    const CI_BOUNDARY_POLICY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-boundary-sshsig/allowed_signers");
    #[cfg(feature = "ci-system-test")]
    const CI_CAPTURE_ALIAS_BOUNDARY_POLICY: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows-boundary-sshsig/capture-key-allowed_signers"
    );
    #[cfg(feature = "ci-system-test")]
    const CI_DEVICE_ALIAS_BOUNDARY_POLICY: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows-boundary-sshsig/device-key-allowed_signers"
    );
    #[cfg(feature = "ci-system-test")]
    const CI_DEVICE_IDENTITY: &str = "device-open@example.test";
    #[cfg(feature = "ci-system-test")]
    const CI_BOUNDARY_IDENTITY: &str = "boundary@example.test";

    pub(crate) struct DeviceOpenStore {
        protected: ProtectedStore,
    }

    pub(crate) enum CompletionStatus {
        Created(Vec<u8>),
        AlreadyCompleted(Vec<u8>),
    }

    impl DeviceOpenStore {
        pub(crate) fn open() -> Result<Self, String> {
            crate::windows::require_non_impersonating_local_system()?;
            let protected = ProtectedStore::open(DEVICE_ROOT)?;
            let store = Self { protected };
            store.validate_fixed_leaves()?;
            store.require_distinct_capture_key()?;
            let _lock = store.protected.lock(LEDGER_LOCK_LEAF)?;
            store.recover()?;
            Ok(store)
        }

        fn load_bound_device_signer(
            &self,
            signed_by: &str,
        ) -> Result<(Zeroizing<Vec<u8>>, String), String> {
            crate::windows::require_non_impersonating_local_system()?;
            let policy = self.load_policy()?;
            let private_key =
                self.protected
                    .read_leaf(PRIVATE_KEY_LEAF, 1, PRIVATE_KEY_MAX_BYTES)?;
            crate::sshsig::verify_private_key_identity(private_key.as_slice(), signed_by, &policy)?;
            Ok((private_key, policy))
        }

        fn reserve(&self, reservation: &Reservation) -> Result<(), String> {
            crate::windows::require_non_impersonating_local_system()?;
            reservation.validated()?;
            let _lock = self.protected.lock(LEDGER_LOCK_LEAF)?;
            let record = reservation.record_bytes()?;
            let names = reservation.marker_names();
            for name in &names {
                if self
                    .protected
                    .read_optional_leaf(name, 0, RESERVATION_MAX_BYTES as u64)?
                    .is_some()
                {
                    return Err("device-open replay identity has already been burned".to_owned());
                }
            }
            // These three creates are one logical burn under the exclusive
            // ledger lock. Any partial failure remains visible and makes
            // recovery refuse the store; identities are never rolled back.
            for name in names {
                self.protected.create_immutable(
                    &name,
                    &record,
                    RESERVATION_MAX_BYTES as u64,
                    "device-open replay marker",
                )?;
            }
            self.require_reservation_triple(reservation, &record)
        }

        /// Atomically burn the reservation before protected key material can
        /// enter the caller's type state.
        pub(crate) fn reserve_and_load_signer(
            &self,
            reservation: &Reservation,
            signed_by: &str,
            boundary_authorized_by: &str,
            boundary_policy_sha256: &str,
            boundary_key_sha256: &str,
        ) -> Result<crate::device_open_receipt::ReservedDeviceOpenSigner, String> {
            self.reserve(reservation)?;
            self.require_boundary_authorizer_key_separation(
                boundary_authorized_by,
                boundary_policy_sha256,
                boundary_key_sha256,
            )?;
            let (private_key, allowed_signers) = self.load_bound_device_signer(signed_by)?;
            Ok(crate::device_open_receipt::ReservedDeviceOpenSigner::new(
                reservation.clone(),
                private_key,
                allowed_signers,
            ))
        }

        pub(crate) fn completed_receipt(
            &self,
            reservation: &Reservation,
        ) -> Result<Option<Vec<u8>>, String> {
            crate::windows::require_non_impersonating_local_system()?;
            let _lock = self.protected.lock(LEDGER_LOCK_LEAF)?;
            self.completed_receipt_locked(reservation)
        }

        pub(crate) fn complete(
            &self,
            reservation: &Reservation,
            signed_receipt: &[u8],
        ) -> Result<CompletionStatus, String> {
            crate::windows::require_non_impersonating_local_system()?;
            let _lock = self.protected.lock(LEDGER_LOCK_LEAF)?;
            let expected_marker = reservation.record_bytes()?;
            self.require_reservation_triple(reservation, &expected_marker)?;
            let policy = self.load_policy()?;
            verify_receipt_signature(signed_receipt, &policy)?;
            let record = completion_record_bytes(reservation, signed_receipt)?;
            let name = reservation.completion_name();
            let created = match self.protected.create_immutable(
                &name,
                &record,
                COMPLETION_MAX_BYTES as u64,
                "device-open completion",
            ) {
                Ok(()) => true,
                Err(error) if error == "device-open completion has already been reserved" => false,
                Err(error) => return Err(error),
            };

            // `create_immutable` closes its write handle before this no-share
            // readback. Do not publish bytes until canonical parsing, SSHSIG,
            // reservation markers, hashes, and exact bytes all revalidate.
            let recovered = self
                .completed_receipt_locked(reservation)?
                .ok_or_else(|| "device-open completion disappeared after creation".to_owned())?;
            if recovered != signed_receipt {
                return Err("durable device-open completion conflicts with receipt".to_owned());
            }
            if created {
                Ok(CompletionStatus::Created(recovered))
            } else {
                Ok(CompletionStatus::AlreadyCompleted(recovered))
            }
        }

        fn validate_fixed_leaves(&self) -> Result<(), String> {
            let policy = self.load_policy()?;
            let key = self
                .protected
                .read_leaf(PRIVATE_KEY_LEAF, 1, PRIVATE_KEY_MAX_BYTES)?;
            crate::sshsig::verify_private_key_identity(
                key.as_slice(),
                policy_identity(&policy)?,
                &policy,
            )?;
            drop(key);
            let _lock = self.protected.lock(LEDGER_LOCK_LEAF)?;
            Ok(())
        }

        fn load_policy(&self) -> Result<String, String> {
            let bytes = self.protected.read_leaf(POLICY_LEAF, 1, POLICY_MAX_BYTES)?;
            if bytes.contains(&0) {
                return Err("device-open allowed-signers policy contains NUL".to_owned());
            }
            String::from_utf8(bytes.to_vec())
                .map_err(|_| "device-open allowed-signers policy is not UTF-8".to_owned())
        }

        fn require_distinct_capture_key(&self) -> Result<(), String> {
            let device_bytes =
                self.protected
                    .read_leaf(PRIVATE_KEY_LEAF, 1, PRIVATE_KEY_MAX_BYTES)?;
            let capture_bytes = self
                .protected
                .read_sibling_leaf(
                    CAPTURE_ROOT,
                    CAPTURE_PRIVATE_KEY_LEAF,
                    1,
                    PRIVATE_KEY_MAX_BYTES,
                )
                .map_err(|error| format!("cannot prove device/capture key separation: {error}"))?;
            crate::sshsig::require_distinct_ed25519_private_keys(
                device_bytes.as_slice(),
                capture_bytes.as_slice(),
            )
            .map_err(|error| format!("device/capture key separation failed: {error}"))
        }

        fn completed_receipt_locked(
            &self,
            reservation: &Reservation,
        ) -> Result<Option<Vec<u8>>, String> {
            let name = reservation.completion_name();
            let Some(bytes) =
                self.protected
                    .read_optional_leaf(&name, 1, COMPLETION_MAX_BYTES as u64)?
            else {
                return Ok(None);
            };
            let completed = validate_completion_record(&bytes, &name)?;
            if completed.reservation != *reservation {
                return Err("device-open completion conflicts with reservation".to_owned());
            }
            let expected_marker = reservation.record_bytes()?;
            self.require_reservation_triple(reservation, &expected_marker)?;
            verify_receipt_signature(&completed.receipt_bytes, &self.load_policy()?)?;
            Ok(Some(completed.receipt_bytes))
        }

        fn require_reservation_triple(
            &self,
            reservation: &Reservation,
            expected: &[u8],
        ) -> Result<(), String> {
            for name in reservation.marker_names() {
                let bytes = self
                    .protected
                    .read_optional_leaf(&name, 1, RESERVATION_MAX_BYTES as u64)?
                    .ok_or_else(|| {
                        "device-open completion lacks its exact replay-marker triple".to_owned()
                    })?;
                let recovered = validate_reservation_record_for_name(&bytes, &name)?;
                if recovered != *reservation || bytes.as_slice() != expected {
                    return Err("device-open replay-marker triple conflicts".to_owned());
                }
            }
            Ok(())
        }

        fn require_boundary_authorizer_key_separation(
            &self,
            authorized_by: &str,
            expected_policy_sha256: &str,
            expected_key_sha256: &str,
        ) -> Result<(), String> {
            let policy_bytes = self.protected.read_sibling_leaf(
                CAPTURE_ROOT,
                AUTHORIZATION_POLICY_LEAF,
                1,
                POLICY_MAX_BYTES,
            )?;
            if policy_bytes.contains(&0) {
                return Err("boundary authorization policy contains NUL".to_owned());
            }
            let policy = String::from_utf8(policy_bytes.to_vec())
                .map_err(|_| "boundary authorization policy is not UTF-8".to_owned())?;
            validate_sha256(
                expected_policy_sha256,
                "boundary authorization policy SHA-256",
            )?;
            validate_sha256(expected_key_sha256, "boundary authorizer key SHA-256")?;
            if sha256(policy.as_bytes()) != expected_policy_sha256 {
                return Err("boundary authorization policy changed after verification".to_owned());
            }
            let boundary_key = crate::sshsig::ed25519_policy_key_sha256(&policy, authorized_by)?;
            if boundary_key != expected_key_sha256 {
                return Err("boundary authorizer key changed after verification".to_owned());
            }
            let device_key =
                self.protected
                    .read_leaf(PRIVATE_KEY_LEAF, 1, PRIVATE_KEY_MAX_BYTES)?;
            let capture_key = self.protected.read_sibling_leaf(
                CAPTURE_ROOT,
                CAPTURE_PRIVATE_KEY_LEAF,
                1,
                PRIVATE_KEY_MAX_BYTES,
            )?;
            let device_key = crate::sshsig::ed25519_private_key_public_sha256(&device_key)?;
            let capture_key = crate::sshsig::ed25519_private_key_public_sha256(&capture_key)?;
            require_pairwise_distinct_role_keys(&boundary_key, &capture_key, &device_key)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "linear recovery is deliberately audit-visible"
        )]
        fn recover(&self) -> Result<(), String> {
            let entries = self.protected.entries()?;
            let fixed = BTreeSet::from([
                POLICY_LEAF.to_owned(),
                PRIVATE_KEY_LEAF.to_owned(),
                LEDGER_LOCK_LEAF.to_owned(),
            ]);
            let present = entries.iter().cloned().collect::<BTreeSet<_>>();
            if !fixed.is_subset(&present) {
                return Err("device-open store lacks an exact fixed trust leaf".to_owned());
            }
            let mut markers = BTreeMap::new();
            let mut completions = BTreeMap::new();
            for name in entries {
                if fixed.contains(&name) {
                    continue;
                }
                let maximum = if is_reservation_marker_name(&name) {
                    RESERVATION_MAX_BYTES as u64
                } else if is_completion_name(&name) {
                    COMPLETION_MAX_BYTES as u64
                } else {
                    return Err(format!(
                        "device-open store contains unexpected entry {name:?}"
                    ));
                };
                let bytes = self.protected.read_leaf(&name, 0, maximum)?;
                if bytes.is_empty() {
                    return Err(format!(
                        "device-open store entry {name:?} is consumed/corrupt (torn create)"
                    ));
                }
                if is_reservation_marker_name(&name) {
                    validate_reservation_record_for_name(&bytes, &name).map_err(|error| {
                        format!("device-open replay marker {name:?} is consumed/corrupt: {error}")
                    })?;
                    markers.insert(name, bytes.to_vec());
                } else {
                    completions.insert(name, bytes.to_vec());
                }
            }

            for (name, bytes) in &markers {
                let reservation = validate_reservation_record_for_name(bytes, name)?;
                let expected = reservation.record_bytes()?;
                for marker_name in reservation.marker_names() {
                    if markers.get(&marker_name) != Some(&expected) {
                        return Err(format!(
                            "device-open replay marker {name:?} lacks its exact triple; consumed/corrupt"
                        ));
                    }
                }
            }

            let policy = if completions.is_empty() {
                None
            } else {
                Some(self.load_policy()?)
            };
            for (name, bytes) in completions {
                let ValidatedCompletion {
                    reservation,
                    receipt_bytes,
                } = validate_completion_record(&bytes, &name).map_err(|error| {
                    format!("device-open completion {name:?} is consumed/corrupt: {error}")
                })?;
                let expected = reservation.record_bytes()?;
                for marker_name in reservation.marker_names() {
                    if markers.get(&marker_name) != Some(&expected) {
                        return Err(format!(
                            "device-open completion {name:?} lacks its exact replay-marker triple"
                        ));
                    }
                }
                verify_receipt_signature(
                    &receipt_bytes,
                    policy.as_deref().ok_or_else(|| {
                        "device-open completion exists without its authorization policy".to_owned()
                    })?,
                )
                .map_err(|error| {
                    format!("device-open completion {name:?} signature is invalid: {error}")
                })?;
            }
            Ok(())
        }
    }

    fn policy_identity(policy: &str) -> Result<&str, String> {
        let mut identity = None;
        for line in policy.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let principal = line
                .split_ascii_whitespace()
                .next()
                .ok_or_else(|| "device-open allowed-signers policy is malformed".to_owned())?;
            if identity.replace(principal).is_some() {
                return Err("device-open policy must contain one exact signer".to_owned());
            }
        }
        identity.ok_or_else(|| "device-open policy has no signer".to_owned())
    }

    #[cfg(feature = "ci-system-test")]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixed three-phase failure-injection lifecycle is intentionally linear"
    )]
    pub(super) fn run_ci_system_test_phase() -> Result<(), String> {
        crate::windows::require_non_impersonating_local_system()?;
        let owner = DeviceOpenCiOwner::open_or_provision(DeviceOpenCiFixture::SameAsCapture)?;
        let phase_one = owner.phase_one_exists();
        let phase_two = owner.phase_two_exists();

        if !phase_one {
            if phase_two {
                return Err("device-store CI phase markers are out of order".to_owned());
            }
            match DeviceOpenStore::open() {
                Err(error) if error.contains("same Ed25519 public key") => {}
                Err(error) => {
                    return Err(format!(
                        "same device/capture key failed for wrong reason: {error}"
                    ));
                }
                Ok(_) => return Err("same device/capture key was accepted".to_owned()),
            }
            owner.replace_root(DeviceOpenCiFixture::DistinctDevice)?;
            let store = DeviceOpenStore::open()?;
            let (boundary_policy_sha256, boundary_key_sha256, capture_key, device_key) =
                ci_role_bindings()?;
            require_pairwise_distinct_role_keys(&boundary_key_sha256, &capture_key, &device_key)?;
            if require_pairwise_distinct_role_keys(&capture_key, &capture_key, &device_key).is_ok()
                || require_pairwise_distinct_role_keys(&device_key, &capture_key, &device_key)
                    .is_ok()
            {
                return Err("same-key role alias was accepted".to_owned());
            }

            drop(store);
            crate::service_store::set_ci_authorization_fixture(
                crate::service_store::CiAuthorizationFixture::Device,
            )?;
            let store = DeviceOpenStore::open()?;
            let device_alias = ci_reservation("device_alias_receipt_nonce_000000001")?;
            match store.reserve_and_load_signer(
                &device_alias,
                CI_DEVICE_IDENTITY,
                CI_BOUNDARY_IDENTITY,
                &sha256(CI_DEVICE_ALIAS_BOUNDARY_POLICY),
                &device_key,
            ) {
                Err(error) if error.contains("roles must use distinct Ed25519 keys") => {}
                Err(error) => {
                    return Err(format!(
                        "boundary=device alias failed for wrong reason: {error}"
                    ));
                }
                Ok(_) => return Err("boundary=device alias was accepted".to_owned()),
            }
            drop(store);
            crate::service_store::set_ci_authorization_fixture(
                crate::service_store::CiAuthorizationFixture::Capture,
            )?;
            let store = DeviceOpenStore::open()?;
            let capture_alias = ci_reservation("capture_alias_receipt_nonce_00000001")?;
            match store.reserve_and_load_signer(
                &capture_alias,
                CI_DEVICE_IDENTITY,
                CI_BOUNDARY_IDENTITY,
                &sha256(CI_CAPTURE_ALIAS_BOUNDARY_POLICY),
                &capture_key,
            ) {
                Err(error) if error.contains("roles must use distinct Ed25519 keys") => {}
                Err(error) => {
                    return Err(format!(
                        "boundary=capture alias failed for wrong reason: {error}"
                    ));
                }
                Ok(_) => return Err("boundary=capture alias was accepted".to_owned()),
            }
            drop(store);
            crate::service_store::set_ci_authorization_fixture(
                crate::service_store::CiAuthorizationFixture::Boundary,
            )?;
            let store = DeviceOpenStore::open()?;
            if store.reserve(&device_alias).is_ok() || store.reserve(&capture_alias).is_ok() {
                return Err("failed alias signer did not burn its replay markers".to_owned());
            }

            let (reservation, receipt) = ci_signed_receipt()?;
            let reserved_signer = store.reserve_and_load_signer(
                &reservation,
                CI_DEVICE_IDENTITY,
                CI_BOUNDARY_IDENTITY,
                &boundary_policy_sha256,
                &boundary_key_sha256,
            )?;
            drop(reserved_signer);
            match store.complete(&reservation, &receipt)? {
                CompletionStatus::Created(bytes) if bytes == receipt => {}
                CompletionStatus::Created(_) => {
                    return Err("new device completion changed receipt bytes".to_owned());
                }
                CompletionStatus::AlreadyCompleted(_) => {
                    return Err("first device completion was unexpectedly cached".to_owned());
                }
            }
            match store.complete(&reservation, &receipt)? {
                CompletionStatus::AlreadyCompleted(bytes) if bytes == receipt => {}
                CompletionStatus::AlreadyCompleted(_) => {
                    return Err("cached device completion changed receipt bytes".to_owned());
                }
                CompletionStatus::Created(_) => {
                    return Err("idempotent device completion was recreated".to_owned());
                }
            }
            owner.mark_phase_one()?;
            return Ok(());
        }
        owner.require_phase_one()?;

        if !phase_two {
            let store = DeviceOpenStore::open()?;
            let (reservation, receipt) = ci_signed_receipt()?;
            if store.completed_receipt(&reservation)?.as_deref() != Some(receipt.as_slice()) {
                return Err("device completion did not survive restart exactly".to_owned());
            }
            if store.reserve(&reservation).is_ok() {
                return Err("completed device reservation replay succeeded".to_owned());
            }
            for alias in [
                ci_reservation("device_alias_receipt_nonce_000000001")?,
                ci_reservation("capture_alias_receipt_nonce_00000001")?,
            ] {
                if store.reserve(&alias).is_ok() {
                    return Err("same-key alias burn did not survive SCM restart".to_owned());
                }
            }
            let torn = ci_reservation("torn_receipt_nonce_000000000000001")?;
            let record = torn.record_bytes()?;
            store.protected.create_immutable(
                &torn.marker_names()[0],
                &record,
                RESERVATION_MAX_BYTES as u64,
                "device-open CI torn marker",
            )?;
            match store.recover() {
                Err(error) if error.contains("lacks its exact triple") => {}
                Err(error) => {
                    return Err(format!(
                        "partial device marker failed for wrong reason: {error}"
                    ));
                }
                Ok(()) => return Err("partial device marker was accepted".to_owned()),
            }
            owner.mark_phase_two()?;
            return Ok(());
        }
        owner.require_phase_two()?;
        match DeviceOpenStore::open() {
            Err(error) if error.contains("lacks its exact triple") => Ok(()),
            Err(error) => Err(format!(
                "device torn-marker restart failed for wrong reason: {error}"
            )),
            Ok(_) => Err("device torn marker was accepted after restart".to_owned()),
        }
    }

    #[cfg(feature = "ci-system-test")]
    pub(super) fn cleanup_ci_system_test() -> Result<(), String> {
        crate::windows::require_non_impersonating_local_system()?;
        DeviceOpenCiOwner::open_or_provision(DeviceOpenCiFixture::DistinctDevice)?.cleanup()
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_role_bindings() -> Result<(String, String, String, String), String> {
        let boundary_policy = std::str::from_utf8(CI_BOUNDARY_POLICY)
            .map_err(|_| "CI boundary policy is not UTF-8".to_owned())?;
        Ok((
            sha256(CI_BOUNDARY_POLICY),
            crate::sshsig::ed25519_policy_key_sha256(boundary_policy, CI_BOUNDARY_IDENTITY)?,
            crate::sshsig::ed25519_private_key_public_sha256(CI_CAPTURE_KEY)?,
            crate::sshsig::ed25519_private_key_public_sha256(CI_DEVICE_KEY)?,
        ))
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_unsigned_receipt(receipt_nonce: &str) -> Result<(Value, Reservation), String> {
        let interface_path_sha256 = sha256(format!("interface:{receipt_nonce}").as_bytes());
        let observation_transcript_sha256 =
            sha256(format!("transcript:{receipt_nonce}").as_bytes());
        let value = json!({
            "schema_version": RECEIPT_SCHEMA,
            "worker_machine_id": "1111111111111111111111111111111111111111111111111111111111111111",
            "receipt_nonce": receipt_nonce,
            "boot_id": "12345678-1234-1234-1234-1234567890ab",
            "interface_path_sha256": interface_path_sha256,
            "observation_transcript_sha256": observation_transcript_sha256,
            "signed_by": CI_DEVICE_IDENTITY,
        });
        let material = serde_json::to_vec(&value)
            .map_err(|error| format!("cannot canonicalize CI device receipt: {error}"))?;
        let reservation = Reservation::new(
            "1111111111111111111111111111111111111111111111111111111111111111",
            receipt_nonce,
            "12345678-1234-1234-1234-1234567890ab",
            &interface_path_sha256,
            &observation_transcript_sha256,
            &sha256(&material),
        )?;
        Ok((value, reservation))
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_reservation(receipt_nonce: &str) -> Result<Reservation, String> {
        ci_unsigned_receipt(receipt_nonce).map(|(_, reservation)| reservation)
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_signed_receipt() -> Result<(Reservation, Vec<u8>), String> {
        let (mut value, reservation) = ci_unsigned_receipt("valid_receipt_nonce_00000000000001")?;
        let material = serde_json::to_vec(&value)
            .map_err(|error| format!("cannot canonicalize CI signed material: {error}"))?;
        let signature = crate::sshsig::sign_ed25519(
            &material,
            Zeroizing::new(CI_DEVICE_KEY.to_vec()),
            RECEIPT_SIGNATURE_NAMESPACE,
        )?;
        value["signature_ssh"] = Value::String(signature);
        let receipt = canonical_line(&value, RECEIPT_MAX_BYTES, "CI device-open receipt")?;
        verify_receipt_signature(
            &receipt,
            std::str::from_utf8(CI_DEVICE_POLICY)
                .map_err(|_| "CI device-open policy is not UTF-8".to_owned())?,
        )?;
        Ok((reservation, receipt))
    }
}

#[cfg(windows)]
#[allow(
    unused_imports,
    reason = "store remains unreachable until broker activation is atomic"
)]
pub(crate) use windows_backend::{CompletionStatus, DeviceOpenStore};

#[cfg(all(windows, feature = "ci-system-test"))]
pub(crate) fn run_ci_system_test_phase() -> Result<(), String> {
    windows_backend::run_ci_system_test_phase()
}

#[cfg(all(windows, feature = "ci-system-test"))]
pub(crate) fn cleanup_ci_system_test() -> Result<(), String> {
    windows_backend::cleanup_ci_system_test()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WORKER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NONCE: &str = "receipt_nonce_000000000000000001";
    const BOOT: &str = "12345678-1234-1234-1234-1234567890ab";
    const PATH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TRANSCRIPT: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn receipt_value() -> Value {
        json!({
            "schema_version": RECEIPT_SCHEMA,
            "worker_machine_id": WORKER,
            "receipt_nonce": NONCE,
            "boot_id": BOOT,
            "interface_path_sha256": PATH,
            "observation_transcript_sha256": TRANSCRIPT,
            "signed_by": "device-open@example.test",
            "signature_ssh": "-----BEGIN SSH SIGNATURE-----\ntest\n-----END SSH SIGNATURE-----"
        })
    }

    fn receipt_bytes() -> Vec<u8> {
        canonical_line(&receipt_value(), RECEIPT_MAX_BYTES, "fixture").unwrap()
    }

    fn reservation() -> Reservation {
        let (_, _, reservation) = validate_receipt(&receipt_bytes()).unwrap();
        reservation
    }

    #[test]
    fn replay_identities_match_python_reference_vectors() {
        let identities = ReplayIdentities::derive(WORKER, NONCE, BOOT, PATH, TRANSCRIPT);
        assert_eq!(
            identities.receipt,
            "2a2136480e3f821eeed5edee7c65b9b9398567a637dc49c8823dc537a36233b2"
        );
        assert_eq!(
            identities.boundary,
            "238511592e9a9ff857404015531457aa54b783e9a1dfda7edfa0029536122614"
        );
        assert_eq!(
            identities.transcript,
            "2a2f8774ee84ebf19e82626aa3870da9220760f7347eb524f3744d32ebee4f3e"
        );
    }

    #[test]
    fn reservation_record_is_canonical_deterministic_and_binds_all_names() {
        let reservation = reservation();
        let first = reservation.record_bytes().unwrap();
        assert_eq!(first, reservation.record_bytes().unwrap());
        assert_eq!(first.last(), Some(&b'\n'));
        for name in reservation.marker_names() {
            assert!(is_reservation_marker_name(&name));
            assert_eq!(
                validate_reservation_record_for_name(&first, &name).unwrap(),
                reservation
            );
        }
        assert!(validate_reservation_record_for_name(&first, "receipt-deadbeef.reserved").is_err());
        assert!(!is_reservation_marker_name("receipt-deadbeef.reserved"));
        assert!(!is_reservation_marker_name(&format!(
            "unknown-{}.reserved",
            "0".repeat(64)
        )));
        assert!(is_completion_name(&reservation.completion_name()));
        assert!(!is_completion_name("completion-deadbeef.json"));
    }

    #[test]
    fn reservation_rejects_each_tampered_identity_and_hash() {
        let record = reservation().record_bytes().unwrap();
        for field in ["receipt_once_id", "boundary_once_id", "transcript_once_id"] {
            let mut value: Value = serde_json::from_slice(&record).unwrap();
            value["reservation"][field] = Value::String("0".repeat(64));
            assert!(
                validate_reservation_record(&canonical_line(&value, 4096, "test").unwrap())
                    .is_err()
            );
        }
        let mut value: Value = serde_json::from_slice(&record).unwrap();
        value["reservation_sha256"] = Value::String("0".repeat(64));
        assert!(
            validate_reservation_record(&canonical_line(&value, 4096, "test").unwrap()).is_err()
        );
    }

    #[test]
    fn reservation_rejects_unknown_duplicate_noncanonical_and_torn_json() {
        let record = reservation().record_bytes().unwrap();
        let mut unknown: Value = serde_json::from_slice(&record).unwrap();
        unknown["unknown"] = Value::Bool(true);
        assert!(
            validate_reservation_record(&canonical_line(&unknown, 4096, "test").unwrap()).is_err()
        );
        let duplicate = String::from_utf8(record.clone()).unwrap().replacen(
            '{',
            "{\"schema_version\":\"duplicate\",",
            1,
        );
        assert!(validate_reservation_record(duplicate.as_bytes()).is_err());
        let pretty =
            serde_json::to_string_pretty(&serde_json::from_slice::<Value>(&record).unwrap())
                .unwrap();
        assert!(validate_reservation_record(format!("{pretty}\n").as_bytes()).is_err());
        assert!(validate_reservation_record(&record[..record.len() - 1]).is_err());
    }

    #[test]
    fn completion_round_trip_recovers_exact_receipt_and_reservation() {
        let reservation = reservation();
        let receipt = receipt_bytes();
        let completion = completion_record_bytes(&reservation, &receipt).unwrap();
        let recovered =
            validate_completion_record(&completion, &reservation.completion_name()).unwrap();
        assert_eq!(recovered.reservation, reservation);
        assert_eq!(recovered.receipt_bytes, receipt);
    }

    #[test]
    fn completion_rejects_wrong_name_hashes_schema_and_receipt_binding() {
        let reservation = reservation();
        let completion = completion_record_bytes(&reservation, &receipt_bytes()).unwrap();
        assert!(validate_completion_record(&completion, "completion-deadbeef.json").is_err());
        for field in ["reservation_record_sha256", "receipt_sha256"] {
            let mut value: Value = serde_json::from_slice(&completion).unwrap();
            value[field] = Value::String("0".repeat(64));
            assert!(
                validate_completion_record(
                    &canonical_line(&value, COMPLETION_MAX_BYTES, "test").unwrap(),
                    &reservation.completion_name(),
                )
                .is_err()
            );
        }
        let mut value: Value = serde_json::from_slice(&completion).unwrap();
        value["schema_version"] = Value::String("unsupported".to_owned());
        assert!(
            validate_completion_record(
                &canonical_line(&value, COMPLETION_MAX_BYTES, "test").unwrap(),
                &reservation.completion_name(),
            )
            .is_err()
        );

        let mut changed = receipt_value();
        changed["receipt_nonce"] = Value::String("other_receipt_nonce_000000000000001".to_owned());
        assert!(
            completion_record_bytes(
                &reservation,
                &canonical_line(&changed, RECEIPT_MAX_BYTES, "test").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_validation_rejects_missing_signature_bad_fields_and_noncanonical_source() {
        for field in [
            "schema_version",
            "worker_machine_id",
            "receipt_nonce",
            "boot_id",
            "interface_path_sha256",
            "observation_transcript_sha256",
            "signature_ssh",
        ] {
            let mut value = receipt_value();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                validate_receipt(&canonical_line(&value, RECEIPT_MAX_BYTES, "test").unwrap())
                    .is_err()
            );
        }
        let pretty = serde_json::to_string_pretty(&receipt_value()).unwrap();
        assert!(validate_receipt(format!("{pretty}\n").as_bytes()).is_err());
        let mut empty_signature = receipt_value();
        empty_signature["signature_ssh"] = Value::String(String::new());
        assert!(
            validate_receipt(&canonical_line(&empty_signature, RECEIPT_MAX_BYTES, "test").unwrap())
                .is_err()
        );
    }

    #[test]
    fn input_validation_rejects_unsafe_nonce_hashes_and_uuid() {
        assert!(Reservation::new(WORKER, "short", BOOT, PATH, TRANSCRIPT, PATH).is_err());
        assert!(
            Reservation::new(
                WORKER,
                NONCE,
                "12345678-1234-1234-1234-1234567890AB",
                PATH,
                TRANSCRIPT,
                PATH
            )
            .is_err()
        );
        assert!(
            Reservation::new("g".repeat(64).as_str(), NONCE, BOOT, PATH, TRANSCRIPT, PATH).is_err()
        );
        assert!(Reservation::new(WORKER, NONCE, BOOT, "0", TRANSCRIPT, PATH).is_err());
    }

    #[test]
    fn signer_roles_require_three_distinct_public_key_fingerprints() {
        let boundary = "1".repeat(64);
        let capture = "2".repeat(64);
        let device = "3".repeat(64);
        require_pairwise_distinct_role_keys(&boundary, &capture, &device).unwrap();
        assert!(require_pairwise_distinct_role_keys(&boundary, &boundary, &device).is_err());
        assert!(require_pairwise_distinct_role_keys(&boundary, &capture, &boundary).is_err());
        assert!(require_pairwise_distinct_role_keys(&capture, &capture, &device).is_err());
    }
}
