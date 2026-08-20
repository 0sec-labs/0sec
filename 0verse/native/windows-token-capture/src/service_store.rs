#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "store remains unreachable until broker activation is atomic"
    )
)]

//! Private storage primitives for the future `LocalSystem` broker.
//!
//! An installer must provision `%ProgramData%\0verse\windows-token-broker`,
//! its fixed policy/key leaves, and `ledger.lock` with the exact protected
//! SYSTEM-only descriptors checked below. The shared `%ProgramData%\0verse`
//! parent is shape-validated but is not a broker trust root. Serving never
//! creates or repairs trust roots. The runtime order remains authority/live verification, bound
//! key loading, durable reservation, fixed adapter execution, canonical
//! capture signing, and durable completion. This module deliberately remains
//! unreachable until that entire ordering and hosted-LocalSystem lifecycle test
//! land atomically.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(all(windows, feature = "ci-system-test"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CiPhase {
    PhaseOne,
    PhaseTwo,
    Complete,
}

#[cfg(all(windows, feature = "ci-system-test"))]
#[derive(Clone, Copy)]
pub(crate) enum CiAuthorizationFixture {
    Boundary,
    Capture,
    Device,
}

const RESERVATION_SCHEMA: &str = "0verse.windows-token-reservation/v2";
const RECORD_SCHEMA: &str = "0verse.windows-token-reservation-record/v2";
const COMPLETION_SCHEMA: &str = "0verse.windows-token-completion-record/v2";
const SLOT_DOMAIN: &[u8] = b"0verse-windows-token-reservation-slot-v2\0";
const RUN_DOMAIN: &[u8] = b"0verse-windows-token-reservation-run-v1\0";
const LEGACY_RESERVATION_SCHEMA: &str = "0verse.windows-token-reservation/v1";
const LEGACY_RECORD_SCHEMA: &str = "0verse.windows-token-reservation-record/v1";
const LEGACY_SLOT_DOMAIN: &[u8] = b"0verse-windows-token-reservation-slot-v1\0";
const COMPLETION_MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CaptureCase {
    Target,
    Control,
}

impl CaptureCase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Control => "control",
        }
    }
}

#[derive(Debug, Serialize)]
struct Reservation<'a> {
    schema_version: &'static str,
    campaign_sha256: &'a str,
    scope_manifest_sha256: &'a str,
    execution_grant_sha256: &'a str,
    grant_nonce: &'a str,
    worker_acceptance_sha256: &'a str,
    acceptance_nonce: &'a str,
    campaign_id: &'a str,
    case: CaptureCase,
    trial: u32,
    run_nonce: &'a str,
    operation_sha256: &'a str,
    worker: &'a str,
    build_lab_ex: &'a str,
    worker_machine_id: &'a str,
    runner_executable_sha256: &'a str,
    witness_user_sid: &'a str,
    witness_session_id: u32,
    witness_authentication_id: &'a str,
    witness_executable_sha256: &'a str,
    capture_signer: &'a str,
}

#[derive(Serialize)]
struct ReservationRecord<'a> {
    schema_version: &'static str,
    reservation: &'a Reservation<'a>,
    reservation_sha256: String,
}

#[derive(Serialize)]
struct CompletionRecord<'a> {
    schema_version: &'static str,
    reservation_record_sha256: String,
    capture_sha256: String,
    capture: &'a serde_json::Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationOwned {
    schema_version: String,
    campaign_sha256: String,
    scope_manifest_sha256: String,
    execution_grant_sha256: String,
    grant_nonce: String,
    worker_acceptance_sha256: String,
    acceptance_nonce: String,
    campaign_id: String,
    case: CaptureCase,
    trial: u32,
    run_nonce: String,
    operation_sha256: String,
    worker: String,
    build_lab_ex: String,
    worker_machine_id: String,
    runner_executable_sha256: String,
    witness_user_sid: String,
    witness_session_id: u32,
    witness_authentication_id: String,
    witness_executable_sha256: String,
    capture_signer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationRecordOwned {
    schema_version: String,
    reservation: ReservationOwned,
    reservation_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyReservationOwned {
    schema_version: String,
    campaign_sha256: String,
    grant_nonce: String,
    acceptance_nonce: String,
    case: CaptureCase,
    trial: u32,
    run_nonce: String,
    operation_sha256: String,
    worker: String,
    worker_machine_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReservationRecordOwned {
    schema_version: String,
    reservation: LegacyReservationOwned,
    reservation_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionRecordOwned {
    schema_version: String,
    reservation_record_sha256: String,
    capture_sha256: String,
    capture: crate::capture_v3::WindowsTokenCaptureV3,
}

struct ValidatedCompletion {
    reservation: ReservationOwned,
    capture_bytes: Vec<u8>,
}

impl ReservationOwned {
    fn validated(&self) -> Result<Reservation<'_>, String> {
        if self.schema_version != RESERVATION_SCHEMA {
            return Err("reservation schema version is unsupported".to_owned());
        }
        Reservation::new(
            &self.campaign_sha256,
            &self.scope_manifest_sha256,
            &self.execution_grant_sha256,
            &self.grant_nonce,
            &self.worker_acceptance_sha256,
            &self.acceptance_nonce,
            &self.campaign_id,
            self.case,
            self.trial,
            &self.run_nonce,
            &self.operation_sha256,
            &self.worker,
            &self.build_lab_ex,
            &self.worker_machine_id,
            &self.runner_executable_sha256,
            &self.witness_user_sid,
            self.witness_session_id,
            &self.witness_authentication_id,
            &self.witness_executable_sha256,
            &self.capture_signer,
        )
    }
}

impl<'a> Reservation<'a> {
    #[allow(clippy::too_many_arguments)] // Exact authority/live binding is intentionally explicit.
    fn new(
        campaign_sha256: &'a str,
        scope_manifest_sha256: &'a str,
        execution_grant_sha256: &'a str,
        grant_nonce: &'a str,
        worker_acceptance_sha256: &'a str,
        acceptance_nonce: &'a str,
        campaign_id: &'a str,
        case: CaptureCase,
        trial: u32,
        run_nonce: &'a str,
        operation_sha256: &'a str,
        worker: &'a str,
        build_lab_ex: &'a str,
        worker_machine_id: &'a str,
        runner_executable_sha256: &'a str,
        witness_user_sid: &'a str,
        witness_session_id: u32,
        witness_authentication_id: &'a str,
        witness_executable_sha256: &'a str,
        capture_signer: &'a str,
    ) -> Result<Self, String> {
        for (value, label) in [
            (campaign_sha256, "campaign SHA-256"),
            (scope_manifest_sha256, "scope manifest SHA-256"),
            (execution_grant_sha256, "execution grant SHA-256"),
            (worker_acceptance_sha256, "worker acceptance SHA-256"),
            (operation_sha256, "operation SHA-256"),
            (runner_executable_sha256, "runner executable SHA-256"),
            (witness_executable_sha256, "witness executable SHA-256"),
        ] {
            validate_sha256(value, label)?;
        }
        for (value, label) in [
            (grant_nonce, "grant nonce"),
            (acceptance_nonce, "acceptance nonce"),
            (run_nonce, "run nonce"),
        ] {
            validate_nonce(value, label)?;
        }
        if grant_nonce == acceptance_nonce
            || grant_nonce == run_nonce
            || acceptance_nonce == run_nonce
        {
            return Err("reservation nonce domains collide".to_owned());
        }
        validate_identity(campaign_id, "campaign ID", 256, b"_.:-")?;
        if !(1..=32).contains(&trial) {
            return Err("reservation trial is outside 1..=32".to_owned());
        }
        validate_identity(worker, "worker", 128, b"_.-")?;
        validate_identity(build_lab_ex, "BuildLabEx", 512, b"_.:-")?;
        validate_identity(worker_machine_id, "worker machine ID", 256, b"_.:-")?;
        crate::capture_v3::validate_witness_provenance(
            witness_user_sid,
            witness_session_id,
            witness_authentication_id,
        )?;
        validate_identity(capture_signer, "capture signer", 256, b"@_.+-")?;
        Ok(Self {
            schema_version: RESERVATION_SCHEMA,
            campaign_sha256,
            scope_manifest_sha256,
            execution_grant_sha256,
            grant_nonce,
            worker_acceptance_sha256,
            acceptance_nonce,
            campaign_id,
            case,
            trial,
            run_nonce,
            operation_sha256,
            worker,
            build_lab_ex,
            worker_machine_id,
            runner_executable_sha256,
            witness_user_sid,
            witness_session_id,
            witness_authentication_id,
            witness_executable_sha256,
            capture_signer,
        })
    }

    fn slot_name(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(SLOT_DOMAIN);
        for value in [
            self.campaign_sha256,
            self.grant_nonce,
            self.acceptance_nonce,
            self.worker_acceptance_sha256,
            self.case.as_str(),
        ] {
            update_bounded(&mut digest, value.as_bytes());
        }
        digest.update(self.trial.to_le_bytes());
        format!("slot-{:x}.reserved", digest.finalize())
    }

    fn legacy_slot_name(&self) -> String {
        legacy_slot_name_parts(
            self.campaign_sha256,
            self.grant_nonce,
            self.acceptance_nonce,
            self.case,
            self.trial,
        )
    }

    fn run_name(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(RUN_DOMAIN);
        update_bounded(&mut digest, self.run_nonce.as_bytes());
        format!("run-{:x}.reserved", digest.finalize())
    }

    fn completion_name(&self) -> String {
        let slot = self.slot_name();
        let digest = slot
            .strip_prefix("slot-")
            .and_then(|value| value.strip_suffix(".reserved"))
            .expect("internally derived slot name has exact grammar");
        format!("completion-{digest}.json")
    }

    fn record_bytes(&self) -> Result<Vec<u8>, String> {
        let reservation_value = serde_json::to_value(self)
            .map_err(|error| format!("cannot canonicalize reservation: {error}"))?;
        let reservation = serde_json::to_vec(&reservation_value)
            .map_err(|error| format!("cannot serialize reservation: {error}"))?;
        let record = ReservationRecord {
            schema_version: RECORD_SCHEMA,
            reservation: self,
            reservation_sha256: format!("{:x}", Sha256::digest(&reservation)),
        };
        let record_value = serde_json::to_value(&record)
            .map_err(|error| format!("cannot canonicalize reservation record: {error}"))?;
        let mut bytes = serde_json::to_vec(&record_value)
            .map_err(|error| format!("cannot serialize reservation record: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() > 4096 {
            return Err("reservation record exceeds its bound".to_owned());
        }
        Ok(bytes)
    }
}

fn canonical_capture_value(bytes: &[u8]) -> Result<(serde_json::Value, Vec<u8>), String> {
    if bytes.len() > COMPLETION_MAX_BYTES || !bytes.ends_with(b"\n") {
        return Err("signed capture is oversized or has no final LF".to_owned());
    }
    let value = crate::broker_protocol::parse_strict_json_object(
        &bytes[..bytes.len() - 1],
        "signed capture",
    )?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize signed capture: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("signed capture is not byte-canonical".to_owned());
    }
    Ok((value, canonical))
}

fn completion_record_bytes(
    reservation: &Reservation<'_>,
    signed_capture: &[u8],
) -> Result<Vec<u8>, String> {
    let (capture, canonical_capture) = canonical_capture_value(signed_capture)?;
    let typed: crate::capture_v3::WindowsTokenCaptureV3 =
        serde_json::from_value(capture.clone())
            .map_err(|error| format!("signed capture schema is invalid: {error}"))?;
    let recovered = reservation_from_capture(&typed)?;
    if recovered.record_bytes()? != reservation.record_bytes()? {
        return Err("signed capture is not bound to the reserved identity".to_owned());
    }
    let reservation_record = reservation.record_bytes()?;
    let record = CompletionRecord {
        schema_version: COMPLETION_SCHEMA,
        reservation_record_sha256: format!("{:x}", Sha256::digest(&reservation_record)),
        capture_sha256: format!("{:x}", Sha256::digest(&canonical_capture)),
        capture: &capture,
    };
    let value = serde_json::to_value(record)
        .map_err(|error| format!("cannot construct completion record: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot serialize completion record: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > COMPLETION_MAX_BYTES {
        return Err("completion record exceeds its bound".to_owned());
    }
    Ok(bytes)
}

fn reservation_from_capture(
    capture: &crate::capture_v3::WindowsTokenCaptureV3,
) -> Result<Reservation<'_>, String> {
    let case = match capture.case.as_str() {
        "target" => CaptureCase::Target,
        "control" => CaptureCase::Control,
        _ => return Err("signed capture case is invalid".to_owned()),
    };
    Reservation::new(
        &capture.campaign_sha256,
        &capture.scope_manifest_sha256,
        &capture.execution_grant_sha256,
        &capture.execution_grant_nonce,
        &capture.worker_acceptance_sha256,
        &capture.worker_acceptance_nonce,
        &capture.campaign_id,
        case,
        capture.trial,
        &capture.run_nonce,
        &capture.operation_sha256,
        &capture.worker,
        &capture.build_lab_ex,
        &capture.worker_machine_id,
        &capture.runner_executable_sha256,
        &capture.witness_user_sid,
        capture.witness_session_id,
        &capture.witness_authentication_id,
        &capture.witness_executable_sha256,
        &capture.signed_by,
    )
}

fn validate_completion_record(bytes: &[u8], name: &str) -> Result<ValidatedCompletion, String> {
    if bytes.len() > COMPLETION_MAX_BYTES || !bytes.ends_with(b"\n") {
        return Err("completion record is oversized or has no final LF".to_owned());
    }
    let value = crate::broker_protocol::parse_strict_json_object(
        &bytes[..bytes.len() - 1],
        "completion record",
    )?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize completion record: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("completion record is not byte-canonical".to_owned());
    }
    let record: CompletionRecordOwned = serde_json::from_value(value)
        .map_err(|error| format!("completion record schema is invalid: {error}"))?;
    if record.schema_version != COMPLETION_SCHEMA {
        return Err("completion record schema version is unsupported".to_owned());
    }
    validate_sha256(
        &record.reservation_record_sha256,
        "completion reservation record SHA-256",
    )?;
    validate_sha256(&record.capture_sha256, "completion capture SHA-256")?;
    let reservation = reservation_from_capture(&record.capture)?;
    if name != reservation.completion_name() {
        return Err("completion record does not bind its filename".to_owned());
    }
    let reservation_record = reservation.record_bytes()?;
    if record.reservation_record_sha256 != format!("{:x}", Sha256::digest(&reservation_record)) {
        return Err("completion record does not bind its reservation bytes".to_owned());
    }
    let capture_value = serde_json::to_value(&record.capture)
        .map_err(|error| format!("cannot canonicalize completed capture: {error}"))?;
    let mut capture_bytes = serde_json::to_vec(&capture_value)
        .map_err(|error| format!("cannot serialize completed capture: {error}"))?;
    capture_bytes.push(b'\n');
    if record.capture_sha256 != format!("{:x}", Sha256::digest(&capture_bytes)) {
        return Err("completion record capture hash is invalid".to_owned());
    }
    Ok(ValidatedCompletion {
        reservation: ReservationOwned {
            schema_version: RESERVATION_SCHEMA.to_owned(),
            campaign_sha256: record.capture.campaign_sha256,
            scope_manifest_sha256: record.capture.scope_manifest_sha256,
            execution_grant_sha256: record.capture.execution_grant_sha256,
            grant_nonce: record.capture.execution_grant_nonce,
            worker_acceptance_sha256: record.capture.worker_acceptance_sha256,
            acceptance_nonce: record.capture.worker_acceptance_nonce,
            campaign_id: record.capture.campaign_id,
            case: match record.capture.case.as_str() {
                "target" => CaptureCase::Target,
                "control" => CaptureCase::Control,
                _ => return Err("completed capture case is invalid".to_owned()),
            },
            trial: record.capture.trial,
            run_nonce: record.capture.run_nonce,
            operation_sha256: record.capture.operation_sha256,
            worker: record.capture.worker,
            build_lab_ex: record.capture.build_lab_ex,
            worker_machine_id: record.capture.worker_machine_id,
            runner_executable_sha256: record.capture.runner_executable_sha256,
            witness_user_sid: record.capture.witness_user_sid,
            witness_session_id: record.capture.witness_session_id,
            witness_authentication_id: record.capture.witness_authentication_id,
            witness_executable_sha256: record.capture.witness_executable_sha256,
            capture_signer: record.capture.signed_by,
        },
        capture_bytes,
    })
}

fn is_completion_name(name: &str) -> bool {
    let digest = name
        .strip_prefix("completion-")
        .and_then(|value| value.strip_suffix(".json"));
    matches!(
        digest,
        Some(value)
            if value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    )
}

fn validate_record(bytes: &[u8]) -> Result<ReservationOwned, String> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err("reservation record is oversized or has no final LF".to_owned());
    }
    let value = crate::broker_protocol::parse_strict_json_object(
        &bytes[..bytes.len() - 1],
        "reservation record",
    )?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize reservation record: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("reservation record is not byte-canonical".to_owned());
    }
    let record: ReservationRecordOwned = serde_json::from_value(value)
        .map_err(|error| format!("reservation record schema is invalid: {error}"))?;
    if record.schema_version != RECORD_SCHEMA
        || record.reservation.schema_version != RESERVATION_SCHEMA
    {
        return Err("reservation record schema version is unsupported".to_owned());
    }
    let reservation = &record.reservation;
    reservation.validated()?;
    validate_sha256(
        &record.reservation_sha256,
        "reservation record payload SHA-256",
    )?;
    let payload = serde_json::to_vec(
        &serde_json::to_value(reservation)
            .map_err(|error| format!("cannot canonicalize recovered reservation: {error}"))?,
    )
    .map_err(|error| format!("cannot serialize recovered reservation: {error}"))?;
    if record.reservation_sha256 != format!("{:x}", Sha256::digest(payload)) {
        return Err("reservation record payload hash is invalid".to_owned());
    }
    Ok(record.reservation)
}

fn validate_record_for_name(bytes: &[u8], name: &str) -> Result<(), String> {
    let owned = validate_record(bytes)?;
    let reservation = owned.validated()?;
    if name != reservation.slot_name() && name != reservation.run_name() {
        return Err("reservation record does not bind its slot/run filename".to_owned());
    }
    Ok(())
}

fn validate_legacy_record(bytes: &[u8]) -> Result<LegacyReservationOwned, String> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err("legacy reservation record is oversized or has no final LF".to_owned());
    }
    let value = crate::broker_protocol::parse_strict_json_object(
        &bytes[..bytes.len() - 1],
        "legacy reservation record",
    )?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize legacy reservation record: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("legacy reservation record is not byte-canonical".to_owned());
    }
    let record: LegacyReservationRecordOwned = serde_json::from_value(value)
        .map_err(|error| format!("legacy reservation record schema is invalid: {error}"))?;
    if record.schema_version != LEGACY_RECORD_SCHEMA
        || record.reservation.schema_version != LEGACY_RESERVATION_SCHEMA
    {
        return Err("legacy reservation record schema version is unsupported".to_owned());
    }
    let reservation = &record.reservation;
    for (value, label) in [
        (&reservation.campaign_sha256, "legacy campaign SHA-256"),
        (&reservation.operation_sha256, "legacy operation SHA-256"),
    ] {
        validate_sha256(value, label)?;
    }
    for (value, label) in [
        (&reservation.grant_nonce, "legacy grant nonce"),
        (&reservation.acceptance_nonce, "legacy acceptance nonce"),
        (&reservation.run_nonce, "legacy run nonce"),
    ] {
        validate_nonce(value, label)?;
    }
    if reservation.grant_nonce == reservation.acceptance_nonce
        || reservation.grant_nonce == reservation.run_nonce
        || reservation.acceptance_nonce == reservation.run_nonce
        || !(1..=32).contains(&reservation.trial)
    {
        return Err("legacy reservation nonce/trial identity is invalid".to_owned());
    }
    validate_identity(&reservation.worker, "legacy worker", 128, b"_.-")?;
    validate_identity(
        &reservation.worker_machine_id,
        "legacy worker machine ID",
        256,
        b"_.:-",
    )?;
    validate_sha256(
        &record.reservation_sha256,
        "legacy reservation payload SHA-256",
    )?;
    let payload = serde_json::to_vec(
        &serde_json::to_value(reservation)
            .map_err(|error| format!("cannot canonicalize legacy reservation: {error}"))?,
    )
    .map_err(|error| format!("cannot serialize legacy reservation: {error}"))?;
    if record.reservation_sha256 != format!("{:x}", Sha256::digest(payload)) {
        return Err("legacy reservation record payload hash is invalid".to_owned());
    }
    Ok(record.reservation)
}

fn legacy_slot_name(reservation: &LegacyReservationOwned) -> String {
    legacy_slot_name_parts(
        &reservation.campaign_sha256,
        &reservation.grant_nonce,
        &reservation.acceptance_nonce,
        reservation.case,
        reservation.trial,
    )
}

fn legacy_slot_name_parts(
    campaign_sha256: &str,
    grant_nonce: &str,
    acceptance_nonce: &str,
    case: CaptureCase,
    trial: u32,
) -> String {
    let mut digest = Sha256::new();
    digest.update(LEGACY_SLOT_DOMAIN);
    for value in [
        campaign_sha256,
        grant_nonce,
        acceptance_nonce,
        case.as_str(),
    ] {
        update_bounded(&mut digest, value.as_bytes());
    }
    digest.update(trial.to_le_bytes());
    format!("slot-{:x}.reserved", digest.finalize())
}

fn legacy_run_name(reservation: &LegacyReservationOwned) -> String {
    let mut digest = Sha256::new();
    digest.update(RUN_DOMAIN);
    update_bounded(&mut digest, reservation.run_nonce.as_bytes());
    format!("run-{:x}.reserved", digest.finalize())
}

fn validate_legacy_record_for_name(bytes: &[u8], name: &str) -> Result<(), String> {
    let reservation = validate_legacy_record(bytes)?;
    if name != legacy_slot_name(&reservation) && name != legacy_run_name(&reservation) {
        return Err("legacy reservation does not bind its slot/run filename".to_owned());
    }
    Ok(())
}

fn update_bounded(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("validated value length fits u64")
            .to_le_bytes(),
    );
    digest.update(value);
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase SHA-256"));
    }
    Ok(())
}

fn validate_nonce(value: &str, label: &str) -> Result<(), String> {
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("{label} is not a bounded URL-safe nonce"));
    }
    Ok(())
}

fn validate_identity(value: &str, label: &str, maximum: usize, extra: &[u8]) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte))
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

#[cfg(windows)]
mod windows_store {
    #![allow(
        dead_code,
        reason = "Windows store is intentionally disconnected until broker activation"
    )]

    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString, c_void};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
        ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid,
        GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_COMPRESSED,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FindClose, FindFirstFileW, FindNextFileW,
        FlushFileBuffers, GetDriveTypeW, GetFileInformationByHandle, GetVolumeInformationByHandleW,
        OPEN_EXISTING, READ_CONTROL, ReadFile, WIN32_FIND_DATAW, WriteFile,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use zeroize::Zeroizing;

    use super::{
        COMPLETION_MAX_BYTES, Reservation, completion_record_bytes, is_completion_name,
        legacy_run_name, legacy_slot_name, validate_completion_record, validate_legacy_record,
        validate_legacy_record_for_name, validate_record, validate_record_for_name,
    };

    #[cfg(feature = "ci-system-test")]
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinLocalSystemSid,
    };
    #[cfg(feature = "ci-system-test")]
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, DeleteFileW, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
        RemoveDirectoryW,
    };
    #[cfg(feature = "ci-system-test")]
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const ROOT_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)";
    #[cfg(feature = "ci-system-test")]
    const COMPANY_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    const FILE_SDDL: &str = "O:SYG:SYD:P(A;;FA;;;SY)";
    const POLICY_MAX_BYTES: u64 = 1024 * 1024;
    const PRIVATE_KEY_MAX_BYTES: u64 = 64 * 1024;

    #[cfg(feature = "ci-system-test")]
    const CI_CONTROL_DIRECTORY: &str = "0verse-windows-store-e2e-control";
    #[cfg(feature = "ci-system-test")]
    const CI_SENTINEL: &str = "owned-by-ci-system-test";
    #[cfg(feature = "ci-system-test")]
    const CI_SENTINEL_COMPANY_CREATED: &[u8] =
        b"0verse.windows-store-ci-owner/v1\ncompany_created=1\n";
    #[cfg(feature = "ci-system-test")]
    const CI_SENTINEL_COMPANY_PREEXISTED: &[u8] =
        b"0verse.windows-store-ci-owner/v1\ncompany_created=0\n";
    #[cfg(feature = "ci-system-test")]
    const CI_PHASE_ONE: &str = "phase-one.complete";
    #[cfg(feature = "ci-system-test")]
    const CI_PHASE_TWO: &str = "phase-two.complete";
    #[cfg(feature = "ci-system-test")]
    const CI_POLICY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");
    #[cfg(feature = "ci-system-test")]
    const CI_AUTHORIZATION_POLICY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-boundary-sshsig/allowed_signers");
    #[cfg(feature = "ci-system-test")]
    const CI_CAPTURE_ALIAS_AUTHORIZATION_POLICY: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows-boundary-sshsig/capture-key-allowed_signers"
    );
    #[cfg(feature = "ci-system-test")]
    const CI_DEVICE_ALIAS_AUTHORIZATION_POLICY: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows-boundary-sshsig/device-key-allowed_signers"
    );
    #[cfg(feature = "ci-system-test")]
    const CI_PRIVATE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/test-only-key");

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                // SAFETY: this object exclusively owns the successful handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct OwnedDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for OwnedDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: descriptor is a LocalAlloc allocation returned by Win32.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    struct OwnedFindHandle(HANDLE);

    impl Drop for OwnedFindHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this object exclusively owns the successful find handle.
                unsafe { FindClose(self.0) };
            }
        }
    }

    enum TrustLeaf {
        AuthorizationPolicy,
        AcceptancePolicy,
        CapturePolicy,
        CapturePrivateKey,
    }

    impl TrustLeaf {
        const fn name(&self) -> &'static str {
            match self {
                Self::AuthorizationPolicy => "authorization.allowed_signers",
                Self::AcceptancePolicy => "acceptance.allowed_signers",
                Self::CapturePolicy => "capture.allowed_signers",
                Self::CapturePrivateKey => "capture_ed25519",
            }
        }

        const fn maximum(&self) -> u64 {
            match self {
                Self::AuthorizationPolicy | Self::AcceptancePolicy | Self::CapturePolicy => {
                    POLICY_MAX_BYTES
                }
                Self::CapturePrivateKey => PRIVATE_KEY_MAX_BYTES,
            }
        }
    }

    struct ServiceStore {
        root: PathBuf,
        _ancestor_handles: Vec<OwnedHandle>,
        _root_handle: OwnedHandle,
    }

    enum CompletionStatus {
        Created(Vec<u8>),
        AlreadyCompleted(Vec<u8>),
    }

    impl ServiceStore {
        fn open() -> Result<Self, String> {
            let mut root = known_program_data()?;
            validate_fixed_drive(&root)?;
            let program_data = open_existing(
                &root,
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_shape(&program_data, true, 0, 0)?;

            root.push("0verse");
            let company_root = open_existing(
                &root,
                GENERIC_READ | READ_CONTROL,
                0,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_shape(&company_root, true, 0, 0)?;

            root.push("windows-token-broker");
            let handle = open_existing(
                &root,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_handle(&handle, true, 0, 0, ROOT_SDDL)?;
            validate_volume(&handle)?;
            let store = Self {
                root,
                _ancestor_handles: vec![program_data, company_root],
                _root_handle: handle,
            };
            store.recover_reservations()?;
            Ok(store)
        }

        fn load_authorization_policy(&self) -> Result<String, String> {
            self.load_policy(&TrustLeaf::AuthorizationPolicy)
        }

        fn load_acceptance_policy(&self) -> Result<String, String> {
            self.load_policy(&TrustLeaf::AcceptancePolicy)
        }

        fn load_policy(&self, leaf: &TrustLeaf) -> Result<String, String> {
            let bytes = self.load_leaf(leaf)?;
            if bytes.contains(&0) {
                return Err("allowed-signers policy contains NUL".to_owned());
            }
            String::from_utf8(bytes.to_vec())
                .map_err(|_| "allowed-signers policy is not UTF-8".to_owned())
        }

        fn load_bound_capture_private_key(
            &self,
            capture_signer: &str,
        ) -> Result<Zeroizing<Vec<u8>>, String> {
            let policy = self.load_policy(&TrustLeaf::CapturePolicy)?;
            let private_key = self.load_leaf(&TrustLeaf::CapturePrivateKey)?;
            crate::sshsig::verify_private_key_identity(
                private_key.as_slice(),
                capture_signer,
                &policy,
            )?;
            Ok(private_key)
        }

        fn load_leaf(&self, leaf: &TrustLeaf) -> Result<Zeroizing<Vec<u8>>, String> {
            let path = self.root.join(leaf.name());
            let handle = open_existing(
                &path,
                GENERIC_READ | READ_CONTROL,
                0,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let information = validate_handle(&handle, false, 1, leaf.maximum(), FILE_SDDL)?;
            read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh)
        }

        fn reserve(&self, reservation: &Reservation<'_>) -> Result<(), String> {
            let lock_path = self.root.join("ledger.lock");
            let lock = open_existing(
                &lock_path,
                GENERIC_READ | READ_CONTROL,
                0,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_handle(&lock, false, 0, 4096, FILE_SDDL)?;

            let record = reservation.record_bytes()?;
            let slot_name = reservation.slot_name();
            let legacy_slot_name = reservation.legacy_slot_name();
            let run_name = reservation.run_name();
            for (name, label) in [
                (&legacy_slot_name, "legacy slot"),
                (&slot_name, "slot"),
                (&run_name, "run nonce"),
            ] {
                if self.load_optional_named_file(name, 4096)?.is_some() {
                    return Err(format!("{label} has already been reserved"));
                }
            }
            self.create_marker(&slot_name, &record, "slot")?;
            self.create_marker(&run_name, &record, "run nonce")?;
            Ok(())
        }

        fn completed_capture(
            &self,
            reservation: &Reservation<'_>,
        ) -> Result<Option<Vec<u8>>, String> {
            let name = reservation.completion_name();
            let Some(bytes) = self.load_optional_named_file(&name, COMPLETION_MAX_BYTES as u64)?
            else {
                return Ok(None);
            };
            let completed = validate_completion_record(&bytes, &name)?;
            if completed.reservation.validated()?.record_bytes()? != reservation.record_bytes()? {
                return Err("durable completion conflicts with requested reservation".to_owned());
            }
            let policy = self.load_policy(&TrustLeaf::CapturePolicy)?;
            crate::capture_v3::verify_signed_capture_bytes(&completed.capture_bytes, &policy)?;
            self.require_reservation_pair(reservation)?;
            Ok(Some(completed.capture_bytes))
        }

        fn complete(
            &self,
            reservation: &Reservation<'_>,
            signed_capture: &[u8],
        ) -> Result<CompletionStatus, String> {
            let lock_path = self.root.join("ledger.lock");
            let lock = open_existing(
                &lock_path,
                GENERIC_READ | READ_CONTROL,
                0,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_handle(&lock, false, 0, 4096, FILE_SDDL)?;
            self.require_reservation_pair(reservation)?;
            let policy = self.load_policy(&TrustLeaf::CapturePolicy)?;
            crate::capture_v3::verify_signed_capture_bytes(signed_capture, &policy)?;
            let record = completion_record_bytes(reservation, signed_capture)?;
            match self.create_immutable(
                &reservation.completion_name(),
                &record,
                "completion",
                COMPLETION_MAX_BYTES as u64,
            ) {
                Ok(()) => Ok(CompletionStatus::Created(signed_capture.to_vec())),
                Err(error) if error == "completion has already been reserved" => {
                    let existing = self.completed_capture(reservation)?.ok_or_else(|| {
                        "completion disappeared during held-ledger lookup".to_owned()
                    })?;
                    if existing != signed_capture {
                        return Err("durable completion conflicts with signed capture".to_owned());
                    }
                    Ok(CompletionStatus::AlreadyCompleted(existing))
                }
                Err(error) => Err(error),
            }
        }

        fn require_reservation_pair(&self, reservation: &Reservation<'_>) -> Result<(), String> {
            let expected = reservation.record_bytes()?;
            for name in [reservation.slot_name(), reservation.run_name()] {
                let bytes = self
                    .load_optional_named_file(&name, 4096)?
                    .ok_or_else(|| "completion has no durable reservation pair".to_owned())?;
                validate_record_for_name(&bytes, &name)?;
                if bytes.as_slice() != expected {
                    return Err("completion reservation pair conflicts with request".to_owned());
                }
            }
            Ok(())
        }

        fn load_optional_named_file(
            &self,
            name: &str,
            maximum: u64,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            let path = self.root.join(name);
            let Some(handle) = open_existing_optional(
                &path,
                GENERIC_READ | READ_CONTROL,
                0,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?
            else {
                return Ok(None);
            };
            let information = validate_handle(&handle, false, 1, maximum, FILE_SDDL)?;
            read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh).map(Some)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "linear current/legacy/completion recovery is deliberately audit-visible"
        )]
        fn recover_reservations(&self) -> Result<(), String> {
            let entries = enumerate_directory(&self.root)?;
            let mut records = BTreeMap::new();
            let mut legacy_records = BTreeMap::new();
            let mut completions = BTreeMap::new();
            for name in entries {
                if is_fixed_store_leaf(&name) {
                    continue;
                }
                if !is_marker_name(&name) && !is_completion_name(&name) {
                    return Err(format!(
                        "service store contains unexpected entry {name:?}; refusing execution"
                    ));
                }
                let path = self.root.join(&name);
                let handle = open_existing(
                    &path,
                    GENERIC_READ | READ_CONTROL,
                    0,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                )?;
                let maximum = if is_completion_name(&name) {
                    COMPLETION_MAX_BYTES as u64
                } else {
                    4096
                };
                let information = validate_handle(&handle, false, 0, maximum, FILE_SDDL)?;
                let size = (u64::from(information.nFileSizeHigh) << 32)
                    | u64::from(information.nFileSizeLow);
                if size == 0 {
                    return Err(format!(
                        "store entry {name:?} is consumed/corrupt (torn after creation)"
                    ));
                }
                let bytes =
                    read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh)?;
                if is_completion_name(&name) {
                    completions.insert(name, bytes.to_vec());
                } else {
                    match validate_record_for_name(&bytes, &name) {
                        Ok(()) => {
                            records.insert(name, bytes.to_vec());
                        }
                        Err(current_error) => {
                            validate_legacy_record_for_name(&bytes, &name).map_err(
                                |legacy_error| {
                                    format!(
                                        "reservation marker {name:?} is consumed/corrupt: current={current_error}; legacy={legacy_error}"
                                    )
                                },
                            )?;
                            legacy_records.insert(name, bytes.to_vec());
                        }
                    }
                }
            }

            for (name, bytes) in &records {
                let owned = validate_record(bytes).map_err(|error| {
                    format!("reservation marker {name:?} is consumed/corrupt: {error}")
                })?;
                let reservation = owned.validated()?;
                let slot = reservation.slot_name();
                let run = reservation.run_name();
                let Some(slot_bytes) = records.get(&slot) else {
                    return Err(format!(
                        "reservation marker {name:?} has no matching slot; consumed/corrupt"
                    ));
                };
                let Some(run_bytes) = records.get(&run) else {
                    return Err(format!(
                        "reservation marker {name:?} has no matching run nonce; consumed/corrupt"
                    ));
                };
                if slot_bytes != bytes || run_bytes != bytes {
                    return Err(format!(
                        "reservation marker {name:?} conflicts with its pair; consumed/corrupt"
                    ));
                }
            }
            for (name, bytes) in &legacy_records {
                let reservation = validate_legacy_record(bytes).map_err(|error| {
                    format!("legacy reservation marker {name:?} is consumed/corrupt: {error}")
                })?;
                let slot = legacy_slot_name(&reservation);
                let run = legacy_run_name(&reservation);
                if legacy_records.get(&slot) != Some(bytes)
                    || legacy_records.get(&run) != Some(bytes)
                {
                    return Err(format!(
                        "legacy reservation marker {name:?} lacks its exact pair; consumed/corrupt"
                    ));
                }
            }
            let capture_policy = if completions.is_empty() {
                None
            } else {
                Some(self.load_policy(&TrustLeaf::CapturePolicy)?)
            };
            for (name, bytes) in completions {
                let completed = validate_completion_record(&bytes, &name)
                    .map_err(|error| format!("completion {name:?} is consumed/corrupt: {error}"))?;
                let reservation = completed.reservation.validated()?;
                let expected = reservation.record_bytes()?;
                for marker in [reservation.slot_name(), reservation.run_name()] {
                    if records.get(&marker) != Some(&expected) {
                        return Err(format!(
                            "completion {name:?} lacks its exact reservation pair; consumed/corrupt"
                        ));
                    }
                }
                crate::capture_v3::verify_signed_capture_bytes(
                    &completed.capture_bytes,
                    capture_policy
                        .as_deref()
                        .expect("capture policy exists when completions exist"),
                )
                .map_err(|error| {
                    format!("completion {name:?} has invalid signed capture: {error}")
                })?;
            }
            Ok(())
        }

        fn create_marker(&self, name: &str, record: &[u8], label: &str) -> Result<(), String> {
            self.create_immutable(name, record, label, 4096)
        }

        fn create_immutable(
            &self,
            name: &str,
            record: &[u8],
            label: &str,
            maximum: u64,
        ) -> Result<(), String> {
            let exact = u64::try_from(record.len())
                .map_err(|_| format!("{label} length does not fit its durable bound"))?;
            if exact == 0 || exact > maximum {
                return Err(format!("{label} exceeds its durable bound"));
            }
            let descriptor = descriptor_from_sddl(FILE_SDDL)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                    .expect("SECURITY_ATTRIBUTES size fits u32"),
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            };
            let path = wide_null(self.root.join(name).as_os_str());
            // SAFETY: path and security descriptor are live and NUL-terminated.
            let raw = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_WRITE | READ_CONTROL,
                    0,
                    &raw const attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                    null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                // SAFETY: called immediately after CreateFileW failed.
                let error = unsafe { GetLastError() };
                if matches!(error, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
                    return Err(format!("{label} has already been reserved"));
                }
                return Err(format!("cannot reserve {label}: Win32 error {error}"));
            }
            let handle = OwnedHandle(raw);
            // Creation itself burns the slot. Every subsequent error leaves the
            // immutable marker in place and therefore fails closed on retry.
            validate_handle(&handle, false, 0, maximum, FILE_SDDL)?;
            write_all(&handle, record)?;
            validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
            // SAFETY: handle is a writable synchronous disk-file handle.
            if unsafe { FlushFileBuffers(handle.0) } == 0 {
                return Err(win32_error("FlushFileBuffers(reservation)"));
            }
            Ok(())
        }
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn known_program_data() -> Result<PathBuf, String> {
        let mut raw = null_mut();
        // SAFETY: folder ID is static and raw is writable task-allocation storage.
        let result = unsafe {
            SHGetKnownFolderPath(
                &FOLDERID_ProgramData,
                KF_FLAG_DEFAULT as u32,
                null_mut(),
                &raw mut raw,
            )
        };
        if result < 0 || raw.is_null() {
            return Err(format!(
                "SHGetKnownFolderPath(ProgramData) failed with HRESULT {result:#x}"
            ));
        }
        let path = (|| {
            let mut length = 0_usize;
            // SAFETY: the API returned a NUL-terminated task allocation.
            while unsafe { *raw.add(length) } != 0 {
                length += 1;
                if length > 32_000 {
                    return Err("ProgramData path exceeds its bound".to_owned());
                }
            }
            // SAFETY: the loop established the initialized UTF-16 slice length.
            Ok(PathBuf::from(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(raw, length)
            })))
        })();
        // SAFETY: raw is the task allocation returned by SHGetKnownFolderPath.
        unsafe { CoTaskMemFree(raw.cast()) };
        path
    }

    fn validate_fixed_drive(path: &Path) -> Result<(), String> {
        let root = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) => format!("{}:\\", char::from(letter)),
                Prefix::VerbatimDisk(letter) => format!(r"\\?\{}:\", char::from(letter)),
                _ => return Err("service store must not use UNC or device paths".to_owned()),
            },
            _ => return Err("service store path has no local drive prefix".to_owned()),
        };
        let root = wide_null(OsStr::new(&root));
        // SAFETY: root is a NUL-terminated drive-root path.
        if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
            return Err("service store must reside on a fixed local drive".to_owned());
        }
        Ok(())
    }

    fn validate_volume(handle: &OwnedHandle) -> Result<(), String> {
        let mut volume_name = [0_u16; 64];
        let mut filesystem_name = [0_u16; 64];
        let mut serial = 0;
        let mut component_length = 0;
        let mut flags = 0;
        // SAFETY: output arrays and scalar pointers are writable for supplied sizes.
        if unsafe {
            GetVolumeInformationByHandleW(
                handle.0,
                volume_name.as_mut_ptr(),
                u32::try_from(volume_name.len()).expect("volume-name bound fits u32"),
                &raw mut serial,
                &raw mut component_length,
                &raw mut flags,
                filesystem_name.as_mut_ptr(),
                u32::try_from(filesystem_name.len()).expect("filesystem-name bound fits u32"),
            )
        } == 0
            || flags & FILE_PERSISTENT_ACLS == 0
        {
            return Err("service store volume lacks persistent ACL support".to_owned());
        }
        Ok(())
    }

    fn open_existing(
        path: &Path,
        access: u32,
        share: u32,
        flags: u32,
    ) -> Result<OwnedHandle, String> {
        let path = wide_null(path.as_os_str());
        // SAFETY: path is NUL-terminated; no security attributes are used for open.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                share,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(win32_error("CreateFileW(service store)"));
        }
        Ok(OwnedHandle(handle))
    }

    fn open_existing_optional(
        path: &Path,
        access: u32,
        share: u32,
        flags: u32,
    ) -> Result<Option<OwnedHandle>, String> {
        let path = wide_null(path.as_os_str());
        // SAFETY: path is NUL-terminated; no security attributes are used for open.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                share,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: read immediately after CreateFileW failed.
            let error = unsafe { GetLastError() };
            if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                return Ok(None);
            }
            return Err(format!(
                "CreateFileW(optional service store leaf) failed with Win32 error {error}"
            ));
        }
        Ok(Some(OwnedHandle(handle)))
    }

    fn enumerate_directory(path: &Path) -> Result<Vec<String>, String> {
        let pattern = wide_null(path.join("*").as_os_str());
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: pattern is NUL-terminated and data is writable for the exact structure.
        let raw = unsafe { FindFirstFileW(pattern.as_ptr(), &raw mut data) };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: read immediately after failed enumeration.
            if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
                return Ok(Vec::new());
            }
            return Err(win32_error("FindFirstFileW(service store)"));
        }
        let find = OwnedFindHandle(raw);
        let mut names = Vec::new();
        loop {
            let length = data
                .cFileName
                .iter()
                .position(|unit| *unit == 0)
                .ok_or_else(|| "service store entry name is not NUL-terminated".to_owned())?;
            let name = String::from_utf16(&data.cFileName[..length])
                .map_err(|_| "service store entry name is not valid UTF-16".to_owned())?;
            if name != "." && name != ".." {
                names.push(name);
            }
            // SAFETY: find is a live search handle and data remains writable.
            if unsafe { FindNextFileW(find.0, &raw mut data) } == 0 {
                // SAFETY: read immediately after the failed enumeration call.
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_MORE_FILES {
                    return Err(format!(
                        "FindNextFileW(service store) failed with Win32 error {error}"
                    ));
                }
                break;
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    fn is_fixed_store_leaf(name: &str) -> bool {
        matches!(
            name,
            "authorization.allowed_signers"
                | "acceptance.allowed_signers"
                | "capture.allowed_signers"
                | "capture_ed25519"
                | "ledger.lock"
        )
    }

    fn is_marker_name(name: &str) -> bool {
        let digest = name
            .strip_prefix("slot-")
            .or_else(|| name.strip_prefix("run-"))
            .and_then(|rest| rest.strip_suffix(".reserved"));
        matches!(
            digest,
            Some(value)
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        )
    }

    fn descriptor_from_sddl(sddl: &str) -> Result<OwnedDescriptor, String> {
        let sddl = wide_null(OsStr::new(sddl));
        let mut descriptor = null_mut();
        // SAFETY: SDDL is NUL-terminated and descriptor storage is writable.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &raw mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(win32_error("ConvertStringSecurityDescriptor"));
        }
        Ok(OwnedDescriptor(descriptor))
    }

    fn validate_handle(
        handle: &OwnedHandle,
        directory: bool,
        minimum: u64,
        maximum: u64,
        expected_sddl: &str,
    ) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
        let information = validate_shape(handle, directory, minimum, maximum)?;
        validate_security(handle, expected_sddl)?;
        Ok(information)
    }

    fn validate_shape(
        handle: &OwnedHandle,
        directory: bool,
        minimum: u64,
        maximum: u64,
    ) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: information is writable for the exact structure size.
        if unsafe { GetFileInformationByHandle(handle.0, &raw mut information) } == 0 {
            return Err(win32_error("GetFileInformationByHandle"));
        }
        let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let unsafe_attributes = FILE_ATTRIBUTE_REPARSE_POINT
            | FILE_ATTRIBUTE_COMPRESSED
            | FILE_ATTRIBUTE_ENCRYPTED
            | FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_SPARSE_FILE;
        if information.dwFileAttributes & unsafe_attributes != 0
            || is_directory != directory
            || (!directory && information.nNumberOfLinks != 1)
        {
            return Err("service store handle type, reparse, or link count is unsafe".to_owned());
        }
        let size =
            (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
        if !directory && (size < minimum || size > maximum) {
            return Err("service store file size is outside its exact bound".to_owned());
        }
        Ok(information)
    }

    fn validate_security(handle: &OwnedHandle, expected_sddl: &str) -> Result<(), String> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: output pointers are writable; descriptor owns the returned allocation.
        let result = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        if result != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
            if !descriptor.is_null() {
                // SAFETY: descriptor is the GetSecurityInfo LocalAlloc result.
                unsafe { LocalFree(descriptor) };
            }
            return Err(format!("GetSecurityInfo failed or returned NULL: {result}"));
        }
        let actual = OwnedDescriptor(descriptor);
        let expected = descriptor_from_sddl(expected_sddl)?;
        compare_descriptors(actual.0, expected.0)
    }

    fn compare_descriptors(
        actual: PSECURITY_DESCRIPTOR,
        expected: PSECURITY_DESCRIPTOR,
    ) -> Result<(), String> {
        let (actual_owner, actual_dacl, actual_control) = descriptor_parts(actual)?;
        let (expected_owner, expected_dacl, expected_control) = descriptor_parts(expected)?;
        // SAFETY: descriptor_parts established both owner SID pointers.
        if unsafe { EqualSid(actual_owner, expected_owner) } == 0
            || actual_control & SE_DACL_PROTECTED == 0
            || expected_control & SE_DACL_PROTECTED == 0
        {
            return Err("service store owner or DACL protection is invalid".to_owned());
        }
        let actual_size = acl_size(actual_dacl)?;
        let expected_size = acl_size(expected_dacl)?;
        if actual_size != expected_size {
            return Err("service store DACL size differs from SYSTEM-only policy".to_owned());
        }
        // SAFETY: GetAclInformation verified both ACL byte lengths.
        let actual_bytes =
            unsafe { std::slice::from_raw_parts(actual_dacl.cast::<u8>(), actual_size as usize) };
        // SAFETY: GetAclInformation verified both ACL byte lengths.
        let expected_bytes = unsafe {
            std::slice::from_raw_parts(expected_dacl.cast::<u8>(), expected_size as usize)
        };
        if actual_bytes != expected_bytes {
            return Err("service store DACL is not the exact SYSTEM-only policy".to_owned());
        }
        Ok(())
    }

    fn descriptor_parts(
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<(PSID, *mut ACL, SECURITY_DESCRIPTOR_CONTROL), String> {
        let mut owner = null_mut();
        let mut owner_defaulted = 0;
        let mut dacl_present = 0;
        let mut dacl_defaulted = 0;
        let mut dacl = null_mut();
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: descriptor is valid for the duration of these calls and outputs are writable.
        if unsafe {
            GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted)
        } == 0
            || unsafe {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &raw mut dacl_present,
                    &raw mut dacl,
                    &raw mut dacl_defaulted,
                )
            } == 0
            || unsafe {
                GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            } == 0
            || owner.is_null()
            || dacl_present == 0
            || dacl.is_null()
            || owner_defaulted != 0
            || dacl_defaulted != 0
        {
            return Err("service store security descriptor is malformed or defaulted".to_owned());
        }
        Ok((owner, dacl, control))
    }

    fn acl_size(acl: *mut ACL) -> Result<u32, String> {
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: ACL pointer came from a validated descriptor and output is writable.
        if unsafe {
            GetAclInformation(
                acl,
                (&raw mut information).cast::<c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
                AclSizeInformation,
            )
        } == 0
        {
            return Err(win32_error("GetAclInformation"));
        }
        if information.AclBytesInUse < u32::try_from(size_of::<ACL>()).expect("ACL size fits u32") {
            return Err("service store DACL byte count is invalid".to_owned());
        }
        Ok(information.AclBytesInUse)
    }

    fn read_exact(
        handle: &OwnedHandle,
        size_low: u32,
        size_high: u32,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let size = (u64::from(size_high) << 32) | u64::from(size_low);
        let size = usize::try_from(size).map_err(|_| "service store size overflow".to_owned())?;
        let mut bytes = Zeroizing::new(vec![0_u8; size]);
        let mut offset = 0;
        while offset < bytes.len() {
            let chunk = u32::try_from(bytes.len() - offset).unwrap_or(u32::MAX);
            let mut read = 0;
            // SAFETY: the remaining vector slice is writable for chunk bytes.
            if unsafe {
                ReadFile(
                    handle.0,
                    bytes[offset..].as_mut_ptr(),
                    chunk,
                    &raw mut read,
                    null_mut(),
                )
            } == 0
                || read == 0
            {
                return Err(win32_error("ReadFile(service store)"));
            }
            offset += usize::try_from(read).map_err(|_| "read count overflow".to_owned())?;
        }
        let mut extra = 0_u8;
        let mut read = 0;
        // SAFETY: extra is writable for one byte and the handle is synchronous.
        if unsafe { ReadFile(handle.0, &raw mut extra, 1, &raw mut read, null_mut()) } == 0
            || read != 0
        {
            return Err("service store file changed size during its held-handle read".to_owned());
        }
        Ok(bytes)
    }

    fn write_all(handle: &OwnedHandle, bytes: &[u8]) -> Result<(), String> {
        let mut offset = 0;
        while offset < bytes.len() {
            let chunk = u32::try_from(bytes.len() - offset).unwrap_or(u32::MAX);
            let mut written = 0;
            // SAFETY: the remaining slice is readable for chunk bytes.
            if unsafe {
                WriteFile(
                    handle.0,
                    bytes[offset..].as_ptr(),
                    chunk,
                    &raw mut written,
                    null_mut(),
                )
            } == 0
                || written == 0
            {
                return Err(win32_error("WriteFile(reservation)"));
            }
            offset += usize::try_from(written).map_err(|_| "write count overflow".to_owned())?;
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn require_local_system() -> Result<(), String> {
        let mut token = null_mut();
        // SAFETY: token storage is writable and the pseudo process handle is always valid.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(win32_error("OpenProcessToken(CI SYSTEM test)"));
        }
        let token = OwnedHandle(token);
        let mut needed = 0;
        // SAFETY: this sizing call intentionally supplies no output buffer.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut needed) };
        if needed < u32::try_from(size_of::<TOKEN_USER>()).expect("TOKEN_USER size fits u32") {
            return Err("GetTokenInformation(TokenUser) returned an invalid size".to_owned());
        }
        let words = usize::try_from(needed)
            .map_err(|_| "TokenUser size overflow".to_owned())?
            .div_ceil(size_of::<usize>());
        let mut user = vec![0_usize; words];
        // SAFETY: the word buffer is suitably aligned and writable for needed bytes.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                user.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(win32_error("GetTokenInformation(TokenUser)"));
        }
        let mut system_sid =
            [0_usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>())];
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        // SAFETY: system_sid is aligned and writable for SECURITY_MAX_SID_SIZE bytes.
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                system_sid.as_mut_ptr().cast(),
                &raw mut sid_size,
            )
        } == 0
        {
            return Err(win32_error("CreateWellKnownSid(LocalSystem)"));
        }
        // SAFETY: GetTokenInformation returned a TOKEN_USER and both SID pointers are live.
        let actual = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() }.User.Sid;
        if actual.is_null() || unsafe { EqualSid(actual, system_sid.as_mut_ptr().cast()) } == 0 {
            return Err("CI store lifecycle must run as LocalSystem".to_owned());
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn path_exists(path: &Path) -> bool {
        let path = wide_null(path.as_os_str());
        // SAFETY: path is NUL-terminated.
        (unsafe { GetFileAttributesW(path.as_ptr()) }) != INVALID_FILE_ATTRIBUTES
    }

    #[cfg(feature = "ci-system-test")]
    fn create_directory_exact(path: &Path, sddl: &str) -> Result<(), String> {
        let descriptor = descriptor_from_sddl(sddl)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let wide = wide_null(path.as_os_str());
        // SAFETY: path and descriptor are valid and live for the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
            return Err(win32_error("CreateDirectoryW(CI store)"));
        }
        let handle = open_existing(
            path,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&handle, true, 0, 0, sddl)?;
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn create_file_exact(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let descriptor = descriptor_from_sddl(FILE_SDDL)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let wide = wide_null(path.as_os_str());
        // SAFETY: path and descriptor are valid and live for the call.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE | READ_CONTROL,
                0,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(win32_error("CreateFileW(CI store leaf)"));
        }
        let handle = OwnedHandle(raw);
        validate_handle(&handle, false, 0, bytes.len() as u64, FILE_SDDL)?;
        write_all(&handle, bytes)?;
        // SAFETY: handle is a writable synchronous disk-file handle.
        if unsafe { FlushFileBuffers(handle.0) } == 0 {
            return Err(win32_error("FlushFileBuffers(CI store leaf)"));
        }
        let exact = u64::try_from(bytes.len()).expect("fixture size fits u64");
        validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn validate_exact_file(path: &Path, expected: &[u8]) -> Result<(), String> {
        let handle = open_existing(
            path,
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let exact = u64::try_from(expected.len()).expect("expected size fits u64");
        let information = validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
        let actual = read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh)?;
        if actual.as_slice() != expected {
            return Err("CI ownership/phase marker content is invalid".to_owned());
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_paths() -> Result<(PathBuf, PathBuf, PathBuf), String> {
        let program_data = known_program_data()?;
        Ok((
            program_data.join(CI_CONTROL_DIRECTORY),
            program_data.join("0verse"),
            program_data.join("0verse").join("windows-token-broker"),
        ))
    }

    #[cfg(feature = "ci-system-test")]
    fn validate_existing_company(path: &Path) -> Result<(), String> {
        let handle = open_existing(
            path,
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_shape(&handle, true, 0, 0)?;
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn company_was_created(control: &Path) -> Result<bool, String> {
        let sentinel = control.join(CI_SENTINEL);
        if validate_exact_file(&sentinel, CI_SENTINEL_COMPANY_CREATED).is_ok() {
            return Ok(true);
        }
        if validate_exact_file(&sentinel, CI_SENTINEL_COMPANY_PREEXISTED).is_ok() {
            return Ok(false);
        }
        Err("CI ownership sentinel content is invalid".to_owned())
    }

    #[cfg(feature = "ci-system-test")]
    fn provision_ci_store() -> Result<(), String> {
        let (control, company, root) = ci_paths()?;
        validate_fixed_drive(&control)?;
        if path_exists(&control) || path_exists(&root) {
            return Err(
                "CI broker/control namespaces must be absent before provisioning".to_owned(),
            );
        }
        let company_preexisted = path_exists(&company);
        if company_preexisted {
            validate_existing_company(&company)?;
        }
        create_directory_exact(&control, ROOT_SDDL)?;
        let sentinel = if company_preexisted {
            CI_SENTINEL_COMPANY_PREEXISTED
        } else {
            CI_SENTINEL_COMPANY_CREATED
        };
        if let Err(error) = create_file_exact(&control.join(CI_SENTINEL), sentinel) {
            if path_exists(&control.join(CI_SENTINEL)) {
                let _ = delete_validated_file(&control.join(CI_SENTINEL));
            }
            let _ = remove_validated_directory(&control, ROOT_SDDL);
            return Err(error);
        }
        if let Err(error) = (|| {
            if !company_preexisted {
                create_directory_exact(&company, COMPANY_SDDL)?;
            }
            create_directory_exact(&root, ROOT_SDDL)?;
            for (leaf, bytes) in [
                ("authorization.allowed_signers", CI_AUTHORIZATION_POLICY),
                ("acceptance.allowed_signers", CI_POLICY),
                ("capture.allowed_signers", CI_POLICY),
                ("capture_ed25519", CI_PRIVATE_KEY),
                ("ledger.lock", b"" as &[u8]),
            ] {
                create_file_exact(&root.join(leaf), bytes)?;
            }
            Ok::<(), String>(())
        })() {
            let _ = cleanup_ci_inner();
            return Err(error);
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_reservation(
        run_nonce: &'static str,
        case: super::CaptureCase,
        trial: u32,
    ) -> Reservation<'static> {
        Reservation::new(
            "1f1d293f3d22a23e4af1b7834ff8ea250b71381b9ddf731e87affd54451976fb",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "grant_nonce_000000000000000000000",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "acceptance_nonce_0000000000000000",
            "hosted-local-system-store-e2e",
            case,
            trial,
            run_nonce,
            "2222222222222222222222222222222222222222222222222222222222222222",
            "canary-worker.example.test",
            "29617.1000.amd64fre.rs_prerelease.260701-1200",
            "machine-canonical-001",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "S-1-5-21-1-2-3-1001",
            1,
            "0000000000001001",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "capture@example.test",
        )
        .expect("fixed CI reservation is valid")
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_signed_capture(reservation: &Reservation<'_>) -> Result<Vec<u8>, String> {
        use crate::capture_v3::{
            CAPTURE_SCHEMA_VERSION, CAPTURE_SIGNATURE_NAMESPACE, CaptureTokenSnapshot,
            WindowsTokenCaptureV3,
        };
        use crate::{SnapshotPhase, derive_token_id};

        fn snapshot(run_nonce: &str, phase: SnapshotPhase) -> CaptureTokenSnapshot {
            let statistics_token_id = 7;
            CaptureTokenSnapshot {
                token_id: derive_token_id(run_nonce, phase, statistics_token_id),
                user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                integrity_rid: 0x2000,
                elevation_type: "default".to_owned(),
                elevated: false,
                admin_group: "absent".to_owned(),
                app_container: false,
                restricted_sid_count: 0,
                enabled_privileges: vec!["SeChangeNotifyPrivilege".to_owned()],
                token_source: "process-fallback-no-thread-token".to_owned(),
                statistics_token_id_before: statistics_token_id,
                statistics_token_id_after: statistics_token_id,
                modified_id_before: 9,
                modified_id_after: 9,
                lpac_supported: true,
                less_privileged_app_container: false,
                session_id: 1,
                authentication_id: "0000000000001001".to_owned(),
            }
        }

        let mut capture = WindowsTokenCaptureV3 {
            schema_version: CAPTURE_SCHEMA_VERSION.to_owned(),
            campaign_sha256: reservation.campaign_sha256.to_owned(),
            scope_manifest_sha256: reservation.scope_manifest_sha256.to_owned(),
            execution_grant_sha256: reservation.execution_grant_sha256.to_owned(),
            execution_grant_nonce: reservation.grant_nonce.to_owned(),
            worker_acceptance_sha256: reservation.worker_acceptance_sha256.to_owned(),
            worker_acceptance_nonce: reservation.acceptance_nonce.to_owned(),
            campaign_id: reservation.campaign_id.to_owned(),
            worker: reservation.worker.to_owned(),
            build_lab_ex: reservation.build_lab_ex.to_owned(),
            worker_machine_id: reservation.worker_machine_id.to_owned(),
            runner_executable_sha256: reservation.runner_executable_sha256.to_owned(),
            witness_user_sid: reservation.witness_user_sid.to_owned(),
            witness_session_id: reservation.witness_session_id,
            witness_authentication_id: reservation.witness_authentication_id.to_owned(),
            witness_executable_sha256: reservation.witness_executable_sha256.to_owned(),
            operation_sha256: reservation.operation_sha256.to_owned(),
            case: reservation.case.as_str().to_owned(),
            trial: reservation.trial,
            run_nonce: reservation.run_nonce.to_owned(),
            capture_nonce: "capture_nonce_0000000000000000000".to_owned(),
            process_instance_id: "hosted-local-system-store-e2e".to_owned(),
            thread_id_before: 10,
            thread_id_after: 10,
            started_at: "2026-07-15T00:00:00Z".to_owned(),
            completed_at: "2026-07-15T00:00:01Z".to_owned(),
            start_token: snapshot(reservation.run_nonce, SnapshotPhase::Start),
            finish_token: snapshot(reservation.run_nonce, SnapshotPhase::Finish),
            signed_by: "capture@example.test".to_owned(),
            signature_ssh: String::new(),
        };
        let material = capture.canonical_signed_material()?;
        capture.signature_ssh = crate::sshsig::sign_ed25519(
            &material,
            Zeroizing::new(CI_PRIVATE_KEY.to_vec()),
            CAPTURE_SIGNATURE_NAMESPACE,
        )?;
        let mut bytes = serde_json::to_vec(
            &serde_json::to_value(capture)
                .map_err(|error| format!("cannot construct CI capture: {error}"))?,
        )
        .map_err(|error| format!("cannot serialize CI capture: {error}"))?;
        bytes.push(b'\n');
        crate::capture_v3::verify_signed_capture_bytes(
            &bytes,
            std::str::from_utf8(CI_POLICY).map_err(|_| "CI capture policy is not UTF-8")?,
        )?;
        Ok(bytes)
    }

    #[cfg(feature = "ci-system-test")]
    fn inject_torn_marker(store: &ServiceStore) -> Result<(), String> {
        let reservation = ci_reservation(
            "torn_run_nonce_000000000000000000000",
            super::CaptureCase::Control,
            1,
        );
        create_file_exact(&store.root.join(reservation.slot_name()), b"")
    }

    #[cfg(feature = "ci-system-test")]
    fn delete_validated_file(path: &Path) -> Result<(), String> {
        let handle = open_existing(
            path,
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&handle, false, 0, POLICY_MAX_BYTES, FILE_SDDL)?;
        drop(handle);
        let wide = wide_null(path.as_os_str());
        // SAFETY: path is NUL-terminated and its parent is a validated SYSTEM-only directory.
        if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
            return Err(win32_error("DeleteFileW(CI cleanup)"));
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn remove_validated_directory(path: &Path, sddl: &str) -> Result<(), String> {
        let handle = open_existing(
            path,
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&handle, true, 0, 0, sddl)?;
        drop(handle);
        let wide = wide_null(path.as_os_str());
        // SAFETY: path is NUL-terminated and was validated immediately before removal.
        if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
            return Err(win32_error("RemoveDirectoryW(CI cleanup)"));
        }
        Ok(())
    }

    #[cfg(feature = "ci-system-test")]
    fn cleanup_ci_inner() -> Result<(), String> {
        let (control, company, root) = ci_paths()?;
        if !path_exists(&control) {
            if path_exists(&root) {
                return Err("CI ownership sentinel is absent; refusing cleanup".to_owned());
            }
            return Ok(());
        }
        let control_handle = open_existing(
            &control,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&control_handle, true, 0, 0, ROOT_SDDL)?;
        let company_created = company_was_created(&control)?;

        if path_exists(&root) {
            let root_handle = open_existing(
                &root,
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            validate_handle(&root_handle, true, 0, 0, ROOT_SDDL)?;
            let names = enumerate_directory(&root)?;
            if names.iter().any(|name| {
                !is_fixed_store_leaf(name) && !is_marker_name(name) && !is_completion_name(name)
            }) {
                return Err(
                    "CI broker root contains an unknown object; refusing cleanup".to_owned(),
                );
            }
            drop(root_handle);
            for name in names {
                delete_validated_file(&root.join(name))?;
            }
            remove_validated_directory(&root, ROOT_SDDL)?;
        }
        if company_created && path_exists(&company) {
            if !enumerate_directory(&company)?.is_empty() {
                return Err("CI company root is not empty; refusing cleanup".to_owned());
            }
            remove_validated_directory(&company, COMPANY_SDDL)?;
        }
        let control_names = enumerate_directory(&control)?;
        if control_names
            .iter()
            .any(|name| !matches!(name.as_str(), CI_SENTINEL | CI_PHASE_ONE | CI_PHASE_TWO))
        {
            return Err("CI control root contains an unknown object; refusing cleanup".to_owned());
        }
        drop(control_handle);
        for name in control_names {
            delete_validated_file(&control.join(name))?;
        }
        remove_validated_directory(&control, ROOT_SDDL)
    }

    #[cfg(feature = "ci-system-test")]
    pub(super) fn run_ci_system_test_phase() -> Result<super::CiPhase, String> {
        require_local_system()?;
        let (control, _, _) = ci_paths()?;
        if !path_exists(&control) {
            provision_ci_store()?;
        }
        company_was_created(&control)?;
        let phase_one = path_exists(&control.join(CI_PHASE_ONE));
        let phase_two = path_exists(&control.join(CI_PHASE_TWO));
        let reservation = ci_reservation(
            "valid_run_nonce_00000000000000000000",
            super::CaptureCase::Target,
            1,
        );

        if !phase_one {
            if phase_two {
                return Err("CI phase markers are out of order".to_owned());
            }
            let store = ServiceStore::open()?;
            store.load_authorization_policy()?;
            store.load_acceptance_policy()?;
            store.load_bound_capture_private_key("capture@example.test")?;
            store.reserve(&reservation)?;
            if store.reserve(&reservation).is_ok() {
                return Err("duplicate reservation unexpectedly succeeded".to_owned());
            }
            let capture = ci_signed_capture(&reservation)?;
            match store.complete(&reservation, &capture)? {
                CompletionStatus::Created(exact) if exact == capture => {}
                CompletionStatus::Created(_) => {
                    return Err("new completion returned changed capture bytes".to_owned());
                }
                CompletionStatus::AlreadyCompleted(_) => {
                    return Err("first completion was unexpectedly cached".to_owned());
                }
            }
            match store.complete(&reservation, &capture)? {
                CompletionStatus::AlreadyCompleted(exact) if exact == capture => {}
                CompletionStatus::AlreadyCompleted(_) => {
                    return Err("cached completion returned changed capture bytes".to_owned());
                }
                CompletionStatus::Created(_) => {
                    return Err(
                        "idempotent completion unexpectedly created a new record".to_owned()
                    );
                }
            }
            create_file_exact(&control.join(CI_PHASE_ONE), b"phase-one\n")?;
            return Ok(super::CiPhase::PhaseOne);
        }
        validate_exact_file(&control.join(CI_PHASE_ONE), b"phase-one\n")?;

        if !phase_two {
            let store = ServiceStore::open()?;
            let capture = ci_signed_capture(&reservation)?;
            if store.completed_capture(&reservation)?.as_deref() != Some(capture.as_slice()) {
                return Err("restart did not recover the exact completed capture".to_owned());
            }
            if store.reserve(&reservation).is_ok() {
                return Err("reservation unexpectedly succeeded after restart".to_owned());
            }
            inject_torn_marker(&store)?;
            match store.recover_reservations() {
                Err(error) if error.contains("torn after creation") => {}
                Err(error) => {
                    return Err(format!(
                        "in-process torn-marker recovery failed for wrong reason: {error}"
                    ));
                }
                Ok(()) => return Err("in-process recovery accepted a torn marker".to_owned()),
            }
            let duplicate_run = ci_reservation(
                "valid_run_nonce_00000000000000000000",
                super::CaptureCase::Control,
                2,
            );
            match store.reserve(&duplicate_run) {
                Err(error) if error.contains("run nonce has already been reserved") => {}
                Err(error) => {
                    return Err(format!(
                        "cross-slot run-nonce replay failed for wrong reason: {error}"
                    ));
                }
                Ok(()) => {
                    return Err("run nonce unexpectedly succeeded in a different slot".to_owned());
                }
            }
            create_file_exact(&control.join(CI_PHASE_TWO), b"phase-two\n")?;
            return Ok(super::CiPhase::PhaseTwo);
        }
        validate_exact_file(&control.join(CI_PHASE_TWO), b"phase-two\n")?;
        match ServiceStore::open() {
            Err(error) if error.contains("consumed/corrupt") => Ok(super::CiPhase::Complete),
            Err(error) => Err(format!(
                "torn-marker recovery failed for wrong reason: {error}"
            )),
            Ok(_) => Err("torn reservation was accepted after restart".to_owned()),
        }
    }

    #[cfg(feature = "ci-system-test")]
    pub(super) fn cleanup_ci_system_test() -> Result<(), String> {
        require_local_system()?;
        cleanup_ci_inner()
    }

    #[cfg(feature = "ci-system-test")]
    pub(super) fn set_ci_authorization_fixture(
        fixture: super::CiAuthorizationFixture,
    ) -> Result<(), String> {
        require_local_system()?;
        let store = ServiceStore::open()?;
        let lock = open_existing(
            &store.root.join("ledger.lock"),
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&lock, false, 0, 4096, FILE_SDDL)?;
        let policy = match fixture {
            super::CiAuthorizationFixture::Boundary => CI_AUTHORIZATION_POLICY,
            super::CiAuthorizationFixture::Capture => CI_CAPTURE_ALIAS_AUTHORIZATION_POLICY,
            super::CiAuthorizationFixture::Device => CI_DEVICE_ALIAS_AUTHORIZATION_POLICY,
        };
        let path = store.root.join("authorization.allowed_signers");
        delete_validated_file(&path)?;
        ci_create_authorization_leaf(&path, policy)?;
        store.load_authorization_policy().map(|_| ())
    }

    #[cfg(feature = "ci-system-test")]
    fn ci_create_authorization_leaf(path: &Path, policy: &[u8]) -> Result<(), String> {
        create_file_exact(path, policy)
    }

    fn win32_error(context: &str) -> String {
        // SAFETY: reads the calling thread's last-error value.
        format!("{context} failed with Win32 error {}", unsafe {
            GetLastError()
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn system_only_descriptors_are_exact_and_role_separated() {
            let file = descriptor_from_sddl(FILE_SDDL).unwrap();
            let root = descriptor_from_sddl(ROOT_SDDL).unwrap();
            compare_descriptors(file.0, file.0).unwrap();
            compare_descriptors(root.0, root.0).unwrap();
            assert!(compare_descriptors(file.0, root.0).is_err());
        }

        #[test]
        fn remote_and_device_roots_are_rejected_before_open() {
            assert!(validate_fixed_drive(Path::new(r"\\server\share\store")).is_err());
            assert!(validate_fixed_drive(Path::new(r"\\.\C:\store")).is_err());
        }
    }
}

#[cfg(all(windows, feature = "ci-system-test"))]
pub(crate) fn run_ci_system_test_phase() -> Result<CiPhase, String> {
    windows_store::run_ci_system_test_phase()
}

#[cfg(all(windows, feature = "ci-system-test"))]
pub(crate) fn cleanup_ci_system_test() -> Result<(), String> {
    windows_store::cleanup_ci_system_test()
}

#[cfg(all(windows, feature = "ci-system-test"))]
pub(crate) fn set_ci_authorization_fixture(fixture: CiAuthorizationFixture) -> Result<(), String> {
    windows_store::set_ci_authorization_fixture(fixture)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");

    fn reservation() -> Reservation<'static> {
        Reservation::new(
            "1f1d293f3d22a23e4af1b7834ff8ea250b71381b9ddf731e87affd54451976fb",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "grant_nonce_000000000000000000000",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "acceptance_nonce_0000000000000000",
            "hosted-local-system-store-e2e",
            CaptureCase::Target,
            2,
            "run_nonce_00000000000000000000000",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "canary-worker.example.test",
            "29617.1000.amd64fre.rs_prerelease.260701-1200",
            "machine-canonical-001",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "S-1-5-21-1-2-3-1001",
            1,
            "0000000000001001",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "capture@example.test",
        )
        .unwrap()
    }

    fn signed_capture(reservation: &Reservation<'_>) -> Vec<u8> {
        use crate::capture_v3::{
            CAPTURE_SCHEMA_VERSION, CAPTURE_SIGNATURE_NAMESPACE, CaptureTokenSnapshot,
            WindowsTokenCaptureV3,
        };
        use crate::{SnapshotPhase, derive_token_id};
        use zeroize::Zeroizing;

        fn snapshot(
            run_nonce: &str,
            phase: SnapshotPhase,
            session_id: u32,
        ) -> CaptureTokenSnapshot {
            let statistics_token_id = 7;
            CaptureTokenSnapshot {
                token_id: derive_token_id(run_nonce, phase, statistics_token_id),
                user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                integrity_rid: 0x2000,
                elevation_type: "default".to_owned(),
                elevated: false,
                admin_group: "absent".to_owned(),
                app_container: false,
                restricted_sid_count: 0,
                enabled_privileges: vec!["SeChangeNotifyPrivilege".to_owned()],
                token_source: "process-fallback-no-thread-token".to_owned(),
                statistics_token_id_before: statistics_token_id,
                statistics_token_id_after: statistics_token_id,
                modified_id_before: 9,
                modified_id_after: 9,
                lpac_supported: true,
                less_privileged_app_container: false,
                session_id,
                authentication_id: "0000000000001001".to_owned(),
            }
        }

        let mut capture = WindowsTokenCaptureV3 {
            schema_version: CAPTURE_SCHEMA_VERSION.to_owned(),
            campaign_sha256: reservation.campaign_sha256.to_owned(),
            scope_manifest_sha256: "3".repeat(64),
            execution_grant_sha256: "4".repeat(64),
            execution_grant_nonce: reservation.grant_nonce.to_owned(),
            worker_acceptance_sha256: "5".repeat(64),
            worker_acceptance_nonce: reservation.acceptance_nonce.to_owned(),
            campaign_id: reservation.campaign_id.to_owned(),
            worker: reservation.worker.to_owned(),
            build_lab_ex: "29617.1000.amd64fre.rs_prerelease.260701-1200".to_owned(),
            worker_machine_id: reservation.worker_machine_id.to_owned(),
            runner_executable_sha256: "6".repeat(64),
            witness_user_sid: reservation.witness_user_sid.to_owned(),
            witness_session_id: reservation.witness_session_id,
            witness_authentication_id: reservation.witness_authentication_id.to_owned(),
            witness_executable_sha256: reservation.witness_executable_sha256.to_owned(),
            operation_sha256: reservation.operation_sha256.to_owned(),
            case: reservation.case.as_str().to_owned(),
            trial: reservation.trial,
            run_nonce: reservation.run_nonce.to_owned(),
            capture_nonce: "capture_nonce_0000000000000000000".to_owned(),
            process_instance_id: "completion-test-process".to_owned(),
            thread_id_before: 10,
            thread_id_after: 10,
            started_at: "2026-07-15T00:00:00Z".to_owned(),
            completed_at: "2026-07-15T00:00:01Z".to_owned(),
            start_token: snapshot(
                reservation.run_nonce,
                SnapshotPhase::Start,
                reservation.witness_session_id,
            ),
            finish_token: snapshot(
                reservation.run_nonce,
                SnapshotPhase::Finish,
                reservation.witness_session_id,
            ),
            signed_by: "capture@example.test".to_owned(),
            signature_ssh: String::new(),
        };
        let material = capture.canonical_signed_material().unwrap();
        capture.signature_ssh = crate::sshsig::sign_ed25519(
            &material,
            Zeroizing::new(PRIVATE_KEY.to_vec()),
            CAPTURE_SIGNATURE_NAMESPACE,
        )
        .unwrap();
        let mut bytes = serde_json::to_vec(&serde_json::to_value(capture).unwrap()).unwrap();
        bytes.push(b'\n');
        crate::capture_v3::verify_signed_capture_bytes(&bytes, POLICY).unwrap();
        bytes
    }

    fn legacy_record() -> (LegacyReservationOwned, Vec<u8>) {
        let current = reservation();
        let reservation = LegacyReservationOwned {
            schema_version: LEGACY_RESERVATION_SCHEMA.to_owned(),
            campaign_sha256: current.campaign_sha256.to_owned(),
            grant_nonce: current.grant_nonce.to_owned(),
            acceptance_nonce: current.acceptance_nonce.to_owned(),
            case: current.case,
            trial: current.trial,
            run_nonce: current.run_nonce.to_owned(),
            operation_sha256: current.operation_sha256.to_owned(),
            worker: current.worker.to_owned(),
            worker_machine_id: current.worker_machine_id.to_owned(),
        };
        let payload = serde_json::to_vec(&serde_json::to_value(&reservation).unwrap()).unwrap();
        let value = serde_json::json!({
            "schema_version": LEGACY_RECORD_SCHEMA,
            "reservation": reservation,
            "reservation_sha256": format!("{:x}", Sha256::digest(payload)),
        });
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        (validate_legacy_record(&bytes).unwrap(), bytes)
    }

    #[test]
    fn reservation_names_are_domain_separated_and_path_safe() {
        let target = reservation();
        let control = Reservation::new(
            target.campaign_sha256,
            target.scope_manifest_sha256,
            target.execution_grant_sha256,
            target.grant_nonce,
            target.worker_acceptance_sha256,
            target.acceptance_nonce,
            target.campaign_id,
            CaptureCase::Control,
            target.trial,
            target.run_nonce,
            target.operation_sha256,
            target.worker,
            target.build_lab_ex,
            target.worker_machine_id,
            target.runner_executable_sha256,
            target.witness_user_sid,
            target.witness_session_id,
            target.witness_authentication_id,
            target.witness_executable_sha256,
            target.capture_signer,
        )
        .unwrap();
        assert_ne!(target.slot_name(), control.slot_name());
        assert_ne!(target.slot_name(), target.run_name());
        for name in [target.slot_name(), target.run_name()] {
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
            );
            assert!(!name.contains(target.run_nonce));
            assert!(!name.contains(target.grant_nonce));
        }
        assert!(is_completion_name(&target.completion_name()));
        assert!(!is_completion_name("completion-deadbeef.json"));
    }

    #[test]
    fn record_is_deterministic_bounded_and_self_hashing() {
        let first = reservation().record_bytes().unwrap();
        let second = reservation().record_bytes().unwrap();
        assert_eq!(first, second);
        assert!(first.len() < 4096);
        assert!(first.ends_with(b"\n"));
        let parsed: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let reservation_payload = serde_json::to_vec(&parsed["reservation"]).unwrap();
        assert_eq!(
            parsed["reservation_sha256"],
            format!("{:x}", Sha256::digest(reservation_payload))
        );
        validate_record(&first).unwrap();
        validate_record_for_name(&first, &reservation().slot_name()).unwrap();
        validate_record_for_name(&first, &reservation().run_name()).unwrap();
        assert!(validate_record_for_name(&first, "slot-deadbeef.reserved").is_err());
    }

    #[test]
    fn legacy_reservation_is_burn_only_and_preserves_run_nonce_identity() {
        let current = reservation();
        let (legacy, bytes) = legacy_record();
        assert!(validate_record(&bytes).is_err());
        validate_legacy_record_for_name(&bytes, &legacy_slot_name(&legacy)).unwrap();
        validate_legacy_record_for_name(&bytes, &legacy_run_name(&legacy)).unwrap();
        assert_eq!(legacy_run_name(&legacy), current.run_name());
        assert_eq!(legacy_slot_name(&legacy), current.legacy_slot_name());
        assert_ne!(legacy_slot_name(&legacy), current.slot_name());
    }

    #[test]
    fn completion_is_canonical_exactly_bound_and_recoverable() {
        let reservation = reservation();
        let capture = signed_capture(&reservation);
        let first = completion_record_bytes(&reservation, &capture).unwrap();
        let second = completion_record_bytes(&reservation, &capture).unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert!(first.len() <= COMPLETION_MAX_BYTES);

        let recovered = validate_completion_record(&first, &reservation.completion_name()).unwrap();
        assert_eq!(recovered.capture_bytes, capture);
        assert_eq!(
            recovered
                .reservation
                .validated()
                .unwrap()
                .record_bytes()
                .unwrap(),
            reservation.record_bytes().unwrap()
        );
        crate::capture_v3::verify_signed_capture_bytes(&recovered.capture_bytes, POLICY).unwrap();
    }

    #[test]
    fn reservation_completion_round_trip_preserves_session_zero() {
        let mut reservation = reservation();
        reservation.witness_session_id = 0;
        let capture = signed_capture(&reservation);
        let record = completion_record_bytes(&reservation, &capture).unwrap();
        let recovered =
            validate_completion_record(&record, &reservation.completion_name()).unwrap();
        assert_eq!(recovered.reservation.witness_session_id, 0);
        let recovered_capture =
            crate::capture_v3::verify_signed_capture_bytes(&recovered.capture_bytes, POLICY)
                .unwrap();
        assert_eq!(recovered_capture.witness_session_id, 0);
    }

    #[test]
    fn completion_rejects_torn_tampered_misnamed_unknown_and_duplicate_records() {
        let reservation = reservation();
        let record = completion_record_bytes(&reservation, &signed_capture(&reservation)).unwrap();
        assert!(
            validate_completion_record(&record[..record.len() - 1], &reservation.completion_name())
                .is_err()
        );
        assert!(
            validate_completion_record(
                &record,
                "completion-0000000000000000000000000000000000000000000000000000000000000000.json"
            )
            .is_err()
        );

        let mut tampered: serde_json::Value = serde_json::from_slice(&record).unwrap();
        tampered["capture_sha256"] = serde_json::Value::String("0".repeat(64));
        let mut tampered = serde_json::to_vec(&tampered).unwrap();
        tampered.push(b'\n');
        assert!(validate_completion_record(&tampered, &reservation.completion_name()).is_err());

        let mut unknown: serde_json::Value = serde_json::from_slice(&record).unwrap();
        unknown["unknown"] = serde_json::Value::Bool(true);
        let mut unknown = serde_json::to_vec(&unknown).unwrap();
        unknown.push(b'\n');
        assert!(validate_completion_record(&unknown, &reservation.completion_name()).is_err());

        let duplicate = format!(
            "{{\"schema_version\":\"{COMPLETION_SCHEMA}\",{}",
            std::str::from_utf8(&record)
                .unwrap()
                .trim_start_matches('{')
        );
        assert!(
            validate_completion_record(duplicate.as_bytes(), &reservation.completion_name())
                .is_err()
        );
    }

    #[test]
    fn recovery_rejects_torn_tampered_unknown_and_duplicate_records() {
        let record = reservation().record_bytes().unwrap();

        assert!(validate_record(&record[..record.len() - 1]).is_err());

        let mut tampered: serde_json::Value = serde_json::from_slice(&record).unwrap();
        tampered["reservation_sha256"] = serde_json::Value::String("0".repeat(64));
        let mut tampered = serde_json::to_vec(&tampered).unwrap();
        tampered.push(b'\n');
        assert!(validate_record(&tampered).is_err());

        let mut unknown: serde_json::Value = serde_json::from_slice(&record).unwrap();
        unknown["unknown"] = serde_json::Value::Bool(true);
        let mut unknown = serde_json::to_vec(&unknown).unwrap();
        unknown.push(b'\n');
        assert!(validate_record(&unknown).is_err());

        let duplicate = format!(
            "{{\"schema_version\":\"{RECORD_SCHEMA}\",{}",
            std::str::from_utf8(&record)
                .unwrap()
                .trim_start_matches('{')
        );
        assert!(validate_record(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn invalid_fields_and_nonce_collisions_fail_closed() {
        assert!(
            Reservation::new(
                "A".repeat(64).as_str(),
                "3".repeat(64).as_str(),
                "4".repeat(64).as_str(),
                "grant_nonce_000000000000000000000",
                "5".repeat(64).as_str(),
                "acceptance_nonce_0000000000000000",
                "campaign-1",
                CaptureCase::Target,
                1,
                "run_nonce_00000000000000000000000",
                "2".repeat(64).as_str(),
                "worker.example.test",
                "29617.1000.amd64fre.rs_prerelease.260701-1200",
                "machine-001",
                "6".repeat(64).as_str(),
                "S-1-5-21-1-2-3-1001",
                1,
                "0000000000001001",
                "7".repeat(64).as_str(),
                "capture@example.test",
            )
            .is_err()
        );
        assert!(
            Reservation::new(
                "1".repeat(64).as_str(),
                "3".repeat(64).as_str(),
                "4".repeat(64).as_str(),
                "same_nonce_0000000000000000000000",
                "5".repeat(64).as_str(),
                "acceptance_nonce_0000000000000000",
                "campaign-1",
                CaptureCase::Target,
                1,
                "same_nonce_0000000000000000000000",
                "2".repeat(64).as_str(),
                "worker.example.test",
                "29617.1000.amd64fre.rs_prerelease.260701-1200",
                "machine-001",
                "6".repeat(64).as_str(),
                "S-1-5-21-1-2-3-1001",
                1,
                "0000000000001001",
                "7".repeat(64).as_str(),
                "capture@example.test",
            )
            .is_err()
        );
    }
}
