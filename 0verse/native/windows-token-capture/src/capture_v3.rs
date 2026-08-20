#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "signing gate remains crate-private until broker activation is complete"
    )
)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{SnapshotPhase, derive_token_id};

pub const CAPTURE_SCHEMA_VERSION: &str = "0verse.windows-token-capture/v3";
pub const CAPTURE_SIGNATURE_NAMESPACE: &str = "0verse-windows-token-capture";
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_SECONDS: i64 = 60 * 60;
const MAX_EVIDENCE_AGE_SECONDS: i64 = 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const DANGEROUS_PRIVILEGES: [&str; 11] = [
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",
    "SeCreateTokenPrivilege",
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeLoadDriverPrivilege",
    "SeRelabelPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege",
];

/// Exact authority and live-host values against which one capture may be signed.
///
/// The fields are deliberately private. Broker activation should construct this
/// only from its private verified-authority capability and freshly sampled host
/// facts; capture data can never nominate its own expected values.
pub(crate) struct CaptureSigningAuthority<'a> {
    campaign_sha256: &'a str,
    scope_manifest_sha256: &'a str,
    execution_grant_sha256: &'a str,
    execution_grant_nonce: &'a str,
    worker_acceptance_sha256: &'a str,
    worker_acceptance_nonce: &'a str,
    campaign_id: &'a str,
    worker: &'a str,
    build_lab_ex: &'a str,
    worker_machine_id: &'a str,
    runner_executable_sha256: &'a str,
    witness_user_sid: &'a str,
    witness_session_id: u32,
    witness_authentication_id: &'a str,
    witness_executable_sha256: &'a str,
    operation_sha256: &'a str,
    case: &'a str,
    trial: u32,
    run_nonce: &'a str,
    capture_signer: &'a str,
    authority_issued_at_unix_seconds: i64,
    authority_expires_at_unix_seconds: i64,
    now_unix_seconds: i64,
}

impl<'a> CaptureSigningAuthority<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        _permit: &crate::authority::CaptureSigningPermit,
        campaign_sha256: &'a str,
        scope_manifest_sha256: &'a str,
        execution_grant_sha256: &'a str,
        execution_grant_nonce: &'a str,
        worker_acceptance_sha256: &'a str,
        worker_acceptance_nonce: &'a str,
        campaign_id: &'a str,
        worker: &'a str,
        build_lab_ex: &'a str,
        worker_machine_id: &'a str,
        runner_executable_sha256: &'a str,
        witness_user_sid: &'a str,
        witness_session_id: u32,
        witness_authentication_id: &'a str,
        witness_executable_sha256: &'a str,
        operation_sha256: &'a str,
        case: &'a str,
        trial: u32,
        run_nonce: &'a str,
        capture_signer: &'a str,
        authority_issued_at_unix_seconds: i64,
        authority_expires_at_unix_seconds: i64,
        now_unix_seconds: i64,
    ) -> Result<Self, String> {
        for (name, digest) in [
            ("campaign SHA-256", campaign_sha256),
            ("scope SHA-256", scope_manifest_sha256),
            ("grant SHA-256", execution_grant_sha256),
            ("acceptance SHA-256", worker_acceptance_sha256),
            ("runner SHA-256", runner_executable_sha256),
            ("witness executable SHA-256", witness_executable_sha256),
            ("operation SHA-256", operation_sha256),
        ] {
            if !is_lower_sha256(digest) {
                return Err(format!("signing authority {name} is invalid"));
            }
        }
        for (name, nonce) in [
            ("grant nonce", execution_grant_nonce),
            ("acceptance nonce", worker_acceptance_nonce),
            ("run nonce", run_nonce),
        ] {
            if !is_nonce(nonce) {
                return Err(format!("signing authority {name} is invalid"));
            }
        }
        if execution_grant_nonce == worker_acceptance_nonce
            || execution_grant_nonce == run_nonce
            || worker_acceptance_nonce == run_nonce
        {
            return Err("signing authority nonce domains collide".to_owned());
        }
        for (name, value) in [
            ("campaign_id", campaign_id),
            ("worker", worker),
            ("build_lab_ex", build_lab_ex),
            ("worker_machine_id", worker_machine_id),
            ("capture_signer", capture_signer),
        ] {
            validate_text(value, name, 256)?;
        }
        validate_witness_provenance(
            witness_user_sid,
            witness_session_id,
            witness_authentication_id,
        )?;
        if !matches!(case, "target" | "control") || !(1..=32).contains(&trial) {
            return Err("signing authority case or trial is invalid".to_owned());
        }
        if authority_issued_at_unix_seconds > now_unix_seconds
            || authority_expires_at_unix_seconds <= now_unix_seconds
            || authority_expires_at_unix_seconds <= authority_issued_at_unix_seconds
        {
            return Err("signing authority time window is not live".to_owned());
        }
        Ok(Self {
            campaign_sha256,
            scope_manifest_sha256,
            execution_grant_sha256,
            execution_grant_nonce,
            worker_acceptance_sha256,
            worker_acceptance_nonce,
            campaign_id,
            worker,
            build_lab_ex,
            worker_machine_id,
            runner_executable_sha256,
            witness_user_sid,
            witness_session_id,
            witness_authentication_id,
            witness_executable_sha256,
            operation_sha256,
            case,
            trial,
            run_nonce,
            capture_signer,
            authority_issued_at_unix_seconds,
            authority_expires_at_unix_seconds,
            now_unix_seconds,
        })
    }
}

pub(crate) struct SignedCaptureBytes {
    bytes: Vec<u8>,
    sha256: String,
}

impl SignedCaptureBytes {
    pub(crate) fn into_parts(self) -> (Vec<u8>, String) {
        (self.bytes, self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CaptureTokenSnapshot {
    pub token_id: String,
    pub user_sid: String,
    pub integrity_rid: u32,
    pub elevation_type: String,
    pub elevated: bool,
    pub admin_group: String,
    pub app_container: bool,
    pub restricted_sid_count: u32,
    pub enabled_privileges: Vec<String>,
    pub token_source: String,
    pub statistics_token_id_before: u64,
    pub statistics_token_id_after: u64,
    pub modified_id_before: u64,
    pub modified_id_after: u64,
    pub lpac_supported: bool,
    pub less_privileged_app_container: bool,
    pub session_id: u32,
    pub authentication_id: String,
}

impl CaptureTokenSnapshot {
    fn validate(&self, name: &str) -> Result<(), String> {
        if self.token_id.is_empty() || self.token_id.len() > 128 {
            return Err(format!("{name}.token_id is invalid"));
        }
        if self.statistics_token_id_before != self.statistics_token_id_after
            || self.modified_id_before != self.modified_id_after
        {
            return Err(format!("{name} changed while facts were captured"));
        }
        if !self.lpac_supported {
            return Err(format!("{name} lacks a fail-closed LPAC fact"));
        }
        if self.authentication_id.len() != 16
            || !self
                .authentication_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || u64::from_str_radix(&self.authentication_id, 16).unwrap_or(0) == 0
        {
            return Err(format!(
                "{name} session or authentication identity is invalid"
            ));
        }
        if !matches!(
            self.token_source.as_str(),
            "thread" | "process-fallback-no-thread-token"
        ) {
            return Err(format!("{name}.token_source is invalid"));
        }
        if !matches!(self.elevation_type.as_str(), "default" | "limited" | "full") {
            return Err(format!("{name}.elevation_type is invalid"));
        }
        if !matches!(
            self.admin_group.as_str(),
            "absent" | "deny-only" | "enabled"
        ) {
            return Err(format!("{name}.admin_group is invalid"));
        }
        if self.enabled_privileges.len() > 256
            || self
                .enabled_privileges
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(format!(
                "{name}.enabled_privileges must be bounded and sorted"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTokenCaptureV3 {
    pub schema_version: String,
    pub campaign_sha256: String,
    pub scope_manifest_sha256: String,
    pub execution_grant_sha256: String,
    pub execution_grant_nonce: String,
    pub worker_acceptance_sha256: String,
    pub worker_acceptance_nonce: String,
    pub campaign_id: String,
    pub worker: String,
    pub build_lab_ex: String,
    pub worker_machine_id: String,
    pub runner_executable_sha256: String,
    pub witness_user_sid: String,
    pub witness_session_id: u32,
    pub witness_authentication_id: String,
    pub witness_executable_sha256: String,
    pub operation_sha256: String,
    pub case: String,
    pub trial: u32,
    pub run_nonce: String,
    pub capture_nonce: String,
    pub process_instance_id: String,
    pub thread_id_before: u32,
    pub thread_id_after: u32,
    pub started_at: String,
    pub completed_at: String,
    pub start_token: CaptureTokenSnapshot,
    pub finish_token: CaptureTokenSnapshot,
    pub signed_by: String,
    pub signature_ssh: String,
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_nonce(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn validate_witness_provenance(
    user_sid: &str,
    _session_id: u32,
    authentication_id: &str,
) -> Result<(), String> {
    let parts = user_sid.split('-').collect::<Vec<_>>();
    if parts.len() != 8 || parts[..4] != ["S", "1", "5", "21"] {
        return Err("witness user SID is not a canonical account SID".to_owned());
    }
    let mut subauthorities = Vec::with_capacity(4);
    for part in &parts[4..] {
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err("witness user SID is not a canonical account SID".to_owned());
        }
        subauthorities.push(
            part.parse::<u32>()
                .map_err(|_| "witness user SID is not a canonical account SID".to_owned())?,
        );
    }
    if subauthorities.last().copied().unwrap_or(0) < 1000 {
        return Err("witness user SID names a built-in account".to_owned());
    }
    if authentication_id.len() != 16
        || !authentication_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || u64::from_str_radix(authentication_id, 16).unwrap_or(0) <= 0x3e7
    {
        return Err("witness session or authentication identity is invalid".to_owned());
    }
    Ok(())
}

fn validate_text(value: &str, name: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character < ' ' || character == '\u{7f}')
    {
        return Err(format!(
            "capture {name} is empty, oversized, untrimmed, or unsafe"
        ));
    }
    Ok(())
}

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn decimal(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_i64, |value, byte| {
        value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))
    })
}

fn exact_utc_seconds(value: &str, name: &str) -> Result<i64, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(format!("capture {name} must be exact UTC RFC3339 seconds"));
    }
    let year = decimal(&bytes[0..4]).ok_or_else(|| format!("capture {name} year is invalid"))?;
    let month = decimal(&bytes[5..7]).ok_or_else(|| format!("capture {name} month is invalid"))?;
    let day = decimal(&bytes[8..10]).ok_or_else(|| format!("capture {name} day is invalid"))?;
    let hour = decimal(&bytes[11..13]).ok_or_else(|| format!("capture {name} hour is invalid"))?;
    let minute =
        decimal(&bytes[14..16]).ok_or_else(|| format!("capture {name} minute is invalid"))?;
    let second =
        decimal(&bytes[17..19]).ok_or_else(|| format!("capture {name} second is invalid"))?;
    let month_days = [
        31,
        if leap(year) { 29 } else { 28 },
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
        return Err(format!("capture {name} timestamp fields are invalid"));
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

fn validate_consumer_safe(capture: &WindowsTokenCaptureV3) -> Result<(i64, i64), String> {
    capture.validate_structure()?;
    for (name, value) in [
        ("campaign_id", capture.campaign_id.as_str()),
        ("worker", capture.worker.as_str()),
        ("build_lab_ex", capture.build_lab_ex.as_str()),
        ("worker_machine_id", capture.worker_machine_id.as_str()),
        ("signed_by", capture.signed_by.as_str()),
    ] {
        validate_text(value, name, 256)?;
    }
    let process = capture.process_instance_id.as_bytes();
    if !(16..=128).contains(&process.len())
        || !process
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("capture process_instance_id is invalid".to_owned());
    }
    for (name, snapshot, phase) in [
        ("start_token", &capture.start_token, SnapshotPhase::Start),
        ("finish_token", &capture.finish_token, SnapshotPhase::Finish),
    ] {
        if snapshot.token_id
            != derive_token_id(
                &capture.run_nonce,
                phase,
                snapshot.statistics_token_id_before,
            )
        {
            return Err(format!("{name}.token_id is not phase/LUID-bound"));
        }
        validate_text(&snapshot.user_sid, &format!("{name}.user_sid"), 256)?;
        if snapshot.less_privileged_app_container {
            return Err(format!("{name} is LPAC and is not authorized"));
        }
        for privilege in &snapshot.enabled_privileges {
            validate_text(privilege, &format!("{name}.enabled_privileges"), 256)?;
        }
    }
    if capture.start_token.user_sid != capture.witness_user_sid
        || capture.start_token.session_id != capture.witness_session_id
        || capture.start_token.authentication_id != capture.witness_authentication_id
        || capture.finish_token.session_id != capture.witness_session_id
    {
        return Err("capture snapshots are not bound to the witness logon session".to_owned());
    }
    let start = &capture.start_token;
    if start.integrity_rid != 0x2000
        || start.elevation_type != "default"
        || start.elevated
        || start.admin_group != "absent"
        || start.app_container
        || start.restricted_sid_count != 0
        || start.token_source != "process-fallback-no-thread-token"
        || start
            .enabled_privileges
            .iter()
            .any(|privilege| DANGEROUS_PRIVILEGES.contains(&privilege.as_str()))
    {
        return Err("capture start token is not a natural standard-user primary token".to_owned());
    }
    let started = exact_utc_seconds(&capture.started_at, "started_at")?;
    let completed = exact_utc_seconds(&capture.completed_at, "completed_at")?;
    if completed < started || completed - started > MAX_CAPTURE_SECONDS {
        return Err("capture timestamps are reversed or exceed one hour".to_owned());
    }
    Ok((started, completed))
}

impl WindowsTokenCaptureV3 {
    /// Validate exact structural invariants which do not require live authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid schema, digest, nonce, case, thread, or
    /// unstable token snapshot. Authority and signature checks belong to A2.
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err("unsupported capture schema".to_owned());
        }
        for (name, digest) in [
            ("campaign_sha256", &self.campaign_sha256),
            ("scope_manifest_sha256", &self.scope_manifest_sha256),
            ("execution_grant_sha256", &self.execution_grant_sha256),
            ("worker_acceptance_sha256", &self.worker_acceptance_sha256),
            ("runner_executable_sha256", &self.runner_executable_sha256),
            ("witness_executable_sha256", &self.witness_executable_sha256),
            ("operation_sha256", &self.operation_sha256),
        ] {
            if !is_lower_sha256(digest) {
                return Err(format!("{name} must be a lowercase SHA-256"));
            }
        }
        let nonces = [
            &self.execution_grant_nonce,
            &self.worker_acceptance_nonce,
            &self.run_nonce,
            &self.capture_nonce,
        ];
        if nonces.iter().any(|nonce| !is_nonce(nonce)) {
            return Err("capture nonce is invalid".to_owned());
        }
        for left in 0..nonces.len() {
            if nonces[left + 1..].contains(&nonces[left]) {
                return Err("capture nonce domains must be distinct".to_owned());
            }
        }
        if !matches!(self.case.as_str(), "target" | "control") || !(1..=32).contains(&self.trial) {
            return Err("capture case or trial is invalid".to_owned());
        }
        validate_witness_provenance(
            &self.witness_user_sid,
            self.witness_session_id,
            &self.witness_authentication_id,
        )?;
        if self.thread_id_before == 0 || self.thread_id_before != self.thread_id_after {
            return Err("capture must remain on one valid OS thread".to_owned());
        }
        if self.start_token.token_id == self.finish_token.token_id {
            return Err("phase-scoped token identities must differ".to_owned());
        }
        self.start_token.validate("start_token")?;
        self.finish_token.validate("finish_token")?;
        Ok(())
    }

    /// Return Python-compatible canonical material with only `signature_ssh` removed.
    ///
    /// This A1 helper establishes byte compatibility only. It is not an A2
    /// signing gate: live timestamp, bounded-text, process identity, token-ID,
    /// authority, host, and runner checks must be added before any signature is
    /// produced.
    ///
    /// # Errors
    ///
    /// Returns an error if structural validation or JSON serialization fails.
    pub fn canonical_signed_material(&self) -> Result<Vec<u8>, String> {
        self.validate_structure()?;
        let mut value = serde_json::to_value(self)
            .map_err(|error| format!("cannot construct capture signing material: {error}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "capture signing material is not an object".to_owned())?;
        object.remove("signature_ssh");
        serde_json::to_vec(&Value::Object(object.clone()))
            .map_err(|error| format!("cannot serialize capture signing material: {error}"))
    }
}

fn canonical_final_bytes(capture: &WindowsTokenCaptureV3) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(capture)
        .map_err(|error| format!("cannot construct final capture JSON: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot serialize final capture JSON: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err("final capture JSON exceeds its bound".to_owned());
    }
    Ok(bytes)
}

/// Parse and cryptographically verify one exact durable capture representation.
///
/// This recovery gate intentionally does not need live authority. It proves the
/// bytes are canonical, consumer-safe, self-consistent, and signed by the exact
/// identity named in the record under the supplied service-owned policy.
pub(crate) fn verify_signed_capture_bytes(
    bytes: &[u8],
    allowed_signers: &str,
) -> Result<WindowsTokenCaptureV3, String> {
    if bytes.len() > MAX_CAPTURE_BYTES || bytes.len() < 2 || !bytes.ends_with(b"\n") {
        return Err("signed capture is oversized or has no final LF".to_owned());
    }
    let value = crate::broker_protocol::parse_strict_json_object(
        &bytes[..bytes.len() - 1],
        "signed capture",
    )?;
    let capture: WindowsTokenCaptureV3 = serde_json::from_value(value)
        .map_err(|error| format!("signed capture schema is invalid: {error}"))?;
    if capture.signature_ssh.is_empty() {
        return Err("signed capture has no SSHSIG".to_owned());
    }
    validate_consumer_safe(&capture)?;
    let material = capture.canonical_signed_material()?;
    crate::sshsig::verify_ed25519(
        &material,
        &capture.signature_ssh,
        &capture.signed_by,
        CAPTURE_SIGNATURE_NAMESPACE,
        allowed_signers,
    )?;
    if canonical_final_bytes(&capture)? != bytes {
        return Err("signed capture JSON is not byte-canonical".to_owned());
    }
    Ok(capture)
}

/// Validate all authority/live bindings, sign, and verify one durable capture.
///
/// The signing key is consumed in a zeroizing allocation. No bytes are returned
/// until the final record has passed the same canonical recovery gate used by
/// the service store.
pub(crate) fn sign_capture(
    mut capture: WindowsTokenCaptureV3,
    authority: &CaptureSigningAuthority<'_>,
    private_key: Zeroizing<Vec<u8>>,
    capture_allowed_signers: &str,
) -> Result<SignedCaptureBytes, String> {
    if !capture.signature_ssh.is_empty() {
        return Err("capture must be unsigned on entry to the signing gate".to_owned());
    }
    let (started, completed) = validate_consumer_safe(&capture)?;
    if capture.campaign_sha256 != authority.campaign_sha256
        || capture.scope_manifest_sha256 != authority.scope_manifest_sha256
        || capture.execution_grant_sha256 != authority.execution_grant_sha256
        || capture.execution_grant_nonce != authority.execution_grant_nonce
        || capture.worker_acceptance_sha256 != authority.worker_acceptance_sha256
        || capture.worker_acceptance_nonce != authority.worker_acceptance_nonce
        || capture.campaign_id != authority.campaign_id
        || capture.worker != authority.worker
        || capture.build_lab_ex != authority.build_lab_ex
        || capture.worker_machine_id != authority.worker_machine_id
        || capture.runner_executable_sha256 != authority.runner_executable_sha256
        || capture.witness_user_sid != authority.witness_user_sid
        || capture.witness_session_id != authority.witness_session_id
        || capture.witness_authentication_id != authority.witness_authentication_id
        || capture.witness_executable_sha256 != authority.witness_executable_sha256
        || capture.operation_sha256 != authority.operation_sha256
        || capture.case != authority.case
        || capture.trial != authority.trial
        || capture.run_nonce != authority.run_nonce
        || capture.signed_by != authority.capture_signer
    {
        return Err("capture is not exactly authority/live-bound".to_owned());
    }
    if started < authority.authority_issued_at_unix_seconds
        || completed > authority.authority_expires_at_unix_seconds
    {
        return Err("capture is outside its authority window".to_owned());
    }
    if completed > authority.now_unix_seconds + CLOCK_SKEW_SECONDS
        || authority.now_unix_seconds - completed > MAX_EVIDENCE_AGE_SECONDS
    {
        return Err("capture is outside the live evidence window".to_owned());
    }
    let material = capture.canonical_signed_material()?;
    capture.signature_ssh =
        crate::sshsig::sign_ed25519(&material, private_key, CAPTURE_SIGNATURE_NAMESPACE)?;
    let bytes = canonical_final_bytes(&capture)?;
    let recovered = verify_signed_capture_bytes(&bytes, capture_allowed_signers)?;
    if recovered != capture {
        return Err("signed capture changed during final verification".to_owned());
    }
    Ok(SignedCaptureBytes {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");

    fn snapshot(token_id: &str) -> CaptureTokenSnapshot {
        CaptureTokenSnapshot {
            token_id: token_id.to_owned(),
            user_sid: "S-1-5-21-1".to_owned(),
            integrity_rid: 0x2000,
            elevation_type: "default".to_owned(),
            elevated: false,
            admin_group: "absent".to_owned(),
            app_container: false,
            restricted_sid_count: 0,
            enabled_privileges: vec!["SeChangeNotifyPrivilege".to_owned()],
            token_source: "process-fallback-no-thread-token".to_owned(),
            statistics_token_id_before: 7,
            statistics_token_id_after: 7,
            modified_id_before: 9,
            modified_id_after: 9,
            lpac_supported: true,
            less_privileged_app_container: false,
            session_id: 1,
            authentication_id: "0000000000001001".to_owned(),
        }
    }

    fn capture() -> WindowsTokenCaptureV3 {
        WindowsTokenCaptureV3 {
            schema_version: CAPTURE_SCHEMA_VERSION.to_owned(),
            campaign_sha256: "a".repeat(64),
            scope_manifest_sha256: "b".repeat(64),
            execution_grant_sha256: "c".repeat(64),
            execution_grant_nonce: "grant_nonce_000000000000000000000".to_owned(),
            worker_acceptance_sha256: "d".repeat(64),
            worker_acceptance_nonce: "acceptance_nonce_0000000000000000".to_owned(),
            campaign_id: "campaign-1".to_owned(),
            worker: "worker.example".to_owned(),
            build_lab_ex: "build".to_owned(),
            worker_machine_id: "machine".to_owned(),
            runner_executable_sha256: "e".repeat(64),
            witness_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            witness_session_id: 1,
            witness_authentication_id: "0000000000001001".to_owned(),
            witness_executable_sha256: "7".repeat(64),
            operation_sha256: "f".repeat(64),
            case: "control".to_owned(),
            trial: 1,
            run_nonce: "run_nonce_00000000000000000000000".to_owned(),
            capture_nonce: "capture_nonce_0000000000000000000".to_owned(),
            process_instance_id: "process-instance-1".to_owned(),
            thread_id_before: 10,
            thread_id_after: 10,
            started_at: "2026-07-15T00:00:00Z".to_owned(),
            completed_at: "2026-07-15T00:00:01Z".to_owned(),
            start_token: snapshot("start-token"),
            finish_token: snapshot("finish-token"),
            signed_by: "capture@example.test".to_owned(),
            signature_ssh: String::new(),
        }
    }

    fn signable_capture() -> WindowsTokenCaptureV3 {
        let mut value = capture();
        value.campaign_id = "canonical-campaign".to_owned();
        value.worker = "canary-worker.example.test".to_owned();
        value.build_lab_ex = "29617.1000.amd64fre.rs_prerelease.260701-1200".to_owned();
        value.worker_machine_id = "canonical-machine-id".to_owned();
        value.process_instance_id = "canonical-process-instance".to_owned();
        value
            .start_token
            .user_sid
            .clone_from(&value.witness_user_sid);
        value
            .finish_token
            .user_sid
            .clone_from(&value.witness_user_sid);
        value.start_token.token_id = derive_token_id(
            &value.run_nonce,
            SnapshotPhase::Start,
            value.start_token.statistics_token_id_before,
        );
        value.finish_token.token_id = derive_token_id(
            &value.run_nonce,
            SnapshotPhase::Finish,
            value.finish_token.statistics_token_id_before,
        );
        value
    }

    fn authority(capture: &WindowsTokenCaptureV3) -> CaptureSigningAuthority<'_> {
        let permit = crate::authority::WitnessBoundAuthority::test_only_signing_permit();
        CaptureSigningAuthority::new(
            &permit,
            &capture.campaign_sha256,
            &capture.scope_manifest_sha256,
            &capture.execution_grant_sha256,
            &capture.execution_grant_nonce,
            &capture.worker_acceptance_sha256,
            &capture.worker_acceptance_nonce,
            &capture.campaign_id,
            &capture.worker,
            &capture.build_lab_ex,
            &capture.worker_machine_id,
            &capture.runner_executable_sha256,
            &capture.witness_user_sid,
            capture.witness_session_id,
            &capture.witness_authentication_id,
            &capture.witness_executable_sha256,
            &capture.operation_sha256,
            &capture.case,
            capture.trial,
            &capture.run_nonce,
            &capture.signed_by,
            exact_utc_seconds("2026-07-14T23:30:00Z", "issued").unwrap(),
            exact_utc_seconds("2026-07-15T00:30:00Z", "expires").unwrap(),
            exact_utc_seconds("2026-07-15T00:00:02Z", "now").unwrap(),
        )
        .unwrap()
    }

    fn sign(value: WindowsTokenCaptureV3) -> Result<SignedCaptureBytes, String> {
        let expected = value.clone();
        sign_capture(
            value,
            &authority(&expected),
            Zeroizing::new(PRIVATE_KEY.to_vec()),
            POLICY,
        )
    }

    #[test]
    fn canonical_material_is_sorted_compact_utf8_and_unsigned() {
        let material = capture().canonical_signed_material().unwrap();
        let text = String::from_utf8(material).unwrap();
        assert!(text.starts_with("{\"build_lab_ex\":"));
        assert!(!text.contains("signature_ssh"));
        assert!(!text.contains(' '));
        assert!(text.contains("SeChangeNotifyPrivilege"));
    }

    #[test]
    fn canonical_material_matches_python_golden_hash() {
        let raw = include_str!("../../../tests/fixtures/windows-token-capture-v3-canonical.json");
        let capture: WindowsTokenCaptureV3 = serde_json::from_str(raw).unwrap();
        let material = capture.canonical_signed_material().unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(material)),
            "e07af9d8777cc5f4a2707dcd0c5a47fc73cfcca264dfbbf3ccb5771dbf58323e"
        );
    }

    #[test]
    fn exact_deserialization_rejects_unknown_and_duplicate_fields() {
        let raw = serde_json::to_string(&capture()).unwrap();
        let unknown = raw.replacen('{', "{\"payload\":\"forbidden\",", 1);
        assert!(serde_json::from_str::<WindowsTokenCaptureV3>(&unknown).is_err());
        let duplicate = raw.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"duplicate\",\"schema_version\":",
            1,
        );
        assert!(serde_json::from_str::<WindowsTokenCaptureV3>(&duplicate).is_err());
    }

    #[test]
    fn unstable_token_and_nonce_reuse_fail_closed() {
        let mut value = capture();
        value.finish_token.modified_id_after += 1;
        assert!(value.validate_structure().is_err());
        let mut value = capture();
        value.capture_nonce.clone_from(&value.run_nonce);
        assert!(value.validate_structure().is_err());
    }

    #[test]
    fn full_gate_signs_deterministic_canonical_recoverable_bytes() {
        let first = sign(signable_capture()).unwrap().into_parts();
        let second = sign(signable_capture()).unwrap().into_parts();
        assert_eq!(first, second);
        assert!(first.0.ends_with(b"\n"));
        assert_eq!(first.1, format!("{:x}", Sha256::digest(&first.0)));
        let recovered = verify_signed_capture_bytes(&first.0, POLICY).unwrap();
        assert_eq!(recovered.campaign_id, "canonical-campaign");
        assert!(!recovered.signature_ssh.is_empty());
    }

    #[test]
    fn full_gate_signs_and_recovers_bound_session_zero() {
        let mut value = signable_capture();
        value.witness_session_id = 0;
        value.start_token.session_id = 0;
        value.finish_token.session_id = 0;
        let signed = sign(value).unwrap().into_parts().0;
        let recovered = verify_signed_capture_bytes(&signed, POLICY).unwrap();
        assert_eq!(recovered.witness_session_id, 0);
        assert_eq!(recovered.start_token.session_id, 0);
        assert_eq!(recovered.finish_token.session_id, 0);
    }

    #[test]
    fn signing_gate_rejects_binding_token_time_and_lpac_drift() {
        let mut binding = signable_capture();
        let expected = binding.clone();
        binding.worker = "other-worker.example.test".to_owned();
        assert!(
            sign_capture(
                binding,
                &authority(&expected),
                Zeroizing::new(PRIVATE_KEY.to_vec()),
                POLICY,
            )
            .is_err()
        );

        let mut token = signable_capture();
        token.start_token.token_id = "forged-token-identity".to_owned();
        assert!(sign(token).is_err());

        let mut reversed = signable_capture();
        reversed.completed_at = "2026-07-14T23:59:59Z".to_owned();
        assert!(sign(reversed).is_err());

        let mut noncanonical = signable_capture();
        noncanonical.started_at = "2026-07-15T00:00:00+00:00".to_owned();
        assert!(sign(noncanonical).is_err());

        let mut lpac = signable_capture();
        lpac.finish_token.less_privileged_app_container = true;
        assert!(sign(lpac).is_err());

        let expected = signable_capture();
        let mut witness_drift = expected.clone();
        witness_drift.witness_session_id = 2;
        witness_drift.start_token.session_id = 2;
        witness_drift.finish_token.session_id = 2;
        assert!(
            sign_capture(
                witness_drift,
                &authority(&expected),
                Zeroizing::new(PRIVATE_KEY.to_vec()),
                POLICY,
            )
            .is_err()
        );

        let mut snapshot_drift = signable_capture();
        snapshot_drift.start_token.authentication_id = "0000000000001002".to_owned();
        assert!(sign(snapshot_drift).is_err());

        let mut high_integrity = signable_capture();
        high_integrity.start_token.integrity_rid = 0x4000;
        let mut filtered_admin = signable_capture();
        filtered_admin.start_token.elevation_type = "limited".to_owned();
        filtered_admin.start_token.admin_group = "deny-only".to_owned();
        let mut elevated = signable_capture();
        elevated.start_token.elevated = true;
        let mut app_container = signable_capture();
        app_container.start_token.app_container = true;
        let mut restricted = signable_capture();
        restricted.start_token.restricted_sid_count = 1;
        let mut dangerous = signable_capture();
        dangerous.start_token.enabled_privileges = vec!["SeDebugPrivilege".to_owned()];
        let mut impersonating = signable_capture();
        impersonating.start_token.token_source = "thread".to_owned();
        for invalid_start in [
            high_integrity,
            filtered_admin,
            elevated,
            app_container,
            restricted,
            dangerous,
            impersonating,
        ] {
            assert!(sign(invalid_start).is_err());
        }
    }

    #[test]
    fn recovery_rejects_noncanonical_tampered_and_unsigned_records() {
        let (bytes, _) = sign(signable_capture()).unwrap().into_parts();
        let mut spaced = bytes.clone();
        spaced.insert(1, b' ');
        assert!(verify_signed_capture_bytes(&spaced, POLICY).is_err());

        let mut tampered = bytes;
        let location = tampered
            .windows(b"canonical-campaign".len())
            .position(|window| window == b"canonical-campaign")
            .unwrap();
        tampered[location] = b'X';
        assert!(verify_signed_capture_bytes(&tampered, POLICY).is_err());

        let unsigned = canonical_final_bytes(&signable_capture()).unwrap();
        assert!(verify_signed_capture_bytes(&unsigned, POLICY).is_err());
    }
}
