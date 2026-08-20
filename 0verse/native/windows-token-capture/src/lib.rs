use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};

mod authority;
pub mod broker_protocol;
pub mod capture_v3;
mod device_open_authority;
pub(crate) mod device_open_protocol;
pub(crate) mod device_open_receipt;
mod device_open_store;
mod fixed_adapter;
mod fixed_adapter_ipc;
mod lpac_launch_profile;
mod service_store;
pub mod sshsig;
mod witness;

pub const SCHEMA_VERSION: &str = "0verse.windows-token-snapshot-pair-fixture/v1";
pub const OPERATION_ID: &str = "fixture.control.noop";
const SNAPSHOT_ID_DOMAIN: &[u8] = b"0verse-token-snapshot-id-v1\0";
const OPERATION_ID_DOMAIN: &[u8] = b"0verse-windows-operation-id-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotPhase {
    Start,
    Finish,
}

impl SnapshotPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Finish => "finish",
        }
    }
}

#[must_use]
pub fn derive_token_id(run_nonce: &str, phase: SnapshotPhase, statistics_token_id: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(SNAPSHOT_ID_DOMAIN);
    hash.update(run_nonce.as_bytes());
    hash.update(b"\0");
    hash.update(phase.as_str().as_bytes());
    hash.update(b"\0");
    hash.update(statistics_token_id.to_le_bytes());
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

#[must_use]
pub fn operation_sha256() -> String {
    let mut hash = Sha256::new();
    hash.update(OPERATION_ID_DOMAIN);
    hash.update(OPERATION_ID.as_bytes());
    format!("{:x}", hash.finalize())
}

/// Validate the bounded path-safe run-nonce wire format.
///
/// # Errors
///
/// Returns an error when the nonce has the wrong length or alphabet.
pub fn validate_run_nonce(value: &str) -> Result<(), &'static str> {
    if !(32..=128).contains(&value.len()) {
        return Err("run nonce must contain 32 to 128 ASCII characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("run nonce may contain only ASCII letters, digits, underscore, and hyphen");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Exact booleans are part of the Python wire contract.
pub struct TokenSnapshot {
    pub token_id: String,
    pub user_sid: String,
    pub integrity_rid: u32,
    pub elevation_type: &'static str,
    pub elevated: bool,
    pub admin_group: &'static str,
    pub app_container: bool,
    pub restricted_sid_count: u32,
    pub enabled_privileges: Vec<String>,
    pub token_source: &'static str,
    pub statistics_token_id_before: u64,
    pub statistics_token_id_after: u64,
    pub modified_id_before: u64,
    pub modified_id_after: u64,
    pub lpac_supported: bool,
    pub less_privileged_app_container: bool,
    pub session_id: u32,
    pub authentication_id: String,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Explicit safety flags must not collapse into one state.
pub struct SnapshotPairFixture {
    pub schema_version: &'static str,
    pub operation_id: &'static str,
    pub operation_sha256: String,
    pub run_nonce: String,
    pub capture_nonce: String,
    pub process_instance_id: String,
    pub recorded_at_unix_ms: u128,
    pub thread_id_before: u32,
    pub thread_id_after: u32,
    pub start_token: TokenSnapshot,
    pub finish_token: TokenSnapshot,
    pub claim_eligible: bool,
    pub fixture: bool,
    pub replay_protection: &'static str,
    pub weaponization: bool,
    pub auto_disclosure: bool,
}

#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_id_matches_python_reference_vector() {
        assert_eq!(
            derive_token_id(
                "per_run_nonce_00000000000000000001",
                SnapshotPhase::Start,
                0x0123_4567_89ab_cdef,
            ),
            "gKIIAtvLD0aQPeH50jftFhe9SgR6ubLeF9KFCTEo-bE"
        );
        assert_eq!(
            derive_token_id(
                "per_run_nonce_00000000000000000001",
                SnapshotPhase::Finish,
                0x0123_4567_89ab_cdef,
            ),
            "_zlR6AYfi4bXd33NtpuQ49HJMGPwD5lHOCydcSoi8EU"
        );
    }

    #[test]
    fn phases_are_domain_separated() {
        let start = derive_token_id("a2345678901234567890123456789012", SnapshotPhase::Start, 42);
        let finish = derive_token_id(
            "a2345678901234567890123456789012",
            SnapshotPhase::Finish,
            42,
        );
        assert_ne!(start, finish);
    }

    #[test]
    fn run_nonce_validation_is_exact() {
        assert!(validate_run_nonce("a2345678901234567890123456789012").is_ok());
        assert!(validate_run_nonce("short").is_err());
        assert!(validate_run_nonce("a234567890123456789012345678901!").is_err());
        assert!(validate_run_nonce(&"a".repeat(129)).is_err());
    }

    #[test]
    fn operation_digest_is_stable() {
        assert_eq!(
            operation_sha256(),
            "d69d69ed93546b781802eebb397fc47265cf133b67a9987364552f8a6cbd49e7"
        );
    }
}
