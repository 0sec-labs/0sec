#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "capabilities remain unreachable until service activation is atomic"
    )
)]

//! Capability types for a kernel-authenticated standard-user witness.
//!
//! Production constructors live only in the Windows rendezvous child module.
//! Plain strings can describe an expected identity, but they cannot mint the
//! token/image capabilities required to reach reservation or signing.

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

const PIPE_ID_DOMAIN: &[u8] = b"0verse-windows-token-witness-pipe-v1\0";
const CHILD_PIPE_ID_DOMAIN: &[u8] = b"0verse-windows-token-witness-child-pipe-v1\0";
const BOOTSTRAP_HELLO: &[u8] = &[0xa1];

pub(crate) const DANGEROUS_PRIVILEGES: [&str; 11] = [
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

const ALLOWED_STANDARD_USER_PRIVILEGES: [&str; 5] = [
    "SeChangeNotifyPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeShutdownPrivilege",
    "SeTimeZonePrivilege",
    "SeUndockPrivilege",
];

pub(crate) fn authentication_id_from_luid_parts(low_part: u32, high_part: i32) -> String {
    let value = (u64::from(high_part.cast_unsigned()) << 32) | u64::from(low_part);
    format!("{value:016x}")
}

pub(crate) fn protected_pipe_sddl(canonical_user_sid: &str) -> String {
    format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;{canonical_user_sid})")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedWitnessIdentity {
    user_sid: String,
    session_id: u32,
    authentication_id: String,
}

impl ExpectedWitnessIdentity {
    pub(crate) fn new(
        user_sid: &str,
        session_id: u32,
        authentication_id: &str,
    ) -> Result<Self, String> {
        crate::capture_v3::validate_witness_provenance(user_sid, session_id, authentication_id)?;
        Ok(Self {
            user_sid: user_sid.to_owned(),
            session_id,
            authentication_id: authentication_id.to_owned(),
        })
    }

    pub(crate) fn user_sid(&self) -> &str {
        &self.user_sid
    }

    pub(crate) const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub(crate) fn authentication_id(&self) -> &str {
        &self.authentication_id
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WitnessRendezvousSpec {
    pipe_name: String,
    binding_sha256: String,
    expected: ExpectedWitnessIdentity,
    expected_hello: Vec<u8>,
}

impl WitnessRendezvousSpec {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        campaign_sha256: &str,
        acceptance_sha256: &str,
        case: &str,
        trial: u32,
        run_nonce: &str,
        user_sid: &str,
        session_id: u32,
        authentication_id: &str,
    ) -> Result<Self, String> {
        for (value, label) in [
            (campaign_sha256, "campaign SHA-256"),
            (acceptance_sha256, "acceptance SHA-256"),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(format!("witness rendezvous {label} is invalid"));
            }
        }
        if !matches!(case, "target" | "control") || !(1..=32).contains(&trial) {
            return Err("witness rendezvous case/trial is invalid".to_owned());
        }
        crate::validate_run_nonce(run_nonce).map_err(str::to_owned)?;
        let expected = ExpectedWitnessIdentity::new(user_sid, session_id, authentication_id)?;
        let mut digest = Sha256::new();
        digest.update(PIPE_ID_DOMAIN);
        for value in [
            campaign_sha256,
            acceptance_sha256,
            case,
            run_nonce,
            expected.user_sid(),
            expected.authentication_id(),
        ] {
            digest.update(
                u64::try_from(value.len())
                    .expect("validated rendezvous field length fits u64")
                    .to_le_bytes(),
            );
            digest.update(value.as_bytes());
        }
        digest.update(trial.to_le_bytes());
        digest.update(expected.session_id().to_le_bytes());
        let binding_sha256 = format!("{:x}", digest.finalize());
        Ok(Self {
            pipe_name: format!(r"\\.\pipe\0verse.windows-token-witness.v1.{binding_sha256}"),
            binding_sha256,
            expected,
            expected_hello: BOOTSTRAP_HELLO.to_vec(),
        })
    }

    pub(crate) fn new_child(
        bootstrap_binding_sha256: &str,
        witness_executable_sha256: &str,
        launch_nonce: &str,
        expected: &ExpectedWitnessIdentity,
    ) -> Result<Self, String> {
        for (value, label) in [
            (bootstrap_binding_sha256, "bootstrap binding SHA-256"),
            (witness_executable_sha256, "witness executable SHA-256"),
            (launch_nonce, "launch nonce"),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(format!("trusted child {label} is invalid"));
            }
        }
        let mut digest = Sha256::new();
        digest.update(CHILD_PIPE_ID_DOMAIN);
        for value in [
            bootstrap_binding_sha256,
            witness_executable_sha256,
            launch_nonce,
            expected.user_sid(),
            expected.authentication_id(),
        ] {
            digest.update(
                u64::try_from(value.len())
                    .expect("validated child rendezvous field length fits u64")
                    .to_le_bytes(),
            );
            digest.update(value.as_bytes());
        }
        digest.update(expected.session_id().to_le_bytes());
        let binding_bytes: [u8; 32] = digest.finalize().into();
        let mut binding_sha256 = String::with_capacity(64);
        for byte in binding_bytes {
            write!(binding_sha256, "{byte:02x}").expect("writing to String cannot fail");
        }
        let mut expected_hello = Vec::with_capacity(34);
        expected_hello.extend([0xa2, 0x01]);
        expected_hello.extend(binding_bytes);
        Ok(Self {
            pipe_name: format!(r"\\.\pipe\0verse.windows-token-witness-child.v1.{binding_sha256}"),
            binding_sha256,
            expected: expected.clone(),
            expected_hello,
        })
    }

    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) const fn expected(&self) -> &ExpectedWitnessIdentity {
        &self.expected
    }

    pub(crate) fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    pub(crate) fn expected_hello(&self) -> &[u8] {
        &self.expected_hello
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct WitnessGroupFact {
    pub(crate) sid: String,
    pub(crate) attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct WitnessPrivilegeFact {
    pub(crate) name: String,
    pub(crate) attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct WitnessTokenProfile {
    pub(crate) user_sid: String,
    pub(crate) session_id: u32,
    pub(crate) authentication_id: String,
    pub(crate) token_type: &'static str,
    pub(crate) integrity_rid: u32,
    pub(crate) elevation_type: &'static str,
    pub(crate) elevated: bool,
    pub(crate) admin_group: &'static str,
    pub(crate) app_container: bool,
    pub(crate) token_restricted: bool,
    pub(crate) restricted_sid_count: u32,
    pub(crate) groups: Vec<WitnessGroupFact>,
    pub(crate) privileges: Vec<WitnessPrivilegeFact>,
    pub(crate) lpac_supported: bool,
    pub(crate) less_privileged_app_container: bool,
}

impl WitnessTokenProfile {
    #[allow(
        dead_code,
        reason = "used by the Windows-only fixed-adapter trusted child"
    )]
    pub(crate) fn sha256(&self) -> Result<String, String> {
        const DOMAIN: &[u8] = b"0verse-windows-witness-token-profile-v1\0";
        let encoded = serde_json::to_vec(self)
            .map_err(|error| format!("serialize witness token profile failed: {error}"))?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(encoded);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(crate) fn validate_primary_standard_user(
        &self,
        expected: &ExpectedWitnessIdentity,
    ) -> Result<(), String> {
        if self.user_sid != expected.user_sid
            || self.session_id != expected.session_id
            || self.authentication_id != expected.authentication_id
        {
            return Err("witness token identity differs from signed acceptance".to_owned());
        }
        if self.token_type != "primary"
            || self.integrity_rid != 0x2000
            || self.elevation_type != "default"
            || self.elevated
            || self.admin_group != "absent"
            || self.app_container
            || self.token_restricted
            || self.restricted_sid_count != 0
            || !self.lpac_supported
            || self.less_privileged_app_container
            || self.privileges.iter().any(|privilege| {
                DANGEROUS_PRIVILEGES.contains(&privilege.name.as_str())
                    || !ALLOWED_STANDARD_USER_PRIVILEGES.contains(&privilege.name.as_str())
            })
        {
            return Err("witness token is not a natural standard-user primary token".to_owned());
        }
        Ok(())
    }

    pub(crate) fn matches_pipe_duplicate_of_process_primary(&self, process: &Self) -> bool {
        const SE_PRIVILEGE_ENABLED: u32 = 0x2;

        let mut pipe_shape = self.clone();
        let pipe_privileges = std::mem::take(&mut pipe_shape.privileges);
        let mut process_shape = process.clone();
        let process_privileges = std::mem::take(&mut process_shape.privileges);
        if pipe_shape != process_shape {
            return false;
        }
        if !pipe_privileges
            .iter()
            .all(|privilege| process_privileges.contains(privilege))
        {
            return false;
        }
        process_privileges.iter().all(|privilege| {
            pipe_privileges.contains(privilege) || privilege.attributes & SE_PRIVILEGE_ENABLED == 0
        })
    }
}

#[cfg(windows)]
struct OwnedKernelHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            // SAFETY: the capability exclusively owns this successful kernel handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// A token whose complete profile matches the pipe opener's process-primary
/// token. It proves accepted logon identity, not executable/writer provenance;
/// the latter requires trusted process creation plus image pinning.
pub(crate) struct AuthenticatedWitnessToken {
    profile: WitnessTokenProfile,
    rendezvous_binding_sha256: String,
    #[cfg(windows)]
    primary_token: OwnedKernelHandle,
    #[cfg(windows)]
    bootstrap_process: OwnedKernelHandle,
}

impl AuthenticatedWitnessToken {
    #[allow(
        dead_code,
        reason = "used by the Windows-only fixed-adapter trusted child"
    )]
    pub(crate) fn profile(&self) -> &WitnessTokenProfile {
        &self.profile
    }

    pub(crate) fn user_sid(&self) -> &str {
        &self.profile.user_sid
    }

    pub(crate) const fn session_id(&self) -> u32 {
        self.profile.session_id
    }

    pub(crate) fn authentication_id(&self) -> &str {
        &self.profile.authentication_id
    }

    pub(crate) fn rendezvous_binding_sha256(&self) -> &str {
        &self.rendezvous_binding_sha256
    }

    #[cfg(test)]
    pub(crate) fn test_only(profile: WitnessTokenProfile, binding_sha256: &str) -> Self {
        Self {
            profile,
            rendezvous_binding_sha256: binding_sha256.to_owned(),
            #[cfg(windows)]
            primary_token: OwnedKernelHandle(std::ptr::null_mut()),
            #[cfg(windows)]
            bootstrap_process: OwnedKernelHandle(std::ptr::null_mut()),
        }
    }
}

/// Joint token/process/image capability. Its only Windows constructor is the
/// private trusted-child transition; no production authority-binding caller
/// exists until the hosted system test and SCM activation land.
pub(crate) struct PinnedAuthenticatedWitness {
    test_token: Option<AuthenticatedWitnessToken>,
    #[cfg(windows)]
    trusted_child: Option<child::TrustedChildCapability>,
    sha256: String,
    rendezvous_binding_sha256: String,
}

impl PinnedAuthenticatedWitness {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn rendezvous_binding_sha256(&self) -> &str {
        &self.rendezvous_binding_sha256
    }

    #[cfg(windows)]
    #[allow(
        dead_code,
        reason = "the authority bridge remains private until the signed producer E2E lands"
    )]
    pub(crate) fn hold_device_open(
        mut self,
        stop_event: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<child::BrokerHeldDeviceOpen, String> {
        self.trusted_child
            .take()
            .ok_or_else(|| "pinned witness lacks its exact child capability".to_owned())?
            .hold_device_open(stop_event)
    }

    #[cfg(test)]
    pub(crate) fn test_only_shape_is_valid(&self) -> bool {
        self.test_token.is_some() && self.rendezvous_binding_sha256.len() == 64 && {
            #[cfg(windows)]
            {
                self.trusted_child.is_none()
            }
            #[cfg(not(windows))]
            {
                true
            }
        }
    }
}

impl AuthenticatedWitnessToken {
    #[cfg(windows)]
    #[allow(
        dead_code,
        reason = "the transition remains unreachable until device-open publication lands"
    )]
    pub(crate) unsafe fn create_exact_child(
        self,
        source_image: &crate::windows::live_facts::PinnedExecutable,
        stop_event: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<PinnedAuthenticatedWitness, String> {
        // SAFETY: the caller owns the token and supplies a retained pinned
        // source-image capability; the child module performs all exact process,
        // token, image, and rendezvous checks before returning.
        unsafe {
            child::create_and_authenticate(
                self,
                std::path::Path::new(source_image.final_path()),
                source_image.sha256(),
                stop_event,
            )
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_pin(self, sha256: &str) -> PinnedAuthenticatedWitness {
        PinnedAuthenticatedWitness {
            rendezvous_binding_sha256: self.rendezvous_binding_sha256.clone(),
            test_token: Some(self),
            #[cfg(windows)]
            trusted_child: None,
            sha256: sha256.to_owned(),
        }
    }
}

#[cfg(windows)]
#[path = "windows/witness_rendezvous.rs"]
pub(crate) mod rendezvous;

#[cfg(windows)]
#[path = "windows/witness_child.rs"]
pub(crate) mod child;

#[cfg(all(windows, feature = "ci-system-test"))]
#[path = "windows/trusted_child_e2e.rs"]
pub(crate) mod ci;

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> ExpectedWitnessIdentity {
        ExpectedWitnessIdentity::new("S-1-5-21-1-2-3-1001", 0, "0000000000001001").unwrap()
    }

    fn profile() -> WitnessTokenProfile {
        WitnessTokenProfile {
            user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            session_id: 0,
            authentication_id: "0000000000001001".to_owned(),
            token_type: "primary",
            integrity_rid: 0x2000,
            elevation_type: "default",
            elevated: false,
            admin_group: "absent",
            app_container: false,
            token_restricted: false,
            restricted_sid_count: 0,
            groups: vec![WitnessGroupFact {
                sid: "S-1-1-0".to_owned(),
                attributes: 0x7,
            }],
            privileges: vec![WitnessPrivilegeFact {
                name: "SeChangeNotifyPrivilege".to_owned(),
                attributes: 0x3,
            }],
            lpac_supported: true,
            less_privileged_app_container: false,
        }
    }

    #[test]
    fn session_zero_standard_user_is_valid() {
        profile()
            .validate_primary_standard_user(&expected())
            .unwrap();
    }

    #[test]
    fn authentication_luid_format_preserves_signed_high_part_bits() {
        assert_eq!(
            authentication_id_from_luid_parts(0x89ab_cdef, 0x0123_4567),
            "0123456789abcdef"
        );
        assert_eq!(authentication_id_from_luid_parts(1, -1), "ffffffff00000001");
    }

    #[test]
    fn strict_profile_rejects_every_privileged_or_synthetic_axis() {
        let mut cases = Vec::new();
        let mut value = profile();
        value.token_type = "impersonation";
        cases.push(value);
        let mut value = profile();
        value.integrity_rid = 0x4000;
        cases.push(value);
        let mut value = profile();
        value.elevation_type = "limited";
        cases.push(value);
        let mut value = profile();
        value.elevated = true;
        cases.push(value);
        let mut value = profile();
        value.admin_group = "deny-only";
        cases.push(value);
        let mut value = profile();
        value.app_container = true;
        cases.push(value);
        let mut value = profile();
        value.token_restricted = true;
        cases.push(value);
        let mut value = profile();
        value.restricted_sid_count = 1;
        cases.push(value);
        let mut value = profile();
        value.lpac_supported = false;
        cases.push(value);
        let mut value = profile();
        value.less_privileged_app_container = true;
        cases.push(value);
        let mut value = profile();
        value.privileges = vec![WitnessPrivilegeFact {
            name: "SeImpersonatePrivilege".to_owned(),
            attributes: 0,
        }];
        cases.push(value);
        let mut value = profile();
        value.privileges = vec![WitnessPrivilegeFact {
            name: "SeUnexpectedCustomPrivilege".to_owned(),
            attributes: 0,
        }];
        cases.push(value);
        for invalid in cases {
            assert!(invalid.validate_primary_standard_user(&expected()).is_err());
        }
    }

    #[test]
    fn pipe_duplicate_may_only_omit_disabled_process_privileges() {
        let pipe = profile();
        let mut process = profile();
        process.privileges.push(WitnessPrivilegeFact {
            name: "SeIncreaseWorkingSetPrivilege".to_owned(),
            attributes: 0,
        });
        assert!(pipe.matches_pipe_duplicate_of_process_primary(&process));

        process.privileges[1].attributes = 0x2;
        assert!(!pipe.matches_pipe_duplicate_of_process_primary(&process));

        let mut wrong_pipe = pipe.clone();
        wrong_pipe.privileges.push(WitnessPrivilegeFact {
            name: "SeTimeZonePrivilege".to_owned(),
            attributes: 0,
        });
        assert!(!wrong_pipe.matches_pipe_duplicate_of_process_primary(&profile()));

        let mut wrong_identity = pipe.clone();
        wrong_identity.authentication_id = "0000000000002002".to_owned();
        assert!(!wrong_identity.matches_pipe_duplicate_of_process_primary(&pipe));
    }

    #[test]
    fn rendezvous_name_is_deterministic_domain_separated_and_path_safe() {
        let first = WitnessRendezvousSpec::new(
            &"a".repeat(64),
            &"b".repeat(64),
            "target",
            1,
            "run_nonce_00000000000000000000000",
            "S-1-5-21-1-2-3-1001",
            0,
            "0000000000001001",
        )
        .unwrap();
        let second = WitnessRendezvousSpec::new(
            &"a".repeat(64),
            &"b".repeat(64),
            "control",
            1,
            "run_nonce_00000000000000000000000",
            "S-1-5-21-1-2-3-1001",
            0,
            "0000000000001001",
        )
        .unwrap();
        let different_identity = WitnessRendezvousSpec::new(
            &"a".repeat(64),
            &"b".repeat(64),
            "target",
            1,
            "run_nonce_00000000000000000000000",
            "S-1-5-21-1-2-3-1001",
            1,
            "0000000000001001",
        )
        .unwrap();
        assert_eq!(first.pipe_name(), first.pipe_name());
        assert_ne!(first.pipe_name(), second.pipe_name());
        assert_ne!(first.pipe_name(), different_identity.pipe_name());
        assert_eq!(first.binding_sha256().len(), 64);
        assert_eq!(first.pipe_name().len(), 105);
        assert!(!first.pipe_name().contains("S-1-5"));
        assert!(!first.pipe_name().contains("run_nonce"));

        let child = WitnessRendezvousSpec::new_child(
            first.binding_sha256(),
            &"c".repeat(64),
            &"d".repeat(64),
            first.expected(),
        )
        .unwrap();
        assert!(
            child
                .pipe_name()
                .starts_with(r"\\.\pipe\0verse.windows-token-witness-child.v1.")
        );
        assert_ne!(child.binding_sha256(), first.binding_sha256());
        assert_eq!(child.expected_hello().len(), 34);
        assert_eq!(&child.expected_hello()[..2], &[0xa2, 0x01]);
    }

    #[test]
    fn witness_pipe_acl_is_system_plus_exact_user_only() {
        let sddl = protected_pipe_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(
            sddl,
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
        for forbidden in [";;;BA", ";;;BU", ";;;AU", ";;;WD"] {
            assert!(!sddl.contains(forbidden));
        }
    }
}
