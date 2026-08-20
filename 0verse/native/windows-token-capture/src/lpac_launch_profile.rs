#![allow(
    dead_code,
    reason = "production registry is intentionally empty until activation is separately reviewed"
)]

//! Inert compile-time LPAC profile selection.
//!
//! This module has no path, argv, environment, handle, Win32, service, or
//! execution surface. Selection consumes verified authority, but production
//! has no selectable entry and no activation-permit constructor.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::authority::LpacVerifiedAuthority;

const PROFILE_SCHEMA: &str = "0verse.windows-lpac-fixed-launch-profile/v1";
const PROFILE_DOMAIN: &[u8] = b"0verse-windows-lpac-fixed-launch-profile-v1\0";
const MAX_CAPABILITIES: usize = 32;
const MAX_OPERATIONS: usize = 16;
const SYNTHETIC_CREATION_FLAGS: u32 = 0x0008_0404;
#[cfg(test)]
const SYNTHETIC_TEST_PROFILE_SHA256: &str =
    "bae303927b8e51d17c2646f7f2559e1b6de284112325e5aacb7a8feff639eea6";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AdapterRelationshipKind {
    DirectSameImage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FixedAdapterId {
    SyntheticNonBountyFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BaseTokenPolicy {
    VerifiedNaturalStandardUserPrimary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JobPolicy {
    KillOnCloseSingleActiveProcess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CapabilityPolicy {
    ExactNamedCapabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApplicationResolutionPolicy {
    AbsolutePinnedHandleNoReparse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PackageProfileLookupPolicy {
    ExistingProfileDeriveSidAndExactMatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ChildProcessPolicy {
    DenyAllChildren,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum HandleInheritancePolicy {
    Deny,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InitialThreadPolicy {
    CreateSuspended,
    CreateRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AllApplicationPackagesPolicy {
    OptOut,
    Include,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JobBreakawayPolicy {
    Deny,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JobClosePolicy {
    KillOnClose,
    KeepAlive,
}

#[derive(Clone, Copy, Debug)]
struct FixedLpacLaunchProfile {
    profile_id: &'static str,
    profile_sha256: &'static str,
    adapter_id: FixedAdapterId,
    adapter_implementation_version: u32,
    adapter_relationship: AdapterRelationshipKind,
    eligible_sandbox: &'static str,
    launcher_executable_sha256: &'static str,
    sandbox_executable_sha256: &'static str,
    package_full_name: &'static str,
    package_family_name: &'static str,
    app_container_sid: &'static str,
    base_token_policy: BaseTokenPolicy,
    job_policy: JobPolicy,
    capability_policy: CapabilityPolicy,
    capability_names: &'static [&'static str],
    application_resolution_policy: ApplicationResolutionPolicy,
    application_path_utf16_sha256: &'static str,
    argv_utf16_sha256: &'static str,
    environment_block_utf16_sha256: &'static str,
    cwd_utf16_sha256: &'static str,
    package_moniker: &'static str,
    package_profile_lookup_policy: PackageProfileLookupPolicy,
    capability_sid_attributes_sha256: &'static str,
    handle_inheritance_policy: HandleInheritancePolicy,
    initial_thread_policy: InitialThreadPolicy,
    all_application_packages_policy: AllApplicationPackagesPolicy,
    creation_flags: u32,
    startupinfoex_attribute_set_sha256: &'static str,
    mitigation_policy_sha256: &'static str,
    child_process_policy: ChildProcessPolicy,
    job_breakaway_policy: JobBreakawayPolicy,
    job_close_policy: JobClosePolicy,
    job_active_process_limit: u32,
    job_process_time_limit_100ns: u64,
    job_process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
    staging_policy_sha256: &'static str,
    temp_policy_sha256: &'static str,
    filesystem_acl_policy_sha256: &'static str,
    process_object_dacl_policy_sha256: &'static str,
    operation_sha256: &'static [&'static str],
}

#[derive(Serialize)]
struct CanonicalProfile<'a> {
    schema_version: &'static str,
    profile_id: &'a str,
    adapter_id: FixedAdapterId,
    adapter_implementation_version: u32,
    adapter_relationship: AdapterRelationshipKind,
    eligible_sandbox: &'a str,
    launcher_executable_sha256: &'a str,
    sandbox_executable_sha256: &'a str,
    package_full_name: &'a str,
    package_family_name: &'a str,
    app_container_sid: &'a str,
    base_token_policy: BaseTokenPolicy,
    job_policy: JobPolicy,
    capability_policy: CapabilityPolicy,
    capability_names: &'a [&'a str],
    application_resolution_policy: ApplicationResolutionPolicy,
    application_path_utf16_sha256: &'a str,
    argv_utf16_sha256: &'a str,
    environment_block_utf16_sha256: &'a str,
    cwd_utf16_sha256: &'a str,
    package_moniker: &'a str,
    package_profile_lookup_policy: PackageProfileLookupPolicy,
    capability_sid_attributes_sha256: &'a str,
    handle_inheritance_policy: HandleInheritancePolicy,
    initial_thread_policy: InitialThreadPolicy,
    all_application_packages_policy: AllApplicationPackagesPolicy,
    creation_flags: u32,
    startupinfoex_attribute_set_sha256: &'a str,
    mitigation_policy_sha256: &'a str,
    child_process_policy: ChildProcessPolicy,
    job_breakaway_policy: JobBreakawayPolicy,
    job_close_policy: JobClosePolicy,
    job_active_process_limit: u32,
    job_process_time_limit_100ns: u64,
    job_process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
    staging_policy_sha256: &'a str,
    temp_policy_sha256: &'a str,
    filesystem_acl_policy_sha256: &'a str,
    process_object_dacl_policy_sha256: &'a str,
    operation_sha256: &'a [&'a str],
}

/// Production is deliberately incapable of selecting a launch profile.
const PRODUCTION_REGISTRY: &[FixedLpacLaunchProfile] = &[];

/// Authority/profile capability only; it has no launch or activation method.
pub(crate) struct SelectedLpacLaunchProfile {
    authority: LpacVerifiedAuthority,
    profile: &'static FixedLpacLaunchProfile,
}

/// A future activation capability. No production constructor exists.
pub(crate) struct LpacLaunchActivationPermit {
    authority_commitment_sha256: String,
    launch_profile_sha256: String,
    _private: (),
}

impl SelectedLpacLaunchProfile {
    pub(crate) fn profile_id(&self) -> &'static str {
        self.profile.profile_id
    }

    pub(crate) fn launch_profile_sha256(&self) -> &'static str {
        self.profile.profile_sha256
    }
}

impl LpacLaunchActivationPermit {
    fn matches(&self, authority_commitment_sha256: &str, launch_profile_sha256: &str) -> bool {
        self.authority_commitment_sha256 == authority_commitment_sha256
            && self.launch_profile_sha256 == launch_profile_sha256
    }

    #[cfg(test)]
    fn test_only(
        authority_commitment_sha256: &str,
        launch_profile_sha256: &str,
    ) -> Result<Self, String> {
        if !valid_sha256(authority_commitment_sha256) || !valid_sha256(launch_profile_sha256) {
            return Err("test LPAC activation permit commitments are invalid".to_owned());
        }
        Ok(Self {
            authority_commitment_sha256: authority_commitment_sha256.to_owned(),
            launch_profile_sha256: launch_profile_sha256.to_owned(),
            _private: (),
        })
    }
}

/// Canonical profile material deliberately excludes `profile_sha256` to avoid
/// a self-referential digest; every executable policy field is included. The
/// declaration order of `CanonicalProfile` and compact serde JSON encoding are
/// the pinned canonicalization algorithm for this schema version.
fn canonical_profile(profile: &FixedLpacLaunchProfile) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CanonicalProfile {
        schema_version: PROFILE_SCHEMA,
        profile_id: profile.profile_id,
        adapter_id: profile.adapter_id,
        adapter_implementation_version: profile.adapter_implementation_version,
        adapter_relationship: profile.adapter_relationship,
        eligible_sandbox: profile.eligible_sandbox,
        launcher_executable_sha256: profile.launcher_executable_sha256,
        sandbox_executable_sha256: profile.sandbox_executable_sha256,
        package_full_name: profile.package_full_name,
        package_family_name: profile.package_family_name,
        app_container_sid: profile.app_container_sid,
        base_token_policy: profile.base_token_policy,
        job_policy: profile.job_policy,
        capability_policy: profile.capability_policy,
        capability_names: profile.capability_names,
        application_resolution_policy: profile.application_resolution_policy,
        application_path_utf16_sha256: profile.application_path_utf16_sha256,
        argv_utf16_sha256: profile.argv_utf16_sha256,
        environment_block_utf16_sha256: profile.environment_block_utf16_sha256,
        cwd_utf16_sha256: profile.cwd_utf16_sha256,
        package_moniker: profile.package_moniker,
        package_profile_lookup_policy: profile.package_profile_lookup_policy,
        capability_sid_attributes_sha256: profile.capability_sid_attributes_sha256,
        handle_inheritance_policy: profile.handle_inheritance_policy,
        initial_thread_policy: profile.initial_thread_policy,
        all_application_packages_policy: profile.all_application_packages_policy,
        creation_flags: profile.creation_flags,
        startupinfoex_attribute_set_sha256: profile.startupinfoex_attribute_set_sha256,
        mitigation_policy_sha256: profile.mitigation_policy_sha256,
        child_process_policy: profile.child_process_policy,
        job_breakaway_policy: profile.job_breakaway_policy,
        job_close_policy: profile.job_close_policy,
        job_active_process_limit: profile.job_active_process_limit,
        job_process_time_limit_100ns: profile.job_process_time_limit_100ns,
        job_process_memory_limit_bytes: profile.job_process_memory_limit_bytes,
        job_memory_limit_bytes: profile.job_memory_limit_bytes,
        staging_policy_sha256: profile.staging_policy_sha256,
        temp_policy_sha256: profile.temp_policy_sha256,
        filesystem_acl_policy_sha256: profile.filesystem_acl_policy_sha256,
        process_object_dacl_policy_sha256: profile.process_object_dacl_policy_sha256,
        operation_sha256: profile.operation_sha256,
    })
    .map_err(|error| format!("cannot serialize canonical LPAC profile: {error}"))
}

fn profile_commitment(profile: &FixedLpacLaunchProfile) -> Result<String, String> {
    let canonical = canonical_profile(profile)?;
    let mut digest = Sha256::new();
    digest.update(PROFILE_DOMAIN);
    digest.update(canonical);
    Ok(format!("{:x}", digest.finalize()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_package_sid(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() == 12
        && parts[..4] == ["S", "1", "15", "2"]
        && parts[4..].iter().all(|part| {
            !part.is_empty()
                && part.len() <= 10
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u32>().is_ok()
        })
}

fn valid_identity(value: &str, maximum: usize, extra: &[u8]) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= maximum
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte))
}

fn strictly_sorted_unique(values: &[&str]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_profile(profile: &FixedLpacLaunchProfile) -> Result<(), String> {
    if !valid_identity(profile.profile_id, 128, b"_.:-")
        || !matches!(
            profile.eligible_sandbox,
            "edge-chromium-renderer"
                | "windows-defender-msengcp"
                | "winhttp-wpad-sandboxed-process"
                | "utcdecoderhost-sandboxed-process"
        )
        || !valid_identity(profile.package_full_name, 256, b"._~-")
        || !valid_identity(profile.package_family_name, 256, b"._~-")
        || !valid_identity(profile.package_moniker, 256, b"._~-")
        || !valid_package_sid(profile.app_container_sid)
    {
        return Err("fixed LPAC profile identity is invalid".to_owned());
    }
    for value in [
        profile.profile_sha256,
        profile.launcher_executable_sha256,
        profile.sandbox_executable_sha256,
        profile.application_path_utf16_sha256,
        profile.argv_utf16_sha256,
        profile.environment_block_utf16_sha256,
        profile.cwd_utf16_sha256,
        profile.capability_sid_attributes_sha256,
        profile.startupinfoex_attribute_set_sha256,
        profile.mitigation_policy_sha256,
        profile.staging_policy_sha256,
        profile.temp_policy_sha256,
        profile.filesystem_acl_policy_sha256,
        profile.process_object_dacl_policy_sha256,
    ] {
        if !valid_sha256(value) {
            return Err("fixed LPAC profile digest is invalid".to_owned());
        }
    }
    if profile.adapter_implementation_version == 0
        || profile.adapter_relationship != AdapterRelationshipKind::DirectSameImage
        || profile.launcher_executable_sha256 != profile.sandbox_executable_sha256
        || profile.handle_inheritance_policy != HandleInheritancePolicy::Deny
        || profile.initial_thread_policy != InitialThreadPolicy::CreateSuspended
        || profile.all_application_packages_policy != AllApplicationPackagesPolicy::OptOut
        || profile.job_breakaway_policy != JobBreakawayPolicy::Deny
        || profile.job_close_policy != JobClosePolicy::KillOnClose
        || profile.job_active_process_limit != 1
        || profile.job_process_time_limit_100ns == 0
        || profile.job_process_memory_limit_bytes == 0
        || profile.job_memory_limit_bytes < profile.job_process_memory_limit_bytes
    {
        return Err("fixed LPAC profile policy is not direct-v2 fail-closed".to_owned());
    }
    if profile.capability_names.len() > MAX_CAPABILITIES
        || profile.operation_sha256.len() > MAX_OPERATIONS
        || !profile
            .capability_names
            .iter()
            .all(|name| valid_identity(name, 128, b"_.:-"))
        || (!profile.capability_names.is_empty()
            && !strictly_sorted_unique(profile.capability_names))
        || !strictly_sorted_unique(profile.operation_sha256)
        || !profile
            .operation_sha256
            .iter()
            .all(|value| valid_sha256(value))
    {
        return Err("fixed LPAC profile capabilities/operations are invalid".to_owned());
    }
    if profile_commitment(profile)? != profile.profile_sha256 {
        return Err("fixed LPAC profile commitment is invalid".to_owned());
    }
    Ok(())
}

fn validate_registry_common(registry: &[FixedLpacLaunchProfile]) -> Result<(), String> {
    for (index, profile) in registry.iter().enumerate() {
        validate_profile(profile)?;
        if registry[index + 1..]
            .iter()
            .any(|other| other.profile_id == profile.profile_id)
        {
            return Err("fixed LPAC registry profile IDs are not globally unique".to_owned());
        }
    }
    Ok(())
}

struct AuthorityKey<'a> {
    eligible_sandbox: &'a str,
    launcher_sha256: &'a str,
    sandbox_sha256: &'a str,
    app_container_sid: &'a str,
    operation_sha256: &'a str,
}

fn find_unique(
    key: &AuthorityKey<'_>,
    registry: &'static [FixedLpacLaunchProfile],
) -> Result<&'static FixedLpacLaunchProfile, String> {
    let mut matches = registry.iter().filter(|profile| {
        profile.eligible_sandbox == key.eligible_sandbox
            && profile.launcher_executable_sha256 == key.launcher_sha256
            && profile.sandbox_executable_sha256 == key.sandbox_sha256
            && profile.app_container_sid == key.app_container_sid
            && profile.operation_sha256.contains(&key.operation_sha256)
    });
    let selected = matches
        .next()
        .ok_or_else(|| "verified LPAC authority has no fixed launch profile".to_owned())?;
    if matches.next().is_some() {
        return Err("verified LPAC authority has ambiguous fixed launch profiles".to_owned());
    }
    Ok(selected)
}

fn match_production_unique(
    key: &AuthorityKey<'_>,
) -> Result<&'static FixedLpacLaunchProfile, String> {
    validate_registry_common(PRODUCTION_REGISTRY)?;
    for profile in PRODUCTION_REGISTRY {
        validate_production_adapter(profile)?;
    }
    find_unique(key, PRODUCTION_REGISTRY)
}

fn validate_production_adapter(profile: &FixedLpacLaunchProfile) -> Result<(), String> {
    match profile.adapter_id {
        FixedAdapterId::SyntheticNonBountyFixture => {
            Err("synthetic LPAC adapter is forbidden in production".to_owned())
        }
    }
}

#[cfg(test)]
fn match_test_unique(
    key: &AuthorityKey<'_>,
    registry: &'static [FixedLpacLaunchProfile],
) -> Result<&'static FixedLpacLaunchProfile, String> {
    validate_registry_common(registry)?;
    for profile in registry {
        match profile.adapter_id {
            FixedAdapterId::SyntheticNonBountyFixture
                if profile.adapter_implementation_version == 1
                    && profile.creation_flags == SYNTHETIC_CREATION_FLAGS
                    && profile.profile_sha256 == SYNTHETIC_TEST_PROFILE_SHA256 => {}
            FixedAdapterId::SyntheticNonBountyFixture => {
                return Err("synthetic LPAC adapter version/policy is unsupported".to_owned());
            }
        }
    }
    find_unique(key, registry)
}

pub(crate) fn select_lpac_launch_profile(
    authority: LpacVerifiedAuthority,
) -> Result<SelectedLpacLaunchProfile, String> {
    let profile = match_production_unique(&AuthorityKey {
        eligible_sandbox: authority.eligible_sandbox(),
        launcher_sha256: authority.launch_app_container_executable_sha256(),
        sandbox_sha256: authority.sandbox_process_executable_sha256(),
        app_container_sid: authority.app_container_sid(),
        operation_sha256: authority.selected_operation_sha256(),
    })?;
    Ok(SelectedLpacLaunchProfile { authority, profile })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OPERATION: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OPERATIONS: &[&str] = &[OPERATION];
    const CAPABILITIES: &[&str] = &["internetClient"];
    const PATH_UTF16: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const ARGV_UTF16: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const ENV_UTF16: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const CWD_UTF16: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const CAPABILITY_SIDS: &str =
        "7777777777777777777777777777777777777777777777777777777777777777";
    const STARTUP_ATTRIBUTES: &str =
        "8888888888888888888888888888888888888888888888888888888888888888";
    const MITIGATIONS: &str = "9999999999999999999999999999999999999999999999999999999999999999";
    const STAGING: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEMP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FILE_ACL: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OBJECT_DACL: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    fn synthetic_with_digest(digest: &'static str) -> FixedLpacLaunchProfile {
        FixedLpacLaunchProfile {
            profile_id: "synthetic-direct-v2",
            profile_sha256: digest,
            adapter_id: FixedAdapterId::SyntheticNonBountyFixture,
            adapter_implementation_version: 1,
            adapter_relationship: AdapterRelationshipKind::DirectSameImage,
            eligible_sandbox: "edge-chromium-renderer",
            launcher_executable_sha256: IMAGE,
            sandbox_executable_sha256: IMAGE,
            package_full_name: "Example.Package_1.0.0.0_x64__example",
            package_family_name: "Example.Package_example",
            app_container_sid: "S-1-15-2-1-2-3-4-5-6-7-8",
            base_token_policy: BaseTokenPolicy::VerifiedNaturalStandardUserPrimary,
            job_policy: JobPolicy::KillOnCloseSingleActiveProcess,
            capability_policy: CapabilityPolicy::ExactNamedCapabilities,
            capability_names: CAPABILITIES,
            application_resolution_policy:
                ApplicationResolutionPolicy::AbsolutePinnedHandleNoReparse,
            application_path_utf16_sha256: PATH_UTF16,
            argv_utf16_sha256: ARGV_UTF16,
            environment_block_utf16_sha256: ENV_UTF16,
            cwd_utf16_sha256: CWD_UTF16,
            package_moniker: "Example.NonBounty.Synthetic",
            package_profile_lookup_policy:
                PackageProfileLookupPolicy::ExistingProfileDeriveSidAndExactMatch,
            capability_sid_attributes_sha256: CAPABILITY_SIDS,
            handle_inheritance_policy: HandleInheritancePolicy::Deny,
            initial_thread_policy: InitialThreadPolicy::CreateSuspended,
            all_application_packages_policy: AllApplicationPackagesPolicy::OptOut,
            creation_flags: SYNTHETIC_CREATION_FLAGS,
            startupinfoex_attribute_set_sha256: STARTUP_ATTRIBUTES,
            mitigation_policy_sha256: MITIGATIONS,
            child_process_policy: ChildProcessPolicy::DenyAllChildren,
            job_breakaway_policy: JobBreakawayPolicy::Deny,
            job_close_policy: JobClosePolicy::KillOnClose,
            job_active_process_limit: 1,
            job_process_time_limit_100ns: 300_000_000,
            job_process_memory_limit_bytes: 256 * 1024 * 1024,
            job_memory_limit_bytes: 256 * 1024 * 1024,
            staging_policy_sha256: STAGING,
            temp_policy_sha256: TEMP,
            filesystem_acl_policy_sha256: FILE_ACL,
            process_object_dacl_policy_sha256: OBJECT_DACL,
            operation_sha256: OPERATIONS,
        }
    }

    fn valid_synthetic() -> &'static FixedLpacLaunchProfile {
        Box::leak(Box::new(synthetic_with_digest(
            SYNTHETIC_TEST_PROFILE_SHA256,
        )))
    }

    fn recommit(mut profile: FixedLpacLaunchProfile) -> FixedLpacLaunchProfile {
        profile.profile_sha256 = "0".repeat(64).leak();
        profile.profile_sha256 = profile_commitment(&profile).unwrap().leak();
        profile
    }

    fn exact_key() -> AuthorityKey<'static> {
        AuthorityKey {
            eligible_sandbox: "edge-chromium-renderer",
            launcher_sha256: IMAGE,
            sandbox_sha256: IMAGE,
            app_container_sid: "S-1-15-2-1-2-3-4-5-6-7-8",
            operation_sha256: OPERATION,
        }
    }

    #[test]
    fn production_registry_is_empty_and_cannot_select() {
        assert!(PRODUCTION_REGISTRY.is_empty());
        assert!(match_production_unique(&exact_key()).is_err());
        assert!(validate_production_adapter(valid_synthetic()).is_err());
    }

    #[test]
    fn exact_single_profile_selects_and_is_canonically_committed() {
        let profile = valid_synthetic();
        let registry = Box::leak(vec![*profile].into_boxed_slice());
        let selected = match_test_unique(&exact_key(), registry).unwrap();
        assert_eq!(selected.profile_id, "synthetic-direct-v2");
        assert_eq!(
            profile_commitment(selected).unwrap(),
            SYNTHETIC_TEST_PROFILE_SHA256
        );
        assert!(canonical_profile(selected).unwrap().starts_with(b"{"));
    }

    #[test]
    fn test_only_activation_permit_is_exactly_commitment_bound() {
        let authority = "7".repeat(64);
        let profile = valid_synthetic();
        let permit =
            LpacLaunchActivationPermit::test_only(&authority, profile.profile_sha256).unwrap();
        assert!(permit.matches(&authority, profile.profile_sha256));
        assert!(!permit.matches(&"8".repeat(64), profile.profile_sha256));
        assert!(!permit.matches(&authority, &"9".repeat(64)));
        assert!(LpacLaunchActivationPermit::test_only("bad", profile.profile_sha256).is_err());
    }

    #[test]
    fn every_authority_axis_and_operation_is_exact() {
        let profile = valid_synthetic();
        let registry = Box::leak(vec![*profile].into_boxed_slice());
        for key in [
            AuthorityKey {
                eligible_sandbox: "windows-defender-msengcp",
                ..exact_key()
            },
            AuthorityKey {
                launcher_sha256: "3".repeat(64).leak(),
                ..exact_key()
            },
            AuthorityKey {
                sandbox_sha256: "4".repeat(64).leak(),
                ..exact_key()
            },
            AuthorityKey {
                app_container_sid: "S-1-15-2-8-7-6-5-4-3-2-1",
                ..exact_key()
            },
            AuthorityKey {
                operation_sha256: "5".repeat(64).leak(),
                ..exact_key()
            },
        ] {
            assert!(match_test_unique(&key, registry).is_err());
        }
    }

    #[test]
    fn ambiguity_mutation_and_two_image_profiles_fail_closed() {
        let profile = *valid_synthetic();
        let mut second = profile;
        second.profile_id = "synthetic-direct-v2-second";
        let ambiguous = Box::leak(vec![profile, recommit(second)].into_boxed_slice());
        assert!(match_test_unique(&exact_key(), ambiguous).is_err());

        let mut mutation = profile;
        mutation.handle_inheritance_policy = HandleInheritancePolicy::Allow;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.initial_thread_policy = InitialThreadPolicy::CreateRunning;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.all_application_packages_policy = AllApplicationPackagesPolicy::Include;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.job_breakaway_policy = JobBreakawayPolicy::Allow;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.job_close_policy = JobClosePolicy::KeepAlive;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.adapter_implementation_version = 2;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.application_path_utf16_sha256 = "e".repeat(64).leak();
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.creation_flags ^= 1;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.job_process_memory_limit_bytes += 1;
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.staging_policy_sha256 = "f".repeat(64).leak();
        assert!(validate_profile(&mutation).is_err());
        let mut mutation = profile;
        mutation.package_family_name = "Changed.Package_family";
        assert!(validate_profile(&mutation).is_err());
        let mut two_image = profile;
        two_image.sandbox_executable_sha256 =
            "6666666666666666666666666666666666666666666666666666666666666666";
        assert!(validate_profile(&two_image).is_err());
    }

    #[test]
    fn registry_bounds_and_global_profile_ids_fail_closed() {
        let profile = *valid_synthetic();
        let duplicate_ids = Box::leak(vec![profile, profile].into_boxed_slice());
        assert!(validate_registry_common(duplicate_ids).is_err());

        let capabilities: &'static [&'static str] =
            Box::leak(vec!["capability"; MAX_CAPABILITIES + 1].into_boxed_slice());
        let mut oversized = profile;
        oversized.capability_names = capabilities;
        assert!(validate_profile(&oversized).is_err());

        let operations: &'static [&'static str] =
            Box::leak(vec![OPERATION; MAX_OPERATIONS + 1].into_boxed_slice());
        let mut oversized = profile;
        oversized.operation_sha256 = operations;
        assert!(validate_profile(&oversized).is_err());
    }
}
