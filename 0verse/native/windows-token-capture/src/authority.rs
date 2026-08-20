#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "verifier is intentionally unreachable until the service-owned nonce ledger lands"
    )
)]

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::broker_protocol::{BrokerRequest, parse_strict_json_object};
use crate::sshsig::verify_ed25519;

const CAMPAIGN_SCHEMA: &str = "0verse.windows-token-campaign/v1";
const LPAC_CAMPAIGN_SCHEMA: &str = "0verse.windows-token-campaign/v2";
const SCOPE_SCHEMA: &str = "0verse.windows-scope/v2";
const GRANT_SCHEMA: &str = "0verse.windows-token-execution-grant/v1";
const ACCEPTANCE_SCHEMA: &str = "0verse.windows-token-worker-acceptance/v2";
const SCOPE_NAMESPACE: &str = "0verse-windows-scope-authorization";
const GRANT_NAMESPACE: &str = "0verse-windows-token-execution-grant";
const ACCEPTANCE_NAMESPACE: &str = "0verse-windows-token-worker-acceptance";
const MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;

/// Host facts and trust policies sampled immediately before privileged capture.
pub(crate) struct LiveAuthorityContext<'a> {
    pub now_unix_seconds: i64,
    pub worker: &'a str,
    pub build_lab_ex: &'a str,
    pub worker_machine_id: &'a str,
    pub runner_executable_sha256: &'a str,
    pub capture_signer: &'a str,
    pub authorization_allowed_signers: &'a str,
    pub acceptance_allowed_signers: &'a str,
}

impl<'a> LiveAuthorityContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        now_unix_seconds: i64,
        worker: &'a str,
        build_lab_ex: &'a str,
        worker_machine_id: &'a str,
        runner_executable_sha256: &'a str,
        capture_signer: &'a str,
        authorization_allowed_signers: &'a str,
        acceptance_allowed_signers: &'a str,
    ) -> Self {
        Self {
            now_unix_seconds,
            worker,
            build_lab_ex,
            worker_machine_id,
            runner_executable_sha256,
            capture_signer,
            authorization_allowed_signers,
            acceptance_allowed_signers,
        }
    }
}

/// Capability produced only after the complete raw-byte authority chain passes.
/// Fields remain private so later service code cannot construct or widen it.
pub(crate) struct VerifiedAuthority {
    campaign_id: String,
    selected_operation_sha256: String,
    campaign_sha256: String,
    scope_sha256: String,
    grant_sha256: String,
    acceptance_sha256: String,
    grant_nonce: String,
    acceptance_nonce: String,
    worker: String,
    build_lab_ex: String,
    worker_machine_id: String,
    runner_executable_sha256: String,
    witness_user_sid: String,
    witness_session_id: u32,
    witness_authentication_id: String,
    witness_executable_sha256: String,
    capture_signer: String,
    case: String,
    trial: u32,
    run_nonce: String,
    authority_issued_at_unix_seconds: i64,
    authority_expires_at_unix_seconds: i64,
    now_unix_seconds: i64,
}

/// Standard campaign authority narrowed to one exact signed device-open
/// boundary manifest. This is structurally distinct from capture authority and
/// cannot construct a capture-v3 signing permit.
#[allow(
    dead_code,
    reason = "the capability remains unreachable until broker request v2 lands"
)]
pub(crate) struct DeviceOpenVerifiedAuthority {
    authority: VerifiedAuthority,
    boundary: crate::device_open_authority::VerifiedDeviceOpenBoundary,
}

/// Capability produced only for an exactly verified eligible-sandbox campaign.
///
/// This deliberately has no witness-binding or capture-v3 signing methods. A
/// campaign-v2 authority can only be consumed by the future service-owned LPAC
/// launch/measurement path.
pub(crate) struct LpacVerifiedAuthority {
    core: AuthorityCore,
    eligible_sandbox: String,
    launch_app_container_executable_sha256: String,
    sandbox_process_executable_sha256: String,
    app_container_sid: String,
}

/// Validated data is not itself a capability. Only the two public verifier
/// entry points below can turn it into a campaign-specific capability.
struct AuthorityCore {
    campaign_id: String,
    selected_operation_sha256: String,
    campaign_sha256: String,
    scope_sha256: String,
    grant_sha256: String,
    acceptance_sha256: String,
    grant_nonce: String,
    acceptance_nonce: String,
    worker: String,
    build_lab_ex: String,
    worker_machine_id: String,
    runner_executable_sha256: String,
    witness_user_sid: String,
    witness_session_id: u32,
    witness_authentication_id: String,
    witness_executable_sha256: String,
    capture_signer: String,
    case: String,
    trial: u32,
    run_nonce: String,
    authority_issued_at_unix_seconds: i64,
    authority_expires_at_unix_seconds: i64,
    now_unix_seconds: i64,
}

impl From<AuthorityCore> for VerifiedAuthority {
    fn from(core: AuthorityCore) -> Self {
        Self {
            campaign_id: core.campaign_id,
            selected_operation_sha256: core.selected_operation_sha256,
            campaign_sha256: core.campaign_sha256,
            scope_sha256: core.scope_sha256,
            grant_sha256: core.grant_sha256,
            acceptance_sha256: core.acceptance_sha256,
            grant_nonce: core.grant_nonce,
            acceptance_nonce: core.acceptance_nonce,
            worker: core.worker,
            build_lab_ex: core.build_lab_ex,
            worker_machine_id: core.worker_machine_id,
            runner_executable_sha256: core.runner_executable_sha256,
            witness_user_sid: core.witness_user_sid,
            witness_session_id: core.witness_session_id,
            witness_authentication_id: core.witness_authentication_id,
            witness_executable_sha256: core.witness_executable_sha256,
            capture_signer: core.capture_signer,
            case: core.case,
            trial: core.trial,
            run_nonce: core.run_nonce,
            authority_issued_at_unix_seconds: core.authority_issued_at_unix_seconds,
            authority_expires_at_unix_seconds: core.authority_expires_at_unix_seconds,
            now_unix_seconds: core.now_unix_seconds,
        }
    }
}

impl LpacVerifiedAuthority {
    #[must_use]
    pub(crate) fn campaign_id(&self) -> &str {
        &self.core.campaign_id
    }

    #[must_use]
    pub(crate) fn selected_operation_sha256(&self) -> &str {
        &self.core.selected_operation_sha256
    }

    #[must_use]
    pub(crate) fn source_hashes(&self) -> [&str; 4] {
        [
            &self.core.campaign_sha256,
            &self.core.scope_sha256,
            &self.core.grant_sha256,
            &self.core.acceptance_sha256,
        ]
    }

    #[must_use]
    pub(crate) fn eligible_sandbox(&self) -> &str {
        &self.eligible_sandbox
    }

    #[must_use]
    pub(crate) fn launch_app_container_executable_sha256(&self) -> &str {
        &self.launch_app_container_executable_sha256
    }

    #[must_use]
    pub(crate) fn sandbox_process_executable_sha256(&self) -> &str {
        &self.sandbox_process_executable_sha256
    }

    #[must_use]
    pub(crate) fn app_container_sid(&self) -> &str {
        &self.app_container_sid
    }

    #[must_use]
    pub(crate) fn lpac_reservation_fields(&self) -> LpacAuthorityReservationFields<'_> {
        LpacAuthorityReservationFields {
            campaign_sha256: &self.core.campaign_sha256,
            scope_manifest_sha256: &self.core.scope_sha256,
            execution_grant_sha256: &self.core.grant_sha256,
            grant_nonce: &self.core.grant_nonce,
            worker_acceptance_sha256: &self.core.acceptance_sha256,
            acceptance_nonce: &self.core.acceptance_nonce,
            campaign_id: &self.core.campaign_id,
            case: &self.core.case,
            trial: self.core.trial,
            run_nonce: &self.core.run_nonce,
            operation_sha256: &self.core.selected_operation_sha256,
            worker: &self.core.worker,
            build_lab_ex: &self.core.build_lab_ex,
            worker_machine_id: &self.core.worker_machine_id,
            runner_executable_sha256: &self.core.runner_executable_sha256,
            authority_issued_at_unix_seconds: self.core.authority_issued_at_unix_seconds,
            authority_expires_at_unix_seconds: self.core.authority_expires_at_unix_seconds,
            now_unix_seconds: self.core.now_unix_seconds,
            eligible_sandbox: &self.eligible_sandbox,
            launch_app_container_executable_sha256: &self.launch_app_container_executable_sha256,
            sandbox_process_executable_sha256: &self.sandbox_process_executable_sha256,
            app_container_sid: &self.app_container_sid,
        }
    }
}

/// Borrowed, non-signing inputs for service-owned LPAC replay reservation.
/// This view carries no signing or witness-binding authority; callers must
/// retain the originating [`LpacVerifiedAuthority`] capability.
pub(crate) struct LpacAuthorityReservationFields<'a> {
    pub(crate) campaign_sha256: &'a str,
    pub(crate) scope_manifest_sha256: &'a str,
    pub(crate) execution_grant_sha256: &'a str,
    pub(crate) grant_nonce: &'a str,
    pub(crate) worker_acceptance_sha256: &'a str,
    pub(crate) acceptance_nonce: &'a str,
    pub(crate) campaign_id: &'a str,
    pub(crate) case: &'a str,
    pub(crate) trial: u32,
    pub(crate) run_nonce: &'a str,
    pub(crate) operation_sha256: &'a str,
    pub(crate) worker: &'a str,
    pub(crate) build_lab_ex: &'a str,
    pub(crate) worker_machine_id: &'a str,
    pub(crate) runner_executable_sha256: &'a str,
    pub(crate) authority_issued_at_unix_seconds: i64,
    pub(crate) authority_expires_at_unix_seconds: i64,
    pub(crate) now_unix_seconds: i64,
    pub(crate) eligible_sandbox: &'a str,
    pub(crate) launch_app_container_executable_sha256: &'a str,
    pub(crate) sandbox_process_executable_sha256: &'a str,
    pub(crate) app_container_sid: &'a str,
}

/// Intermediate capability: the kernel token identity is bound, but the client
/// executable has not yet been handle-pinned. It cannot reserve or sign.
pub(crate) struct WitnessIdentityBoundAuthority {
    authority: VerifiedAuthority,
    _token_capability: crate::witness::AuthenticatedWitnessToken,
}

/// Final capability that exists only after token identity and pinned executable agree.
pub(crate) struct WitnessBoundAuthority {
    authority: VerifiedAuthority,
    witness_capability: crate::witness::PinnedAuthenticatedWitness,
}

/// Unforgeable outside this module; required to construct capture-signing
/// authority even from elsewhere in the crate.
pub(crate) struct CaptureSigningPermit(());

impl VerifiedAuthority {
    #[must_use]
    pub(crate) fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    #[must_use]
    pub(crate) fn selected_operation_sha256(&self) -> &str {
        &self.selected_operation_sha256
    }

    #[must_use]
    pub(crate) fn source_hashes(&self) -> [&str; 4] {
        [
            &self.campaign_sha256,
            &self.scope_sha256,
            &self.grant_sha256,
            &self.acceptance_sha256,
        ]
    }

    pub(crate) fn witness_rendezvous_spec(
        &self,
    ) -> Result<crate::witness::WitnessRendezvousSpec, String> {
        crate::witness::WitnessRendezvousSpec::new(
            &self.campaign_sha256,
            &self.acceptance_sha256,
            &self.case,
            self.trial,
            &self.run_nonce,
            &self.witness_user_sid,
            self.witness_session_id,
            &self.witness_authentication_id,
        )
    }

    pub(crate) fn bind_witness_identity(
        self,
        token: crate::witness::AuthenticatedWitnessToken,
    ) -> Result<WitnessIdentityBoundAuthority, String> {
        let expected_binding = self.witness_rendezvous_spec()?.binding_sha256().to_owned();
        if self.witness_user_sid != token.user_sid()
            || self.witness_session_id != token.session_id()
            || self.witness_authentication_id != token.authentication_id()
            || expected_binding != token.rendezvous_binding_sha256()
        {
            return Err(
                "authenticated witness token is not bound to this worker acceptance run".to_owned(),
            );
        }
        Ok(WitnessIdentityBoundAuthority {
            authority: self,
            _token_capability: token,
        })
    }

    /// Consume broad standard-campaign authority and narrow it to the exact
    /// raw signed device-open manifest selected by this target/control run.
    #[allow(
        dead_code,
        reason = "the capability remains unreachable until broker request v2 lands"
    )]
    pub(crate) fn bind_device_open_boundary(
        self,
        boundary: crate::device_open_authority::VerifiedDeviceOpenBoundary,
    ) -> Result<DeviceOpenVerifiedAuthority, String> {
        if self.campaign_id != boundary.campaign_id()
            || self.selected_operation_sha256 != boundary.manifest_sha256()
            || boundary.receipt_signer() == boundary.authorized_by()
            || boundary.receipt_signer() == self.capture_signer
            || boundary.authorized_by() == self.capture_signer
        {
            return Err(
                "device-open boundary manifest operation or signer separation is invalid"
                    .to_owned(),
            );
        }
        Ok(DeviceOpenVerifiedAuthority {
            authority: self,
            boundary,
        })
    }
}

#[allow(
    dead_code,
    reason = "the capability remains unreachable until broker request v2 lands"
)]
impl DeviceOpenVerifiedAuthority {
    pub(crate) fn campaign_id(&self) -> &str {
        &self.authority.campaign_id
    }

    pub(crate) fn worker(&self) -> &str {
        &self.authority.worker
    }

    pub(crate) fn worker_machine_id(&self) -> &str {
        &self.authority.worker_machine_id
    }

    pub(crate) fn worker_acceptance_sha256(&self) -> &str {
        &self.authority.acceptance_sha256
    }

    pub(crate) fn runner_executable_sha256(&self) -> &str {
        &self.authority.runner_executable_sha256
    }

    pub(crate) fn build_lab_ex(&self) -> &str {
        &self.authority.build_lab_ex
    }

    pub(crate) fn boundary(&self) -> &crate::device_open_authority::VerifiedDeviceOpenBoundary {
        &self.boundary
    }

    pub(crate) fn witness_rendezvous_spec(
        &self,
    ) -> Result<crate::witness::WitnessRendezvousSpec, String> {
        self.authority.witness_rendezvous_spec()
    }

    pub(crate) fn bind_witness_identity(
        self,
        token: crate::witness::AuthenticatedWitnessToken,
    ) -> Result<DeviceOpenWitnessIdentityBoundAuthority, String> {
        let expected_binding = self.witness_rendezvous_spec()?.binding_sha256().to_owned();
        if self.authority.witness_user_sid != token.user_sid()
            || self.authority.witness_session_id != token.session_id()
            || self.authority.witness_authentication_id != token.authentication_id()
            || expected_binding != token.rendezvous_binding_sha256()
        {
            return Err(
                "authenticated witness token is not bound to this device-open run".to_owned(),
            );
        }
        Ok(DeviceOpenWitnessIdentityBoundAuthority {
            authority: self,
            token,
        })
    }
}

/// Intermediate device-open capability. The token is retained rather than
/// converted into the ordinary capture path.
#[allow(
    dead_code,
    reason = "the capability remains unreachable until exact-child activation lands"
)]
pub(crate) struct DeviceOpenWitnessIdentityBoundAuthority {
    authority: DeviceOpenVerifiedAuthority,
    token: crate::witness::AuthenticatedWitnessToken,
}

fn device_open_executable_hashes_match(
    collector_sha256: &str,
    accepted_runner_sha256: &str,
    accepted_witness_sha256: &str,
    pinned_sha256: &str,
) -> bool {
    collector_sha256 == pinned_sha256
        && accepted_runner_sha256 == pinned_sha256
        && accepted_witness_sha256 == pinned_sha256
}

#[allow(
    clippy::too_many_arguments,
    reason = "every independent freshness bound is explicit"
)]
fn device_open_times_are_fresh(
    authority_issued_at: i64,
    authority_expires_at: i64,
    boundary_issued_at: i64,
    boundary_expires_at: i64,
    sampled_at: i64,
    now: i64,
) -> bool {
    now >= authority_issued_at - CLOCK_SKEW_SECONDS
        && now < authority_expires_at
        && now >= boundary_issued_at - CLOCK_SKEW_SECONDS
        && now < boundary_expires_at
        && sampled_at <= now + CLOCK_SKEW_SECONDS
        && now - sampled_at <= CLOCK_SKEW_SECONDS
}

#[cfg(windows)]
impl DeviceOpenWitnessIdentityBoundAuthority {
    /// Launch the exact handle-pinned broker image as the authenticated child,
    /// perform the sole fixed query-only open, and retain every capability
    /// needed for later signing and immutable publication.
    #[allow(
        dead_code,
        reason = "the transition remains unreachable until sign-and-publish lands"
    )]
    pub(crate) fn hold_fixed_device_open(
        self,
        live: crate::windows::live_facts::LiveFacts,
        stop_event: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<BrokerHeldDeviceOpenAuthority, String> {
        let Self { authority, token } = self;
        let core = &authority.authority;
        let now = crate::windows::live_facts::now_unix_seconds()?;
        if live.worker != core.worker
            || live.build_lab_ex != core.build_lab_ex
            || live.worker_machine_id != core.worker_machine_id
            || !device_open_executable_hashes_match(
                authority.boundary.collector_sha256(),
                &core.runner_executable_sha256,
                &core.witness_executable_sha256,
                live.runner.sha256(),
            )
            || !device_open_times_are_fresh(
                core.authority_issued_at_unix_seconds,
                core.authority_expires_at_unix_seconds,
                authority.boundary.issued_at_unix_seconds(),
                authority.boundary.expires_at_unix_seconds(),
                live.now_unix_seconds,
                now,
            )
        {
            return Err(
                "pinned device-open runner, collector, or fresh authority binding is invalid"
                    .to_owned(),
            );
        }
        let expected_binding = authority
            .witness_rendezvous_spec()?
            .binding_sha256()
            .to_owned();
        // SAFETY: the source path comes from a retained, handle-pinned current
        // executable; token identity was bound above; child authentication
        // rechecks exact process, token, staged bytes, and channel binding.
        let pinned = unsafe { token.create_exact_child(&live.runner, stop_event) }?;
        if pinned.sha256() != core.witness_executable_sha256
            || pinned.rendezvous_binding_sha256() != expected_binding
        {
            return Err(
                "authenticated device-open child differs from verified authority".to_owned(),
            );
        }
        let held = pinned.hold_device_open(stop_event)?;
        Ok(BrokerHeldDeviceOpenAuthority {
            authority,
            live,
            held,
        })
    }
}

/// The only capability from which a production device-open receipt may be
/// prepared. It retains the pinned runner and broker duplicate together.
#[cfg(windows)]
#[allow(
    dead_code,
    reason = "the capability remains unreachable until sign-and-publish lands"
)]
pub(crate) struct BrokerHeldDeviceOpenAuthority {
    pub(super) authority: DeviceOpenVerifiedAuthority,
    pub(super) live: crate::windows::live_facts::LiveFacts,
    pub(super) held: crate::witness::child::BrokerHeldDeviceOpen,
}

#[cfg(windows)]
#[allow(
    dead_code,
    reason = "called by the staged sign-and-publish transition once store wiring lands"
)]
impl BrokerHeldDeviceOpenAuthority {
    pub(crate) fn require_fresh_for_signing(&self) -> Result<(), String> {
        let now = crate::windows::live_facts::now_unix_seconds()?;
        let core = &self.authority.authority;
        if !device_open_times_are_fresh(
            core.authority_issued_at_unix_seconds,
            core.authority_expires_at_unix_seconds,
            self.authority.boundary.issued_at_unix_seconds(),
            self.authority.boundary.expires_at_unix_seconds(),
            self.live.now_unix_seconds,
            now,
        ) {
            return Err("device-open authority expired before receipt signing".to_owned());
        }
        Ok(())
    }

    /// Burn all replay identities, sign with the dedicated protected key, and
    /// return a capability only after immutable close/reopen readback succeeds.
    pub(crate) fn sign_and_publish(
        self,
        store: &crate::device_open_store::DeviceOpenStore,
    ) -> Result<crate::device_open_receipt::PublishedDeviceOpenReceipt, String> {
        crate::device_open_receipt::sign_and_publish(self, store)
    }
}

impl WitnessIdentityBoundAuthority {
    #[cfg(test)]
    pub(crate) fn bind_witness_executable(
        self,
        executable_sha256: &str,
    ) -> Result<WitnessBoundAuthority, String> {
        let Self {
            authority,
            _token_capability: token_capability,
        } = self;
        let witness_capability = token_capability.test_only_pin(executable_sha256);
        let expected_binding = authority
            .witness_rendezvous_spec()?
            .binding_sha256()
            .to_owned();
        if authority.witness_executable_sha256 != witness_capability.sha256()
            || expected_binding != witness_capability.rendezvous_binding_sha256()
        {
            return Err("pinned witness executable is not bound to worker acceptance".to_owned());
        }
        Ok(WitnessBoundAuthority {
            authority,
            witness_capability,
        })
    }
}

impl WitnessBoundAuthority {
    pub(crate) fn signing_authority(
        &self,
    ) -> Result<crate::capture_v3::CaptureSigningAuthority<'_>, String> {
        let authority = &self.authority;
        crate::capture_v3::CaptureSigningAuthority::new(
            &CaptureSigningPermit(()),
            &authority.campaign_sha256,
            &authority.scope_sha256,
            &authority.grant_sha256,
            &authority.grant_nonce,
            &authority.acceptance_sha256,
            &authority.acceptance_nonce,
            &authority.campaign_id,
            &authority.worker,
            &authority.build_lab_ex,
            &authority.worker_machine_id,
            &authority.runner_executable_sha256,
            &authority.witness_user_sid,
            authority.witness_session_id,
            &authority.witness_authentication_id,
            &authority.witness_executable_sha256,
            &authority.selected_operation_sha256,
            &authority.case,
            authority.trial,
            &authority.run_nonce,
            &authority.capture_signer,
            authority.authority_issued_at_unix_seconds,
            authority.authority_expires_at_unix_seconds,
            authority.now_unix_seconds,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_only_signing_permit() -> CaptureSigningPermit {
        CaptureSigningPermit(())
    }

    pub(crate) fn reservation_fields(&self) -> AuthorityReservationFields<'_> {
        let authority = &self.authority;
        AuthorityReservationFields {
            campaign_sha256: &authority.campaign_sha256,
            scope_manifest_sha256: &authority.scope_sha256,
            execution_grant_sha256: &authority.grant_sha256,
            grant_nonce: &authority.grant_nonce,
            worker_acceptance_sha256: &authority.acceptance_sha256,
            acceptance_nonce: &authority.acceptance_nonce,
            campaign_id: &authority.campaign_id,
            case: &authority.case,
            trial: authority.trial,
            run_nonce: &authority.run_nonce,
            operation_sha256: &authority.selected_operation_sha256,
            worker: &authority.worker,
            build_lab_ex: &authority.build_lab_ex,
            worker_machine_id: &authority.worker_machine_id,
            runner_executable_sha256: &authority.runner_executable_sha256,
            witness_user_sid: &authority.witness_user_sid,
            witness_session_id: authority.witness_session_id,
            witness_authentication_id: &authority.witness_authentication_id,
            witness_executable_sha256: &authority.witness_executable_sha256,
            capture_signer: &authority.capture_signer,
        }
    }
}

pub(crate) struct AuthorityReservationFields<'a> {
    pub(crate) campaign_sha256: &'a str,
    pub(crate) scope_manifest_sha256: &'a str,
    pub(crate) execution_grant_sha256: &'a str,
    pub(crate) grant_nonce: &'a str,
    pub(crate) worker_acceptance_sha256: &'a str,
    pub(crate) acceptance_nonce: &'a str,
    pub(crate) campaign_id: &'a str,
    pub(crate) case: &'a str,
    pub(crate) trial: u32,
    pub(crate) run_nonce: &'a str,
    pub(crate) operation_sha256: &'a str,
    pub(crate) worker: &'a str,
    pub(crate) build_lab_ex: &'a str,
    pub(crate) worker_machine_id: &'a str,
    pub(crate) runner_executable_sha256: &'a str,
    pub(crate) witness_user_sid: &'a str,
    pub(crate) witness_session_id: u32,
    pub(crate) witness_authentication_id: &'a str,
    pub(crate) witness_executable_sha256: &'a str,
    pub(crate) capture_signer: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Exact external campaign schema.
struct StandardCampaign {
    schema_version: String,
    campaign_id: String,
    worker: String,
    starting_context: String,
    finishing_principal: String,
    target_operation_sha256: String,
    control_operation_sha256: String,
    trials: u32,
    minimum_confirmations: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Exact external campaign schema.
struct LpacCampaign {
    schema_version: String,
    campaign_id: String,
    worker: String,
    starting_context: String,
    finishing_principal: String,
    target_operation_sha256: String,
    control_operation_sha256: String,
    trials: u32,
    minimum_confirmations: u32,
    eligible_sandbox: String,
    launch_app_container_executable_sha256: String,
    sandbox_process_executable_sha256: String,
    app_container_sid: String,
}

enum Campaign {
    Standard(StandardCampaign),
    Lpac(LpacCampaign),
}

struct CampaignView<'a> {
    schema_version: &'a str,
    campaign_id: &'a str,
    worker: &'a str,
    starting_context: &'a str,
    finishing_principal: &'a str,
    target_operation_sha256: &'a str,
    control_operation_sha256: &'a str,
    trials: u32,
    minimum_confirmations: u32,
}

impl Campaign {
    fn view(&self) -> CampaignView<'_> {
        match self {
            Self::Standard(campaign) => CampaignView {
                schema_version: &campaign.schema_version,
                campaign_id: &campaign.campaign_id,
                worker: &campaign.worker,
                starting_context: &campaign.starting_context,
                finishing_principal: &campaign.finishing_principal,
                target_operation_sha256: &campaign.target_operation_sha256,
                control_operation_sha256: &campaign.control_operation_sha256,
                trials: campaign.trials,
                minimum_confirmations: campaign.minimum_confirmations,
            },
            Self::Lpac(campaign) => CampaignView {
                schema_version: &campaign.schema_version,
                campaign_id: &campaign.campaign_id,
                worker: &campaign.worker,
                starting_context: &campaign.starting_context,
                finishing_principal: &campaign.finishing_principal,
                target_operation_sha256: &campaign.target_operation_sha256,
                control_operation_sha256: &campaign.control_operation_sha256,
                trials: campaign.trials,
                minimum_confirmations: campaign.minimum_confirmations,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Exact external scope schema.
struct Scope {
    schema_version: String,
    campaign_id: String,
    program: String,
    scope_url: String,
    target_feature: String,
    reachability: String,
    authorization: String,
    worker: String,
    latest_build_verified_at: String,
    latest_build_number: String,
    latest_build_source_url: String,
    preflight: ScopePreflight,
    authorized_by: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    signature_ssh: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePreflight {
    ok: bool,
    program: String,
    checked_at: String,
    build_lab_ex: String,
    product_name: String,
    #[serde(rename = "hyperv_available")]
    _hyperv_available: bool,
    insider: ScopeInsider,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeInsider {
    ring: String,
    content_type: String,
    branch_name: String,
    channel_family: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    schema_version: String,
    campaign_sha256: String,
    scope_manifest_sha256: String,
    campaign_id: String,
    worker: String,
    target_operation_sha256: String,
    control_operation_sha256: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    authorized_by: String,
    signature_ssh: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acceptance {
    schema_version: String,
    campaign_sha256: String,
    scope_manifest_sha256: String,
    execution_grant_sha256: String,
    execution_grant_nonce: String,
    campaign_id: String,
    worker: String,
    build_lab_ex: String,
    worker_machine_id: String,
    runner_executable_sha256: String,
    witness_user_sid: String,
    witness_session_id: u32,
    witness_authentication_id: String,
    witness_executable_sha256: String,
    target_operation_sha256: String,
    control_operation_sha256: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
    accepted_by: String,
    capture_signer: String,
    signature_ssh: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<(T, Value), String> {
    let value = parse_strict_json_object(bytes, label)?;
    let typed = serde_json::from_value(value.clone())
        .map_err(|error| format!("{label} schema is invalid: {error}"))?;
    Ok((typed, value))
}

fn parse_campaign(bytes: &[u8]) -> Result<Campaign, String> {
    let value = parse_strict_json_object(bytes, "campaign")?;
    let schema = value
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| "campaign schema_version must be a string".to_owned())?;
    match schema {
        CAMPAIGN_SCHEMA => serde_json::from_value(value)
            .map(Campaign::Standard)
            .map_err(|error| format!("campaign schema is invalid: {error}")),
        LPAC_CAMPAIGN_SCHEMA => serde_json::from_value(value)
            .map(Campaign::Lpac)
            .map_err(|error| format!("campaign schema is invalid: {error}")),
        _ => Err("authority schema version is unsupported".to_owned()),
    }
}

fn canonical_signed_material(mut value: Value, label: &str) -> Result<Vec<u8>, String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.remove("signature_ssh").is_none() {
        return Err(format!("{label} has no detached signature"));
    }
    serde_json::to_vec(&value).map_err(|error| format!("cannot canonicalize {label}: {error}"))
}

fn safe_text(value: &str, label: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character < ' ' || character == '\u{7f}')
    {
        return Err(format!("{label} is empty, oversized, untrimmed, or unsafe"));
    }
    Ok(())
}

fn is_identifier(value: &str, maximum: usize, extra: &[u8]) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= maximum
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte))
}

fn validate_worker(value: &str) -> Result<(), String> {
    const DENIED: [&str; 4] = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
    if !is_identifier(value, 128, b"_.-")
        || DENIED
            .iter()
            .any(|denied| value.eq_ignore_ascii_case(denied))
    {
        return Err("authority worker is invalid or denied".to_owned());
    }
    Ok(())
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

fn validate_package_app_container_sid(value: &str) -> Result<(), String> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 12 || parts[..4] != ["S", "1", "15", "2"] {
        return Err("campaign AppContainer SID is not an exact package SID".to_owned());
    }
    for rid in &parts[4..] {
        if rid.is_empty()
            || rid.len() > 10
            || !rid.bytes().all(|byte| byte.is_ascii_digit())
            || (rid.len() > 1 && rid.starts_with('0'))
            || rid.parse::<u32>().is_err()
        {
            return Err("campaign AppContainer SID is not an exact package SID".to_owned());
        }
    }
    Ok(())
}

fn validate_eligible_sandbox(value: &str) -> Result<(), String> {
    if !matches!(
        value,
        "edge-chromium-renderer"
            | "windows-defender-msengcp"
            | "winhttp-wpad-sandboxed-process"
            | "utcdecoderhost-sandboxed-process"
    ) {
        return Err("campaign eligible_sandbox is not an exact eligible value".to_owned());
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

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn parse_two(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(i64::from(bytes[0] - b'0') * 10 + i64::from(bytes[1] - b'0'))
}

fn parse_four(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_i64, |value, byte| {
        value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))
    })
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
    let year = parse_four(&bytes[0..4]).ok_or_else(|| format!("{label} year is invalid"))?;
    let month = parse_two(&bytes[5..7]).ok_or_else(|| format!("{label} month is invalid"))?;
    let day = parse_two(&bytes[8..10]).ok_or_else(|| format!("{label} day is invalid"))?;
    let hour = parse_two(&bytes[11..13]).ok_or_else(|| format!("{label} hour is invalid"))?;
    let minute = parse_two(&bytes[14..16]).ok_or_else(|| format!("{label} minute is invalid"))?;
    let second = parse_two(&bytes[17..19]).ok_or_else(|| format!("{label} second is invalid"))?;
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

fn validate_window(issued: &str, expires: &str, now: i64, label: &str) -> Result<(), String> {
    let issued = timestamp(issued, &format!("{label} issued_at"))?;
    let expires = timestamp(expires, &format!("{label} expires_at"))?;
    if issued > now + CLOCK_SKEW_SECONDS || now - issued > MAX_AGE_SECONDS {
        return Err(format!("{label} issued_at is outside the 24-hour window"));
    }
    if expires <= now || expires <= issued || expires - issued > MAX_AGE_SECONDS {
        return Err(format!("{label} expiry interval is invalid"));
    }
    Ok(())
}

fn validate_fresh(value: &str, now: i64, label: &str) -> Result<(), String> {
    let checked = timestamp(value, label)?;
    if checked > now || now - checked > MAX_AGE_SECONDS {
        return Err(format!("{label} is not fresh"));
    }
    Ok(())
}

fn build_number(build_lab_ex: &str) -> Result<&str, String> {
    let first = build_lab_ex
        .split('.')
        .next()
        .ok_or_else(|| "BuildLabEx has no major build".to_owned())?;
    let second = build_lab_ex
        .split('.')
        .nth(1)
        .ok_or_else(|| "BuildLabEx has no revision".to_owned())?;
    if first.is_empty()
        || second.is_empty()
        || !first.bytes().all(|b| b.is_ascii_digit())
        || !second.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("BuildLabEx has no numeric major.revision".to_owned());
    }
    let length = first.len() + 1 + second.len();
    Ok(&build_lab_ex[..length])
}

#[derive(Clone, Copy)]
enum RequiredCampaign {
    Standard,
    Lpac,
}

struct LpacCampaignFields {
    eligible_sandbox: String,
    launch_app_container_executable_sha256: String,
    sandbox_process_executable_sha256: String,
    app_container_sid: String,
}

/// Verify a standard-user campaign-v1 authority chain.
///
/// # Errors
///
/// Fails closed for every invalid authority or live-host binding, including an
/// otherwise valid campaign-v2 chain.
pub(crate) fn verify_authority(
    request: &BrokerRequest,
    live: &LiveAuthorityContext<'_>,
) -> Result<VerifiedAuthority, String> {
    let (core, lpac) = verify_authority_core(request, live, RequiredCampaign::Standard)?;
    if lpac.is_some() {
        return Err("campaign-v2 authority cannot bind the standard witness".to_owned());
    }
    Ok(core.into())
}

/// Verify a standard authority chain and narrow it to the exact raw signed
/// device-open manifest transported by the distinct device-open request.
#[allow(
    dead_code,
    reason = "the device-open transport remains unreachable until SCM activation"
)]
pub(crate) fn verify_device_open_authority(
    request: &crate::broker_protocol::DeviceOpenBrokerRequest,
    live: &LiveAuthorityContext<'_>,
    boundary_allowed_signers: &str,
) -> Result<DeviceOpenVerifiedAuthority, String> {
    let materials = request.authority_materials()?;
    let standard = request.standard_request();
    let authority = verify_authority(&standard, live)?;
    let boundary = crate::device_open_authority::verify_device_open_boundary(
        &materials.boundary_manifest,
        boundary_allowed_signers,
        live.now_unix_seconds,
    )?;
    authority.bind_device_open_boundary(boundary)
}

/// Verify an eligible-sandbox campaign-v2 authority chain.
///
/// # Errors
///
/// Fails closed for every invalid authority or live-host binding, including an
/// otherwise valid campaign-v1 chain.
pub(crate) fn verify_lpac_authority(
    request: &BrokerRequest,
    live: &LiveAuthorityContext<'_>,
) -> Result<LpacVerifiedAuthority, String> {
    let (core, lpac) = verify_authority_core(request, live, RequiredCampaign::Lpac)?;
    let lpac = lpac.ok_or_else(|| "campaign-v1 authority cannot authorize LPAC".to_owned())?;
    Ok(LpacVerifiedAuthority {
        core,
        eligible_sandbox: lpac.eligible_sandbox,
        launch_app_container_executable_sha256: lpac.launch_app_container_executable_sha256,
        sandbox_process_executable_sha256: lpac.sandbox_process_executable_sha256,
        app_container_sid: lpac.app_container_sid,
    })
}

/// Verify the complete native authority chain and live host binding.
///
/// # Errors
///
/// Fails closed for malformed schemas, duplicate keys, invalid signatures or
/// freshness, broken raw-byte bindings, unsupported Phase-A scope, or any live
/// host/request mismatch.
#[allow(clippy::too_many_lines)] // Audit-friendly linear fail-closed validation pipeline.
fn verify_authority_core(
    request: &BrokerRequest,
    live: &LiveAuthorityContext<'_>,
    required_campaign: RequiredCampaign,
) -> Result<(AuthorityCore, Option<LpacCampaignFields>), String> {
    if request.schema_version != crate::broker_protocol::BROKER_REQUEST_SCHEMA {
        return Err("broker request schema is unsupported".to_owned());
    }
    crate::validate_run_nonce(&request.run_nonce).map_err(str::to_owned)?;
    if !(0..=253_402_300_799).contains(&live.now_unix_seconds) {
        return Err("live UTC time is outside the supported range".to_owned());
    }
    let materials = request.authority_materials()?;
    let campaign_document = parse_campaign(&materials.campaign)?;
    let lpac_fields = match (&campaign_document, required_campaign) {
        (Campaign::Standard(_), RequiredCampaign::Standard) => None,
        (Campaign::Lpac(campaign), RequiredCampaign::Lpac) => Some(LpacCampaignFields {
            eligible_sandbox: campaign.eligible_sandbox.clone(),
            launch_app_container_executable_sha256: campaign
                .launch_app_container_executable_sha256
                .clone(),
            sandbox_process_executable_sha256: campaign.sandbox_process_executable_sha256.clone(),
            app_container_sid: campaign.app_container_sid.clone(),
        }),
        (Campaign::Standard(_), RequiredCampaign::Lpac) => {
            return Err("campaign-v1 authority cannot authorize LPAC".to_owned());
        }
        (Campaign::Lpac(_), RequiredCampaign::Standard) => {
            return Err("campaign-v2 authority cannot bind the standard witness".to_owned());
        }
    };
    let campaign = campaign_document.view();
    let (scope, scope_value): (Scope, _) = parse(&materials.scope_manifest, "scope manifest")?;
    let (grant, grant_value): (Grant, _) = parse(&materials.execution_grant, "execution grant")?;
    let (acceptance, acceptance_value): (Acceptance, _) =
        parse(&materials.worker_acceptance, "worker acceptance")?;

    if scope.schema_version != SCOPE_SCHEMA
        || grant.schema_version != GRANT_SCHEMA
        || acceptance.schema_version != ACCEPTANCE_SCHEMA
    {
        return Err("authority schema version is unsupported".to_owned());
    }
    if !is_identifier(campaign.campaign_id, 256, b"_.:-") {
        return Err("campaign_id is invalid".to_owned());
    }
    validate_worker(campaign.worker)?;
    for (value, label) in [
        (
            &campaign.target_operation_sha256,
            "campaign target operation",
        ),
        (
            &campaign.control_operation_sha256,
            "campaign control operation",
        ),
    ] {
        validate_sha256(value, label)?;
    }
    if campaign.target_operation_sha256 == campaign.control_operation_sha256
        || !(2..=32).contains(&campaign.trials)
        || !(2..=campaign.trials).contains(&campaign.minimum_confirmations)
    {
        return Err("campaign is outside the Phase-A LPE contract".to_owned());
    }
    match &campaign_document {
        Campaign::Standard(_)
            if campaign.starting_context != "standard-user"
                || campaign.finishing_principal != "local-system" =>
        {
            return Err("campaign is outside the Phase-A LPE contract".to_owned());
        }
        Campaign::Lpac(lpac) => {
            if campaign.schema_version != LPAC_CAMPAIGN_SCHEMA
                || campaign.starting_context != "eligible-sandbox"
                || !matches!(
                    campaign.finishing_principal,
                    "elevated-user" | "local-system"
                )
            {
                return Err("campaign is outside the LPAC LPE contract".to_owned());
            }
            validate_eligible_sandbox(&lpac.eligible_sandbox)?;
            validate_sha256(
                &lpac.launch_app_container_executable_sha256,
                "campaign launch AppContainer executable",
            )?;
            validate_sha256(
                &lpac.sandbox_process_executable_sha256,
                "campaign sandbox process executable",
            )?;
            validate_package_app_container_sid(&lpac.app_container_sid)?;
        }
        Campaign::Standard(_) => {
            if campaign.schema_version != CAMPAIGN_SCHEMA {
                return Err("authority schema version is unsupported".to_owned());
            }
        }
    }

    for (value, label) in [
        (&scope.target_feature, "scope target_feature"),
        (&scope.reachability, "scope reachability"),
        (&scope.authorization, "scope authorization"),
        (&scope.preflight.product_name, "scope product_name"),
        (&scope.preflight.insider.content_type, "scope content_type"),
    ] {
        safe_text(value, label, 512)?;
    }
    validate_worker(&scope.worker)?;
    validate_nonce(&scope.nonce, "scope nonce")?;
    safe_text(&scope.authorized_by, "scope authorized_by", 256)?;
    validate_window(
        &scope.issued_at,
        &scope.expires_at,
        live.now_unix_seconds,
        "scope",
    )?;
    validate_fresh(
        &scope.latest_build_verified_at,
        live.now_unix_seconds,
        "latest build verification",
    )?;
    validate_fresh(
        &scope.preflight.checked_at,
        live.now_unix_seconds,
        "scope preflight",
    )?;
    if scope.program != "windows-canary"
        || scope.preflight.program != scope.program
        || !scope.preflight.ok
        || scope.reachability != "unprivileged local user"
        || scope.scope_url != "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview"
        || scope.latest_build_source_url
            != "https://learn.microsoft.com/en-us/windows-insider/flight-hub"
        || build_number(&scope.preflight.build_lab_ex)? != scope.latest_build_number
        || scope.preflight.insider.channel_family != "experimental-future-platforms"
        || (!scope
            .preflight
            .insider
            .ring
            .to_ascii_lowercase()
            .contains("future platforms")
            && scope.preflight.insider.branch_name.is_empty())
        || build_number(&scope.preflight.build_lab_ex)?
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0)
            < 29_000
    {
        return Err(
            "scope is not an exact current Windows Canary-successor authorization".to_owned(),
        );
    }
    let scope_material = canonical_signed_material(scope_value, "scope manifest")?;
    verify_ed25519(
        &scope_material,
        &scope.signature_ssh,
        &scope.authorized_by,
        SCOPE_NAMESPACE,
        live.authorization_allowed_signers,
    )?;

    for (value, label) in [
        (&grant.campaign_sha256, "grant campaign hash"),
        (&grant.scope_manifest_sha256, "grant scope hash"),
        (&grant.target_operation_sha256, "grant target operation"),
        (&grant.control_operation_sha256, "grant control operation"),
    ] {
        validate_sha256(value, label)?;
    }
    validate_worker(&grant.worker)?;
    validate_nonce(&grant.nonce, "grant nonce")?;
    safe_text(&grant.authorized_by, "grant authorized_by", 256)?;
    validate_window(
        &grant.issued_at,
        &grant.expires_at,
        live.now_unix_seconds,
        "grant",
    )?;
    if grant.target_operation_sha256 == grant.control_operation_sha256 {
        return Err("grant operation hashes are equal".to_owned());
    }
    let grant_material = canonical_signed_material(grant_value, "execution grant")?;
    verify_ed25519(
        &grant_material,
        &grant.signature_ssh,
        &grant.authorized_by,
        GRANT_NAMESPACE,
        live.authorization_allowed_signers,
    )?;

    for (value, label) in [
        (&acceptance.campaign_sha256, "acceptance campaign hash"),
        (&acceptance.scope_manifest_sha256, "acceptance scope hash"),
        (&acceptance.execution_grant_sha256, "acceptance grant hash"),
        (
            &acceptance.runner_executable_sha256,
            "acceptance runner hash",
        ),
        (
            &acceptance.witness_executable_sha256,
            "acceptance witness executable hash",
        ),
        (
            &acceptance.target_operation_sha256,
            "acceptance target operation",
        ),
        (
            &acceptance.control_operation_sha256,
            "acceptance control operation",
        ),
    ] {
        validate_sha256(value, label)?;
    }
    validate_worker(&acceptance.worker)?;
    validate_nonce(&acceptance.execution_grant_nonce, "acceptance grant nonce")?;
    validate_nonce(&acceptance.nonce, "acceptance nonce")?;
    safe_text(&acceptance.accepted_by, "acceptance accepted_by", 256)?;
    safe_text(&acceptance.capture_signer, "acceptance capture_signer", 256)?;
    safe_text(&acceptance.worker_machine_id, "acceptance machine id", 256)?;
    crate::capture_v3::validate_witness_provenance(
        &acceptance.witness_user_sid,
        acceptance.witness_session_id,
        &acceptance.witness_authentication_id,
    )?;
    safe_text(&acceptance.build_lab_ex, "acceptance BuildLabEx", 512)?;
    validate_window(
        &acceptance.issued_at,
        &acceptance.expires_at,
        live.now_unix_seconds,
        "acceptance",
    )?;
    if acceptance.nonce == acceptance.execution_grant_nonce
        || request.run_nonce == acceptance.nonce
        || request.run_nonce == acceptance.execution_grant_nonce
        || acceptance.target_operation_sha256 == acceptance.control_operation_sha256
    {
        return Err("acceptance nonce or operation separation is invalid".to_owned());
    }
    let acceptance_material = canonical_signed_material(acceptance_value, "worker acceptance")?;
    verify_ed25519(
        &acceptance_material,
        &acceptance.signature_ssh,
        &acceptance.accepted_by,
        ACCEPTANCE_NAMESPACE,
        live.acceptance_allowed_signers,
    )?;

    let campaign_sha256 = sha256(&materials.campaign);
    let scope_sha256 = sha256(&materials.scope_manifest);
    let grant_sha256 = sha256(&materials.execution_grant);
    let acceptance_sha256 = sha256(&materials.worker_acceptance);
    if grant.campaign_sha256 != campaign_sha256
        || grant.scope_manifest_sha256 != scope_sha256
        || acceptance.campaign_sha256 != campaign_sha256
        || acceptance.scope_manifest_sha256 != scope_sha256
        || acceptance.execution_grant_sha256 != grant_sha256
        || acceptance.execution_grant_nonce != grant.nonce
        || grant.campaign_id != campaign.campaign_id
        || scope.campaign_id != campaign.campaign_id
        || acceptance.campaign_id != campaign.campaign_id
        || grant.worker != campaign.worker
        || scope.worker != campaign.worker
        || acceptance.worker != campaign.worker
        || grant.target_operation_sha256 != campaign.target_operation_sha256
        || grant.control_operation_sha256 != campaign.control_operation_sha256
        || acceptance.target_operation_sha256 != campaign.target_operation_sha256
        || acceptance.control_operation_sha256 != campaign.control_operation_sha256
        || acceptance.build_lab_ex != scope.preflight.build_lab_ex
    {
        return Err("authority documents are not bound to one raw-byte chain".to_owned());
    }

    validate_worker(live.worker)?;
    validate_sha256(live.runner_executable_sha256, "live runner hash")?;
    if live.worker != campaign.worker
        || live.build_lab_ex != scope.preflight.build_lab_ex
        || live.worker_machine_id != acceptance.worker_machine_id
        || live.runner_executable_sha256 != acceptance.runner_executable_sha256
        || live.capture_signer != acceptance.capture_signer
        || request.trial == 0
        || request.trial > campaign.trials
    {
        return Err("live worker or broker selector is not authority-bound".to_owned());
    }
    let selected_operation_sha256 = match request.case.as_str() {
        "target" => campaign.target_operation_sha256.to_owned(),
        "control" => campaign.control_operation_sha256.to_owned(),
        _ => return Err("broker case is invalid".to_owned()),
    };

    let authority_issued_at_unix_seconds = [
        timestamp(&scope.issued_at, "scope issued_at")?,
        timestamp(&grant.issued_at, "grant issued_at")?,
        timestamp(&acceptance.issued_at, "acceptance issued_at")?,
    ]
    .into_iter()
    .max()
    .expect("authority chain has three issued timestamps");
    let authority_expires_at_unix_seconds = [
        timestamp(&scope.expires_at, "scope expires_at")?,
        timestamp(&grant.expires_at, "grant expires_at")?,
        timestamp(&acceptance.expires_at, "acceptance expires_at")?,
    ]
    .into_iter()
    .min()
    .expect("authority chain has three expiry timestamps");

    Ok((
        AuthorityCore {
            campaign_id: campaign.campaign_id.to_owned(),
            selected_operation_sha256,
            campaign_sha256,
            scope_sha256,
            grant_sha256,
            acceptance_sha256,
            grant_nonce: grant.nonce,
            acceptance_nonce: acceptance.nonce,
            worker: acceptance.worker,
            build_lab_ex: acceptance.build_lab_ex,
            worker_machine_id: acceptance.worker_machine_id,
            runner_executable_sha256: acceptance.runner_executable_sha256,
            witness_user_sid: acceptance.witness_user_sid,
            witness_session_id: acceptance.witness_session_id,
            witness_authentication_id: acceptance.witness_authentication_id,
            witness_executable_sha256: acceptance.witness_executable_sha256,
            capture_signer: acceptance.capture_signer,
            case: request.case.clone(),
            trial: request.trial,
            run_nonce: request.run_nonce.clone(),
            authority_issued_at_unix_seconds,
            authority_expires_at_unix_seconds,
            now_unix_seconds: live.now_unix_seconds,
        },
        lpac_fields,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_protocol::AuthorityMaterials;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    const CAMPAIGN: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v1/campaign.json");
    const SCOPE: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v1/scope.json");
    const GRANT: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v1/grant.json");
    const ACCEPTANCE: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v1/acceptance.json");
    const LPAC_CAMPAIGN: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v2/campaign.json");
    const LPAC_GRANT: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v2/grant.json");
    const LPAC_ACCEPTANCE: &[u8] =
        include_bytes!("../../../tests/fixtures/windows-token-authority-v2/acceptance.json");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");

    fn materials() -> AuthorityMaterials {
        AuthorityMaterials {
            campaign: CAMPAIGN.to_vec(),
            scope_manifest: SCOPE.to_vec(),
            execution_grant: GRANT.to_vec(),
            worker_acceptance: ACCEPTANCE.to_vec(),
        }
    }

    fn request() -> BrokerRequest {
        request_with_materials(materials())
    }

    fn lpac_materials() -> AuthorityMaterials {
        AuthorityMaterials {
            campaign: LPAC_CAMPAIGN.to_vec(),
            scope_manifest: SCOPE.to_vec(),
            execution_grant: LPAC_GRANT.to_vec(),
            worker_acceptance: LPAC_ACCEPTANCE.to_vec(),
        }
    }

    fn lpac_request() -> BrokerRequest {
        request_with_materials(lpac_materials())
    }

    fn request_with_materials(materials: AuthorityMaterials) -> BrokerRequest {
        BrokerRequest {
            schema_version: crate::broker_protocol::BROKER_REQUEST_SCHEMA.to_owned(),
            campaign_json_b64: URL_SAFE_NO_PAD.encode(materials.campaign),
            scope_manifest_json_b64: URL_SAFE_NO_PAD.encode(materials.scope_manifest),
            execution_grant_json_b64: URL_SAFE_NO_PAD.encode(materials.execution_grant),
            worker_acceptance_json_b64: URL_SAFE_NO_PAD.encode(materials.worker_acceptance),
            case: "target".to_owned(),
            trial: 1,
            run_nonce: "run_nonce_00000000000000000000000".to_owned(),
        }
    }

    fn live() -> LiveAuthorityContext<'static> {
        LiveAuthorityContext::new(
            timestamp("2026-07-15T00:00:00Z", "now").unwrap(),
            "canary-worker.example.test",
            "29617.1000.amd64fre.rs_prerelease.260701-1200",
            "machine-canonical-001",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "capture@example.test",
            POLICY,
            POLICY,
        )
    }

    fn witness_token(
        user_sid: &str,
        session_id: u32,
        authentication_id: &str,
    ) -> crate::witness::AuthenticatedWitnessToken {
        let binding = verify_authority(&request(), &live())
            .unwrap()
            .witness_rendezvous_spec()
            .unwrap()
            .binding_sha256()
            .to_owned();
        witness_token_with_binding(user_sid, session_id, authentication_id, &binding)
    }

    fn witness_token_with_binding(
        user_sid: &str,
        session_id: u32,
        authentication_id: &str,
        binding: &str,
    ) -> crate::witness::AuthenticatedWitnessToken {
        crate::witness::AuthenticatedWitnessToken::test_only(
            crate::witness::WitnessTokenProfile {
                user_sid: user_sid.to_owned(),
                session_id,
                authentication_id: authentication_id.to_owned(),
                token_type: "primary",
                integrity_rid: 0x2000,
                elevation_type: "default",
                elevated: false,
                admin_group: "absent",
                app_container: false,
                token_restricted: false,
                restricted_sid_count: 0,
                groups: vec![crate::witness::WitnessGroupFact {
                    sid: "S-1-1-0".to_owned(),
                    attributes: 0x7,
                }],
                privileges: vec![crate::witness::WitnessPrivilegeFact {
                    name: "SeChangeNotifyPrivilege".to_owned(),
                    attributes: 0x3,
                }],
                lpac_supported: true,
                less_privileged_app_container: false,
            },
            binding,
        )
    }

    #[test]
    fn verifies_cross_language_raw_byte_chain() {
        let verified = verify_authority(&request(), &live()).unwrap();
        assert_eq!(verified.campaign_id(), "canonical-lpe-001");
        assert_eq!(verified.selected_operation_sha256(), "1".repeat(64));
        let source_hashes = verified.source_hashes().map(str::to_owned);
        let spec = verified.witness_rendezvous_spec().unwrap();
        assert_eq!(spec.expected().user_sid(), "S-1-5-21-1-2-3-1001");
        assert_eq!(spec.expected().session_id(), 1);
        assert_eq!(spec.expected().authentication_id(), "0000000000001001");
        let identity_bound = verified
            .bind_witness_identity(witness_token("S-1-5-21-1-2-3-1001", 1, "0000000000001001"))
            .unwrap();
        let bound = identity_bound
            .bind_witness_executable(&"7".repeat(64))
            .unwrap();
        assert!(bound.witness_capability.test_only_shape_is_valid());
        assert!(bound.signing_authority().is_ok());
        let reservation = bound.reservation_fields();
        assert_eq!(reservation.case, "target");
        assert_eq!(reservation.trial, 1);
        assert_eq!(reservation.worker, "canary-worker.example.test");
        assert_eq!(reservation.campaign_sha256, source_hashes[0]);
        assert_eq!(reservation.scope_manifest_sha256, source_hashes[1]);
        assert_eq!(reservation.execution_grant_sha256, source_hashes[2]);
        assert_eq!(reservation.worker_acceptance_sha256, source_hashes[3]);
        assert_eq!(reservation.grant_nonce, "grant_nonce_000000000000000000000");
        assert_eq!(
            reservation.acceptance_nonce,
            "acceptance_nonce_0000000000000000"
        );
        assert_eq!(reservation.run_nonce, request().run_nonce);
        assert_eq!(reservation.operation_sha256, "1".repeat(64));
        assert_eq!(reservation.campaign_id, "canonical-lpe-001");
        assert_eq!(
            reservation.build_lab_ex,
            "29617.1000.amd64fre.rs_prerelease.260701-1200"
        );
        assert_eq!(reservation.worker_machine_id, "machine-canonical-001");
        assert_eq!(reservation.runner_executable_sha256, "3".repeat(64));
        assert_eq!(reservation.witness_user_sid, "S-1-5-21-1-2-3-1001");
        assert_eq!(reservation.witness_session_id, 1);
        assert_eq!(reservation.witness_authentication_id, "0000000000001001");
        assert_eq!(reservation.witness_executable_sha256, "7".repeat(64));
        assert_eq!(reservation.capture_signer, "capture@example.test");
        assert_eq!(
            source_hashes,
            [
                "70416b456f3b0f601083a4575c78ea4560e93d011544cff4a39cd8a5bcf824e9".to_owned(),
                "18fa1042a5dc39e341260d6594f56716040499503159169da796ffa4c2bc9506".to_owned(),
                "a73af300820d73a82e9e1ce6fbb627e956b55e278d052532e1590bfb05f99523".to_owned(),
                "a65dc8af644649570682c954f65dcce10c8771623166613a58b243a9a4c5a2ab".to_owned(),
            ]
        );
    }

    #[test]
    fn verifies_lpac_raw_byte_chain_into_distinct_capability() {
        let verified = verify_lpac_authority(&lpac_request(), &live()).unwrap();
        assert_eq!(verified.campaign_id(), "canonical-lpe-001");
        assert_eq!(verified.selected_operation_sha256(), "1".repeat(64));
        assert_eq!(verified.eligible_sandbox(), "windows-defender-msengcp");
        assert_eq!(
            verified.launch_app_container_executable_sha256(),
            "4".repeat(64)
        );
        assert_eq!(verified.sandbox_process_executable_sha256(), "5".repeat(64));
        assert_eq!(verified.app_container_sid(), "S-1-15-2-1-2-3-4-5-6-7-8");
        assert_eq!(
            verified.source_hashes(),
            [
                "cb6cb1cc3e3902227c76099b16105eb096f158d5cfdc44a224bf82fa799186a6",
                "18fa1042a5dc39e341260d6594f56716040499503159169da796ffa4c2bc9506",
                "c671558fa3496c5a26b980e3a9b57937a233759908064db328e4bfb1fd3fe455",
                "320ff9f2b9bf48c757e0e4d6873026ecc2d17144beecaf864b60fb06ff416728",
            ]
        );
        let reservation = verified.lpac_reservation_fields();
        assert_eq!(reservation.campaign_sha256, verified.source_hashes()[0]);
        assert_eq!(
            reservation.scope_manifest_sha256,
            verified.source_hashes()[1]
        );
        assert_eq!(
            reservation.execution_grant_sha256,
            verified.source_hashes()[2]
        );
        assert_eq!(
            reservation.worker_acceptance_sha256,
            verified.source_hashes()[3]
        );
        assert_eq!(reservation.grant_nonce, "grant_nonce_000000000000000000000");
        assert_eq!(
            reservation.acceptance_nonce,
            "acceptance_nonce_0000000000000000"
        );
        assert_eq!(reservation.campaign_id, "canonical-lpe-001");
        assert_eq!(reservation.case, "target");
        assert_eq!(reservation.trial, 1);
        assert_eq!(reservation.run_nonce, lpac_request().run_nonce);
        assert_eq!(reservation.operation_sha256, "1".repeat(64));
        assert_eq!(reservation.worker, "canary-worker.example.test");
        assert_eq!(
            reservation.build_lab_ex,
            "29617.1000.amd64fre.rs_prerelease.260701-1200"
        );
        assert_eq!(reservation.worker_machine_id, "machine-canonical-001");
        assert_eq!(reservation.runner_executable_sha256, "3".repeat(64));
        assert_eq!(
            reservation.authority_issued_at_unix_seconds,
            timestamp("2026-07-14T23:30:00Z", "issued").unwrap()
        );
        assert_eq!(
            reservation.authority_expires_at_unix_seconds,
            timestamp("2026-07-15T00:30:00Z", "expires").unwrap()
        );
        assert_eq!(reservation.now_unix_seconds, live().now_unix_seconds);
        assert_eq!(reservation.eligible_sandbox, "windows-defender-msengcp");
        assert_eq!(
            reservation.launch_app_container_executable_sha256,
            "4".repeat(64)
        );
        assert_eq!(
            reservation.sandbox_process_executable_sha256,
            "5".repeat(64)
        );
        assert_eq!(reservation.app_container_sid, "S-1-15-2-1-2-3-4-5-6-7-8");
    }

    #[test]
    fn campaign_capabilities_are_not_cross_issued() {
        assert!(
            verify_authority(&lpac_request(), &live())
                .err()
                .expect("campaign-v2 must not issue standard authority")
                .contains("cannot bind the standard witness")
        );
        assert!(
            verify_lpac_authority(&request(), &live())
                .err()
                .expect("campaign-v1 must not issue LPAC authority")
                .contains("cannot authorize LPAC")
        );
    }

    #[test]
    fn device_open_capability_requires_exact_selected_raw_manifest_digest() {
        let verified = verify_authority(&request(), &live()).unwrap();
        let selected = verified.selected_operation_sha256.clone();
        let campaign_id = verified.campaign_id.clone();
        let exact = crate::device_open_authority::VerifiedDeviceOpenBoundary::test_only(
            &selected,
            &campaign_id,
        );
        assert!(verified.bind_device_open_boundary(exact).is_ok());

        let wrong = verify_authority(&request(), &live()).unwrap();
        let drifted = crate::device_open_authority::VerifiedDeviceOpenBoundary::test_only(
            &"0".repeat(64),
            &campaign_id,
        );
        assert!(wrong.bind_device_open_boundary(drifted).is_err());

        let wrong_campaign = verify_authority(&request(), &live()).unwrap();
        let drifted_campaign = crate::device_open_authority::VerifiedDeviceOpenBoundary::test_only(
            &selected,
            "other-campaign",
        );
        assert!(
            wrong_campaign
                .bind_device_open_boundary(drifted_campaign)
                .is_err()
        );

        let role_collision = verify_authority(&request(), &live()).unwrap();
        let capture_signer = role_collision.capture_signer.clone();
        let colliding =
            crate::device_open_authority::VerifiedDeviceOpenBoundary::test_only_with_receipt_signer(
                &selected,
                &campaign_id,
                &capture_signer,
            );
        assert!(role_collision.bind_device_open_boundary(colliding).is_err());

        let authorization_collision = verify_authority(&request(), &live()).unwrap();
        let colliding =
            crate::device_open_authority::VerifiedDeviceOpenBoundary::test_only_with_receipt_signer(
                &selected,
                &campaign_id,
                "boundary-authorizer@example.test",
            );
        assert!(
            authorization_collision
                .bind_device_open_boundary(colliding)
                .is_err()
        );
    }

    #[test]
    fn device_open_execution_hash_and_freshness_axes_fail_independently() {
        let hash = "1".repeat(64);
        assert!(device_open_executable_hashes_match(
            &hash, &hash, &hash, &hash
        ));
        for values in [
            ("0".repeat(64), hash.clone(), hash.clone(), hash.clone()),
            (hash.clone(), "0".repeat(64), hash.clone(), hash.clone()),
            (hash.clone(), hash.clone(), "0".repeat(64), hash.clone()),
            (hash.clone(), hash.clone(), hash.clone(), "0".repeat(64)),
        ] {
            assert!(!device_open_executable_hashes_match(
                &values.0, &values.1, &values.2, &values.3
            ));
        }

        assert!(device_open_times_are_fresh(100, 1_000, 200, 900, 500, 500));
        assert!(!device_open_times_are_fresh(100, 500, 200, 900, 500, 500));
        assert!(!device_open_times_are_fresh(100, 1_000, 200, 500, 500, 500));
        assert!(!device_open_times_are_fresh(100, 1_000, 200, 900, 100, 500));
    }

    fn lpac_request_with_campaign_change(
        mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> BrokerRequest {
        let mut request = lpac_request();
        let mut value = parse_strict_json_object(LPAC_CAMPAIGN, "campaign").unwrap();
        mutate(value.as_object_mut().unwrap());
        request.campaign_json_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
        request
    }

    #[test]
    fn rejects_inexact_lpac_campaign_fields_before_chain_issuance() {
        let invalid = [
            (
                "starting_context",
                Value::String("appcontainer".to_owned()),
                "LPAC LPE contract",
            ),
            (
                "eligible_sandbox",
                Value::String("generic-appcontainer".to_owned()),
                "exact eligible value",
            ),
            (
                "launch_app_container_executable_sha256",
                Value::String("4".repeat(63)),
                "lowercase SHA-256",
            ),
            (
                "sandbox_process_executable_sha256",
                Value::String("G".repeat(64)),
                "lowercase SHA-256",
            ),
            (
                "app_container_sid",
                Value::String("S-1-15-2-1".to_owned()),
                "exact package SID",
            ),
            (
                "app_container_sid",
                Value::String(format!("S-1-15-2-{}-2-3-4-5-6-7-8", "9".repeat(5_000))),
                "exact package SID",
            ),
        ];
        for (field, value, message) in invalid {
            let changed = lpac_request_with_campaign_change(|campaign| {
                campaign.insert(field.to_owned(), value);
            });
            let error = verify_lpac_authority(&changed, &live())
                .err()
                .expect("invalid LPAC field must be rejected");
            assert!(error.contains(message), "unexpected {field} error: {error}");
        }

        let missing = lpac_request_with_campaign_change(|campaign| {
            campaign.remove("eligible_sandbox");
        });
        assert!(
            verify_lpac_authority(&missing, &live())
                .err()
                .expect("missing LPAC field must be rejected")
                .contains("missing field")
        );
        let unknown = lpac_request_with_campaign_change(|campaign| {
            campaign.insert("generic_sandbox".to_owned(), Value::Bool(true));
        });
        assert!(
            verify_lpac_authority(&unknown, &live())
                .err()
                .expect("unknown LPAC field must be rejected")
                .contains("unknown field")
        );
    }

    #[test]
    fn lpac_authority_rejects_raw_chain_and_live_host_mismatch() {
        let mut changed = lpac_request();
        changed.campaign_json_b64 = URL_SAFE_NO_PAD.encode([LPAC_CAMPAIGN, b" "].concat());
        assert!(
            verify_lpac_authority(&changed, &live())
                .err()
                .expect("mutated LPAC raw bytes must be rejected")
                .contains("raw-byte chain")
        );

        let wrong_machine = LiveAuthorityContext {
            worker_machine_id: "other-machine",
            ..live()
        };
        assert!(
            verify_lpac_authority(&lpac_request(), &wrong_machine)
                .err()
                .expect("LPAC live-host mismatch must be rejected")
                .contains("live worker")
        );
    }

    #[test]
    fn rejects_raw_mutation_live_mismatch_and_expiry() {
        let mut changed = request();
        changed.campaign_json_b64 = URL_SAFE_NO_PAD.encode([CAMPAIGN, b" "].concat());
        assert!(verify_authority(&changed, &live()).is_err());

        let wrong_worker = LiveAuthorityContext {
            worker: "other.example.test",
            ..live()
        };
        assert!(verify_authority(&request(), &wrong_worker).is_err());

        let stale = LiveAuthorityContext {
            now_unix_seconds: timestamp("2026-07-15T00:31:00Z", "now").unwrap(),
            ..live()
        };
        assert!(verify_authority(&request(), &stale).is_err());

        for witness in [
            witness_token("S-1-5-21-1-2-3-1002", 1, "0000000000001001"),
            witness_token("S-1-5-21-1-2-3-1001", 2, "0000000000001001"),
            witness_token("S-1-5-21-1-2-3-1001", 1, "0000000000001002"),
        ] {
            assert!(
                verify_authority(&request(), &live())
                    .unwrap()
                    .bind_witness_identity(witness)
                    .is_err()
            );
        }
        assert!(
            verify_authority(&request(), &live())
                .unwrap()
                .bind_witness_identity(witness_token_with_binding(
                    "S-1-5-21-1-2-3-1001",
                    1,
                    "0000000000001001",
                    &"f".repeat(64),
                ))
                .is_err()
        );

        let identity_bound = verify_authority(&request(), &live())
            .unwrap()
            .bind_witness_identity(witness_token("S-1-5-21-1-2-3-1001", 1, "0000000000001001"))
            .unwrap();
        assert!(
            identity_bound
                .bind_witness_executable(&"8".repeat(64))
                .is_err()
        );
    }

    #[test]
    fn rejects_recursive_duplicates_and_out_of_range_trial() {
        let mut changed = request();
        changed.scope_manifest_json_b64 = URL_SAFE_NO_PAD.encode(
            br#"{"schema_version":"0verse.windows-scope/v2","preflight":{"ok":true,"ok":false}}"#,
        );
        assert!(verify_authority(&changed, &live()).is_err());

        let out_of_range = BrokerRequest {
            trial: 3,
            ..request()
        };
        assert!(verify_authority(&out_of_range, &live()).is_err());

        let nonce_collision = BrokerRequest {
            run_nonce: "grant_nonce_000000000000000000000".to_owned(),
            ..request()
        };
        assert!(verify_authority(&nonce_collision, &live()).is_err());

        let invalid_clock = LiveAuthorityContext {
            now_unix_seconds: i64::MAX,
            ..live()
        };
        assert!(verify_authority(&request(), &invalid_clock).is_err());
    }
}
