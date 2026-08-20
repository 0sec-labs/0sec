#![allow(
    dead_code,
    reason = "the platform-neutral signing gate lands before the reviewed Windows broker wiring"
)]

//! Strict, capability-only Windows device-open receipt construction.
//!
//! This module has no Windows APIs and accepts no raw handle value as receipt
//! input. The source handle remains confined to the authenticated observation
//! transcript; only its digest crosses into the signed receipt.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
#[cfg(any(test, windows))]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(test)]
use crate::device_open_protocol::DeviceOpenObservation;

const SCHEMA_VERSION: &str = "0verse.windows-device-open-boundary-receipt/v2";
const SIGNATURE_NAMESPACE: &str = "0verse-windows-device-open-boundary-receipt-v2";
const OBSERVATION_KIND: &str = "natural-standard-user-device-open";
const EVIDENCE_CLASS: &str = "candidate-capability-only";
const PRODUCER_AUTHORITY: &str = "system-held-device-open-broker";
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 512;
const MAX_OBSERVATION_AGE_MS: i128 = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS: i128 = 5 * 60 * 1000;

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct BrokerAuthorityFacts {
    duplicate_handle_held_during_signing: bool,
    revalidated_primary_token: bool,
    reenumerated_interface: bool,
    child_source_handle_closed_cleanly: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct LiveMachineFacts<'a> {
    worker: &'a str,
    worker_machine_id: &'a str,
    worker_acceptance_sha256: &'a str,
    windows_build_lab_ex: &'a str,
    windows_ubr: u32,
    boot_id: &'a str,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct CollectorFacts<'a> {
    boundary_manifest_sha256: &'a str,
    collector_id: &'a str,
    collector_sha256: &'a str,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct InstalledDriverFacts<'a> {
    driver_id: &'a str,
    driver_service_name: &'a str,
    driver_image_sha256: &'a str,
    interface_class_guid: &'a str,
    interface_instance_id: &'a str,
    interface_path_sha256: &'a str,
}

#[cfg(test)]
#[derive(Debug)]
struct ReceiptInputs<'a> {
    authority: BrokerAuthorityFacts,
    live: LiveMachineFacts<'a>,
    collector: CollectorFacts<'a>,
    installed_driver: InstalledDriverFacts<'a>,
    observation: &'a DeviceOpenObservation,
    receipt_nonce: &'a str,
    signed_by: &'a str,
}

#[derive(Debug, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    reason = "field names and explicit booleans are the exact Python wire contract"
)]
struct Receipt<'a> {
    schema_version: &'static str,
    observation_kind: &'static str,
    evidence_class: &'static str,
    producer_authority: &'static str,
    broker_duplicate_handle_held_during_signing: bool,
    broker_revalidated_primary_token: bool,
    broker_reenumerated_interface: bool,
    worker: &'a str,
    worker_machine_id: &'a str,
    worker_acceptance_sha256: &'a str,
    windows_build_lab_ex: &'a str,
    windows_ubr: u32,
    boot_id: &'a str,
    boundary_manifest_sha256: &'a str,
    collector_id: &'a str,
    collector_sha256: &'a str,
    collector_registry_sha256: &'a str,
    driver_id: &'a str,
    driver_service_name: &'a str,
    driver_image_sha256: &'a str,
    interface_class_guid: &'a str,
    interface_instance_id: &'a str,
    interface_path_sha256: &'a str,
    enumeration_api: &'a str,
    enumeration_flags: u32,
    interface_count: u32,
    selected_interface_index: u32,
    create_file_api: &'a str,
    desired_access: u32,
    share_mode: u32,
    security_attributes_null: bool,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template_file_null: bool,
    process_id: u32,
    process_creation_filetime: u64,
    primary_token_id: u64,
    primary_token_modified_id: u64,
    token_type: &'a str,
    thread_token_present: bool,
    impersonation_active: bool,
    elevation_type: &'a str,
    elevated: bool,
    integrity_rid: u32,
    admin_group_present: bool,
    linked_token_present: bool,
    token_restricted: bool,
    restricted_sid_count: u32,
    enabled_privileges: &'a [String],
    app_container: bool,
    debug_privilege_present: bool,
    user_sid: &'a str,
    authentication_id: &'a str,
    session_id: u32,
    observation_started_at: &'a str,
    observation_completed_at: &'a str,
    create_file_succeeded: bool,
    handle_held_during_observation: bool,
    handle_closed_cleanly: bool,
    device_io_control_call_count: u32,
    driver_load_call_count: u32,
    device_handle_read_call_count: u32,
    device_handle_write_call_count: u32,
    observation_transcript_sha256: String,
    receipt_nonce: &'a str,
    signed_by: &'a str,
    signature_ssh: String,
}

/// Unsigned receipt material that can exist only while the broker-held device
/// capability (including its duplicated handle) remains borrowed and live.
#[cfg(windows)]
struct PreparedDeviceOpenReceipt<'a> {
    authority: &'a crate::authority::BrokerHeldDeviceOpenAuthority,
    receipt: Receipt<'a>,
    reservation: crate::device_open_store::Reservation,
}

/// Signed, immediately verified bytes still borrowing the broker-held device
/// capability. Publication code cannot drop the duplicate before consuming
/// these bytes into the immutable completion store.
#[cfg(windows)]
struct SignedDeviceOpenReceipt<'a> {
    _authority: &'a crate::authority::BrokerHeldDeviceOpenAuthority,
    reservation: crate::device_open_store::Reservation,
    bytes: Vec<u8>,
}

/// Protected key material that can be minted only after this exact receipt's
/// replay identities have been durably reserved.
#[cfg(windows)]
pub(crate) struct ReservedDeviceOpenSigner {
    reservation: crate::device_open_store::Reservation,
    private_key: Zeroizing<Vec<u8>>,
    allowed_signers: String,
}

#[cfg(windows)]
impl ReservedDeviceOpenSigner {
    pub(crate) fn new(
        reservation: crate::device_open_store::Reservation,
        private_key: Zeroizing<Vec<u8>>,
        allowed_signers: String,
    ) -> Self {
        Self {
            reservation,
            private_key,
            allowed_signers,
        }
    }
}

#[cfg(windows)]
impl<'a> PreparedDeviceOpenReceipt<'a> {
    fn reservation(&self) -> &crate::device_open_store::Reservation {
        &self.reservation
    }

    /// Sign and immediately verify while the broker duplicate remains held.
    fn sign(self, signer: ReservedDeviceOpenSigner) -> Result<SignedDeviceOpenReceipt<'a>, String> {
        self.authority.require_fresh_for_signing()?;
        if signer.reservation != self.reservation {
            return Err(
                "reserved device-open signer does not bind the prepared receipt".to_owned(),
            );
        }
        let bytes =
            sign_constructed_receipt(self.receipt, signer.private_key, &signer.allowed_signers)?;
        Ok(SignedDeviceOpenReceipt {
            _authority: self.authority,
            reservation: self.reservation,
            bytes,
        })
    }
}

/// Prepare the exact unsigned receipt and replay reservation from opaque,
/// already-verified capabilities. No raw broker booleans or collector/driver
/// strings cross this production boundary.
#[cfg(windows)]
fn prepare_device_open_receipt<'a>(
    authority: &'a crate::authority::BrokerHeldDeviceOpenAuthority,
    receipt_nonce: &'a str,
) -> Result<PreparedDeviceOpenReceipt<'a>, String> {
    authority.require_fresh_for_signing()?;
    let observation = authority.held.observation();
    observation.validate()?;
    let installed_driver = authority.held.installed_driver();
    let boundary = authority.authority.boundary();
    let transcript = serde_json::to_vec(observation)
        .map_err(|error| format!("cannot canonicalize device-open observation: {error}"))?;
    let transcript_sha256 = format!("{:x}", Sha256::digest(&transcript));
    let receipt = Receipt {
        schema_version: SCHEMA_VERSION,
        observation_kind: OBSERVATION_KIND,
        evidence_class: EVIDENCE_CLASS,
        producer_authority: PRODUCER_AUTHORITY,
        broker_duplicate_handle_held_during_signing: true,
        broker_revalidated_primary_token: true,
        broker_reenumerated_interface: true,
        worker: authority.authority.worker(),
        worker_machine_id: authority.authority.worker_machine_id(),
        worker_acceptance_sha256: authority.authority.worker_acceptance_sha256(),
        windows_build_lab_ex: authority.authority.build_lab_ex(),
        windows_ubr: authority.live.windows_ubr,
        boot_id: &authority.live.boot_id,
        boundary_manifest_sha256: boundary.manifest_sha256(),
        collector_id: boundary.collector_id(),
        collector_sha256: boundary.collector_sha256(),
        collector_registry_sha256: &observation.collector_registry_sha256,
        driver_id: &observation.driver_id,
        driver_service_name: installed_driver.service_name,
        driver_image_sha256: &installed_driver.sha256,
        interface_class_guid: &observation.interface_class_guid,
        interface_instance_id: &observation.interface_instance_id,
        interface_path_sha256: &observation.interface_path_sha256,
        enumeration_api: &observation.enumeration_api,
        enumeration_flags: observation.enumeration_flags,
        interface_count: observation.interface_count,
        selected_interface_index: observation.selected_interface_index,
        create_file_api: &observation.create_file_api,
        desired_access: observation.desired_access,
        share_mode: observation.share_mode,
        security_attributes_null: observation.security_attributes_null,
        creation_disposition: observation.creation_disposition,
        flags_and_attributes: observation.flags_and_attributes,
        template_file_null: observation.template_file_null,
        process_id: observation.process_id,
        process_creation_filetime: observation.process_creation_filetime,
        primary_token_id: observation.primary_token_id,
        primary_token_modified_id: observation.primary_token_modified_id,
        token_type: &observation.token_type,
        thread_token_present: observation.thread_token_present,
        impersonation_active: observation.impersonation_active,
        elevation_type: &observation.elevation_type,
        elevated: observation.elevated,
        integrity_rid: observation.integrity_rid,
        admin_group_present: observation.admin_group_present,
        linked_token_present: observation.linked_token_present,
        token_restricted: observation.token_restricted,
        restricted_sid_count: observation.restricted_sid_count,
        enabled_privileges: &observation.enabled_privileges,
        app_container: observation.app_container,
        debug_privilege_present: observation.debug_privilege_present,
        user_sid: &observation.user_sid,
        authentication_id: &observation.authentication_id,
        session_id: observation.session_id,
        observation_started_at: &observation.observation_started_at,
        observation_completed_at: &observation.observation_completed_at,
        create_file_succeeded: observation.create_file_succeeded,
        handle_held_during_observation: observation.handle_held_during_observation,
        handle_closed_cleanly: true,
        device_io_control_call_count: observation.device_io_control_call_count,
        driver_load_call_count: observation.driver_load_call_count,
        device_handle_read_call_count: observation.device_handle_read_call_count,
        device_handle_write_call_count: observation.device_handle_write_call_count,
        observation_transcript_sha256: transcript_sha256.clone(),
        receipt_nonce,
        signed_by: boundary.receipt_signer(),
        signature_ssh: String::new(),
    };
    let now_ms = live_unix_milliseconds()?;
    validate_constructed_receipt(&receipt, now_ms)?;
    let material = canonical_json_without_signature(&receipt)?;
    let unsigned_receipt_sha256 = format!("{:x}", Sha256::digest(&material));
    let reservation = crate::device_open_store::Reservation::new(
        authority.authority.worker_machine_id(),
        receipt_nonce,
        &authority.live.boot_id,
        &observation.interface_path_sha256,
        &transcript_sha256,
        &unsigned_receipt_sha256,
    )?;
    Ok(PreparedDeviceOpenReceipt {
        authority,
        receipt,
        reservation,
    })
}

/// The sole production transition that can use the protected receipt key.
/// It does not return receipt bytes until all replay burns and immutable
/// close/reopen readback have succeeded.
#[cfg(windows)]
pub(crate) fn sign_and_publish(
    authority: crate::authority::BrokerHeldDeviceOpenAuthority,
    store: &crate::device_open_store::DeviceOpenStore,
) -> Result<PublishedDeviceOpenReceipt, String> {
    let receipt_nonce = crate::windows::random_identifier()?;
    let receipt_bytes = {
        let prepared = prepare_device_open_receipt(&authority, &receipt_nonce)?;
        let reserved_signer = store.reserve_and_load_signer(
            prepared.reservation(),
            authority.authority.boundary().receipt_signer(),
            authority.authority.boundary().authorized_by(),
            authority.authority.boundary().authorization_policy_sha256(),
            authority.authority.boundary().authorizer_key_sha256(),
        )?;
        let signed_receipt = prepared.sign(reserved_signer)?;
        match store.complete(&signed_receipt.reservation, &signed_receipt.bytes)? {
            crate::device_open_store::CompletionStatus::Created(bytes)
            | crate::device_open_store::CompletionStatus::AlreadyCompleted(bytes) => bytes,
        }
    };
    Ok(PublishedDeviceOpenReceipt {
        authority,
        receipt_bytes,
    })
}

/// Durable publication capability. Receipt bytes remain private until the
/// exact child has exited and the broker duplicate has been dropped.
#[cfg(windows)]
pub(crate) struct PublishedDeviceOpenReceipt {
    authority: crate::authority::BrokerHeldDeviceOpenAuthority,
    receipt_bytes: Vec<u8>,
}

#[cfg(windows)]
impl PublishedDeviceOpenReceipt {
    pub(crate) fn shutdown_after_publication(
        self,
        stop_event: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<Vec<u8>, String> {
        let Self {
            authority,
            receipt_bytes,
        } = self;
        authority.held.shutdown_after_publication(stop_event)?;
        Ok(receipt_bytes)
    }
}

/// Construct, sign, immediately verify, and canonically encode one receipt.
///
/// The private key buffer is consumed by the SSHSIG primitive and zeroized.
/// The returned JSON is Python-compatible canonical JSON followed by one LF.
///
/// # Errors
///
/// Fails closed for an invalid observation, incomplete authority, mismatched
/// live bindings, stale data, unsafe signing inputs, or failed verification.
#[cfg(test)]
fn sign_device_open_receipt(
    inputs: &ReceiptInputs<'_>,
    private_key_pem: Zeroizing<Vec<u8>>,
    allowed_signers: &str,
) -> Result<Vec<u8>, String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_millis();
    let now_ms = i128::try_from(now_ms).map_err(|_| "system clock is out of range".to_owned())?;
    sign_device_open_receipt_at(inputs, private_key_pem, allowed_signers, now_ms)
}

#[cfg(test)]
fn sign_device_open_receipt_at(
    inputs: &ReceiptInputs<'_>,
    private_key_pem: Zeroizing<Vec<u8>>,
    allowed_signers: &str,
    now_unix_ms: i128,
) -> Result<Vec<u8>, String> {
    inputs.observation.validate()?;
    validate_inputs(inputs, now_unix_ms)?;

    let transcript = serde_json::to_vec(inputs.observation)
        .map_err(|error| format!("cannot canonicalize device-open observation: {error}"))?;
    let transcript_sha256 = format!("{:x}", Sha256::digest(&transcript));
    let observation = inputs.observation;
    let receipt = Receipt {
        schema_version: SCHEMA_VERSION,
        observation_kind: OBSERVATION_KIND,
        evidence_class: EVIDENCE_CLASS,
        producer_authority: PRODUCER_AUTHORITY,
        broker_duplicate_handle_held_during_signing: inputs
            .authority
            .duplicate_handle_held_during_signing,
        broker_revalidated_primary_token: inputs.authority.revalidated_primary_token,
        broker_reenumerated_interface: inputs.authority.reenumerated_interface,
        worker: inputs.live.worker,
        worker_machine_id: inputs.live.worker_machine_id,
        worker_acceptance_sha256: inputs.live.worker_acceptance_sha256,
        windows_build_lab_ex: inputs.live.windows_build_lab_ex,
        windows_ubr: inputs.live.windows_ubr,
        boot_id: inputs.live.boot_id,
        boundary_manifest_sha256: inputs.collector.boundary_manifest_sha256,
        collector_id: inputs.collector.collector_id,
        collector_sha256: inputs.collector.collector_sha256,
        collector_registry_sha256: &observation.collector_registry_sha256,
        driver_id: inputs.installed_driver.driver_id,
        driver_service_name: inputs.installed_driver.driver_service_name,
        driver_image_sha256: inputs.installed_driver.driver_image_sha256,
        interface_class_guid: inputs.installed_driver.interface_class_guid,
        interface_instance_id: inputs.installed_driver.interface_instance_id,
        interface_path_sha256: inputs.installed_driver.interface_path_sha256,
        enumeration_api: &observation.enumeration_api,
        enumeration_flags: observation.enumeration_flags,
        interface_count: observation.interface_count,
        selected_interface_index: observation.selected_interface_index,
        create_file_api: &observation.create_file_api,
        desired_access: observation.desired_access,
        share_mode: observation.share_mode,
        security_attributes_null: observation.security_attributes_null,
        creation_disposition: observation.creation_disposition,
        flags_and_attributes: observation.flags_and_attributes,
        template_file_null: observation.template_file_null,
        process_id: observation.process_id,
        process_creation_filetime: observation.process_creation_filetime,
        primary_token_id: observation.primary_token_id,
        primary_token_modified_id: observation.primary_token_modified_id,
        token_type: &observation.token_type,
        thread_token_present: observation.thread_token_present,
        impersonation_active: observation.impersonation_active,
        elevation_type: &observation.elevation_type,
        elevated: observation.elevated,
        integrity_rid: observation.integrity_rid,
        admin_group_present: observation.admin_group_present,
        linked_token_present: observation.linked_token_present,
        token_restricted: observation.token_restricted,
        restricted_sid_count: observation.restricted_sid_count,
        enabled_privileges: &observation.enabled_privileges,
        app_container: observation.app_container,
        debug_privilege_present: observation.debug_privilege_present,
        user_sid: &observation.user_sid,
        authentication_id: &observation.authentication_id,
        session_id: observation.session_id,
        observation_started_at: &observation.observation_started_at,
        observation_completed_at: &observation.observation_completed_at,
        create_file_succeeded: observation.create_file_succeeded,
        handle_held_during_observation: observation.handle_held_during_observation,
        handle_closed_cleanly: inputs.authority.child_source_handle_closed_cleanly,
        device_io_control_call_count: observation.device_io_control_call_count,
        driver_load_call_count: observation.driver_load_call_count,
        device_handle_read_call_count: observation.device_handle_read_call_count,
        device_handle_write_call_count: observation.device_handle_write_call_count,
        observation_transcript_sha256: transcript_sha256,
        receipt_nonce: inputs.receipt_nonce,
        signed_by: inputs.signed_by,
        signature_ssh: String::new(),
    };

    sign_constructed_receipt(receipt, private_key_pem, allowed_signers)
}

fn live_unix_milliseconds() -> Result<i128, String> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_millis();
    i128::try_from(milliseconds).map_err(|_| "system clock is out of range".to_owned())
}

fn validate_constructed_receipt(receipt: &Receipt<'_>, now_unix_ms: i128) -> Result<(), String> {
    if !receipt.broker_duplicate_handle_held_during_signing
        || !receipt.broker_revalidated_primary_token
        || !receipt.broker_reenumerated_interface
        || !receipt.handle_closed_cleanly
    {
        return Err("Windows device-open receipt lacks broker-held authority facts".to_owned());
    }
    for (name, value) in [
        ("worker_machine_id", receipt.worker_machine_id),
        ("worker_acceptance_sha256", receipt.worker_acceptance_sha256),
        ("boundary_manifest_sha256", receipt.boundary_manifest_sha256),
        ("collector_sha256", receipt.collector_sha256),
        (
            "collector_registry_sha256",
            receipt.collector_registry_sha256,
        ),
        ("driver_image_sha256", receipt.driver_image_sha256),
        ("interface_path_sha256", receipt.interface_path_sha256),
        (
            "observation_transcript_sha256",
            &receipt.observation_transcript_sha256,
        ),
    ] {
        if !valid_sha256(value) {
            return Err(format!(
                "Windows device-open receipt {name} must be a SHA-256"
            ));
        }
    }
    for (name, value) in [
        ("worker", receipt.worker),
        ("windows_build_lab_ex", receipt.windows_build_lab_ex),
        ("collector_id", receipt.collector_id),
        ("driver_id", receipt.driver_id),
        ("driver_service_name", receipt.driver_service_name),
        ("interface_instance_id", receipt.interface_instance_id),
        ("signed_by", receipt.signed_by),
    ] {
        safe_text(value, name)?;
    }
    validate_uuid(receipt.boot_id)?;
    validate_guid(receipt.interface_class_guid)?;
    validate_nonce(receipt.receipt_nonce)?;
    let target = crate::device_open_protocol::fixed_target();
    if receipt.driver_id != target.driver_id
        || receipt.driver_service_name != target.driver_service_name
        || receipt.driver_image_sha256 != target.expected_installed_driver_image_sha256
        || receipt.interface_class_guid != target.interface_class_guid
        || receipt.interface_instance_id != target.interface_instance_id
    {
        return Err(
            "Windows device-open receipt differs from the fixed installed driver".to_owned(),
        );
    }
    let started = parse_timestamp_ms(receipt.observation_started_at)?;
    let completed = parse_timestamp_ms(receipt.observation_completed_at)?;
    if completed < started || completed - started > MAX_FUTURE_SKEW_MS {
        return Err(
            "Windows device-open receipt timestamps are out of order or too long".to_owned(),
        );
    }
    if completed > now_unix_ms + MAX_FUTURE_SKEW_MS
        || now_unix_ms - completed > MAX_OBSERVATION_AGE_MS
    {
        return Err(
            "Windows device-open receipt is outside the 24-hour evidence window".to_owned(),
        );
    }
    Ok(())
}

fn sign_constructed_receipt(
    mut receipt: Receipt<'_>,
    private_key_pem: Zeroizing<Vec<u8>>,
    allowed_signers: &str,
) -> Result<Vec<u8>, String> {
    let material = canonical_json_without_signature(&receipt)?;
    crate::sshsig::verify_private_key_identity(
        private_key_pem.as_slice(),
        receipt.signed_by,
        allowed_signers,
    )?;
    receipt.signature_ssh =
        crate::sshsig::sign_ed25519(&material, private_key_pem, SIGNATURE_NAMESPACE)?;
    crate::sshsig::verify_ed25519(
        &material,
        &receipt.signature_ssh,
        receipt.signed_by,
        SIGNATURE_NAMESPACE,
        allowed_signers,
    )?;
    let mut source = canonical_json(&receipt)?;
    source.push(b'\n');
    if source.len() > MAX_RECEIPT_BYTES {
        return Err("Windows device-open receipt exceeds the size limit".to_owned());
    }
    Ok(source)
}

#[cfg(test)]
fn validate_inputs(inputs: &ReceiptInputs<'_>, now_unix_ms: i128) -> Result<(), String> {
    let authority = inputs.authority;
    if !authority.duplicate_handle_held_during_signing
        || !authority.revalidated_primary_token
        || !authority.reenumerated_interface
        || !authority.child_source_handle_closed_cleanly
    {
        return Err("Windows device-open receipt lacks broker-held authority facts".to_owned());
    }
    for (name, value) in [
        ("worker_machine_id", inputs.live.worker_machine_id),
        (
            "worker_acceptance_sha256",
            inputs.live.worker_acceptance_sha256,
        ),
        (
            "boundary_manifest_sha256",
            inputs.collector.boundary_manifest_sha256,
        ),
        ("collector_sha256", inputs.collector.collector_sha256),
        (
            "driver_image_sha256",
            inputs.installed_driver.driver_image_sha256,
        ),
        (
            "interface_path_sha256",
            inputs.installed_driver.interface_path_sha256,
        ),
    ] {
        if !valid_sha256(value) {
            return Err(format!(
                "Windows device-open receipt {name} must be a SHA-256"
            ));
        }
    }
    for (name, value) in [
        ("worker", inputs.live.worker),
        ("windows_build_lab_ex", inputs.live.windows_build_lab_ex),
        ("collector_id", inputs.collector.collector_id),
        ("driver_id", inputs.installed_driver.driver_id),
        (
            "driver_service_name",
            inputs.installed_driver.driver_service_name,
        ),
        (
            "interface_instance_id",
            inputs.installed_driver.interface_instance_id,
        ),
        ("signed_by", inputs.signed_by),
    ] {
        safe_text(value, name)?;
    }
    if !valid_sha256(&inputs.observation.collector_registry_sha256) {
        return Err(
            "Windows device-open receipt collector_registry_sha256 must be a SHA-256".to_owned(),
        );
    }
    validate_uuid(inputs.live.boot_id)?;
    validate_guid(inputs.installed_driver.interface_class_guid)?;
    validate_nonce(inputs.receipt_nonce)?;

    let observation = inputs.observation;
    if inputs.installed_driver.driver_id != observation.driver_id
        || inputs.installed_driver.driver_service_name != observation.driver_service_name
        || inputs.installed_driver.driver_image_sha256
            != crate::device_open_protocol::fixed_target().expected_installed_driver_image_sha256
        || inputs.installed_driver.interface_class_guid != observation.interface_class_guid
        || inputs.installed_driver.interface_instance_id != observation.interface_instance_id
        || inputs.installed_driver.interface_path_sha256 != observation.interface_path_sha256
    {
        return Err(
            "Windows device-open receipt installed-driver binding does not match observation"
                .to_owned(),
        );
    }
    let started = parse_timestamp_ms(&observation.observation_started_at)?;
    let completed = parse_timestamp_ms(&observation.observation_completed_at)?;
    if completed < started || completed - started > MAX_FUTURE_SKEW_MS {
        return Err(
            "Windows device-open receipt timestamps are out of order or too long".to_owned(),
        );
    }
    if completed > now_unix_ms + MAX_FUTURE_SKEW_MS
        || now_unix_ms - completed > MAX_OBSERVATION_AGE_MS
    {
        return Err(
            "Windows device-open receipt is outside the 24-hour evidence window".to_owned(),
        );
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("cannot construct device-open receipt JSON: {error}"))?;
    serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize device-open receipt JSON: {error}"))
}

fn canonical_json_without_signature<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| format!("cannot construct device-open receipt JSON: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "device-open receipt must be a JSON object".to_owned())?;
    if object.remove("signature_ssh").is_none() {
        return Err("device-open receipt is missing signature_ssh".to_owned());
    }
    serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize signed device-open material: {error}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_text(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > MAX_TEXT_BYTES
        || value
            .chars()
            .any(|character| character < ' ' || character == '\u{7f}')
    {
        return Err(format!("Windows device-open receipt {name} is invalid"));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), String> {
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("Windows device-open receipt nonce is invalid".to_owned());
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<(), String> {
    if !valid_grouped_hex(value, &[8, 4, 4, 4, 12], false) {
        return Err("Windows device-open receipt boot_id is not a canonical UUID".to_owned());
    }
    Ok(())
}

fn validate_guid(value: &str) -> Result<(), String> {
    if !valid_grouped_hex(value, &[8, 4, 4, 4, 12], true) {
        return Err("Windows device-open receipt interface class GUID is not canonical".to_owned());
    }
    Ok(())
}

fn valid_grouped_hex(value: &str, widths: &[usize], braces: bool) -> bool {
    let inner = if braces {
        let Some(inner) = value
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix('}'))
        else {
            return false;
        };
        inner
    } else {
        value
    };
    let groups = inner.split('-').collect::<Vec<_>>();
    groups.len() == widths.len()
        && groups.iter().zip(widths).all(|(group, width)| {
            group.len() == *width
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn parse_timestamp_ms(value: &str) -> Result<i128, String> {
    if value.len() != 24 {
        return Err("Windows device-open receipt timestamp must use UTC milliseconds".to_owned());
    }
    let bytes = value.as_bytes();
    if [4, 7, 10, 13, 16, 19, 23]
        .into_iter()
        .zip(*b"--T::.Z")
        .any(|(index, expected)| bytes[index] != expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            ![4, 7, 10, 13, 16, 19, 23].contains(&index) && !byte.is_ascii_digit()
        })
    {
        return Err("Windows device-open receipt timestamp must use UTC milliseconds".to_owned());
    }
    let number = |start: usize, end: usize| -> Result<i64, String> {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(|part| part.parse().ok())
            .ok_or_else(|| "Windows device-open receipt timestamp is invalid".to_owned())
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let millisecond = number(20, 23)?;
    if !(1601..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
        || !(0..=999).contains(&millisecond)
    {
        return Err("Windows device-open receipt timestamp is invalid".to_owned());
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return Err("Windows device-open receipt timestamp is invalid".to_owned());
    }
    let days = days_from_civil(year, month, day);
    Ok(
        (i128::from(days) * 86_400 + i128::from(hour * 3_600 + minute * 60 + second)) * 1_000
            + i128::from(millisecond),
    )
}

// Howard Hinnant's civil-date conversion, shifted to the Unix epoch.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_open_protocol::{OBSERVATION_SCHEMA, fixed_target, registry_sha256};
    use serde_json::Value;

    const PRIVATE_KEY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/test-only-key");
    const POLICY: &str =
        include_str!("../../../tests/fixtures/windows-token-sshsig/allowed_signers");
    const IDENTITY: &str = "capture@example.test";
    const NOW_MS: i128 = 1_784_112_313_000; // 2026-07-15T10:45:13Z

    fn observation() -> DeviceOpenObservation {
        let target = fixed_target();
        DeviceOpenObservation {
            schema_version: OBSERVATION_SCHEMA.to_owned(),
            target_id: target.target_id.to_owned(),
            collector_registry_sha256: registry_sha256().unwrap(),
            driver_id: target.driver_id.to_owned(),
            driver_service_name: target.driver_service_name.to_owned(),
            interface_class_guid: target.interface_class_guid.to_owned(),
            interface_instance_id: target.interface_instance_id.to_owned(),
            interface_path_sha256: format!("{:x}", Sha256::digest(b"opaque device path")),
            enumeration_api: target.enumeration_api.to_owned(),
            enumeration_flags: target.enumeration_flags,
            interface_count: 1,
            selected_interface_index: 0,
            create_file_api: target.create_file_api.to_owned(),
            desired_access: target.desired_access,
            share_mode: target.share_mode,
            security_attributes_null: target.security_attributes_null,
            creation_disposition: target.creation_disposition,
            flags_and_attributes: target.flags_and_attributes,
            template_file_null: target.template_file_null,
            process_id: 4242,
            process_creation_filetime: 133_700_000_000_000_000,
            primary_token_id: 0x1_0000,
            primary_token_modified_id: 0x2_0000,
            source_handle_value: 0x184,
            token_type: "TokenPrimary".to_owned(),
            thread_token_present: false,
            impersonation_active: false,
            elevation_type: "TokenElevationTypeDefault".to_owned(),
            elevated: false,
            integrity_rid: 8192,
            admin_group_present: false,
            linked_token_present: false,
            token_restricted: false,
            restricted_sid_count: 0,
            enabled_privileges: vec!["SeChangeNotifyPrivilege".to_owned()],
            app_container: false,
            debug_privilege_present: false,
            user_sid: "S-1-5-21-111111111-222222222-333333333-1001".to_owned(),
            authentication_id: "00000000000abcde".to_owned(),
            session_id: 1,
            observation_started_at: "2026-07-15T10:45:12.345Z".to_owned(),
            observation_completed_at: "2026-07-15T10:45:12.370Z".to_owned(),
            observation_duration_ms: 25,
            create_file_succeeded: true,
            handle_held_during_observation: true,
            device_io_control_call_count: 0,
            driver_load_call_count: 0,
            device_handle_read_call_count: 0,
            device_handle_write_call_count: 0,
        }
    }

    fn authority() -> BrokerAuthorityFacts {
        BrokerAuthorityFacts {
            duplicate_handle_held_during_signing: true,
            revalidated_primary_token: true,
            reenumerated_interface: true,
            child_source_handle_closed_cleanly: true,
        }
    }

    fn inputs(observation: &DeviceOpenObservation) -> ReceiptInputs<'_> {
        ReceiptInputs {
            authority: authority(),
            live: LiveMachineFacts {
                worker: "windows-ci-worker-01",
                worker_machine_id: "11".repeat(32).leak(),
                worker_acceptance_sha256: "22".repeat(32).leak(),
                windows_build_lab_ex: "26100.1.amd64fre.ge_release.240331-1435",
                windows_ubr: 4652,
                boot_id: "12345678-1234-1234-1234-1234567890ab",
            },
            collector: CollectorFacts {
                boundary_manifest_sha256: "33".repeat(32).leak(),
                collector_id: "device-open-collector-v1",
                collector_sha256: "44".repeat(32).leak(),
            },
            installed_driver: InstalledDriverFacts {
                driver_id: &observation.driver_id,
                driver_service_name: &observation.driver_service_name,
                driver_image_sha256: fixed_target().expected_installed_driver_image_sha256,
                interface_class_guid: &observation.interface_class_guid,
                interface_instance_id: &observation.interface_instance_id,
                interface_path_sha256: &observation.interface_path_sha256,
            },
            observation,
            receipt_nonce: "receipt_nonce_000000000000000001",
            signed_by: IDENTITY,
        }
    }

    fn sign(inputs: &ReceiptInputs<'_>) -> Result<Vec<u8>, String> {
        sign_device_open_receipt_at(
            inputs,
            Zeroizing::new(PRIVATE_KEY.as_bytes().to_vec()),
            POLICY,
            NOW_MS,
        )
    }

    #[test]
    fn emits_python_canonical_v2_and_immediately_verifies() {
        let observation = observation();
        let source = sign(&inputs(&observation)).unwrap();
        // Independent Python `json.dumps(sort_keys=True, separators=(",", ":"))`
        // plus OpenSSH produced this complete canonical-source vector.
        assert_eq!(
            format!("{:x}", Sha256::digest(&source)),
            "3fef5c8eb1f43dac86270ff9093db4052a56c28d9e98404d37d0920d49867bc5"
        );
        assert_eq!(source.last(), Some(&b'\n'));
        let raw: Value = serde_json::from_slice(&source).unwrap();
        assert_eq!(raw["schema_version"], SCHEMA_VERSION);
        assert_eq!(raw["evidence_class"], EVIDENCE_CLASS);
        assert_eq!(raw["producer_authority"], PRODUCER_AUTHORITY);
        assert_eq!(raw["primary_token_id"], 0x1_0000);
        assert_eq!(raw["primary_token_modified_id"], 0x2_0000);
        assert_eq!(raw["device_handle_read_call_count"], 0);
        assert_eq!(raw["device_handle_write_call_count"], 0);
        assert!(raw.get("source_handle_value").is_none());

        let mut without_signature = raw.clone();
        let signature = without_signature
            .as_object_mut()
            .unwrap()
            .remove("signature_ssh")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let material = serde_json::to_vec(&without_signature).unwrap();
        crate::sshsig::verify_ed25519(&material, &signature, IDENTITY, SIGNATURE_NAMESPACE, POLICY)
            .unwrap();
        let canonical = serde_json::to_vec(&raw).unwrap();
        assert_eq!(&source[..source.len() - 1], canonical);
    }

    #[test]
    fn transcript_digest_is_exact_canonical_observation() {
        let observation = observation();
        let raw: Value = serde_json::from_slice(&sign(&inputs(&observation)).unwrap()).unwrap();
        let transcript = serde_json::to_vec(&observation).unwrap();
        assert_eq!(
            raw["observation_transcript_sha256"],
            format!("{:x}", Sha256::digest(transcript))
        );
    }

    #[test]
    fn rejects_missing_authority_and_capability_boundary_crossing() {
        let base_observation = observation();
        let mut input = inputs(&base_observation);
        input.authority.duplicate_handle_held_during_signing = false;
        assert!(sign(&input).is_err());

        let mut unsafe_observation = observation();
        unsafe_observation.device_handle_read_call_count = 1;
        assert!(sign(&inputs(&unsafe_observation)).is_err());
    }

    #[test]
    fn rejects_driver_token_time_and_signer_mismatches() {
        let base_observation = observation();
        let mut input = inputs(&base_observation);
        input.installed_driver.interface_path_sha256 = "66".repeat(32).leak();
        assert!(sign(&input).is_err());

        let mut changed_token = observation();
        changed_token.primary_token_id = 0;
        assert!(sign(&inputs(&changed_token)).is_err());

        let mut stale = inputs(&base_observation);
        stale.live.boot_id = "12345678-1234-1234-1234-1234567890AB";
        assert!(sign(&stale).is_err());

        let mut wrong_signer = inputs(&base_observation);
        wrong_signer.signed_by = "other@example.test";
        assert!(sign(&wrong_signer).is_err());
    }

    #[test]
    fn timestamp_parser_matches_unix_reference_and_rejects_noncanonical_dates() {
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00.000Z").unwrap(), 0);
        assert_eq!(
            parse_timestamp_ms("2024-02-29T12:34:56.789Z").unwrap(),
            1_709_210_096_789
        );
        assert!(parse_timestamp_ms("2023-02-29T12:34:56.789Z").is_err());
        assert!(parse_timestamp_ms("2024-02-29T12:34:56+00:00").is_err());
    }
}
