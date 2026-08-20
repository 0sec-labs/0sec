#![allow(
    dead_code,
    reason = "the contract is consumed only by the Windows trusted-child transport"
)]

//! Compile-time-only Windows adapter registry and one-request wire contract.
//!
//! This module deliberately has no path, command, argument, environment, DLL,
//! target, tenant, or timeout input. The authenticated exact-child channel uses
//! it only for the feature-gated control no-op; production SCM, authority,
//! reservation, signing, and completion remain disconnected.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_SCHEMA: &str = "0verse.windows-fixed-adapter-request/v1";
const RESULT_SCHEMA: &str = "0verse.windows-fixed-adapter-unsigned-result/v1";
const EXECUTION_SCHEMA: &str = "0verse.windows-fixed-adapter-child-execution/v1";
pub(crate) const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const CONTROL_NOOP_OPERATION_SHA256: &str =
    "d69d69ed93546b781802eebb397fc47265cf133b67a9987364552f8a6cbd49e7";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterRequest {
    schema_version: String,
    operation_sha256: String,
    run_nonce: String,
    input_sha256: String,
    input_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedAdapter {
    ControlNoop,
}

impl FixedAdapter {
    const fn operation_id(self) -> &'static str {
        match self {
            Self::ControlNoop => crate::OPERATION_ID,
        }
    }

    const fn operation_sha256(self) -> &'static str {
        match self {
            Self::ControlNoop => CONTROL_NOOP_OPERATION_SHA256,
        }
    }

    const fn max_input_bytes(self) -> usize {
        match self {
            Self::ControlNoop => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "explicit non-claim booleans are the unsigned result wire contract"
)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnsignedAdapterResult {
    pub(crate) schema_version: String,
    pub(crate) operation_id: String,
    pub(crate) operation_sha256: String,
    pub(crate) run_nonce: String,
    pub(crate) input_sha256: String,
    pub(crate) output_sha256: String,
    pub(crate) status: String,
    pub(crate) claim_eligible: bool,
    pub(crate) authority_bound: bool,
    pub(crate) reservation_performed: bool,
    pub(crate) operation_signed: bool,
    pub(crate) weaponization: bool,
    pub(crate) auto_disclosure: bool,
    pub(crate) human_report_gate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnsignedChildExecution {
    pub(crate) schema_version: String,
    pub(crate) adapter_result: UnsignedAdapterResult,
    pub(crate) thread_id_start: u32,
    pub(crate) thread_id_finish: u32,
    pub(crate) start_profile_sha256: String,
    pub(crate) finish_profile_sha256: String,
    pub(crate) same_thread: bool,
    pub(crate) token_profile_equal: bool,
}

/// A locally validated request whose exact bytes are safe to place on the
/// authenticated child channel. Construction is intentionally registry-owned.
pub(crate) struct PreparedAdapterRequest {
    request: AdapterRequest,
    bytes: Vec<u8>,
}

impl PreparedAdapterRequest {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct ValidatedAdapterRequest {
    request: AdapterRequest,
    adapter: FixedAdapter,
    input: Vec<u8>,
}

fn validate_lower_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase SHA-256"));
    }
    Ok(())
}

fn lookup_exact(operation_sha256: &str) -> Result<FixedAdapter, String> {
    validate_lower_sha256(operation_sha256, "adapter operation digest")?;
    match operation_sha256 {
        CONTROL_NOOP_OPERATION_SHA256 => Ok(FixedAdapter::ControlNoop),
        _ => Err("adapter operation digest is not in the compile-time registry".to_owned()),
    }
}

fn decode_request(bytes: &[u8]) -> Result<ValidatedAdapterRequest, String> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("fixed adapter request length is invalid".to_owned());
    }
    let strict = crate::broker_protocol::parse_strict_json_object(bytes, "fixed adapter request")?;
    let request: AdapterRequest = serde_json::from_value(strict)
        .map_err(|error| format!("fixed adapter request shape is invalid: {error}"))?;
    if request.schema_version != REQUEST_SCHEMA {
        return Err("fixed adapter request schema is unsupported".to_owned());
    }
    crate::validate_run_nonce(&request.run_nonce).map_err(str::to_owned)?;
    validate_lower_sha256(&request.input_sha256, "adapter input digest")?;
    if request.input_b64.len() > MAX_INPUT_BYTES.div_ceil(3) * 4 {
        return Err("fixed adapter input encoding exceeds its bound".to_owned());
    }
    let input = URL_SAFE_NO_PAD
        .decode(&request.input_b64)
        .map_err(|_| "fixed adapter input is not canonical base64url".to_owned())?;
    if input.len() > MAX_INPUT_BYTES || URL_SAFE_NO_PAD.encode(&input) != request.input_b64 {
        return Err("fixed adapter input is oversized or non-canonical".to_owned());
    }
    let actual_input_sha256 = format!("{:x}", Sha256::digest(&input));
    if actual_input_sha256 != request.input_sha256 {
        return Err("fixed adapter input digest does not match its bytes".to_owned());
    }
    let adapter = lookup_exact(&request.operation_sha256)?;
    if input.len() > adapter.max_input_bytes() {
        return Err("fixed adapter input exceeds the selected registry entry".to_owned());
    }
    Ok(ValidatedAdapterRequest {
        request,
        adapter,
        input,
    })
}

fn execute_unsigned(validated: ValidatedAdapterRequest) -> UnsignedAdapterResult {
    match validated.adapter {
        FixedAdapter::ControlNoop => std::hint::black_box(()),
    }
    let output = [];
    UnsignedAdapterResult {
        schema_version: RESULT_SCHEMA.to_owned(),
        operation_id: validated.adapter.operation_id().to_owned(),
        operation_sha256: validated.adapter.operation_sha256().to_owned(),
        run_nonce: validated.request.run_nonce,
        input_sha256: validated.request.input_sha256,
        output_sha256: format!("{:x}", Sha256::digest(output)),
        status: "completed_neutral".to_owned(),
        claim_eligible: false,
        authority_bound: false,
        reservation_performed: false,
        operation_signed: false,
        weaponization: false,
        auto_disclosure: false,
        human_report_gate: true,
    }
}

pub(crate) fn prepare_control_noop(run_nonce: &str) -> Result<PreparedAdapterRequest, String> {
    let request = AdapterRequest {
        schema_version: REQUEST_SCHEMA.to_owned(),
        operation_sha256: CONTROL_NOOP_OPERATION_SHA256.to_owned(),
        run_nonce: run_nonce.to_owned(),
        input_sha256: EMPTY_SHA256.to_owned(),
        input_b64: String::new(),
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serialize fixed adapter request failed: {error}"))?;
    let validated = decode_request(&bytes)?;
    if validated.request != request || !validated.input.is_empty() {
        return Err("prepared fixed adapter request changed during validation".to_owned());
    }
    Ok(PreparedAdapterRequest { request, bytes })
}

pub(crate) fn execute_encoded(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let result = execute_unsigned(decode_request(bytes)?);
    serde_json::to_vec(&result)
        .map_err(|error| format!("serialize fixed adapter result failed: {error}"))
}

pub(crate) fn encode_child_execution(
    adapter_result: &[u8],
    thread_id_start: u32,
    thread_id_finish: u32,
    start_profile_sha256: &str,
    finish_profile_sha256: &str,
) -> Result<Vec<u8>, String> {
    let strict = crate::broker_protocol::parse_strict_json_object(
        adapter_result,
        "fixed adapter child result",
    )?;
    let adapter_result: UnsignedAdapterResult = serde_json::from_value(strict)
        .map_err(|error| format!("fixed adapter child result shape is invalid: {error}"))?;
    validate_lower_sha256(start_profile_sha256, "start token profile digest")?;
    validate_lower_sha256(finish_profile_sha256, "finish token profile digest")?;
    if thread_id_start == 0 || thread_id_finish == 0 {
        return Err("fixed adapter child thread ID is zero".to_owned());
    }
    let execution = UnsignedChildExecution {
        schema_version: EXECUTION_SCHEMA.to_owned(),
        adapter_result,
        thread_id_start,
        thread_id_finish,
        start_profile_sha256: start_profile_sha256.to_owned(),
        finish_profile_sha256: finish_profile_sha256.to_owned(),
        same_thread: thread_id_start == thread_id_finish,
        token_profile_equal: start_profile_sha256 == finish_profile_sha256,
    };
    serde_json::to_vec(&execution)
        .map_err(|error| format!("serialize fixed adapter child execution failed: {error}"))
}

pub(crate) fn validate_result(
    prepared: &PreparedAdapterRequest,
    bytes: &[u8],
) -> Result<UnsignedAdapterResult, String> {
    let strict = crate::broker_protocol::parse_strict_json_object(bytes, "fixed adapter result")?;
    let result: UnsignedAdapterResult = serde_json::from_value(strict)
        .map_err(|error| format!("fixed adapter result shape is invalid: {error}"))?;
    validate_lower_sha256(&result.operation_sha256, "result operation digest")?;
    validate_lower_sha256(&result.input_sha256, "result input digest")?;
    validate_lower_sha256(&result.output_sha256, "result output digest")?;
    if result.schema_version != RESULT_SCHEMA
        || result.operation_id != crate::OPERATION_ID
        || result.operation_sha256 != prepared.request.operation_sha256
        || result.run_nonce != prepared.request.run_nonce
        || result.input_sha256 != prepared.request.input_sha256
        || result.output_sha256 != EMPTY_SHA256
        || result.status != "completed_neutral"
    {
        return Err("fixed adapter result is not bound to its prepared request".to_owned());
    }
    if result.claim_eligible
        || result.authority_bound
        || result.reservation_performed
        || result.operation_signed
        || result.weaponization
        || result.auto_disclosure
        || !result.human_report_gate
    {
        return Err("fixed adapter result violates the neutral safety contract".to_owned());
    }
    Ok(result)
}

pub(crate) fn validate_child_execution(
    prepared: &PreparedAdapterRequest,
    bytes: &[u8],
    expected_profile_sha256: &str,
) -> Result<UnsignedChildExecution, String> {
    validate_lower_sha256(expected_profile_sha256, "expected token profile digest")?;
    let strict =
        crate::broker_protocol::parse_strict_json_object(bytes, "fixed adapter child execution")?;
    let execution: UnsignedChildExecution = serde_json::from_value(strict)
        .map_err(|error| format!("fixed adapter child execution shape is invalid: {error}"))?;
    let adapter = serde_json::to_vec(&execution.adapter_result)
        .map_err(|error| format!("serialize nested fixed adapter result failed: {error}"))?;
    validate_result(prepared, &adapter)?;
    validate_lower_sha256(
        &execution.start_profile_sha256,
        "start token profile digest",
    )?;
    validate_lower_sha256(
        &execution.finish_profile_sha256,
        "finish token profile digest",
    )?;
    if execution.schema_version != EXECUTION_SCHEMA
        || execution.thread_id_start == 0
        || execution.thread_id_start != execution.thread_id_finish
        || !execution.same_thread
        || !execution.token_profile_equal
        || execution.start_profile_sha256 != execution.finish_profile_sha256
        || execution.start_profile_sha256 != expected_profile_sha256
    {
        return Err("fixed adapter child execution lost thread or token binding".to_owned());
    }
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AdapterRequest {
        AdapterRequest {
            schema_version: REQUEST_SCHEMA.to_owned(),
            operation_sha256: CONTROL_NOOP_OPERATION_SHA256.to_owned(),
            run_nonce: "adapter_run_000000000000000000000".to_owned(),
            input_sha256: EMPTY_SHA256.to_owned(),
            input_b64: String::new(),
        }
    }

    fn bytes(request: &AdapterRequest) -> Vec<u8> {
        serde_json::to_vec(request).unwrap()
    }

    #[test]
    fn exact_registry_digest_resolves_and_matches_public_operation_hash() {
        let adapter = lookup_exact(CONTROL_NOOP_OPERATION_SHA256).unwrap();
        assert_eq!(adapter.operation_id(), crate::OPERATION_ID);
        assert_eq!(adapter.operation_sha256(), crate::operation_sha256());
        assert!(lookup_exact(&"a".repeat(64)).is_err());
        assert!(lookup_exact(&CONTROL_NOOP_OPERATION_SHA256.to_uppercase()).is_err());
    }

    #[test]
    fn strict_request_rejects_dynamic_surfaces_and_duplicate_keys() {
        let encoded = String::from_utf8(bytes(&request())).unwrap();
        for field in [
            "path",
            "argv",
            "environment",
            "command",
            "dll",
            "timeout_ms",
        ] {
            let injected = encoded.replacen('{', &format!("{{\"{field}\":\"x\","), 1);
            assert!(decode_request(injected.as_bytes()).is_err());
        }
        let duplicate = encoded.replacen(
            "\"run_nonce\":",
            "\"run_nonce\":\"duplicate_nonce_00000000000000000\",\"run_nonce\":",
            1,
        );
        assert!(decode_request(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn request_rejects_noncanonical_mismatched_oversized_and_nonempty_input() {
        let mut changed = request();
        changed.input_b64 = "=".to_owned();
        assert!(decode_request(&bytes(&changed)).is_err());

        let mut changed = request();
        changed.input_sha256 = "0".repeat(64);
        assert!(decode_request(&bytes(&changed)).is_err());

        let mut changed = request();
        let input = vec![0u8; MAX_INPUT_BYTES + 1];
        changed.input_b64 = URL_SAFE_NO_PAD.encode(&input);
        changed.input_sha256 = format!("{:x}", Sha256::digest(&input));
        assert!(decode_request(&bytes(&changed)).is_err());

        let mut changed = request();
        changed.input_b64 = URL_SAFE_NO_PAD.encode(b"candidate");
        changed.input_sha256 = format!("{:x}", Sha256::digest(b"candidate"));
        assert!(decode_request(&bytes(&changed)).is_err());
    }

    #[test]
    fn noop_result_is_unsigned_and_nonclaiming() {
        let validated = decode_request(&bytes(&request())).unwrap();
        assert!(validated.input.is_empty());
        let result = execute_unsigned(validated);
        assert_eq!(result.status, "completed_neutral");
        assert_eq!(result.output_sha256, EMPTY_SHA256);
        assert!(!result.claim_eligible);
        assert!(!result.authority_bound);
        assert!(!result.reservation_performed);
        assert!(!result.operation_signed);
        assert!(!result.weaponization);
        assert!(!result.auto_disclosure);
        assert!(result.human_report_gate);
    }

    #[test]
    fn prepared_noop_and_child_execution_are_cross_bound_and_neutral() {
        let nonce = "adapter_run_000000000000000000000";
        let prepared = prepare_control_noop(nonce).unwrap();
        let adapter = execute_encoded(prepared.bytes()).unwrap();
        let profile = "a".repeat(64);
        let child = encode_child_execution(&adapter, 41, 41, &profile, &profile).unwrap();
        let execution = validate_child_execution(&prepared, &child, &profile).unwrap();
        assert_eq!(execution.adapter_result.run_nonce, nonce);
        assert!(execution.same_thread);
        assert!(execution.token_profile_equal);

        assert!(validate_child_execution(&prepared, &child, &"b".repeat(64)).is_err());
        let changed = String::from_utf8(child).unwrap().replacen(
            "\"thread_id_finish\":41",
            "\"thread_id_finish\":42",
            1,
        );
        assert!(validate_child_execution(&prepared, changed.as_bytes(), &profile).is_err());
    }

    #[test]
    fn result_revalidation_rejects_claim_and_binding_changes() {
        let prepared = prepare_control_noop("adapter_run_000000000000000000000").unwrap();
        let encoded = execute_encoded(prepared.bytes()).unwrap();
        assert!(validate_result(&prepared, &encoded).is_ok());
        let changed = String::from_utf8(encoded.clone()).unwrap().replacen(
            "\"claim_eligible\":false",
            "\"claim_eligible\":true",
            1,
        );
        assert!(validate_result(&prepared, changed.as_bytes()).is_err());
        let changed = String::from_utf8(encoded).unwrap().replacen(
            "adapter_run_000000000000000000000",
            "adapter_run_111111111111111111111",
            1,
        );
        assert!(validate_result(&prepared, changed.as_bytes()).is_err());
    }
}
