#![allow(
    dead_code,
    reason = "the platform-neutral contract lands before the reviewed Windows producer"
)]

//! Inert device-open target registry and bounded child/broker wire contract.
//!
//! There is deliberately no target selector in this module. An observe request
//! has an empty body, and the sole target plus every `CreateFileW` argument is
//! compiled into this binary. This module performs no device enumeration, file
//! open, handle duplication, IOCTL, signing, or publication.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REGISTRY_SCHEMA: &str = "0verse.windows-device-open-target-registry/v1";
pub(crate) const OBSERVATION_SCHEMA: &str = "0verse.windows-device-open-observation/v1";
const REGISTRY_DOMAIN: &[u8] = b"0verse-windows-device-open-target-registry-v1\0";

const ENUMERATION_API: &str = concat!(
    "SetupDiGetClassDevsW+SetupDiEnumDeviceInterfaces+",
    "SetupDiGetDeviceInterfaceDetailW"
);
const CREATE_FILE_API: &str = "CreateFileW";
const ENUMERATION_FLAGS: u32 = 0x12; // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
const QUERY_ONLY_DESIRED_ACCESS: u32 = 0;
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const MEDIUM_INTEGRITY_RID: u32 = 8192;
const MAX_INTERFACES: u32 = 256;
pub(crate) const MAX_OBSERVATION_BODY_BYTES: usize = 16 * 1024;
const HEADER_BYTES: usize = 32;
pub(crate) const MAX_RESPONSE_FRAME_BYTES: usize = HEADER_BYTES + MAX_OBSERVATION_BODY_BYTES;
const ERROR_BODY_BYTES: usize = 8;
const MAGIC: [u8; 4] = *b"0VDO";
const VERSION: u8 = 1;

const ALLOWED_STANDARD_USER_PRIVILEGES: &[&str] = &[
    "SeChangeNotifyPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeShutdownPrivilege",
    "SeTimeZonePrivilege",
    "SeUndockPrivilege",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct DeviceOpenTarget {
    pub(crate) target_id: &'static str,
    pub(crate) driver_id: &'static str,
    pub(crate) driver_service_name: &'static str,
    pub(crate) expected_installed_driver_image_sha256: &'static str,
    pub(crate) interface_class_guid: &'static str,
    pub(crate) interface_instance_id: &'static str,
    pub(crate) enumeration_api: &'static str,
    pub(crate) enumeration_flags: u32,
    pub(crate) create_file_api: &'static str,
    pub(crate) desired_access: u32,
    pub(crate) share_mode: u32,
    pub(crate) security_attributes_null: bool,
    pub(crate) creation_disposition: u32,
    pub(crate) flags_and_attributes: u32,
    pub(crate) template_file_null: bool,
}

/// The only compiled target is an owned, explicitly non-bounty fixture.
const SYNTHETIC_FIXTURE_TARGET: DeviceOpenTarget = DeviceOpenTarget {
    target_id: "synthetic-non-bounty-buffered-fixture",
    driver_id: "0verse-fixture-buffered",
    driver_service_name: "ZeroverseFixtureBuffered",
    expected_installed_driver_image_sha256: "8f2fe04d8b2d6e8a1870460d72e83fb5321156dc8f22d4e618fd80f56a397f22",
    interface_class_guid: "{12345678-1234-1234-1234-1234567890ab}",
    interface_instance_id: "ROOT\\ZEROVERSEFIXTURE\\0000",
    enumeration_api: ENUMERATION_API,
    enumeration_flags: ENUMERATION_FLAGS,
    create_file_api: CREATE_FILE_API,
    desired_access: QUERY_ONLY_DESIRED_ACCESS,
    share_mode: FILE_SHARE_READ_WRITE,
    security_attributes_null: true,
    creation_disposition: OPEN_EXISTING,
    flags_and_attributes: FILE_ATTRIBUTE_NORMAL,
    template_file_null: true,
};

/// One entry is intentional: there is no runtime target index or lookup key.
const TARGET_REGISTRY: [DeviceOpenTarget; 1] = [SYNTHETIC_FIXTURE_TARGET];

#[derive(Serialize)]
struct CanonicalRegistry<'a> {
    schema_version: &'static str,
    targets: &'a [DeviceOpenTarget],
}

pub(crate) const fn fixed_target() -> &'static DeviceOpenTarget {
    &TARGET_REGISTRY[0]
}

pub(crate) fn registry_sha256() -> Result<String, String> {
    let canonical = serde_json::to_vec(&CanonicalRegistry {
        schema_version: REGISTRY_SCHEMA,
        targets: &TARGET_REGISTRY,
    })
    .map_err(|error| format!("cannot canonicalize device-open target registry: {error}"))?;
    let mut digest = Sha256::new();
    digest.update(REGISTRY_DOMAIN);
    digest.update(canonical);
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct DeviceOpenObservation {
    pub(crate) schema_version: String,
    pub(crate) target_id: String,
    pub(crate) collector_registry_sha256: String,
    pub(crate) driver_id: String,
    pub(crate) driver_service_name: String,
    pub(crate) interface_class_guid: String,
    pub(crate) interface_instance_id: String,
    pub(crate) interface_path_sha256: String,
    pub(crate) enumeration_api: String,
    pub(crate) enumeration_flags: u32,
    pub(crate) interface_count: u32,
    pub(crate) selected_interface_index: u32,
    pub(crate) create_file_api: String,
    pub(crate) desired_access: u32,
    pub(crate) share_mode: u32,
    pub(crate) security_attributes_null: bool,
    pub(crate) creation_disposition: u32,
    pub(crate) flags_and_attributes: u32,
    pub(crate) template_file_null: bool,
    pub(crate) process_id: u32,
    pub(crate) process_creation_filetime: u64,
    pub(crate) primary_token_id: u64,
    pub(crate) primary_token_modified_id: u64,
    pub(crate) source_handle_value: u64,
    pub(crate) token_type: String,
    pub(crate) thread_token_present: bool,
    pub(crate) impersonation_active: bool,
    pub(crate) elevation_type: String,
    pub(crate) elevated: bool,
    pub(crate) integrity_rid: u32,
    pub(crate) admin_group_present: bool,
    pub(crate) linked_token_present: bool,
    pub(crate) token_restricted: bool,
    pub(crate) restricted_sid_count: u32,
    pub(crate) enabled_privileges: Vec<String>,
    pub(crate) app_container: bool,
    pub(crate) debug_privilege_present: bool,
    pub(crate) user_sid: String,
    pub(crate) authentication_id: String,
    pub(crate) session_id: u32,
    pub(crate) observation_started_at: String,
    pub(crate) observation_completed_at: String,
    pub(crate) observation_duration_ms: u32,
    pub(crate) create_file_succeeded: bool,
    pub(crate) handle_held_during_observation: bool,
    pub(crate) device_io_control_call_count: u32,
    pub(crate) driver_load_call_count: u32,
    pub(crate) device_handle_read_call_count: u32,
    pub(crate) device_handle_write_call_count: u32,
}

impl DeviceOpenObservation {
    #[allow(
        clippy::too_many_lines,
        reason = "the exact observation contract validates each safety field in one audit gate"
    )]
    pub(crate) fn validate(&self) -> Result<(), String> {
        let target = fixed_target();
        if self.schema_version != OBSERVATION_SCHEMA {
            return Err("unsupported device-open observation schema".to_owned());
        }
        let exact_registry_fields = [
            ("target_id", self.target_id.as_str(), target.target_id),
            ("driver_id", self.driver_id.as_str(), target.driver_id),
            (
                "driver_service_name",
                self.driver_service_name.as_str(),
                target.driver_service_name,
            ),
            (
                "interface_class_guid",
                self.interface_class_guid.as_str(),
                target.interface_class_guid,
            ),
            (
                "interface_instance_id",
                self.interface_instance_id.as_str(),
                target.interface_instance_id,
            ),
            (
                "enumeration_api",
                self.enumeration_api.as_str(),
                target.enumeration_api,
            ),
            (
                "create_file_api",
                self.create_file_api.as_str(),
                target.create_file_api,
            ),
        ];
        if let Some((name, _, _)) = exact_registry_fields
            .iter()
            .find(|(_, actual, expected)| actual != expected)
        {
            return Err(format!(
                "device-open observation {name} differs from fixed registry"
            ));
        }
        if self.collector_registry_sha256 != registry_sha256()? {
            return Err(
                "device-open observation registry digest differs from compiled registry".to_owned(),
            );
        }
        if !valid_sha256(&self.interface_path_sha256) {
            return Err("device-open observation interface path digest is invalid".to_owned());
        }
        if self.enumeration_flags != target.enumeration_flags
            || !(1..=MAX_INTERFACES).contains(&self.interface_count)
            || self.selected_interface_index >= self.interface_count
        {
            return Err("device-open observation interface selection is invalid".to_owned());
        }
        if self.desired_access != target.desired_access
            || self.share_mode != target.share_mode
            || self.security_attributes_null != target.security_attributes_null
            || self.creation_disposition != target.creation_disposition
            || self.flags_and_attributes != target.flags_and_attributes
            || self.template_file_null != target.template_file_null
        {
            return Err(
                "device-open observation CreateFileW arguments are not query-only".to_owned(),
            );
        }
        if self.process_id == 0
            || self.process_creation_filetime == 0
            || self.primary_token_id == 0
            || self.primary_token_modified_id == 0
            || matches!(self.source_handle_value, 0 | u64::MAX)
        {
            return Err(
                "device-open observation process or source handle identity is invalid".to_owned(),
            );
        }
        if self.token_type != "TokenPrimary"
            || self.thread_token_present
            || self.impersonation_active
            || self.elevation_type != "TokenElevationTypeDefault"
            || self.elevated
            || self.integrity_rid != MEDIUM_INTEGRITY_RID
            || self.admin_group_present
            || self.linked_token_present
            || self.token_restricted
            || self.restricted_sid_count != 0
            || self.app_container
            || self.debug_privilege_present
        {
            return Err(
                "device-open observation is not a natural standard-user context".to_owned(),
            );
        }
        validate_privileges(&self.enabled_privileges)?;
        validate_account_sid(&self.user_sid)?;
        validate_authentication_id(&self.authentication_id)?;
        if !valid_utc_millisecond_timestamp(&self.observation_started_at)
            || !valid_utc_millisecond_timestamp(&self.observation_completed_at)
            || self.observation_completed_at < self.observation_started_at
            || self.observation_duration_ms > 5 * 60 * 1000
        {
            return Err("device-open observation timing is invalid".to_owned());
        }
        if !self.create_file_succeeded || !self.handle_held_during_observation {
            return Err("device-open observation lacks a held successful open".to_owned());
        }
        if [
            self.device_io_control_call_count,
            self.driver_load_call_count,
            self.device_handle_read_call_count,
            self.device_handle_write_call_count,
        ]
        .into_iter()
        .any(|count| count != 0)
        {
            return Err("device-open observation crossed the capability-only boundary".to_owned());
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_privileges(privileges: &[String]) -> Result<(), String> {
    if privileges.is_empty()
        || !privileges.windows(2).all(|pair| pair[0] < pair[1])
        || privileges
            .iter()
            .any(|value| !ALLOWED_STANDARD_USER_PRIVILEGES.contains(&value.as_str()))
    {
        return Err("device-open observation privileges are incomplete or unsafe".to_owned());
    }
    Ok(())
}

fn validate_account_sid(value: &str) -> Result<(), String> {
    let Some(parts) = value.strip_prefix("S-1-5-21-") else {
        return Err("device-open observation user SID is not a canonical account SID".to_owned());
    };
    let components = parts.split('-').collect::<Vec<_>>();
    if components.len() != 4
        || components.iter().any(|part| {
            part.is_empty()
                || part.len() > 10
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || part.starts_with('0') && part.len() != 1
                || part.parse::<u32>().is_err()
        })
        || components[3].parse::<u32>().unwrap_or(0) < 1000
    {
        return Err("device-open observation user SID is not a canonical account SID".to_owned());
    }
    Ok(())
}

fn validate_authentication_id(value: &str) -> Result<(), String> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || u64::from_str_radix(value, 16).map_or(true, |identifier| identifier <= 0x3e7)
    {
        return Err("device-open observation authentication ID is invalid".to_owned());
    }
    Ok(())
}

fn valid_utc_millisecond_timestamp(value: &str) -> bool {
    if value.len() != 24 {
        return false;
    }
    let bytes = value.as_bytes();
    if ![4, 7, 10, 13, 16, 19]
        .into_iter()
        .zip(*b"--T::.")
        .all(|(index, expected)| bytes[index] == expected)
        || bytes[23] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            ![4, 7, 10, 13, 16, 19, 23].contains(&index) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    let Some(year @ 1601..=9999) = number(0..4) else {
        return false;
    };
    let Some(month @ 1..=12) = number(5..7) else {
        return false;
    };
    let Some(day) = number(8..10) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
        && matches!(number(11..13), Some(0..=23))
        && matches!(number(14..16), Some(0..=59))
        && matches!(number(17..19), Some(0..=59))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FrameKind {
    ObserveRequest = 0x01,
    CloseSourceRequest = 0x02,
    ObserveResult = 0x81,
    ObserveError = 0x82,
    CloseSourceAck = 0x83,
}

impl FrameKind {
    fn from_wire(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::ObserveRequest),
            0x02 => Ok(Self::CloseSourceRequest),
            0x81 => Ok(Self::ObserveResult),
            0x82 => Ok(Self::ObserveError),
            0x83 => Ok(Self::CloseSourceAck),
            _ => Err(CodecError::UnknownKind(value)),
        }
    }

    const fn maximum_body_bytes(self) -> usize {
        match self {
            Self::ObserveRequest | Self::CloseSourceRequest | Self::CloseSourceAck => 0,
            Self::ObserveResult => MAX_OBSERVATION_BODY_BYTES,
            Self::ObserveError => ERROR_BODY_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame<'a> {
    kind: FrameKind,
    exchange_id: [u8; 16],
    body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ObservationErrorCode {
    InvalidRequest = 1,
    EnumerationFailed = 2,
    InterfaceMismatch = 3,
    OpenFailed = 4,
    UnsafeToken = 5,
    ResponseEncodingFailed = 6,
}

impl ObservationErrorCode {
    fn from_wire(value: u16) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::EnumerationFailed),
            3 => Ok(Self::InterfaceMismatch),
            4 => Ok(Self::OpenFailed),
            5 => Ok(Self::UnsafeToken),
            6 => Ok(Self::ResponseEncodingFailed),
            _ => Err(CodecError::UnknownErrorCode(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ObservationResponse {
    Observation(Box<DeviceOpenObservation>),
    Error(ObservationErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodecError {
    MessageTooShort,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    NonzeroFlags,
    NonzeroReserved,
    ZeroExchangeId,
    UnexpectedKind(FrameKind),
    ExchangeIdMismatch,
    BodyRequired(FrameKind),
    BodyForbidden(FrameKind),
    BodyTooLarge { kind: FrameKind, actual: usize },
    LengthMismatch { declared: usize, actual: usize },
    InvalidObservation(String),
    NoncanonicalObservation,
    InvalidErrorBodyLength(usize),
    UnsupportedErrorSchema(u16),
    UnknownErrorCode(u16),
    NonzeroErrorReserved,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "device-open IPC message is invalid: {self:?}")
    }
}

impl std::error::Error for CodecError {}

pub(crate) fn encode_observe_request(exchange_id: [u8; 16]) -> Result<Vec<u8>, CodecError> {
    encode_frame(FrameKind::ObserveRequest, exchange_id, &[])
}

pub(crate) fn decode_observe_request(bytes: &[u8]) -> Result<[u8; 16], CodecError> {
    let frame = decode_frame(bytes)?;
    if frame.kind != FrameKind::ObserveRequest {
        return Err(CodecError::UnexpectedKind(frame.kind));
    }
    Ok(frame.exchange_id)
}

pub(crate) fn encode_close_source_request(exchange_id: [u8; 16]) -> Result<Vec<u8>, CodecError> {
    encode_frame(FrameKind::CloseSourceRequest, exchange_id, &[])
}

pub(crate) fn decode_close_source_request(bytes: &[u8]) -> Result<[u8; 16], CodecError> {
    let frame = decode_frame(bytes)?;
    if frame.kind != FrameKind::CloseSourceRequest {
        return Err(CodecError::UnexpectedKind(frame.kind));
    }
    Ok(frame.exchange_id)
}

pub(crate) fn encode_close_source_ack(exchange_id: [u8; 16]) -> Result<Vec<u8>, CodecError> {
    encode_frame(FrameKind::CloseSourceAck, exchange_id, &[])
}

pub(crate) fn decode_close_source_ack(
    bytes: &[u8],
    expected_exchange_id: [u8; 16],
) -> Result<(), CodecError> {
    validate_exchange_id(expected_exchange_id)?;
    let frame = decode_frame(bytes)?;
    if frame.exchange_id != expected_exchange_id {
        return Err(CodecError::ExchangeIdMismatch);
    }
    if frame.kind != FrameKind::CloseSourceAck {
        return Err(CodecError::UnexpectedKind(frame.kind));
    }
    Ok(())
}

pub(crate) fn encode_observation_response(
    exchange_id: [u8; 16],
    observation: &DeviceOpenObservation,
) -> Result<Vec<u8>, CodecError> {
    observation
        .validate()
        .map_err(CodecError::InvalidObservation)?;
    let body = serde_json::to_vec(observation)
        .map_err(|error| CodecError::InvalidObservation(error.to_string()))?;
    encode_frame(FrameKind::ObserveResult, exchange_id, &body)
}

pub(crate) fn encode_error_response(
    exchange_id: [u8; 16],
    code: ObservationErrorCode,
) -> Result<Vec<u8>, CodecError> {
    let mut body = [0u8; ERROR_BODY_BYTES];
    body[..2].copy_from_slice(&1u16.to_le_bytes());
    body[2..4].copy_from_slice(&(code as u16).to_le_bytes());
    encode_frame(FrameKind::ObserveError, exchange_id, &body)
}

pub(crate) fn decode_observation_response(
    bytes: &[u8],
    expected_exchange_id: [u8; 16],
) -> Result<ObservationResponse, CodecError> {
    validate_exchange_id(expected_exchange_id)?;
    let frame = decode_frame(bytes)?;
    if frame.exchange_id != expected_exchange_id {
        return Err(CodecError::ExchangeIdMismatch);
    }
    match frame.kind {
        FrameKind::ObserveResult => {
            let observation: DeviceOpenObservation = serde_json::from_slice(frame.body)
                .map_err(|error| CodecError::InvalidObservation(error.to_string()))?;
            observation
                .validate()
                .map_err(CodecError::InvalidObservation)?;
            let canonical = serde_json::to_vec(&observation)
                .map_err(|error| CodecError::InvalidObservation(error.to_string()))?;
            if canonical != frame.body {
                return Err(CodecError::NoncanonicalObservation);
            }
            Ok(ObservationResponse::Observation(Box::new(observation)))
        }
        FrameKind::ObserveError => decode_error_body(frame.body).map(ObservationResponse::Error),
        FrameKind::ObserveRequest | FrameKind::CloseSourceRequest | FrameKind::CloseSourceAck => {
            Err(CodecError::UnexpectedKind(frame.kind))
        }
    }
}

fn encode_frame(
    kind: FrameKind,
    exchange_id: [u8; 16],
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    validate_exchange_id(exchange_id)?;
    validate_body(kind, body)?;
    let body_len = u32::try_from(body.len()).map_err(|_| CodecError::BodyTooLarge {
        kind,
        actual: body.len(),
    })?;
    let mut encoded = Vec::with_capacity(HEADER_BYTES + body.len());
    encoded.extend(MAGIC);
    encoded.push(VERSION);
    encoded.push(kind as u8);
    encoded.extend(0u16.to_le_bytes());
    encoded.extend(body_len.to_le_bytes());
    encoded.extend(0u32.to_le_bytes());
    encoded.extend(exchange_id);
    encoded.extend(body);
    Ok(encoded)
}

fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, CodecError> {
    if bytes.len() < HEADER_BYTES {
        return Err(CodecError::MessageTooShort);
    }
    if bytes[..4] != MAGIC {
        return Err(CodecError::BadMagic);
    }
    if bytes[4] != VERSION {
        return Err(CodecError::UnsupportedVersion(bytes[4]));
    }
    let kind = FrameKind::from_wire(bytes[5])?;
    if read_u16(&bytes[6..8]) != 0 {
        return Err(CodecError::NonzeroFlags);
    }
    let declared = read_u32(&bytes[8..12]) as usize;
    if read_u32(&bytes[12..16]) != 0 {
        return Err(CodecError::NonzeroReserved);
    }
    let mut exchange_id = [0u8; 16];
    exchange_id.copy_from_slice(&bytes[16..32]);
    validate_exchange_id(exchange_id)?;
    let body = &bytes[HEADER_BYTES..];
    if declared != body.len() {
        return Err(CodecError::LengthMismatch {
            declared,
            actual: body.len(),
        });
    }
    validate_body(kind, body)?;
    Ok(Frame {
        kind,
        exchange_id,
        body,
    })
}

fn validate_exchange_id(exchange_id: [u8; 16]) -> Result<(), CodecError> {
    if exchange_id == [0; 16] {
        return Err(CodecError::ZeroExchangeId);
    }
    Ok(())
}

fn validate_body(kind: FrameKind, body: &[u8]) -> Result<(), CodecError> {
    let body_must_be_empty = matches!(
        kind,
        FrameKind::ObserveRequest | FrameKind::CloseSourceRequest | FrameKind::CloseSourceAck
    );
    if body_must_be_empty && !body.is_empty() {
        return Err(CodecError::BodyForbidden(kind));
    }
    if !body_must_be_empty && body.is_empty() {
        return Err(CodecError::BodyRequired(kind));
    }
    if body.len() > kind.maximum_body_bytes() {
        return Err(CodecError::BodyTooLarge {
            kind,
            actual: body.len(),
        });
    }
    if kind == FrameKind::ObserveError && body.len() != ERROR_BODY_BYTES {
        return Err(CodecError::InvalidErrorBodyLength(body.len()));
    }
    Ok(())
}

fn decode_error_body(bytes: &[u8]) -> Result<ObservationErrorCode, CodecError> {
    if bytes.len() != ERROR_BODY_BYTES {
        return Err(CodecError::InvalidErrorBodyLength(bytes.len()));
    }
    let schema = read_u16(&bytes[..2]);
    if schema != 1 {
        return Err(CodecError::UnsupportedErrorSchema(schema));
    }
    let code = ObservationErrorCode::from_wire(read_u16(&bytes[2..4]))?;
    if read_u32(&bytes[4..8]) != 0 {
        return Err(CodecError::NonzeroErrorReserved);
    }
    Ok(code)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXCHANGE_ID: [u8; 16] = [0x41; 16];

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
            integrity_rid: MEDIUM_INTEGRITY_RID,
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
            observation_started_at: "2026-07-15T10:11:12.345Z".to_owned(),
            observation_completed_at: "2026-07-15T10:11:12.370Z".to_owned(),
            observation_duration_ms: 25,
            create_file_succeeded: true,
            handle_held_during_observation: true,
            device_io_control_call_count: 0,
            driver_load_call_count: 0,
            device_handle_read_call_count: 0,
            device_handle_write_call_count: 0,
        }
    }

    fn result_body(observation: &DeviceOpenObservation) -> Vec<u8> {
        serde_json::to_vec(observation).unwrap()
    }

    #[test]
    fn registry_is_exactly_one_non_bounty_query_only_target() {
        assert_eq!(TARGET_REGISTRY.len(), 1);
        let target = fixed_target();
        assert_eq!(target.target_id, "synthetic-non-bounty-buffered-fixture");
        assert_eq!(target.desired_access, 0);
        assert_eq!(target.share_mode, 3);
        assert_eq!(target.creation_disposition, 3);
        assert_eq!(target.flags_and_attributes, 0x80);
        assert_eq!(
            registry_sha256().unwrap(),
            "20a570dc9759c0f944f556363802c04b96658058c3c7f11c1a5bdb6de9018767"
        );
    }

    #[test]
    fn request_is_a_stable_zero_input_frame() {
        let request = encode_observe_request(EXCHANGE_ID).unwrap();
        assert_eq!(request.len(), HEADER_BYTES);
        assert_eq!(&request[..4], b"0VDO");
        assert_eq!(request[4], 1);
        assert_eq!(request[5], 1);
        assert_eq!(&request[6..16], &[0; 10]);
        assert_eq!(&request[16..], &EXCHANGE_ID);
        assert_eq!(decode_observe_request(&request).unwrap(), EXCHANGE_ID);
    }

    #[test]
    fn source_close_handshake_is_empty_and_exchange_bound() {
        let request = encode_close_source_request(EXCHANGE_ID).unwrap();
        assert_eq!(request.len(), HEADER_BYTES);
        assert_eq!(request[5], FrameKind::CloseSourceRequest as u8);
        assert_eq!(decode_close_source_request(&request).unwrap(), EXCHANGE_ID);

        let ack = encode_close_source_ack(EXCHANGE_ID).unwrap();
        assert_eq!(ack.len(), HEADER_BYTES);
        assert_eq!(ack[5], FrameKind::CloseSourceAck as u8);
        assert_eq!(decode_close_source_ack(&ack, EXCHANGE_ID), Ok(()));
        assert_eq!(
            decode_close_source_ack(&ack, [0x42; 16]),
            Err(CodecError::ExchangeIdMismatch)
        );
        assert_eq!(
            encode_frame(FrameKind::CloseSourceRequest, EXCHANGE_ID, b"handle"),
            Err(CodecError::BodyForbidden(FrameKind::CloseSourceRequest))
        );
        assert_eq!(
            encode_frame(FrameKind::CloseSourceAck, EXCHANGE_ID, b"closed"),
            Err(CodecError::BodyForbidden(FrameKind::CloseSourceAck))
        );
    }

    #[test]
    fn safe_observation_is_canonical_bounded_and_round_trips() {
        let observation = observation();
        let encoded = encode_observation_response(EXCHANGE_ID, &observation).unwrap();
        assert!(encoded.len() <= HEADER_BYTES + MAX_OBSERVATION_BODY_BYTES);
        assert_eq!(
            decode_observation_response(&encoded, EXCHANGE_ID).unwrap(),
            ObservationResponse::Observation(Box::new(observation))
        );
    }

    #[test]
    fn every_header_field_and_exchange_binding_fails_closed() {
        let valid = encode_observe_request(EXCHANGE_ID).unwrap();
        let mut changed = valid.clone();
        changed[0] ^= 1;
        assert_eq!(decode_observe_request(&changed), Err(CodecError::BadMagic));
        let mut changed = valid.clone();
        changed[4] = 2;
        assert_eq!(
            decode_observe_request(&changed),
            Err(CodecError::UnsupportedVersion(2))
        );
        let mut changed = valid.clone();
        changed[5] = 0xff;
        assert_eq!(
            decode_observe_request(&changed),
            Err(CodecError::UnknownKind(0xff))
        );
        let mut changed = valid.clone();
        changed[6] = 1;
        assert_eq!(
            decode_observe_request(&changed),
            Err(CodecError::NonzeroFlags)
        );
        let mut changed = valid.clone();
        changed[12] = 1;
        assert_eq!(
            decode_observe_request(&changed),
            Err(CodecError::NonzeroReserved)
        );
        let mut changed = valid.clone();
        changed[16..32].fill(0);
        assert_eq!(
            decode_observe_request(&changed),
            Err(CodecError::ZeroExchangeId)
        );

        let result = encode_observation_response(EXCHANGE_ID, &observation()).unwrap();
        assert_eq!(
            decode_observation_response(&result, [0x42; 16]),
            Err(CodecError::ExchangeIdMismatch)
        );
        assert_eq!(
            decode_observation_response(&valid, EXCHANGE_ID),
            Err(CodecError::UnexpectedKind(FrameKind::ObserveRequest))
        );
    }

    #[test]
    fn request_rejects_any_input_and_lengths_are_exact() {
        assert_eq!(
            decode_observe_request(&[0; HEADER_BYTES - 1]),
            Err(CodecError::MessageTooShort)
        );
        assert_eq!(
            encode_frame(FrameKind::ObserveRequest, EXCHANGE_ID, b"target"),
            Err(CodecError::BodyForbidden(FrameKind::ObserveRequest))
        );
        let mut trailing = encode_observe_request(EXCHANGE_ID).unwrap();
        trailing.push(0);
        assert_eq!(
            decode_observe_request(&trailing),
            Err(CodecError::LengthMismatch {
                declared: 0,
                actual: 1
            })
        );
        let mut declared = encode_observe_request(EXCHANGE_ID).unwrap();
        declared[8] = 1;
        assert_eq!(
            decode_observe_request(&declared),
            Err(CodecError::LengthMismatch {
                declared: 1,
                actual: 0
            })
        );
        assert_eq!(
            encode_frame(FrameKind::ObserveResult, EXCHANGE_ID, &[]),
            Err(CodecError::BodyRequired(FrameKind::ObserveResult))
        );
        assert_eq!(
            encode_frame(
                FrameKind::ObserveResult,
                EXCHANGE_ID,
                &vec![0; MAX_OBSERVATION_BODY_BYTES + 1]
            ),
            Err(CodecError::BodyTooLarge {
                kind: FrameKind::ObserveResult,
                actual: MAX_OBSERVATION_BODY_BYTES + 1
            })
        );
    }

    #[test]
    fn unknown_missing_duplicate_and_noncanonical_observation_json_fail() {
        let observation = observation();
        let canonical = result_body(&observation);

        let mut value = serde_json::to_value(&observation).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("runtime_target".to_owned(), "forbidden".into());
        let encoded = encode_frame(
            FrameKind::ObserveResult,
            EXCHANGE_ID,
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            decode_observation_response(&encoded, EXCHANGE_ID),
            Err(CodecError::InvalidObservation(_))
        ));

        value.as_object_mut().unwrap().remove("target_id");
        let encoded = encode_frame(
            FrameKind::ObserveResult,
            EXCHANGE_ID,
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            decode_observation_response(&encoded, EXCHANGE_ID),
            Err(CodecError::InvalidObservation(_))
        ));

        let duplicate = String::from_utf8(canonical.clone()).unwrap().replacen(
            "{\"schema_version\":",
            "{\"schema_version\":\"duplicate\",\"schema_version\":",
            1,
        );
        let encoded =
            encode_frame(FrameKind::ObserveResult, EXCHANGE_ID, duplicate.as_bytes()).unwrap();
        assert!(matches!(
            decode_observation_response(&encoded, EXCHANGE_ID),
            Err(CodecError::InvalidObservation(_))
        ));

        let mut whitespace = canonical;
        whitespace.push(b' ');
        let encoded = encode_frame(FrameKind::ObserveResult, EXCHANGE_ID, &whitespace).unwrap();
        assert_eq!(
            decode_observation_response(&encoded, EXCHANGE_ID),
            Err(CodecError::NoncanonicalObservation)
        );
    }

    #[test]
    fn registry_target_and_query_only_fields_cannot_drift() {
        let base = observation();
        let mut variants = Vec::new();
        let mut value = base.clone();
        value.target_id = "other".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.driver_service_name = "Other".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.interface_class_guid = "{00000000-0000-0000-0000-000000000000}".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.interface_instance_id = "ROOT\\OTHER\\0000".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.collector_registry_sha256 = "0".repeat(64);
        variants.push(value);
        let mut value = base.clone();
        value.enumeration_flags = 0;
        variants.push(value);
        let mut value = base.clone();
        value.interface_count = 0;
        variants.push(value);
        let mut value = base.clone();
        value.selected_interface_index = 1;
        variants.push(value);
        let mut value = base.clone();
        value.desired_access = 0x8000_0000;
        variants.push(value);
        let mut value = base.clone();
        value.share_mode = 1;
        variants.push(value);
        let mut value = base.clone();
        value.security_attributes_null = false;
        variants.push(value);
        let mut value = base.clone();
        value.creation_disposition = 4;
        variants.push(value);
        let mut value = base.clone();
        value.flags_and_attributes = 0;
        variants.push(value);
        let mut value = base.clone();
        value.template_file_null = false;
        variants.push(value);
        for variant in variants {
            assert!(variant.validate().is_err());
            assert!(matches!(
                encode_observation_response(EXCHANGE_ID, &variant),
                Err(CodecError::InvalidObservation(_))
            ));
        }
    }

    #[test]
    fn unsafe_identity_handle_token_timing_and_device_activity_fail_closed() {
        let base = observation();
        let mut variants = Vec::new();
        let mut value = base.clone();
        value.process_id = 0;
        variants.push(value);
        let mut value = base.clone();
        value.process_creation_filetime = 0;
        variants.push(value);

        let mut value = observation();
        value.primary_token_id = 0;
        variants.push(value);

        let mut value = observation();
        value.primary_token_modified_id = 0;
        variants.push(value);
        let mut value = base.clone();
        value.source_handle_value = 0;
        variants.push(value);
        let mut value = base.clone();
        value.source_handle_value = u64::MAX;
        variants.push(value);
        let mut value = base.clone();
        value.thread_token_present = true;
        variants.push(value);
        let mut value = base.clone();
        value.impersonation_active = true;
        variants.push(value);
        let mut value = base.clone();
        value.elevated = true;
        variants.push(value);
        let mut value = base.clone();
        value.integrity_rid = 12_288;
        variants.push(value);
        let mut value = base.clone();
        value.admin_group_present = true;
        variants.push(value);
        let mut value = base.clone();
        value.linked_token_present = true;
        variants.push(value);
        let mut value = base.clone();
        value.token_restricted = true;
        variants.push(value);
        let mut value = base.clone();
        value.restricted_sid_count = 1;
        variants.push(value);
        let mut value = base.clone();
        value.enabled_privileges = vec!["SeImpersonatePrivilege".to_owned()];
        variants.push(value);
        let mut value = base.clone();
        value.app_container = true;
        variants.push(value);
        let mut value = base.clone();
        value.debug_privilege_present = true;
        variants.push(value);
        let mut value = base.clone();
        value.user_sid = "S-1-5-18".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.authentication_id = "00000000000003e7".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.observation_completed_at = "2026-07-15T10:11:12.344Z".to_owned();
        variants.push(value);
        let mut value = base.clone();
        value.observation_duration_ms = 300_001;
        variants.push(value);
        let mut value = base.clone();
        value.create_file_succeeded = false;
        variants.push(value);
        let mut value = base.clone();
        value.handle_held_during_observation = false;
        variants.push(value);
        let mut value = base.clone();
        value.device_io_control_call_count = 1;
        variants.push(value);
        let mut value = base.clone();
        value.driver_load_call_count = 1;
        variants.push(value);
        let mut value = base.clone();
        value.device_handle_read_call_count = 1;
        variants.push(value);
        let mut value = base.clone();
        value.device_handle_write_call_count = 1;
        variants.push(value);
        for variant in variants {
            assert!(variant.validate().is_err());
        }
    }

    #[test]
    fn error_responses_are_fixed_versioned_and_closed_to_unknown_values() {
        for code in [
            ObservationErrorCode::InvalidRequest,
            ObservationErrorCode::EnumerationFailed,
            ObservationErrorCode::InterfaceMismatch,
            ObservationErrorCode::OpenFailed,
            ObservationErrorCode::UnsafeToken,
            ObservationErrorCode::ResponseEncodingFailed,
        ] {
            let encoded = encode_error_response(EXCHANGE_ID, code).unwrap();
            assert_eq!(
                decode_observation_response(&encoded, EXCHANGE_ID).unwrap(),
                ObservationResponse::Error(code)
            );
        }
        let valid =
            encode_error_response(EXCHANGE_ID, ObservationErrorCode::InvalidRequest).unwrap();
        let mut changed = valid.clone();
        changed[32] = 2;
        assert_eq!(
            decode_observation_response(&changed, EXCHANGE_ID),
            Err(CodecError::UnsupportedErrorSchema(2))
        );
        let mut changed = valid.clone();
        changed[34..36].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode_observation_response(&changed, EXCHANGE_ID),
            Err(CodecError::UnknownErrorCode(99))
        );
        let mut changed = valid;
        changed[36] = 1;
        assert_eq!(
            decode_observation_response(&changed, EXCHANGE_ID),
            Err(CodecError::NonzeroErrorReserved)
        );
    }

    #[test]
    fn helper_validators_reject_noncanonical_edges() {
        for invalid in ["", &"g".repeat(64), &"A".repeat(64), &"0".repeat(63)] {
            assert!(!valid_sha256(invalid));
        }
        for invalid in [
            "S-1-5-18",
            "S-1-5-21-1-2-3-500",
            "S-1-5-21-01-2-3-1000",
            "S-1-5-21-4294967296-2-3-1000",
        ] {
            assert!(validate_account_sid(invalid).is_err());
        }
        for invalid in [
            "2026-07-15T10:11:12Z",
            "2026-13-15T10:11:12.000Z",
            "2026-02-29T10:11:12.000Z",
            "2026-04-31T10:11:12.000Z",
            "2026-07-15T24:11:12.000Z",
            "2026-07-15T10:60:12.000Z",
            "2026-07-15T10:11:12.000+00:00",
        ] {
            assert!(!valid_utc_millisecond_timestamp(invalid));
        }
    }

    #[test]
    fn windows_opener_source_has_one_open_and_no_device_activity_surface() {
        let source = include_str!("windows/device_open.rs");
        for forbidden in [
            concat!("DeviceIo", "Control("),
            concat!("Read", "File("),
            concat!("Write", "File("),
            concat!("NtLoad", "Driver("),
            concat!("Start", "ServiceW("),
        ] {
            assert!(!source.contains(forbidden));
        }
        assert_eq!(source.matches("        CreateFileW(").count(), 1);
    }
}
