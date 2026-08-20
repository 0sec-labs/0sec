use std::collections::HashSet;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

pub const BROKER_REQUEST_SCHEMA: &str = "0verse.windows-token-broker-request/v1";
pub const DEVICE_OPEN_BROKER_REQUEST_SCHEMA: &str = "0verse.windows-device-open-broker-request/v1";
pub const BROKER_RESPONSE_SCHEMA: &str = "0verse.windows-token-broker-response/v1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_AUTHORITY_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityMaterials {
    pub campaign: Vec<u8>,
    pub scope_manifest: Vec<u8>,
    pub execution_grant: Vec<u8>,
    pub worker_acceptance: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceOpenAuthorityMaterials {
    pub standard: AuthorityMaterials,
    pub boundary_manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    pub schema_version: String,
    pub campaign_json_b64: String,
    pub scope_manifest_json_b64: String,
    pub execution_grant_json_b64: String,
    pub worker_acceptance_json_b64: String,
    pub case: String,
    pub trial: u32,
    pub run_nonce: String,
}

/// Exact transport for a standard authority chain plus one signed fixed
/// device-open boundary manifest. It is a distinct schema so v1 capture
/// requests cannot acquire device-open meaning through an optional field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceOpenBrokerRequest {
    pub schema_version: String,
    pub campaign_json_b64: String,
    pub scope_manifest_json_b64: String,
    pub execution_grant_json_b64: String,
    pub worker_acceptance_json_b64: String,
    pub device_open_boundary_manifest_json_b64: String,
    pub case: String,
    pub trial: u32,
    pub run_nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerResponseCode {
    ValidationError,
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    pub schema_version: String,
    pub code: BrokerResponseCode,
    pub message: String,
}

struct StrictJsonValue(serde_json::Value);

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            values.insert(key, map.next_value::<StrictJsonValue>()?.0);
        }
        Ok(StrictJsonValue(serde_json::Value::Object(values)))
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn decode_authority(value: &str, name: &str) -> Result<Vec<u8>, String> {
    if value.len() > MAX_AUTHORITY_BYTES.div_ceil(3) * 4 {
        return Err(format!("{name} encoding exceeds its bound"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{name} is not canonical base64url"))?;
    if decoded.len() > MAX_AUTHORITY_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(format!("{name} is oversized or non-canonical"));
    }
    parse_strict_json_object(&decoded, name)?;
    Ok(decoded)
}

/// Parse one UTF-8 JSON object while rejecting duplicate keys at every depth.
///
/// This is crate-private so the authority verifier can re-parse raw broker
/// material instead of trusting validation performed at the transport edge.
pub(crate) fn parse_strict_json_object(
    bytes: &[u8],
    name: &str,
) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{name} is not UTF-8 JSON"))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{name} is not strict JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|_| format!("{name} is not one JSON value"))?;
    if !value.0.is_object() {
        return Err(format!("{name} must be a JSON object"));
    }
    Ok(value.0)
}

impl BrokerRequest {
    /// Validate the request and recover the exact raw authority bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, unsafe invocation selector,
    /// invalid nonce, or malformed/oversized authority material.
    pub fn authority_materials(&self) -> Result<AuthorityMaterials, String> {
        if self.schema_version != BROKER_REQUEST_SCHEMA {
            return Err("unsupported broker request schema".to_owned());
        }
        if !matches!(self.case.as_str(), "target" | "control") || !(1..=32).contains(&self.trial) {
            return Err("broker case or trial is invalid".to_owned());
        }
        crate::validate_run_nonce(&self.run_nonce).map_err(str::to_owned)?;
        Ok(AuthorityMaterials {
            campaign: decode_authority(&self.campaign_json_b64, "campaign")?,
            scope_manifest: decode_authority(&self.scope_manifest_json_b64, "scope manifest")?,
            execution_grant: decode_authority(&self.execution_grant_json_b64, "execution grant")?,
            worker_acceptance: decode_authority(
                &self.worker_acceptance_json_b64,
                "worker acceptance",
            )?,
        })
    }
}

impl DeviceOpenBrokerRequest {
    /// Validate and recover every exact signed source document.
    pub(crate) fn authority_materials(&self) -> Result<DeviceOpenAuthorityMaterials, String> {
        if self.schema_version != DEVICE_OPEN_BROKER_REQUEST_SCHEMA {
            return Err("unsupported device-open broker request schema".to_owned());
        }
        let standard_request = self.standard_request();
        Ok(DeviceOpenAuthorityMaterials {
            standard: standard_request.authority_materials()?,
            boundary_manifest: decode_authority(
                &self.device_open_boundary_manifest_json_b64,
                "device-open boundary manifest",
            )?,
        })
    }

    pub(crate) fn standard_request(&self) -> BrokerRequest {
        BrokerRequest {
            schema_version: BROKER_REQUEST_SCHEMA.to_owned(),
            campaign_json_b64: self.campaign_json_b64.clone(),
            scope_manifest_json_b64: self.scope_manifest_json_b64.clone(),
            execution_grant_json_b64: self.execution_grant_json_b64.clone(),
            worker_acceptance_json_b64: self.worker_acceptance_json_b64.clone(),
            case: self.case.clone(),
            trial: self.trial,
            run_nonce: self.run_nonce.clone(),
        }
    }
}

/// Decode an exact device-open request frame without accepting ordinary broker
/// requests or optional authority material.
#[allow(
    dead_code,
    reason = "the distinct transport remains unreachable until SCM activation"
)]
pub(crate) fn decode_device_open_request_frame(
    frame: &[u8],
) -> Result<(DeviceOpenBrokerRequest, DeviceOpenAuthorityMaterials), String> {
    let payload = decode_frame_payload(frame)?;
    let value = parse_strict_json_object(payload, "device-open broker request")?;
    let request: DeviceOpenBrokerRequest = serde_json::from_value(value)
        .map_err(|error| format!("device-open broker request schema is invalid: {error}"))?;
    let materials = request.authority_materials()?;
    Ok((request, materials))
}

#[allow(
    dead_code,
    reason = "used only by the staged device-open transport decoder"
)]
fn decode_frame_payload(frame: &[u8]) -> Result<&[u8], String> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or_else(|| "broker frame is truncated".to_owned())?
        .try_into()
        .map_err(|_| "broker frame prefix is malformed".to_owned())?;
    let declared = usize::try_from(u32::from_le_bytes(prefix))
        .map_err(|_| "broker frame length does not fit this platform".to_owned())?;
    if declared == 0 || declared > MAX_FRAME_BYTES {
        return Err("broker frame length is invalid".to_owned());
    }
    if frame.len() != 4 + declared {
        return Err("broker frame is truncated or has trailing bytes".to_owned());
    }
    Ok(&frame[4..])
}

/// Decode exactly one little-endian length-prefixed broker request frame.
///
/// # Errors
///
/// Returns an error for a truncated, oversized, trailing, duplicate-key, or
/// unknown-field frame, or for invalid embedded authority material.
pub fn decode_request_frame(frame: &[u8]) -> Result<(BrokerRequest, AuthorityMaterials), String> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or_else(|| "broker frame is truncated".to_owned())?
        .try_into()
        .map_err(|_| "broker frame prefix is malformed".to_owned())?;
    let declared = usize::try_from(u32::from_le_bytes(prefix))
        .map_err(|_| "broker frame length does not fit this platform".to_owned())?;
    if declared == 0 || declared > MAX_FRAME_BYTES {
        return Err("broker frame length is invalid".to_owned());
    }
    if frame.len() != 4 + declared {
        return Err("broker frame is truncated or has trailing bytes".to_owned());
    }
    let request: BrokerRequest = serde_json::from_slice(&frame[4..])
        .map_err(|error| format!("broker request JSON is invalid: {error}"))?;
    let materials = request.authority_materials()?;
    Ok((request, materials))
}

/// Encode one bounded broker response frame.
///
/// # Errors
///
/// Returns an error if the response cannot be serialized or exceeds the frame bound.
pub fn encode_response_frame(response: &BrokerResponse) -> Result<Vec<u8>, String> {
    if response.schema_version != BROKER_RESPONSE_SCHEMA
        || response.message.is_empty()
        || response.message.len() > 1024
    {
        return Err("broker response is invalid".to_owned());
    }
    let body = serde_json::to_vec(response)
        .map_err(|error| format!("cannot serialize broker response: {error}"))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err("broker response exceeds the frame bound".to_owned());
    }
    let length =
        u32::try_from(body.len()).map_err(|_| "broker response is too large".to_owned())?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BrokerRequest {
        let authority = URL_SAFE_NO_PAD.encode(br#"{"schema_version":"test/v1"}"#);
        BrokerRequest {
            schema_version: BROKER_REQUEST_SCHEMA.to_owned(),
            campaign_json_b64: authority.clone(),
            scope_manifest_json_b64: authority.clone(),
            execution_grant_json_b64: authority.clone(),
            worker_acceptance_json_b64: authority,
            case: "control".to_owned(),
            trial: 1,
            run_nonce: "run_nonce_00000000000000000000000".to_owned(),
        }
    }

    fn device_open_request() -> DeviceOpenBrokerRequest {
        let request = request();
        DeviceOpenBrokerRequest {
            schema_version: DEVICE_OPEN_BROKER_REQUEST_SCHEMA.to_owned(),
            campaign_json_b64: request.campaign_json_b64,
            scope_manifest_json_b64: request.scope_manifest_json_b64,
            execution_grant_json_b64: request.execution_grant_json_b64,
            worker_acceptance_json_b64: request.worker_acceptance_json_b64,
            device_open_boundary_manifest_json_b64: URL_SAFE_NO_PAD
                .encode(br#"{"schema_version":"device-open/test-v1"}"#),
            case: request.case,
            trial: request.trial,
            run_nonce: request.run_nonce,
        }
    }

    fn frame(value: &[u8]) -> Vec<u8> {
        let mut framed = u32::try_from(value.len()).unwrap().to_le_bytes().to_vec();
        framed.extend_from_slice(value);
        framed
    }

    #[test]
    fn bounded_frame_round_trips_exact_authority_bytes() {
        let body = serde_json::to_vec(&request()).unwrap();
        let (decoded, materials) = decode_request_frame(&frame(&body)).unwrap();
        assert_eq!(decoded.case, "control");
        assert_eq!(materials.campaign, br#"{"schema_version":"test/v1"}"#);
    }

    #[test]
    fn device_open_transport_is_distinct_and_retains_exact_fifth_document() {
        let request = device_open_request();
        let body = serde_json::to_vec(&request).unwrap();
        let (decoded, materials) = decode_device_open_request_frame(&frame(&body)).unwrap();
        assert_eq!(decoded.case, "control");
        assert_eq!(
            materials.standard.campaign,
            br#"{"schema_version":"test/v1"}"#
        );
        assert_eq!(
            materials.boundary_manifest,
            br#"{"schema_version":"device-open/test-v1"}"#
        );

        let ordinary = request.standard_request();
        let ordinary_body = serde_json::to_vec(&ordinary).unwrap();
        assert!(decode_device_open_request_frame(&frame(&ordinary_body)).is_err());
        assert!(decode_request_frame(&frame(&body)).is_err());
    }

    #[test]
    fn device_open_transport_rejects_missing_duplicate_and_dynamic_fields() {
        let body = serde_json::to_string(&device_open_request()).unwrap();
        let missing = body.replace(
            &format!(
                "\"device_open_boundary_manifest_json_b64\":\"{}\",",
                device_open_request().device_open_boundary_manifest_json_b64
            ),
            "",
        );
        assert!(decode_device_open_request_frame(&frame(missing.as_bytes())).is_err());
        let duplicate = body.replacen("\"case\":", "\"case\":\"target\",\"case\":", 1);
        assert!(decode_device_open_request_frame(&frame(duplicate.as_bytes())).is_err());
        let dynamic = body.replacen('{', "{\"device_path\":\"\\\\.\\\\unsafe\",", 1);
        assert!(decode_device_open_request_frame(&frame(dynamic.as_bytes())).is_err());
    }

    #[test]
    fn dynamic_execution_surfaces_and_duplicate_keys_are_rejected() {
        let body = serde_json::to_string(&request()).unwrap();
        let with_argv = body.replacen('{', "{\"argv\":[\"cmd.exe\"],", 1);
        assert!(decode_request_frame(&frame(with_argv.as_bytes())).is_err());
        let duplicate = body.replacen("\"case\":", "\"case\":\"target\",\"case\":", 1);
        assert!(decode_request_frame(&frame(duplicate.as_bytes())).is_err());

        let mut nested_duplicate = request();
        nested_duplicate.campaign_json_b64 =
            URL_SAFE_NO_PAD.encode(br#"{"schema_version":"test/v1","nested":{"x":1,"x":2}}"#);
        let body = serde_json::to_vec(&nested_duplicate).unwrap();
        assert!(decode_request_frame(&frame(&body)).is_err());
    }

    #[test]
    fn framing_rejects_truncation_trailing_bytes_and_oversize() {
        let body = serde_json::to_vec(&request()).unwrap();
        let mut valid = frame(&body);
        valid.pop();
        assert!(decode_request_frame(&valid).is_err());
        let mut valid = frame(&body);
        valid.push(0);
        assert!(decode_request_frame(&valid).is_err());
        assert!(decode_request_frame(&(u32::MAX).to_le_bytes()).is_err());
    }

    #[test]
    fn response_is_typed_and_bounded() {
        let response = BrokerResponse {
            schema_version: BROKER_RESPONSE_SCHEMA.to_owned(),
            code: BrokerResponseCode::NotImplemented,
            message: "A1 cannot execute operations or emit evidence".to_owned(),
        };
        let encoded = encode_response_frame(&response).unwrap();
        assert_eq!(
            usize::try_from(u32::from_le_bytes(encoded[..4].try_into().unwrap())).unwrap(),
            encoded.len() - 4
        );
    }
}
