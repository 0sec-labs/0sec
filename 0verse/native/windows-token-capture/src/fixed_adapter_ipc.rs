#![allow(
    dead_code,
    reason = "the platform-neutral codec is private until the Windows transport lands"
)]

//! Bounded, versioned framing for the trusted-child fixed-adapter exchange.
//!
//! Each encoded value is one complete message-mode pipe message. The legacy
//! shutdown remains a distinct one-byte message so the existing no-request
//! trusted-child lifecycle stays wire-compatible.

use std::fmt;

pub(crate) const HEADER_BYTES: usize = 32;
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
pub(crate) const MAX_RESULT_BODY_BYTES: usize = 16 * 1024;
pub(crate) const SHUTDOWN_MESSAGE: [u8; 1] = [0xa3];

const MAGIC: [u8; 4] = *b"0VFA";
const VERSION: u8 = 1;
const ERROR_BODY_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(
    clippy::enum_variant_names,
    reason = "the shared Execute prefix is the audited wire vocabulary"
)]
pub(crate) enum FrameKind {
    ExecuteRequest = 0x01,
    ExecuteResult = 0x81,
    ExecuteError = 0x82,
}

impl FrameKind {
    fn from_wire(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::ExecuteRequest),
            0x81 => Ok(Self::ExecuteResult),
            0x82 => Ok(Self::ExecuteError),
            _ => Err(CodecError::UnknownKind(value)),
        }
    }

    const fn max_body_bytes(self) -> usize {
        match self {
            Self::ExecuteRequest => MAX_REQUEST_BODY_BYTES,
            Self::ExecuteResult => MAX_RESULT_BODY_BYTES,
            Self::ExecuteError => ERROR_BODY_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) kind: FrameKind,
    pub(crate) exchange_id: [u8; 16],
    pub(crate) body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireMessage {
    Shutdown,
    Frame(Frame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProtocolErrorCode {
    InvalidFrame = 1,
    UnsupportedVersion = 2,
    UnexpectedKind = 3,
    InvalidRequest = 4,
    ExecutionFailed = 5,
    ResponseEncodingFailed = 6,
}

impl ProtocolErrorCode {
    fn from_wire(value: u16) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::InvalidFrame),
            2 => Ok(Self::UnsupportedVersion),
            3 => Ok(Self::UnexpectedKind),
            4 => Ok(Self::InvalidRequest),
            5 => Ok(Self::ExecutionFailed),
            6 => Ok(Self::ResponseEncodingFailed),
            _ => Err(CodecError::UnknownErrorCode(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolErrorBody {
    pub(crate) code: ProtocolErrorCode,
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
    EmptyBody(FrameKind),
    BodyTooLarge {
        kind: FrameKind,
        actual: usize,
        maximum: usize,
    },
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    ExchangeIdMismatch,
    UnexpectedResponseKind(FrameKind),
    InvalidErrorBodyLength(usize),
    UnsupportedErrorSchema(u16),
    UnknownErrorCode(u16),
    NonzeroErrorReserved,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fixed-adapter IPC frame is invalid: {self:?}")
    }
}

impl std::error::Error for CodecError {}

pub(crate) fn encode_frame(
    kind: FrameKind,
    exchange_id: [u8; 16],
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    validate_exchange_id(exchange_id)?;
    validate_body(kind, body)?;
    let body_len = u32::try_from(body.len()).map_err(|_| CodecError::BodyTooLarge {
        kind,
        actual: body.len(),
        maximum: kind.max_body_bytes(),
    })?;
    let total = HEADER_BYTES
        .checked_add(body.len())
        .ok_or(CodecError::BodyTooLarge {
            kind,
            actual: body.len(),
            maximum: kind.max_body_bytes(),
        })?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend(MAGIC);
    encoded.push(VERSION);
    encoded.push(kind as u8);
    encoded.extend(0u16.to_le_bytes());
    encoded.extend(body_len.to_le_bytes());
    encoded.extend(0u32.to_le_bytes());
    encoded.extend(exchange_id);
    encoded.extend(body);
    debug_assert_eq!(encoded.len(), total);
    Ok(encoded)
}

pub(crate) fn decode_message(bytes: &[u8]) -> Result<WireMessage, CodecError> {
    if bytes == SHUTDOWN_MESSAGE {
        return Ok(WireMessage::Shutdown);
    }
    decode_frame(bytes).map(WireMessage::Frame)
}

pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Frame, CodecError> {
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
    let declared = usize::try_from(read_u32(&bytes[8..12]))
        .expect("u32 frame length always fits usize on supported Windows targets");
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
        body: body.to_vec(),
    })
}

pub(crate) fn decode_response(
    bytes: &[u8],
    expected_exchange_id: [u8; 16],
) -> Result<Frame, CodecError> {
    validate_exchange_id(expected_exchange_id)?;
    let frame = decode_frame(bytes)?;
    if frame.exchange_id != expected_exchange_id {
        return Err(CodecError::ExchangeIdMismatch);
    }
    if !matches!(
        frame.kind,
        FrameKind::ExecuteResult | FrameKind::ExecuteError
    ) {
        return Err(CodecError::UnexpectedResponseKind(frame.kind));
    }
    Ok(frame)
}

pub(crate) fn encode_error_body(code: ProtocolErrorCode) -> [u8; ERROR_BODY_BYTES] {
    let mut body = [0u8; ERROR_BODY_BYTES];
    body[..2].copy_from_slice(&1u16.to_le_bytes());
    body[2..4].copy_from_slice(&(code as u16).to_le_bytes());
    body
}

pub(crate) fn decode_error_body(bytes: &[u8]) -> Result<ProtocolErrorBody, CodecError> {
    if bytes.len() != ERROR_BODY_BYTES {
        return Err(CodecError::InvalidErrorBodyLength(bytes.len()));
    }
    let schema = read_u16(&bytes[..2]);
    if schema != 1 {
        return Err(CodecError::UnsupportedErrorSchema(schema));
    }
    let code = ProtocolErrorCode::from_wire(read_u16(&bytes[2..4]))?;
    if read_u32(&bytes[4..8]) != 0 {
        return Err(CodecError::NonzeroErrorReserved);
    }
    Ok(ProtocolErrorBody { code })
}

fn validate_exchange_id(exchange_id: [u8; 16]) -> Result<(), CodecError> {
    if exchange_id == [0u8; 16] {
        return Err(CodecError::ZeroExchangeId);
    }
    Ok(())
}

fn validate_body(kind: FrameKind, body: &[u8]) -> Result<(), CodecError> {
    if body.is_empty() {
        return Err(CodecError::EmptyBody(kind));
    }
    let maximum = kind.max_body_bytes();
    if body.len() > maximum {
        return Err(CodecError::BodyTooLarge {
            kind,
            actual: body.len(),
            maximum,
        });
    }
    if kind == FrameKind::ExecuteError && body.len() != ERROR_BODY_BYTES {
        return Err(CodecError::InvalidErrorBodyLength(body.len()));
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("codec passes an exact u16 slice"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("codec passes an exact u32 slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXCHANGE_ID: [u8; 16] = [0x11; 16];

    fn request() -> Vec<u8> {
        encode_frame(FrameKind::ExecuteRequest, EXCHANGE_ID, b"{}").unwrap()
    }

    #[test]
    fn request_has_stable_golden_header_and_round_trips() {
        let encoded = request();
        assert_eq!(&encoded[..4], b"0VFA");
        assert_eq!(encoded[4], 1);
        assert_eq!(encoded[5], 0x01);
        assert_eq!(&encoded[6..8], &[0, 0]);
        assert_eq!(&encoded[8..12], &[2, 0, 0, 0]);
        assert_eq!(&encoded[12..16], &[0, 0, 0, 0]);
        assert_eq!(&encoded[16..32], &EXCHANGE_ID);
        assert_eq!(&encoded[32..], b"{}");
        assert_eq!(
            decode_message(&encoded).unwrap(),
            WireMessage::Frame(Frame {
                kind: FrameKind::ExecuteRequest,
                exchange_id: EXCHANGE_ID,
                body: b"{}".to_vec(),
            })
        );
    }

    #[test]
    fn all_frame_kinds_round_trip_at_their_exact_bounds() {
        for (kind, length) in [
            (FrameKind::ExecuteRequest, MAX_REQUEST_BODY_BYTES),
            (FrameKind::ExecuteResult, MAX_RESULT_BODY_BYTES),
            (FrameKind::ExecuteError, ERROR_BODY_BYTES),
        ] {
            let body = vec![0x5a; length];
            let encoded = encode_frame(kind, EXCHANGE_ID, &body).unwrap();
            let decoded = decode_frame(&encoded).unwrap();
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.exchange_id, EXCHANGE_ID);
            assert_eq!(decoded.body, body);
        }
    }

    #[test]
    fn shutdown_is_only_the_exact_legacy_one_byte_message() {
        assert_eq!(
            decode_message(&SHUTDOWN_MESSAGE).unwrap(),
            WireMessage::Shutdown
        );
        assert_eq!(
            decode_message(&[0xa3, 0]).unwrap_err(),
            CodecError::MessageTooShort
        );
        assert_eq!(
            decode_message(&[0xa3; HEADER_BYTES]).unwrap_err(),
            CodecError::BadMagic
        );
    }

    #[test]
    fn every_fixed_header_field_is_validated() {
        let valid = request();

        let mut changed = valid.clone();
        changed[0] ^= 1;
        assert_eq!(decode_frame(&changed).unwrap_err(), CodecError::BadMagic);

        let mut changed = valid.clone();
        changed[4] = 2;
        assert_eq!(
            decode_frame(&changed).unwrap_err(),
            CodecError::UnsupportedVersion(2)
        );

        let mut changed = valid.clone();
        changed[5] = 0xff;
        assert_eq!(
            decode_frame(&changed).unwrap_err(),
            CodecError::UnknownKind(0xff)
        );

        let mut changed = valid.clone();
        changed[6] = 1;
        assert_eq!(
            decode_frame(&changed).unwrap_err(),
            CodecError::NonzeroFlags
        );

        let mut changed = valid.clone();
        changed[12] = 1;
        assert_eq!(
            decode_frame(&changed).unwrap_err(),
            CodecError::NonzeroReserved
        );

        let mut changed = valid;
        changed[16..32].fill(0);
        assert_eq!(
            decode_frame(&changed).unwrap_err(),
            CodecError::ZeroExchangeId
        );
    }

    #[test]
    fn lengths_reject_short_truncated_trailing_empty_and_oversized_messages() {
        assert_eq!(
            decode_frame(&[0; HEADER_BYTES - 1]).unwrap_err(),
            CodecError::MessageTooShort
        );

        let mut truncated = request();
        truncated.pop();
        assert_eq!(
            decode_frame(&truncated).unwrap_err(),
            CodecError::LengthMismatch {
                declared: 2,
                actual: 1,
            }
        );

        let mut trailing = request();
        trailing.push(0);
        assert_eq!(
            decode_frame(&trailing).unwrap_err(),
            CodecError::LengthMismatch {
                declared: 2,
                actual: 3,
            }
        );

        assert_eq!(
            encode_frame(FrameKind::ExecuteRequest, EXCHANGE_ID, &[]).unwrap_err(),
            CodecError::EmptyBody(FrameKind::ExecuteRequest)
        );

        let oversized = vec![0; MAX_REQUEST_BODY_BYTES + 1];
        assert_eq!(
            encode_frame(FrameKind::ExecuteRequest, EXCHANGE_ID, &oversized).unwrap_err(),
            CodecError::BodyTooLarge {
                kind: FrameKind::ExecuteRequest,
                actual: MAX_REQUEST_BODY_BYTES + 1,
                maximum: MAX_REQUEST_BODY_BYTES,
            }
        );
    }

    #[test]
    fn decode_applies_kind_specific_bounds_even_with_a_self_consistent_length() {
        let mut encoded = request();
        let body = vec![0x41; MAX_RESULT_BODY_BYTES + 1];
        encoded[5] = FrameKind::ExecuteResult as u8;
        encoded[8..12].copy_from_slice(
            &u32::try_from(body.len())
                .expect("test body length fits u32")
                .to_le_bytes(),
        );
        encoded.truncate(HEADER_BYTES);
        encoded.extend(body);
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CodecError::BodyTooLarge {
                kind: FrameKind::ExecuteResult,
                actual: MAX_RESULT_BODY_BYTES + 1,
                maximum: MAX_RESULT_BODY_BYTES,
            }
        );
    }

    #[test]
    fn response_must_have_matching_exchange_id_and_response_kind() {
        let result = encode_frame(FrameKind::ExecuteResult, EXCHANGE_ID, b"{}").unwrap();
        assert_eq!(
            decode_response(&result, [0x22; 16]).unwrap_err(),
            CodecError::ExchangeIdMismatch
        );

        let request = request();
        assert_eq!(
            decode_response(&request, EXCHANGE_ID).unwrap_err(),
            CodecError::UnexpectedResponseKind(FrameKind::ExecuteRequest)
        );
        assert_eq!(
            decode_response(&result, [0; 16]).unwrap_err(),
            CodecError::ZeroExchangeId
        );
    }

    #[test]
    fn protocol_error_body_is_fixed_versioned_and_closed_to_unknown_values() {
        for code in [
            ProtocolErrorCode::InvalidFrame,
            ProtocolErrorCode::UnsupportedVersion,
            ProtocolErrorCode::UnexpectedKind,
            ProtocolErrorCode::InvalidRequest,
            ProtocolErrorCode::ExecutionFailed,
            ProtocolErrorCode::ResponseEncodingFailed,
        ] {
            let encoded = encode_error_body(code);
            assert_eq!(decode_error_body(&encoded).unwrap().code, code);
            let frame = encode_frame(FrameKind::ExecuteError, EXCHANGE_ID, &encoded).unwrap();
            assert_eq!(decode_response(&frame, EXCHANGE_ID).unwrap().body, encoded);
        }

        let mut changed = encode_error_body(ProtocolErrorCode::InvalidFrame);
        changed[0] = 2;
        assert_eq!(
            decode_error_body(&changed).unwrap_err(),
            CodecError::UnsupportedErrorSchema(2)
        );

        let mut changed = encode_error_body(ProtocolErrorCode::InvalidFrame);
        changed[2..4].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode_error_body(&changed).unwrap_err(),
            CodecError::UnknownErrorCode(99)
        );

        let mut changed = encode_error_body(ProtocolErrorCode::InvalidFrame);
        changed[4] = 1;
        assert_eq!(
            decode_error_body(&changed).unwrap_err(),
            CodecError::NonzeroErrorReserved
        );

        assert_eq!(
            decode_error_body(&[0; ERROR_BODY_BYTES - 1]).unwrap_err(),
            CodecError::InvalidErrorBodyLength(ERROR_BODY_BYTES - 1)
        );
        assert_eq!(
            encode_frame(
                FrameKind::ExecuteError,
                EXCHANGE_ID,
                &[0; ERROR_BODY_BYTES - 1]
            )
            .unwrap_err(),
            CodecError::InvalidErrorBodyLength(ERROR_BODY_BYTES - 1)
        );
    }

    #[test]
    fn body_length_uses_unsigned_little_endian_and_cannot_hide_trailing_bytes() {
        let mut encoded = request();
        encoded[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CodecError::LengthMismatch {
                declared: usize::try_from(u32::MAX).unwrap(),
                actual: 2,
            }
        );
    }
}
