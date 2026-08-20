#![allow(
    dead_code,
    reason = "rendezvous is feature-tested but remains disconnected from production SCM activation"
)]

//! Stop-safe, SID-scoped named-pipe rendezvous for an unprivileged witness.
//!
//! This module authenticates a kernel token only. It cannot bind the accepted
//! executable, reserve a slot, load a signing key, execute an operation, or emit
//! evidence, so the production service remains fail-closed after this slice.

use std::ffi::OsStr;
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_IO_PENDING,
    ERROR_MORE_DATA, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, WaitForMultipleObjects,
    WaitForSingleObject,
};

use super::{AuthenticatedWitnessToken, OwnedKernelHandle, WitnessRendezvousSpec};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const PIPE_BUFFER_BYTES: u32 = 4096;
const RENDEZVOUS_TIMEOUT_MS: u32 = 30_000;
const CHILD_EXCHANGE_TIMEOUT_MS: u32 = 10_000;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn last_error(context: &str) -> String {
    // SAFETY: GetLastError has no preconditions and is sampled immediately.
    let error = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {error}")
}

fn canonical_sid(value: &str) -> Result<String, String> {
    crate::capture_v3::validate_witness_provenance(value, 0, "0000000000001000")?;
    let input = wide_null(OsStr::new(value));
    let mut sid: PSID = null_mut();
    // SAFETY: input is NUL-terminated and sid is writable pointer storage.
    if unsafe { ConvertStringSidToSidW(input.as_ptr(), &raw mut sid) } == 0 {
        return Err(last_error("ConvertStringSidToSidW(witness)"));
    }
    let mut output = null_mut();
    // SAFETY: sid is the valid LocalAlloc result and output is writable.
    let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut output) };
    if converted == 0 {
        let error = unsafe { GetLastError() };
        // SAFETY: sid is the allocation returned by ConvertStringSidToSidW.
        unsafe { LocalFree(sid.cast()) };
        return Err(format!(
            "ConvertSidToStringSidW(witness) failed with Win32 error {error}"
        ));
    }
    let result = (|| {
        let mut length = 0usize;
        // SAFETY: output is a NUL-terminated LocalAlloc string.
        while unsafe { *output.add(length) } != 0 {
            length += 1;
            if length > 256 {
                return Err("canonical witness SID exceeds its bound".to_owned());
            }
        }
        // SAFETY: the loop established the initialized UTF-16 extent.
        String::from_utf16(unsafe { std::slice::from_raw_parts(output, length) })
            .map_err(|_| "canonical witness SID is not valid UTF-16".to_owned())
    })();
    // SAFETY: both values are the documented LocalAlloc results.
    unsafe {
        LocalFree(output.cast());
        LocalFree(sid.cast());
    }
    let result = result?;
    if result != value {
        return Err("witness SID is not in canonical Windows form".to_owned());
    }
    Ok(result)
}

pub(super) struct PipeHandle {
    raw: HANDLE,
    connected: bool,
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        if self.raw != INVALID_HANDLE_VALUE && !self.raw.is_null() {
            if self.connected {
                // SAFETY: this is the owned connected server pipe.
                unsafe { DisconnectNamedPipe(self.raw) };
            }
            // SAFETY: this object exclusively owns the successful handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.raw) };
        }
    }
}

struct ImpersonationGuard {
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl ImpersonationGuard {
    fn begin(pipe: HANDLE) -> Result<Self, String> {
        // SAFETY: pipe is a connected server handle after a message was read.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(last_error("ImpersonateNamedPipeClient"));
        }
        Ok(Self {
            active: true,
            _not_send: PhantomData,
        })
    }

    fn revert_or_abort(mut self) {
        // Continuing as the client in LocalSystem code is not recoverable.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: unwind guard executes on the same thread. Failure is
            // process-fatal because returning as the client would cross trust domains.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
}

enum PendingOutcome {
    Complete(u32),
    Stopped,
    TimedOut,
}

enum ChildPendingOutcome {
    Complete(u32),
    Stopped,
    ChildExited,
    TimedOut,
}

fn cancel_and_drain(pipe: HANDLE, overlapped: &OVERLAPPED) -> Result<(), String> {
    // SAFETY: the OVERLAPPED remains pinned and belongs to this pipe operation.
    if unsafe { CancelIoEx(pipe, overlapped) } == 0 {
        // ERROR_NOT_FOUND is the documented completion race.
        let error = unsafe { GetLastError() };
        if error != ERROR_NOT_FOUND {
            // The kernel may still own pointers to the caller's OVERLAPPED and
            // buffer. Unwinding would be memory-unsafe, so terminate the
            // LocalSystem broker fail-closed if cancellation cannot be proven.
            std::process::abort();
        }
    }
    let mut transferred = 0u32;
    // SAFETY: waiting drains the operation before its OVERLAPPED/buffer can drop.
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 1) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_OPERATION_ABORTED {
            return Err(format!(
                "GetOverlappedResult(cancel witness rendezvous) failed with Win32 error {error}"
            ));
        }
    }
    Ok(())
}

fn wait_pending(
    pipe: HANDLE,
    overlapped: &OVERLAPPED,
    stop_event: HANDLE,
    timeout_ms: u32,
) -> Result<PendingOutcome, String> {
    let handles = [stop_event, overlapped.hEvent];
    // SAFETY: both handles and the two-element array remain live for the wait.
    let result = unsafe {
        WaitForMultipleObjects(
            u32::try_from(handles.len()).expect("fixed wait set fits u32"),
            handles.as_ptr(),
            0,
            timeout_ms,
        )
    };
    if result == WAIT_OBJECT_0 {
        cancel_and_drain(pipe, overlapped)?;
        return Ok(PendingOutcome::Stopped);
    }
    if result == WAIT_TIMEOUT {
        cancel_and_drain(pipe, overlapped)?;
        return Ok(PendingOutcome::TimedOut);
    }
    if result == WAIT_FAILED {
        // Preserve the wait failure before cancellation/draining mutates the
        // thread-local last-error slot.
        let wait_error = unsafe { GetLastError() };
        cancel_and_drain(pipe, overlapped)?;
        return Err(format!(
            "WaitForMultipleObjects(witness rendezvous) failed with Win32 error {wait_error}"
        ));
    }
    if result != WAIT_OBJECT_0 + 1 {
        cancel_and_drain(pipe, overlapped)?;
        return Err(format!("witness rendezvous wait returned {result}"));
    }
    let mut transferred = 0u32;
    // SAFETY: the event signaled; this finalizes the still-live operation.
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
        return Err(last_error("GetOverlappedResult(witness rendezvous)"));
    }
    Ok(PendingOutcome::Complete(transferred))
}

fn wait_child_pending(
    pipe: HANDLE,
    overlapped: &OVERLAPPED,
    stop_event: HANDLE,
    child_process: HANDLE,
    timeout_ms: u32,
) -> Result<ChildPendingOutcome, String> {
    let handles = [stop_event, child_process, overlapped.hEvent];
    // SAFETY: all three handles and the fixed array remain live for the wait.
    let result = unsafe {
        WaitForMultipleObjects(
            u32::try_from(handles.len()).expect("fixed child wait set fits u32"),
            handles.as_ptr(),
            0,
            timeout_ms,
        )
    };
    if result == WAIT_OBJECT_0 {
        cancel_and_drain(pipe, overlapped)?;
        return Ok(ChildPendingOutcome::Stopped);
    }
    if result == WAIT_OBJECT_0 + 1 {
        cancel_and_drain(pipe, overlapped)?;
        return Ok(ChildPendingOutcome::ChildExited);
    }
    if result == WAIT_TIMEOUT {
        cancel_and_drain(pipe, overlapped)?;
        return Ok(ChildPendingOutcome::TimedOut);
    }
    if result == WAIT_FAILED {
        let wait_error = unsafe { GetLastError() };
        cancel_and_drain(pipe, overlapped)?;
        return Err(format!(
            "WaitForMultipleObjects(trusted child I/O) failed with Win32 error {wait_error}"
        ));
    }
    if result != WAIT_OBJECT_0 + 2 {
        cancel_and_drain(pipe, overlapped)?;
        return Err(format!("trusted child I/O wait returned {result}"));
    }
    let mut transferred = 0u32;
    // SAFETY: the I/O event signaled and the pinned operation remains live.
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
        return Err(last_error("GetOverlappedResult(trusted child I/O)"));
    }
    Ok(ChildPendingOutcome::Complete(transferred))
}

fn remaining_timeout(deadline: Instant) -> Option<u32> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let millis = remaining.as_millis().clamp(1, u128::from(u32::MAX));
    Some(u32::try_from(millis).expect("clamped rendezvous timeout fits u32"))
}

fn create_event() -> Result<OwnedKernelHandle, String> {
    // SAFETY: no attributes/name; request a manual-reset nonsignaled event.
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(last_error("CreateEventW(witness rendezvous)"));
    }
    Ok(OwnedKernelHandle(event))
}

fn duplicate_wait_handle(handle: HANDLE, label: &str) -> Result<OwnedKernelHandle, String> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("{label} handle is invalid"));
    }
    let mut duplicate = null_mut();
    // SAFETY: the source is validated by DuplicateHandle; the destination is
    // writable storage in this process and receives the same granted access.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last_error(&format!("DuplicateHandle({label})")));
    }
    Ok(OwnedKernelHandle(duplicate))
}

fn write_child_message(
    pipe: HANDLE,
    bytes: &[u8],
    stop_event: HANDLE,
    child_process: HANDLE,
    deadline: Instant,
    label: &str,
) -> Result<(), String> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| format!("{label} message length exceeds the Win32 bound"))?;
    let Some(timeout_ms) = remaining_timeout(deadline) else {
        return Err(format!("{label} timed out before write"));
    };
    let event = create_event()?;
    let mut overlapped = Box::new(OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    });
    let mut immediate = 0u32;
    // SAFETY: the buffer and pinned OVERLAPPED remain live through completion
    // or cancellation and drain below.
    if unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            length,
            &raw mut immediate,
            &raw mut *overlapped,
        )
    } != 0
    {
        if immediate != length {
            return Err(format!("{label} write was truncated"));
        }
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    if error != ERROR_IO_PENDING {
        return Err(format!(
            "WriteFile({label}) failed with Win32 error {error}"
        ));
    }
    match wait_child_pending(pipe, &overlapped, stop_event, child_process, timeout_ms)? {
        ChildPendingOutcome::Complete(transferred) if transferred == length => Ok(()),
        ChildPendingOutcome::Complete(_) => Err(format!("{label} write was truncated")),
        ChildPendingOutcome::Stopped => Err(format!("{label} was stopped")),
        ChildPendingOutcome::ChildExited => Err(format!("{label} child exited")),
        ChildPendingOutcome::TimedOut => Err(format!("{label} timed out")),
    }
}

fn read_child_message(
    pipe: HANDLE,
    maximum: usize,
    stop_event: HANDLE,
    child_process: HANDLE,
    deadline: Instant,
    label: &str,
) -> Result<Vec<u8>, String> {
    let Some(timeout_ms) = remaining_timeout(deadline) else {
        return Err(format!("{label} timed out before read"));
    };
    let event = create_event()?;
    let mut overlapped = Box::new(OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    });
    // One extra byte distinguishes the exact maximum from the smallest
    // oversized complete message. Larger message-mode writes report
    // ERROR_MORE_DATA and are rejected without attempting another read.
    let capacity = maximum
        .checked_add(1)
        .ok_or_else(|| format!("{label} response bound overflowed"))?;
    let mut response = vec![0u8; capacity];
    let capacity = u32::try_from(response.len())
        .map_err(|_| format!("{label} response bound exceeds the Win32 limit"))?;
    let mut immediate = 0u32;
    // SAFETY: the buffer and pinned OVERLAPPED remain live through completion
    // or cancellation and drain below.
    let transferred = if unsafe {
        ReadFile(
            pipe,
            response.as_mut_ptr(),
            capacity,
            &raw mut immediate,
            &raw mut *overlapped,
        )
    } != 0
    {
        immediate
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_MORE_DATA {
            return Err(format!("{label} response is oversized"));
        }
        if error != ERROR_IO_PENDING {
            return Err(format!("ReadFile({label}) failed with Win32 error {error}"));
        }
        match wait_child_pending(pipe, &overlapped, stop_event, child_process, timeout_ms)? {
            ChildPendingOutcome::Complete(bytes) => bytes,
            ChildPendingOutcome::Stopped => return Err(format!("{label} was stopped")),
            ChildPendingOutcome::ChildExited => {
                return Err(format!("{label} child exited before responding"));
            }
            ChildPendingOutcome::TimedOut => return Err(format!("{label} timed out")),
        }
    };
    let transferred =
        usize::try_from(transferred).map_err(|_| format!("{label} response length overflowed"))?;
    if transferred == 0 || transferred > maximum {
        return Err(format!("{label} response length is invalid"));
    }
    response.truncate(transferred);
    Ok(response)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildChannelState {
    Ready,
    AdapterResponseReceived,
    DeviceOpenObservationReceived { exchange_id: [u8; 16] },
    DeviceOpenSourceClosed { exchange_id: [u8; 16] },
    Poisoned,
    ShutdownSent,
}

impl ChildChannelState {
    fn device_open_exchange_id(self) -> Result<[u8; 16], String> {
        match self {
            Self::DeviceOpenObservationReceived { exchange_id } => Ok(exchange_id),
            _ => Err(
                "trusted child channel cannot close a device source before an observation response"
                    .to_owned(),
            ),
        }
    }

    const fn permits_shutdown(self) -> bool {
        matches!(
            self,
            Self::AdapterResponseReceived | Self::DeviceOpenSourceClosed { .. }
        )
    }
}

fn require_device_open_observation(
    response: crate::device_open_protocol::ObservationResponse,
) -> Result<Box<crate::device_open_protocol::DeviceOpenObservation>, String> {
    match response {
        crate::device_open_protocol::ObservationResponse::Observation(observation) => {
            Ok(observation)
        }
        crate::device_open_protocol::ObservationResponse::Error(code) => Err(format!(
            "trusted child rejected the device-open observation with code {code:?}"
        )),
    }
}

pub(crate) enum AcceptOutcome {
    Authenticated(Box<AuthenticatedWitnessToken>),
    Stopped,
    TimedOut,
}

pub(super) struct AuthenticatedChildChannel {
    pub(super) token: AuthenticatedWitnessToken,
    pub(super) pipe: PipeHandle,
    pub(super) child_binding_sha256: String,
    state: ChildChannelState,
}

impl AuthenticatedChildChannel {
    #[allow(
        clippy::too_many_lines,
        reason = "the single write/read overlapped lifetime is kept linear for security auditability"
    )]
    pub(super) fn exchange_once(
        &mut self,
        request_frame: &[u8],
        child_process: HANDLE,
        stop_event: HANDLE,
    ) -> Result<Vec<u8>, String> {
        if self.state != ChildChannelState::Ready {
            return Err("trusted child channel does not accept another request".to_owned());
        }
        let request = crate::fixed_adapter_ipc::decode_frame(request_frame)
            .map_err(|error| error.to_string())?;
        if request.kind != crate::fixed_adapter_ipc::FrameKind::ExecuteRequest {
            return Err("trusted child request frame has the wrong kind".to_owned());
        }
        let stop_event = duplicate_wait_handle(stop_event, "trusted child stop event")?;
        let child_process = duplicate_wait_handle(child_process, "trusted child process")?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(CHILD_EXCHANGE_TIMEOUT_MS));

        // Pessimistically poison before the first byte can reach the child. No
        // failure after this point may be retried on this authenticated channel.
        self.state = ChildChannelState::Poisoned;
        write_child_message(
            self.pipe.raw,
            request_frame,
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child adapter request",
        )?;

        let Some(timeout_ms) = remaining_timeout(deadline) else {
            return Err("trusted child adapter response timed out".to_owned());
        };
        let event = create_event()?;
        let mut overlapped = Box::new(OVERLAPPED {
            hEvent: event.0,
            ..OVERLAPPED::default()
        });
        let maximum = crate::fixed_adapter_ipc::HEADER_BYTES
            .checked_add(crate::fixed_adapter_ipc::MAX_RESULT_BODY_BYTES)
            .expect("fixed adapter response bound does not overflow");
        // One extra byte distinguishes the exact maximum from the smallest
        // oversized complete message. Larger messages report ERROR_MORE_DATA.
        let mut response = vec![0u8; maximum + 1];
        let capacity =
            u32::try_from(response.len()).expect("fixed adapter response buffer length fits u32");
        let mut immediate = 0u32;
        let transferred = if unsafe {
            ReadFile(
                self.pipe.raw,
                response.as_mut_ptr(),
                capacity,
                &raw mut immediate,
                &raw mut *overlapped,
            )
        } != 0
        {
            immediate
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_MORE_DATA {
                return Err("trusted child adapter response is oversized".to_owned());
            }
            if error != ERROR_IO_PENDING {
                return Err(format!(
                    "ReadFile(trusted child adapter response) failed with Win32 error {error}"
                ));
            }
            match wait_child_pending(
                self.pipe.raw,
                &overlapped,
                stop_event.0,
                child_process.0,
                timeout_ms,
            )? {
                ChildPendingOutcome::Complete(bytes) => bytes,
                ChildPendingOutcome::Stopped => {
                    return Err("trusted child adapter response was stopped".to_owned());
                }
                ChildPendingOutcome::ChildExited => {
                    return Err("trusted child exited before its adapter response".to_owned());
                }
                ChildPendingOutcome::TimedOut => {
                    return Err("trusted child adapter response timed out".to_owned());
                }
            }
        };
        let transferred = usize::try_from(transferred)
            .map_err(|_| "trusted child adapter response length overflowed")?;
        if transferred == 0 || transferred > maximum {
            return Err("trusted child adapter response length is invalid".to_owned());
        }
        response.truncate(transferred);
        let decoded = crate::fixed_adapter_ipc::decode_response(&response, request.exchange_id)
            .map_err(|error| error.to_string())?;
        if decoded.kind == crate::fixed_adapter_ipc::FrameKind::ExecuteError {
            crate::fixed_adapter_ipc::decode_error_body(&decoded.body)
                .map_err(|error| error.to_string())?;
        }
        self.state = ChildChannelState::AdapterResponseReceived;
        Ok(response)
    }

    /// Perform the sealed, zero-input device-open observation exchange.
    ///
    /// The caller supplies only a broker-generated exchange identifier. The
    /// request kind and empty body are constructed here, and the response is
    /// decoded and bound to that identifier before this channel can advance.
    pub(super) fn observe_device_open(
        &mut self,
        exchange_id: [u8; 16],
        child_process: HANDLE,
        stop_event: HANDLE,
    ) -> Result<Box<crate::device_open_protocol::DeviceOpenObservation>, String> {
        if self.state != ChildChannelState::Ready {
            return Err("trusted child channel does not accept a device-open request".to_owned());
        }
        let request = crate::device_open_protocol::encode_observe_request(exchange_id)
            .map_err(|error| error.to_string())?;
        let stop_event = duplicate_wait_handle(stop_event, "device-open child stop event")?;
        let child_process = duplicate_wait_handle(child_process, "device-open child process")?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(CHILD_EXCHANGE_TIMEOUT_MS));

        // Pessimistically poison before the first byte can reach the child. A
        // partial write, timeout, child exit, oversized response, wrong kind,
        // or wrong exchange ID can therefore never be retried.
        self.state = ChildChannelState::Poisoned;
        write_child_message(
            self.pipe.raw,
            &request,
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child device-open observe request",
        )?;
        let response = read_child_message(
            self.pipe.raw,
            crate::device_open_protocol::MAX_RESPONSE_FRAME_BYTES,
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child device-open observe response",
        )?;
        let decoded =
            crate::device_open_protocol::decode_observation_response(&response, exchange_id)
                .map_err(|error| error.to_string())?;
        let observation = require_device_open_observation(decoded)?;
        self.state = ChildChannelState::DeviceOpenObservationReceived { exchange_id };
        Ok(observation)
    }

    /// Require the child to close its source device handle and acknowledge the
    /// close using the observation exchange identifier.
    pub(super) fn close_device_open_source(
        &mut self,
        child_process: HANDLE,
        stop_event: HANDLE,
    ) -> Result<(), String> {
        let exchange_id = self.state.device_open_exchange_id()?;
        let request = crate::device_open_protocol::encode_close_source_request(exchange_id)
            .map_err(|error| error.to_string())?;
        let stop_event = duplicate_wait_handle(stop_event, "device-open child stop event")?;
        let child_process = duplicate_wait_handle(child_process, "device-open child process")?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(CHILD_EXCHANGE_TIMEOUT_MS));

        self.state = ChildChannelState::Poisoned;
        write_child_message(
            self.pipe.raw,
            &request,
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child device-open close-source request",
        )?;
        // The acknowledgment is an empty-body frame and therefore must have
        // exactly the same length as the empty-body request.
        let response = read_child_message(
            self.pipe.raw,
            request.len(),
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child device-open close-source acknowledgment",
        )?;
        crate::device_open_protocol::decode_close_source_ack(&response, exchange_id)
            .map_err(|error| error.to_string())?;
        self.state = ChildChannelState::DeviceOpenSourceClosed { exchange_id };
        Ok(())
    }

    pub(super) fn send_shutdown(
        &mut self,
        child_process: HANDLE,
        stop_event: HANDLE,
    ) -> Result<(), String> {
        if !self.state.permits_shutdown() {
            return Err(
                "trusted child channel cannot send shutdown in its current state".to_owned(),
            );
        }
        let stop_event = duplicate_wait_handle(stop_event, "trusted child stop event")?;
        let child_process = duplicate_wait_handle(child_process, "trusted child process")?;
        self.state = ChildChannelState::Poisoned;
        let deadline = Instant::now() + Duration::from_millis(u64::from(CHILD_EXCHANGE_TIMEOUT_MS));
        write_child_message(
            self.pipe.raw,
            &crate::fixed_adapter_ipc::SHUTDOWN_MESSAGE,
            stop_event.0,
            child_process.0,
            deadline,
            "trusted child shutdown",
        )?;
        self.state = ChildChannelState::ShutdownSent;
        Ok(())
    }
}

pub(super) enum ExactAcceptOutcome {
    Authenticated(Box<AuthenticatedChildChannel>),
    Stopped,
    TimedOut,
}

struct ExpectedProcess {
    pid: u32,
    handle: HANDLE,
}

enum ConnectedOutcome {
    Authenticated(Box<(WitnessRendezvous, AuthenticatedWitnessToken)>),
    Stopped,
    TimedOut,
}

pub(crate) struct WitnessRendezvous {
    pipe: PipeHandle,
    spec: WitnessRendezvousSpec,
}

impl WitnessRendezvous {
    pub(crate) fn prepare(spec: WitnessRendezvousSpec) -> Result<Self, String> {
        let sid = canonical_sid(spec.expected().user_sid())?;
        let sddl = super::protected_pipe_sddl(&sid);
        let sddl = wide_null(OsStr::new(&sddl));
        let mut descriptor = null_mut();
        // SAFETY: SDDL is NUL-terminated and descriptor is writable.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &raw mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(witness pipe)",
            ));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide_null(OsStr::new(spec.pipe_name()));
        // SAFETY: name/descriptor remain live; CreateNamedPipeW copies the descriptor.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &raw const attributes,
            )
        };
        let create_error = (raw == INVALID_HANDLE_VALUE).then(|| unsafe { GetLastError() });
        // SAFETY: descriptor is the converter's LocalAlloc result.
        unsafe { LocalFree(descriptor) };
        if let Some(error) = create_error {
            return Err(format!(
                "CreateNamedPipeW(witness rendezvous) failed with Win32 error {error}"
            ));
        }
        Ok(Self {
            pipe: PipeHandle {
                raw,
                connected: false,
            },
            spec,
        })
    }

    pub(crate) fn name(&self) -> &str {
        self.spec.pipe_name()
    }

    /// # Safety
    ///
    /// `stop_event` must remain a valid event handle until this function has
    /// duplicated it. The owned duplicate is retained through every pending
    /// operation and cancellation/drain path.
    pub(crate) unsafe fn accept(self, stop_event: HANDLE) -> Result<AcceptOutcome, String> {
        match unsafe { self.accept_connected(stop_event, None) }? {
            ConnectedOutcome::Authenticated(connected) => {
                let (_, token) = *connected;
                Ok(AcceptOutcome::Authenticated(Box::new(token)))
            }
            ConnectedOutcome::Stopped => Ok(AcceptOutcome::Stopped),
            ConnectedOutcome::TimedOut => Ok(AcceptOutcome::TimedOut),
        }
    }

    /// Accept only the exact process object returned by service-owned child creation.
    ///
    /// # Safety
    ///
    /// Both raw handles must remain live until this function duplicates/uses
    /// them. `expected_process` must grant query and synchronize access.
    pub(super) unsafe fn accept_exact(
        self,
        stop_event: HANDLE,
        expected_pid: u32,
        expected_process: HANDLE,
    ) -> Result<ExactAcceptOutcome, String> {
        let expected = ExpectedProcess {
            pid: expected_pid,
            handle: expected_process,
        };
        match unsafe { self.accept_connected(stop_event, Some(&expected)) }? {
            ConnectedOutcome::Authenticated(connected) => {
                let (rendezvous, token) = *connected;
                let binding = rendezvous.spec.binding_sha256().to_owned();
                Ok(ExactAcceptOutcome::Authenticated(Box::new(
                    AuthenticatedChildChannel {
                        token,
                        pipe: rendezvous.pipe,
                        child_binding_sha256: binding,
                        state: ChildChannelState::Ready,
                    },
                )))
            }
            ConnectedOutcome::Stopped => Ok(ExactAcceptOutcome::Stopped),
            ConnectedOutcome::TimedOut => Ok(ExactAcceptOutcome::TimedOut),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the linear overlapped connect/read lifetime is kept visible for auditability"
    )]
    unsafe fn accept_connected(
        mut self,
        stop_event: HANDLE,
        expected_process: Option<&ExpectedProcess>,
    ) -> Result<ConnectedOutcome, String> {
        // Validate before issuing I/O so no error path can drop a pending
        // operation without cancellation and drain.
        if stop_event.is_null() || stop_event == INVALID_HANDLE_VALUE {
            return Err("witness rendezvous stop event is invalid".to_owned());
        }
        let mut owned_stop = null_mut();
        // SAFETY: duplicate the caller's event into this process before any I/O
        // so a concurrent close/reuse cannot invalidate the wait set.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                stop_event,
                GetCurrentProcess(),
                &raw mut owned_stop,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last_error("DuplicateHandle(witness stop event)"));
        }
        let owned_stop = OwnedKernelHandle(owned_stop);
        let deadline = Instant::now() + Duration::from_millis(u64::from(RENDEZVOUS_TIMEOUT_MS));
        let connect_event = create_event()?;
        let mut connect = Box::new(OVERLAPPED {
            hEvent: connect_event.0,
            ..OVERLAPPED::default()
        });
        // SAFETY: pipe and pinned OVERLAPPED are live for the entire operation.
        if unsafe { ConnectNamedPipe(self.pipe.raw, &raw mut *connect) } == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_IO_PENDING {
                let Some(timeout_ms) = remaining_timeout(deadline) else {
                    cancel_and_drain(self.pipe.raw, &connect)?;
                    return Ok(ConnectedOutcome::TimedOut);
                };
                match wait_pending(self.pipe.raw, &connect, owned_stop.0, timeout_ms)? {
                    PendingOutcome::Complete(_) => {}
                    PendingOutcome::Stopped => return Ok(ConnectedOutcome::Stopped),
                    PendingOutcome::TimedOut => return Ok(ConnectedOutcome::TimedOut),
                }
            } else if error != ERROR_PIPE_CONNECTED {
                return Err(format!(
                    "ConnectNamedPipe(witness rendezvous) failed with Win32 error {error}"
                ));
            }
        }
        self.pipe.connected = true;

        if remaining_timeout(deadline).is_none() {
            return Ok(ConnectedOutcome::TimedOut);
        }

        let read_event = create_event()?;
        let mut read = Box::new(OVERLAPPED {
            hEvent: read_event.0,
            ..OVERLAPPED::default()
        });
        let expected_hello = self.spec.expected_hello();
        if expected_hello.is_empty() || expected_hello.len() > 64 {
            return Err("witness hello contract is invalid".to_owned());
        }
        let mut hello = vec![0u8; expected_hello.len()];
        let mut immediate = 0u32;
        // SAFETY: the bounded hello buffer and pinned OVERLAPPED remain live until drain.
        let transferred = if unsafe {
            ReadFile(
                self.pipe.raw,
                hello.as_mut_ptr(),
                u32::try_from(hello.len()).expect("bounded witness hello length fits u32"),
                &raw mut immediate,
                &raw mut *read,
            )
        } != 0
        {
            immediate
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_MORE_DATA {
                return Err("witness hello is oversized".to_owned());
            }
            if error != ERROR_IO_PENDING {
                return Err(format!(
                    "ReadFile(witness hello) failed with Win32 error {error}"
                ));
            }
            let Some(timeout_ms) = remaining_timeout(deadline) else {
                cancel_and_drain(self.pipe.raw, &read)?;
                return Ok(ConnectedOutcome::TimedOut);
            };
            match wait_pending(self.pipe.raw, &read, owned_stop.0, timeout_ms)? {
                PendingOutcome::Complete(bytes) => bytes,
                PendingOutcome::Stopped => return Ok(ConnectedOutcome::Stopped),
                PendingOutcome::TimedOut => return Ok(ConnectedOutcome::TimedOut),
            }
        };
        if usize::try_from(transferred).ok() != Some(hello.len()) || hello != expected_hello {
            return Err("witness hello is invalid".to_owned());
        }

        let authenticated = authenticate_client(
            self.pipe.raw,
            self.spec.expected(),
            self.spec.binding_sha256(),
            expected_process,
        )?;
        Ok(ConnectedOutcome::Authenticated(Box::new((
            self,
            authenticated,
        ))))
    }
}

fn retain_process_primary(
    process: &OwnedKernelHandle,
    expected: &super::ExpectedWitnessIdentity,
    pipe_profile: &super::WitnessTokenProfile,
) -> Result<(OwnedKernelHandle, super::WitnessTokenProfile), String> {
    // SAFETY: zero-time wait is a liveness check on the pinned process handle.
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
        return Err("witness client exited before authentication completed".to_owned());
    }
    let mut process_token = null_mut();
    // SAFETY: process is pinned and process_token is writable handle storage.
    if unsafe {
        OpenProcessToken(
            process.0,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut process_token,
        )
    } == 0
    {
        return Err(last_error("OpenProcessToken(witness client)"));
    }
    let process_token = OwnedKernelHandle(process_token);
    let process_profile = crate::windows::witness_token_profile(process_token.0)?;
    process_profile.validate_primary_standard_user(expected)?;
    if !pipe_profile.matches_pipe_duplicate_of_process_primary(&process_profile) {
        #[cfg(feature = "ci-system-test")]
        return Err(format!(
            "pipe client token differs from its pinned process primary token: pipe={}; process={}",
            serde_json::to_string(pipe_profile)
                .unwrap_or_else(|error| format!("<serialize failed: {error}>")),
            serde_json::to_string(&process_profile)
                .unwrap_or_else(|error| format!("<serialize failed: {error}>")),
        ));
        #[cfg(not(feature = "ci-system-test"))]
        return Err("pipe client token differs from its pinned process primary token".to_owned());
    }
    Ok((process_token, process_profile))
}

fn authenticate_client(
    pipe: HANDLE,
    expected: &super::ExpectedWitnessIdentity,
    rendezvous_binding_sha256: &str,
    expected_process: Option<&ExpectedProcess>,
) -> Result<AuthenticatedWitnessToken, String> {
    let mut client_pid = 0u32;
    // SAFETY: pipe is connected and client_pid is writable.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut client_pid) } == 0 || client_pid == 0 {
        return Err(last_error("GetNamedPipeClientProcessId"));
    }
    if let Some(expected_process) = expected_process {
        if client_pid != expected_process.pid {
            return Err("trusted child pipe was opened by the wrong process ID".to_owned());
        }
        if unsafe { WaitForSingleObject(expected_process.handle, 0) } != WAIT_TIMEOUT {
            return Err("expected trusted child exited before authentication".to_owned());
        }
    }

    // Pin the process object immediately after kernel PID discovery, while the
    // server is still LocalSystem. Later token and executable checks must use
    // this same handle rather than resolving the PID again.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            client_pid,
        )
    };
    if process.is_null() {
        return Err(last_error("OpenProcess(witness client)"));
    }
    let process = OwnedKernelHandle(process);
    if let Some(expected_process) = expected_process
        && unsafe { CompareObjectHandles(process.0, expected_process.handle) } == 0
    {
        return Err(
            "trusted child pipe process is not the service-created process object".to_owned(),
        );
    }
    // SAFETY: zero-time wait is a liveness check on the pinned process handle.
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
        return Err("witness client exited before authentication began".to_owned());
    }

    let guard = ImpersonationGuard::begin(pipe)?;
    let mut donor = null_mut();
    // SAFETY: current thread is impersonating; donor is writable handle storage.
    let open_result = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            1,
            &raw mut donor,
        )
    };
    if open_result == 0 {
        return Err(last_error("OpenThreadToken(witness client)"));
    }
    let donor = OwnedKernelHandle(donor);
    crate::windows::validate_pipe_impersonation_token(donor.0)?;
    let mut primary = null_mut();
    // SAFETY: donor is a queryable/duplicable impersonation token.
    if unsafe {
        DuplicateTokenEx(
            donor.0,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        )
    } == 0
    {
        return Err(last_error("DuplicateTokenEx(witness primary)"));
    }
    let primary = OwnedKernelHandle(primary);
    guard.revert_or_abort();
    drop(donor);

    let duplicate_profile = crate::windows::witness_token_profile(primary.0)?;
    duplicate_profile.validate_primary_standard_user(expected)?;
    let (process_token, process_profile) =
        retain_process_primary(&process, expected, &duplicate_profile)?;
    drop(primary);

    Ok(AuthenticatedWitnessToken {
        profile: process_profile,
        rendezvous_binding_sha256: rendezvous_binding_sha256.to_owned(),
        primary_token: process_token,
        bootstrap_process: process,
    })
}

#[cfg(test)]
mod tests {
    use super::{ChildChannelState, require_device_open_observation};
    use crate::device_open_protocol::{ObservationErrorCode, ObservationResponse};

    const EXCHANGE_ID: [u8; 16] = [0x41; 16];

    #[test]
    fn device_open_close_requires_observation_response() {
        for state in [
            ChildChannelState::Ready,
            ChildChannelState::AdapterResponseReceived,
            ChildChannelState::Poisoned,
            ChildChannelState::ShutdownSent,
            ChildChannelState::DeviceOpenSourceClosed {
                exchange_id: EXCHANGE_ID,
            },
        ] {
            assert!(state.device_open_exchange_id().is_err());
        }
        assert_eq!(
            ChildChannelState::DeviceOpenObservationReceived {
                exchange_id: EXCHANGE_ID,
            }
            .device_open_exchange_id(),
            Ok(EXCHANGE_ID)
        );
    }

    #[test]
    fn device_open_shutdown_requires_source_close_ack() {
        assert!(
            !ChildChannelState::Ready.permits_shutdown()
                && !ChildChannelState::DeviceOpenObservationReceived {
                    exchange_id: EXCHANGE_ID,
                }
                .permits_shutdown()
                && !ChildChannelState::Poisoned.permits_shutdown()
        );
        assert!(
            ChildChannelState::DeviceOpenSourceClosed {
                exchange_id: EXCHANGE_ID,
            }
            .permits_shutdown()
        );
        // The legacy fixed-adapter exchange remains a distinct complete path.
        assert!(ChildChannelState::AdapterResponseReceived.permits_shutdown());
    }

    #[test]
    fn device_open_error_response_cannot_advance_the_channel() {
        assert!(
            require_device_open_observation(ObservationResponse::Error(
                ObservationErrorCode::OpenFailed,
            ))
            .is_err()
        );
    }
}
