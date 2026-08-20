#![allow(
    dead_code,
    reason = "trusted child is feature-tested but remains unreachable from production authority"
)]

//! Exact-image, suspended standard-user witness child construction.
//!
//! This module deliberately stops before authority binding. It converts a
//! kernel-authenticated bootstrap token into a service-created process object
//! while retaining the exact staged image and a kill-on-close job. It then
//! authenticates that exact process object over a distinct child pipe before
//! constructing `PinnedAuthenticatedWitness`. No production caller can bind
//! that capability to signing authority in this slice.

use std::ffi::{OsStr, c_void};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OVERLAPPED, FILE_ID_INFO, FILE_SHARE_READ, FileIdInfo, GetFileAttributesW,
    GetFileInformationByHandleEx, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::{PIPE_READMODE_MESSAGE, SetNamedPipeHandleState};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_DEFAULT_ERROR_MODE, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    CreateEventW, CreateProcessAsUserW, GetCurrentThreadId, GetExitCodeProcess, GetProcessId,
    GetProcessIdOfThread, GetThreadId, PROCESS_INFORMATION, QueryFullProcessImageNameW,
    ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

use super::rendezvous::{AuthenticatedChildChannel, ExactAcceptOutcome, WitnessRendezvous};
use super::{
    AuthenticatedWitnessToken, ExpectedWitnessIdentity, OwnedKernelHandle,
    PinnedAuthenticatedWitness, WitnessRendezvousSpec,
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const MAX_WITNESS_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PATH_U16: usize = 32_768;
const CHILD_PIPE_PREFIX: &str = r"\\.\pipe\0verse.windows-token-witness-child.v1.";
const CHILD_MODE: &str = "--trusted-witness-child";
const TERMINATION_EXIT_CODE: u32 = 0x0c01_0001;
const CHILD_TEARDOWN_TIMEOUT_MS: u32 = 10_000;
const CHILD_COMMIT_LIMIT_BYTES: usize = 256 * 1024 * 1024;
const CHILD_USER_CPU_LIMIT_100NS: i64 = 30 * 10_000_000;
const CHILD_IO_TIMEOUT_MS: u32 = 10_000;

fn last_error(context: &str) -> String {
    let error = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {error}")
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) || wide.len() >= MAX_PATH_U16 {
        return Err("trusted witness path contains NUL or exceeds its bound".to_owned());
    }
    wide.push(0);
    Ok(wide)
}

struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn security_descriptor(sddl: &str) -> Result<LocalSecurityDescriptor, String> {
    let sddl = wide_null(OsStr::new(sddl))?;
    let mut descriptor = null_mut();
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
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(trusted witness)",
        ));
    }
    Ok(LocalSecurityDescriptor(descriptor))
}

fn security_attributes(descriptor: &LocalSecurityDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits u32"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

fn program_data() -> Result<PathBuf, String> {
    let mut raw = null_mut();
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &raw mut raw,
        )
    };
    if result < 0 || raw.is_null() {
        return Err(format!(
            "SHGetKnownFolderPath(ProgramData) failed with HRESULT {result:#x}"
        ));
    }
    let parsed = (|| {
        let mut length = 0usize;
        while unsafe { *raw.add(length) } != 0 {
            length += 1;
            if length >= MAX_PATH_U16 {
                return Err("ProgramData path exceeds its bound".to_owned());
            }
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
            .map_err(|_| "ProgramData path is not valid UTF-16".to_owned())?;
        Ok(PathBuf::from(value))
    })();
    unsafe { CoTaskMemFree(raw.cast()) };
    parsed
}

fn random_hex<const N: usize>() -> Result<String, String> {
    let mut random = [0u8; N];
    if N == 0 || N > 64 {
        return Err("trusted witness random byte length is invalid".to_owned());
    }
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            u32::try_from(random.len()).expect("fixed random length fits u32"),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!(
            "BCryptGenRandom(trusted witness directory) failed with NTSTATUS {status:#x}"
        ));
    }
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn random_exchange_id() -> Result<[u8; 16], String> {
    let mut random = [0u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            u32::try_from(random.len()).expect("fixed exchange ID length fits u32"),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 || random == [0u8; 16] {
        return Err(format!(
            "BCryptGenRandom(trusted witness exchange ID) failed with NTSTATUS {status:#x}"
        ));
    }
    Ok(random)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle().cast()
}

fn file_identity(file: &File) -> Result<FileIdentity, String> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits u32"),
        )
    } == 0
    {
        return Err(last_error("GetFileInformationByHandleEx(FileIdInfo)"));
    }
    Ok(FileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

fn hash_file(file: &mut File) -> Result<(String, u64), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek trusted witness image failed: {error}"))?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read trusted witness image failed: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| "trusted witness image length overflowed".to_owned())?;
        if total > MAX_WITNESS_IMAGE_BYTES {
            return Err("trusted witness image exceeds the supported size".to_owned());
        }
        digest.update(&buffer[..read]);
    }
    if total == 0 {
        return Err("trusted witness image is empty".to_owned());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewind trusted witness image failed: {error}"))?;
    Ok((format!("{:x}", digest.finalize()), total))
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("expected trusted witness SHA-256 is invalid".to_owned());
    }
    Ok(())
}

pub(super) struct TrustedImage {
    file: Option<File>,
    path: PathBuf,
    directory: PathBuf,
    sha256: String,
    size: u64,
    identity: FileIdentity,
}

impl TrustedImage {
    pub(super) fn stage(
        source: &Path,
        expected_sha256: &str,
        exact_user_sid: &str,
    ) -> Result<Self, String> {
        validate_sha256(expected_sha256)?;
        if !source.is_absolute() {
            return Err("trusted witness source path must be absolute".to_owned());
        }

        let directory = program_data()?.join(format!("0verse-witness-{}", random_hex::<16>()?));
        let directory_sddl = format!("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;GRGX;;;{exact_user_sid})");
        let descriptor = security_descriptor(&directory_sddl)?;
        let attributes = security_attributes(&descriptor);
        let directory_wide = wide_null(directory.as_os_str())?;
        if unsafe { CreateDirectoryW(directory_wide.as_ptr(), &raw const attributes) } == 0 {
            return Err(last_error("CreateDirectoryW(trusted witness stage)"));
        }
        let mut cleanup = StageCleanup {
            file: None,
            directory: Some(directory.clone()),
        };
        let directory_attributes = unsafe { GetFileAttributesW(directory_wide.as_ptr()) };
        if directory_attributes == INVALID_FILE_ATTRIBUTES
            || directory_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err("trusted witness stage directory is invalid or a reparse point".to_owned());
        }

        let path = directory.join("witness.exe");
        let mut source_file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(source)
            .map_err(|error| format!("open trusted witness source failed: {error}"))?;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&path)
            .map_err(|error| format!("create trusted witness stage file failed: {error}"))?;
        cleanup.file = Some(path.clone());
        let mut total = 0u64;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|error| format!("read trusted witness source failed: {error}"))?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(read).expect("buffer length fits u64"))
                .ok_or_else(|| "trusted witness copy length overflowed".to_owned())?;
            if total > MAX_WITNESS_IMAGE_BYTES {
                return Err("trusted witness source exceeds the supported size".to_owned());
            }
            target
                .write_all(&buffer[..read])
                .map_err(|error| format!("write trusted witness stage failed: {error}"))?;
        }
        if total == 0 {
            return Err("trusted witness source is empty".to_owned());
        }
        target
            .sync_all()
            .map_err(|error| format!("flush trusted witness stage failed: {error}"))?;
        drop(target);
        drop(source_file);

        let mut held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .map_err(|error| format!("pin trusted witness stage failed: {error}"))?;
        let (sha256, size) = hash_file(&mut held)?;
        if sha256 != expected_sha256 {
            return Err("staged trusted witness hash differs from worker acceptance".to_owned());
        }
        let identity = file_identity(&held)?;
        cleanup.file = None;
        cleanup.directory = None;
        Ok(Self {
            file: Some(held),
            path,
            directory,
            sha256,
            size,
            identity,
        })
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn identity(&self) -> &FileIdentity {
        &self.identity
    }
}

impl Drop for TrustedImage {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

struct StageCleanup {
    file: Option<PathBuf>,
    directory: Option<PathBuf>,
}

impl Drop for StageCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.file.take() {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = self.directory.take() {
            let _ = fs::remove_dir(path);
        }
    }
}

fn windows_directory() -> Result<String, String> {
    let mut capacity = 260usize;
    loop {
        if capacity > MAX_PATH_U16 {
            return Err("Windows directory exceeds its bound".to_owned());
        }
        let mut buffer = vec![0u16; capacity];
        let written = unsafe {
            GetWindowsDirectoryW(
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| "Windows path capacity overflow")?,
            )
        };
        if written == 0 {
            return Err(last_error("GetWindowsDirectoryW"));
        }
        let written = usize::try_from(written).map_err(|_| "Windows path length overflow")?;
        if written < buffer.len() {
            return String::from_utf16(&buffer[..written])
                .map_err(|_| "Windows directory is not valid UTF-16".to_owned());
        }
        capacity = written
            .checked_add(1)
            .ok_or_else(|| "Windows path capacity overflowed".to_owned())?;
    }
}

fn sanitized_environment(stage_directory: &Path) -> Result<Vec<u16>, String> {
    let root = windows_directory()?;
    let temp = stage_directory
        .to_str()
        .ok_or_else(|| "trusted witness stage path is not valid Unicode".to_owned())?;
    let mut values = [
        format!("SystemRoot={root}"),
        format!("TEMP={temp}"),
        format!("TMP={temp}"),
    ];
    values.sort_unstable_by_key(|value| value.to_ascii_uppercase());
    let mut block = Vec::new();
    for value in values {
        if value.encode_utf16().any(|unit| unit == 0) {
            return Err("trusted witness environment contains NUL".to_owned());
        }
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn valid_child_pipe_name(value: &str) -> bool {
    value.strip_prefix(CHILD_PIPE_PREFIX).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn child_hello(pipe_name: &str) -> Result<[u8; 34], String> {
    if !valid_child_pipe_name(pipe_name) {
        return Err("trusted witness child pipe name is invalid".to_owned());
    }
    let suffix = pipe_name
        .strip_prefix(CHILD_PIPE_PREFIX)
        .expect("validated child pipe has its fixed prefix");
    let mut hello = [0u8; 34];
    hello[0] = 0xa2;
    hello[1] = 0x01;
    for (index, chunk) in suffix.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("validated child pipe suffix is ASCII");
        hello[index + 2] =
            u8::from_str_radix(text, 16).expect("validated child pipe suffix is hexadecimal");
    }
    Ok(hello)
}

fn cancel_child_io(pipe: HANDLE, overlapped: &OVERLAPPED) -> Result<(), String> {
    let cancel_error = if unsafe { CancelIoEx(pipe, overlapped) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_NOT_FOUND {
            None
        } else {
            Some(error)
        }
    } else {
        None
    };
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 1) } == 0 {
        let error = unsafe { GetLastError() };
        if error != windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED {
            // Returning would drop buffers that the kernel may still own. A
            // process abort is the only sound fail-closed outcome when drain
            // completion cannot be proved.
            std::process::abort();
        }
    }
    if let Some(error) = cancel_error {
        return Err(format!(
            "CancelIoEx(trusted witness child) failed with Win32 error {error} after I/O drain"
        ));
    }
    Ok(())
}

fn finish_child_io(
    pipe: HANDLE,
    overlapped: &OVERLAPPED,
    event: HANDLE,
    immediate: Option<u32>,
    context: &str,
) -> Result<u32, String> {
    if let Some(transferred) = immediate {
        return Ok(transferred);
    }
    let wait = unsafe { WaitForSingleObject(event, CHILD_IO_TIMEOUT_MS) };
    if wait == WAIT_TIMEOUT {
        cancel_child_io(pipe, overlapped)?;
        return Err(format!("{context} timed out"));
    }
    if wait != WAIT_OBJECT_0 {
        let wait_error = (wait == WAIT_FAILED).then(|| unsafe { GetLastError() });
        cancel_child_io(pipe, overlapped)?;
        return Err(match wait_error {
            Some(error) => format!("{context} wait failed with Win32 error {error}"),
            None => format!("{context} wait returned unexpected value {wait}"),
        });
    }
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
        return Err(last_error(context));
    }
    Ok(transferred)
}

fn write_child_message(pipe: HANDLE, bytes: &[u8], context: &str) -> Result<(), String> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(last_error("CreateEventW(trusted witness child write)"));
    }
    let event = OwnedKernelHandle(event);
    let mut overlapped = Box::new(OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    });
    let mut transferred = 0u32;
    let immediate = if unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            u32::try_from(bytes.len()).map_err(|_| "trusted child write length overflow")?,
            &raw mut transferred,
            &raw mut *overlapped,
        )
    } != 0
    {
        Some(transferred)
    } else {
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(format!("{context} failed with Win32 error {error}"));
        }
        None
    };
    let transferred = finish_child_io(pipe, &overlapped, event.0, immediate, context)?;
    if usize::try_from(transferred).ok() != Some(bytes.len()) {
        return Err(format!("{context} was truncated"));
    }
    Ok(())
}

fn read_child_message(pipe: HANDLE, maximum: usize, context: &str) -> Result<Vec<u8>, String> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(last_error("CreateEventW(trusted witness child read)"));
    }
    let event = OwnedKernelHandle(event);
    let mut bytes = vec![0u8; maximum];
    let mut overlapped = Box::new(OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    });
    let mut transferred = 0u32;
    let immediate = if unsafe {
        ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            u32::try_from(bytes.len()).map_err(|_| "trusted child read length overflow")?,
            &raw mut transferred,
            &raw mut *overlapped,
        )
    } != 0
    {
        Some(transferred)
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_MORE_DATA {
            return Err(format!("{context} exceeded its message bound"));
        }
        if error != ERROR_IO_PENDING {
            return Err(format!("{context} failed with Win32 error {error}"));
        }
        None
    };
    let transferred = finish_child_io(pipe, &overlapped, event.0, immediate, context)?;
    let transferred = usize::try_from(transferred).map_err(|_| "child read length overflow")?;
    if transferred == 0 || transferred > maximum {
        return Err(format!("{context} returned an invalid message length"));
    }
    bytes.truncate(transferred);
    Ok(bytes)
}

fn write_protocol_error(
    pipe: HANDLE,
    exchange_id: [u8; 16],
    code: crate::fixed_adapter_ipc::ProtocolErrorCode,
) -> Result<(), String> {
    let body = crate::fixed_adapter_ipc::encode_error_body(code);
    let frame = crate::fixed_adapter_ipc::encode_frame(
        crate::fixed_adapter_ipc::FrameKind::ExecuteError,
        exchange_id,
        &body,
    )
    .map_err(|error| error.to_string())?;
    write_child_message(pipe, &frame, "WriteFile(trusted child protocol error)")
}

fn run_device_open_request(pipe: HANDLE, first: &[u8]) -> Result<(), String> {
    let exchange_id = crate::device_open_protocol::decode_observe_request(first)
        .map_err(|error| error.to_string())?;
    let expected_profile = crate::windows::current_effective_witness_profile()?;
    let opened =
        match crate::windows::device_open::open_fixed_target_with_profile(&expected_profile) {
            Ok(opened) => opened,
            Err(error) => {
                let response = crate::device_open_protocol::encode_error_response(
                    exchange_id,
                    crate::device_open_protocol::ObservationErrorCode::OpenFailed,
                )
                .map_err(|encode| encode.to_string())?;
                write_child_message(
                    pipe,
                    &response,
                    "WriteFile(trusted child device-open error)",
                )?;
                return Err(format!("trusted witness child device-open failed: {error}"));
            }
        };
    let crate::windows::device_open::OpenedDeviceObservation {
        observation,
        source,
    } = opened;
    let response =
        crate::device_open_protocol::encode_observation_response(exchange_id, &observation)
            .map_err(|error| error.to_string())?;
    write_child_message(
        pipe,
        &response,
        "WriteFile(trusted child device-open observation)",
    )?;

    // Keep the exact source handle live until the authenticated broker confirms
    // that its same-access duplicate is retained.
    let close = read_child_message(
        pipe,
        crate::fixed_adapter_ipc::HEADER_BYTES,
        "ReadFile(trusted child device-open close-source request)",
    )?;
    let close_exchange_id = crate::device_open_protocol::decode_close_source_request(&close)
        .map_err(|error| error.to_string())?;
    if close_exchange_id != exchange_id {
        return Err("trusted witness child close-source exchange ID changed".to_owned());
    }
    source.close()?;
    let acknowledgment = crate::device_open_protocol::encode_close_source_ack(exchange_id)
        .map_err(|error| error.to_string())?;
    write_child_message(
        pipe,
        &acknowledgment,
        "WriteFile(trusted child device-open close-source acknowledgment)",
    )?;

    let terminal = read_child_message(
        pipe,
        crate::fixed_adapter_ipc::HEADER_BYTES,
        "ReadFile(trusted child device-open terminal control)",
    )?;
    match crate::fixed_adapter_ipc::decode_message(&terminal) {
        Ok(crate::fixed_adapter_ipc::WireMessage::Shutdown) => Ok(()),
        Ok(crate::fixed_adapter_ipc::WireMessage::Frame(_)) => {
            Err("trusted witness child rejected a request after device close".to_owned())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the one-request child state machine is kept linear for security auditability"
)]
pub(crate) fn run_client(pipe_name: &str) -> Result<(), String> {
    let hello = child_hello(pipe_name)?;
    let pipe_name = wide_null(OsStr::new(pipe_name))?;
    let raw = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(trusted witness child pipe)"));
    }
    let pipe = OwnedKernelHandle(raw);
    let read_mode = PIPE_READMODE_MESSAGE;
    if unsafe { SetNamedPipeHandleState(pipe.0, &raw const read_mode, null(), null()) } == 0 {
        return Err(last_error(
            "SetNamedPipeHandleState(trusted witness child message mode)",
        ));
    }
    write_child_message(pipe.0, &hello, "WriteFile(trusted witness child hello)")?;
    let maximum_request = crate::fixed_adapter_ipc::HEADER_BYTES
        .checked_add(crate::fixed_adapter_ipc::MAX_REQUEST_BODY_BYTES)
        .expect("fixed adapter request bound fits usize");
    let first = read_child_message(
        pipe.0,
        maximum_request,
        "ReadFile(trusted witness child request)",
    )?;
    if first.starts_with(b"0VDO") {
        return run_device_open_request(pipe.0, &first);
    }
    let request = match crate::fixed_adapter_ipc::decode_message(&first) {
        Ok(crate::fixed_adapter_ipc::WireMessage::Shutdown) => return Ok(()),
        Ok(crate::fixed_adapter_ipc::WireMessage::Frame(frame))
            if frame.kind == crate::fixed_adapter_ipc::FrameKind::ExecuteRequest =>
        {
            frame
        }
        Ok(crate::fixed_adapter_ipc::WireMessage::Frame(frame)) => {
            write_protocol_error(
                pipe.0,
                frame.exchange_id,
                crate::fixed_adapter_ipc::ProtocolErrorCode::UnexpectedKind,
            )?;
            return Err("trusted witness child received an unexpected frame kind".to_owned());
        }
        Err(error) => return Err(error.to_string()),
    };

    let thread_id_start = unsafe { GetCurrentThreadId() };
    let start_profile = crate::windows::current_effective_witness_profile()?;
    let start_profile_sha256 = start_profile.sha256()?;
    let Ok(adapter_result) = crate::fixed_adapter::execute_encoded(&request.body) else {
        write_protocol_error(
            pipe.0,
            request.exchange_id,
            crate::fixed_adapter_ipc::ProtocolErrorCode::InvalidRequest,
        )?;
        return Err("trusted witness child rejected its fixed adapter request".to_owned());
    };
    let finish_profile = crate::windows::current_effective_witness_profile()?;
    let thread_id_finish = unsafe { GetCurrentThreadId() };
    let finish_profile_sha256 = finish_profile.sha256()?;
    if thread_id_start != thread_id_finish || start_profile != finish_profile {
        write_protocol_error(
            pipe.0,
            request.exchange_id,
            crate::fixed_adapter_ipc::ProtocolErrorCode::ExecutionFailed,
        )?;
        return Err("trusted witness child token or thread changed during execution".to_owned());
    }
    let execution = crate::fixed_adapter::encode_child_execution(
        &adapter_result,
        thread_id_start,
        thread_id_finish,
        &start_profile_sha256,
        &finish_profile_sha256,
    )
    .map_err(|_| "trusted witness child could not encode its neutral result".to_owned())?;
    let response = crate::fixed_adapter_ipc::encode_frame(
        crate::fixed_adapter_ipc::FrameKind::ExecuteResult,
        request.exchange_id,
        &execution,
    )
    .map_err(|error| error.to_string())?;
    write_child_message(pipe.0, &response, "WriteFile(trusted witness child result)")?;

    let terminal = read_child_message(
        pipe.0,
        maximum_request,
        "ReadFile(trusted witness child terminal control)",
    )?;
    match crate::fixed_adapter_ipc::decode_message(&terminal) {
        Ok(crate::fixed_adapter_ipc::WireMessage::Shutdown) => Ok(()),
        Ok(crate::fixed_adapter_ipc::WireMessage::Frame(frame)) => {
            write_protocol_error(
                pipe.0,
                frame.exchange_id,
                crate::fixed_adapter_ipc::ProtocolErrorCode::UnexpectedKind,
            )?;
            Err("trusted witness child rejected a second request".to_owned())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn command_line(image: &Path, child_pipe_name: &str) -> Result<Vec<u16>, String> {
    if !valid_child_pipe_name(child_pipe_name) {
        return Err("trusted witness child pipe name is invalid".to_owned());
    }
    let image = image
        .to_str()
        .ok_or_else(|| "trusted witness image path is not valid Unicode".to_owned())?;
    if image.contains('"') {
        return Err("trusted witness image path contains a quote".to_owned());
    }
    wide_null(OsStr::new(&format!(
        "\"{image}\" {CHILD_MODE} {child_pipe_name}"
    )))
}

fn create_job() -> Result<OwnedKernelHandle, String> {
    let raw = unsafe { CreateJobObjectW(null(), null()) };
    if raw.is_null() {
        return Err(last_error("CreateJobObjectW(trusted witness)"));
    }
    let job = OwnedKernelHandle(raw);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = CHILD_USER_CPU_LIMIT_100NS;
    limits.ProcessMemoryLimit = CHILD_COMMIT_LIMIT_BYTES;
    limits.JobMemoryLimit = CHILD_COMMIT_LIMIT_BYTES;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .expect("job information size fits u32"),
        )
    } == 0
    {
        return Err(last_error("SetInformationJobObject(trusted witness)"));
    }
    let mut observed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let information_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .expect("job information size fits u32");
    if unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw mut observed).cast(),
            information_size,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("QueryInformationJobObject(trusted witness)"));
    }
    if observed.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags
        || observed.BasicLimitInformation.ActiveProcessLimit != 1
        || observed.BasicLimitInformation.PerProcessUserTimeLimit != CHILD_USER_CPU_LIMIT_100NS
        || observed.ProcessMemoryLimit != CHILD_COMMIT_LIMIT_BYTES
        || observed.JobMemoryLimit != CHILD_COMMIT_LIMIT_BYTES
    {
        return Err("trusted witness job limits failed readback verification".to_owned());
    }
    Ok(job)
}

fn query_process_image(process: HANDLE) -> Result<PathBuf, String> {
    let mut capacity = 260usize;
    loop {
        if capacity > MAX_PATH_U16 {
            return Err("trusted witness process image path exceeds its bound".to_owned());
        }
        let mut buffer = vec![0u16; capacity];
        let mut length = u32::try_from(buffer.len()).map_err(|_| "image path capacity overflow")?;
        if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &raw mut length) }
            != 0
        {
            let length = usize::try_from(length).map_err(|_| "image path length overflow")?;
            if length == 0 || length > buffer.len() || buffer[..length].contains(&0) {
                return Err("trusted witness process image path is malformed".to_owned());
            }
            let value = String::from_utf16(&buffer[..length])
                .map_err(|_| "trusted witness process image path is not UTF-16".to_owned())?;
            return Ok(PathBuf::from(value));
        }
        let error = unsafe { GetLastError() };
        if error != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(format!(
                "QueryFullProcessImageNameW(trusted witness) failed with Win32 error {error}"
            ));
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| "image path capacity overflowed".to_owned())?;
    }
}

pub(super) struct RunningTrustedChild {
    bootstrap: Option<AuthenticatedWitnessToken>,
    image: Option<TrustedImage>,
    process: Option<OwnedKernelHandle>,
    thread: Option<OwnedKernelHandle>,
    job: Option<OwnedKernelHandle>,
    pid: u32,
    child_pipe_name: String,
    resumed: bool,
}

pub(super) struct TrustedChildCapability {
    running: RunningTrustedChild,
    channel: AuthenticatedChildChannel,
}

impl TrustedChildCapability {
    fn child_binding_sha256(&self) -> &str {
        &self.channel.child_binding_sha256
    }

    pub(super) fn hold_device_open(
        mut self,
        stop_event: HANDLE,
    ) -> Result<BrokerHeldDeviceOpen, String> {
        let process = self.running.process_handle();
        let expected_profile = self.channel.token.profile().clone();
        let exchange_id = random_exchange_id()?;
        let observation = self
            .channel
            .observe_device_open(exchange_id, process, stop_event)?;
        if observation.process_id != self.running.pid() {
            return Err("device-open observation came from a different child PID".to_owned());
        }
        crate::windows::device_open::revalidate_child_process(
            process,
            &observation,
            &expected_profile,
        )?;
        let duplicate = crate::windows::device_open::SourceDeviceHandle::duplicate_from_process(
            process,
            observation.source_handle_value,
        )?;
        self.channel.close_device_open_source(process, stop_event)?;
        crate::windows::device_open::revalidate_child_process(
            process,
            &observation,
            &expected_profile,
        )?;
        crate::windows::device_open::reenumerate_fixed_target(&observation)?;
        let installed_driver = crate::windows::driver_file::measure_fixed_installed_driver()?;
        Ok(BrokerHeldDeviceOpen {
            child: Some(self),
            observation,
            duplicate,
            installed_driver,
        })
    }

    #[cfg(feature = "ci-system-test")]
    pub(super) fn ci_execute_noop_and_shutdown(
        mut self,
        run_nonce: &str,
        stop_event: HANDLE,
    ) -> Result<CiShutdownResult, String> {
        let pid = self.running.pid;
        let binding_sha256 = self.child_binding_sha256().to_owned();
        let image_path = self.running.image().path.clone();
        let stage_directory = self.running.image().directory.clone();
        let process = self.running.process_handle();
        let prepared = crate::fixed_adapter::prepare_control_noop(run_nonce)?;
        let exchange_id = random_exchange_id()?;
        let request = crate::fixed_adapter_ipc::encode_frame(
            crate::fixed_adapter_ipc::FrameKind::ExecuteRequest,
            exchange_id,
            prepared.bytes(),
        )
        .map_err(|error| error.to_string())?;
        let response = self.channel.exchange_once(&request, process, stop_event)?;
        let response = crate::fixed_adapter_ipc::decode_response(&response, exchange_id)
            .map_err(|error| error.to_string())?;
        if response.kind == crate::fixed_adapter_ipc::FrameKind::ExecuteError {
            let error = crate::fixed_adapter_ipc::decode_error_body(&response.body)
                .map_err(|error| error.to_string())?;
            return Err(format!(
                "trusted witness child rejected the fixed adapter exchange with code {:?}",
                error.code
            ));
        }
        let expected_profile_sha256 = self.channel.token.profile().sha256()?;
        let execution = crate::fixed_adapter::validate_child_execution(
            &prepared,
            &response.body,
            &expected_profile_sha256,
        )?;
        self.channel.send_shutdown(process, stop_event)?;
        if unsafe { WaitForSingleObject(process, CHILD_TEARDOWN_TIMEOUT_MS) } != WAIT_OBJECT_0 {
            return Err("trusted witness child did not exit after fixed shutdown".to_owned());
        }
        let mut exit_code = u32::MAX;
        if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
            return Err(last_error("GetExitCodeProcess(trusted witness child)"));
        }
        if exit_code != 0 {
            return Err(format!(
                "trusted witness child exited with unexpected code {exit_code}"
            ));
        }
        drop(self);
        if image_path.exists() || stage_directory.exists() {
            return Err("trusted witness stage remained after capability drop".to_owned());
        }
        Ok(CiShutdownResult {
            pid,
            binding_sha256,
            execution,
        })
    }
}

/// Broker-owned query-only capability retained across receipt construction and
/// signing. The duplicate is intentionally private and cannot be used for I/O.
pub(crate) struct BrokerHeldDeviceOpen {
    child: Option<TrustedChildCapability>,
    observation: Box<crate::device_open_protocol::DeviceOpenObservation>,
    duplicate: crate::windows::device_open::SourceDeviceHandle,
    installed_driver: crate::windows::driver_file::InstalledDriverFileMeasurement,
}

impl BrokerHeldDeviceOpen {
    pub(crate) fn observation(&self) -> &crate::device_open_protocol::DeviceOpenObservation {
        &self.observation
    }

    pub(crate) fn installed_driver(
        &self,
    ) -> &crate::windows::driver_file::InstalledDriverFileMeasurement {
        let _ = &self.duplicate;
        &self.installed_driver
    }

    /// Call only after the immutable signed receipt has been published and
    /// verified. This closes the broker duplicate when the capability drops.
    pub(crate) fn shutdown_after_publication(mut self, stop_event: HANDLE) -> Result<(), String> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| "device-open child capability is absent".to_owned())?;
        let process = child.running.process_handle();
        child.channel.send_shutdown(process, stop_event)?;
        if unsafe { WaitForSingleObject(process, CHILD_TEARDOWN_TIMEOUT_MS) } != WAIT_OBJECT_0 {
            return Err("device-open child did not exit after fixed shutdown".to_owned());
        }
        let mut exit_code = u32::MAX;
        if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
            return Err(last_error("GetExitCodeProcess(device-open child)"));
        }
        if exit_code != 0 {
            return Err(format!(
                "device-open child exited with unexpected code {exit_code}"
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "ci-system-test")]
pub(super) struct CiShutdownResult {
    pub(super) pid: u32,
    pub(super) binding_sha256: String,
    pub(super) execution: crate::fixed_adapter::UnsignedChildExecution,
}

/// Create the exact child and authenticate its retained process object.
///
/// This transition is private to the witness module. Production authority
/// binding remains unreachable until the hosted E2E validates it.
pub(super) unsafe fn create_and_authenticate(
    bootstrap: AuthenticatedWitnessToken,
    source_image: &Path,
    expected_sha256: &str,
    stop_event: HANDLE,
) -> Result<PinnedAuthenticatedWitness, String> {
    let expected = ExpectedWitnessIdentity::new(
        &bootstrap.profile.user_sid,
        bootstrap.profile.session_id,
        &bootstrap.profile.authentication_id,
    )?;
    let bootstrap_binding = bootstrap.rendezvous_binding_sha256.clone();
    let spec = WitnessRendezvousSpec::new_child(
        &bootstrap_binding,
        expected_sha256,
        &random_hex::<32>()?,
        &expected,
    )?;
    let child_binding = spec.binding_sha256().to_owned();
    let rendezvous = WitnessRendezvous::prepare(spec)?;
    let running =
        RunningTrustedChild::launch(bootstrap, source_image, expected_sha256, rendezvous.name())?;
    let outcome =
        unsafe { rendezvous.accept_exact(stop_event, running.pid(), running.process_handle()) }?;
    let channel = match outcome {
        ExactAcceptOutcome::Authenticated(channel) => *channel,
        ExactAcceptOutcome::Stopped => {
            return Err("trusted witness child authentication was stopped".to_owned());
        }
        ExactAcceptOutcome::TimedOut => {
            return Err("trusted witness child authentication timed out".to_owned());
        }
    };
    let bootstrap_profile = running
        .bootstrap
        .as_ref()
        .expect("running trusted child retains bootstrap token")
        .profile
        .clone();
    if channel.token.profile != bootstrap_profile {
        return Err("trusted witness child token differs from its bootstrap token".to_owned());
    }
    if channel.child_binding_sha256 != child_binding {
        return Err("trusted witness child channel binding changed".to_owned());
    }
    let capability = TrustedChildCapability { running, channel };
    Ok(PinnedAuthenticatedWitness {
        test_token: None,
        trusted_child: Some(capability),
        sha256: expected_sha256.to_owned(),
        rendezvous_binding_sha256: bootstrap_binding,
    })
}

impl RunningTrustedChild {
    pub(super) fn launch(
        bootstrap: AuthenticatedWitnessToken,
        source_image: &Path,
        expected_sha256: &str,
        child_pipe_name: &str,
    ) -> Result<Self, String> {
        if unsafe { WaitForSingleObject(bootstrap.bootstrap_process.0, 0) } != WAIT_TIMEOUT {
            return Err("bootstrap witness exited before trusted child launch".to_owned());
        }
        let image =
            TrustedImage::stage(source_image, expected_sha256, &bootstrap.profile.user_sid)?;
        let application = wide_null(image.path.as_os_str())?;
        let mut command = command_line(&image.path, child_pipe_name)?;
        let mut environment = sanitized_environment(&image.directory)?;
        let current_directory = wide_null(image.directory.as_os_str())?;
        let object_descriptor = security_descriptor("O:SYG:SYD:P(A;;GA;;;SY)")?;
        let object_attributes = security_attributes(&object_descriptor);
        let startup = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>()).expect("STARTUPINFOW size fits u32"),
            ..STARTUPINFOW::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();
        let job = create_job()?;
        let created = unsafe {
            CreateProcessAsUserW(
                bootstrap.primary_token.0,
                application.as_ptr(),
                command.as_mut_ptr(),
                &raw const object_attributes,
                &raw const object_attributes,
                0,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_DEFAULT_ERROR_MODE
                    | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw const startup,
                &raw mut process_info,
            )
        };
        if created == 0 {
            return Err(last_error("CreateProcessAsUserW(trusted witness)"));
        }
        let mut child = Self {
            bootstrap: Some(bootstrap),
            image: Some(image),
            process: Some(OwnedKernelHandle(process_info.hProcess)),
            thread: Some(OwnedKernelHandle(process_info.hThread)),
            job: Some(job),
            pid: process_info.dwProcessId,
            child_pipe_name: child_pipe_name.to_owned(),
            resumed: false,
        };
        child.validate_created_process(process_info.dwThreadId)?;
        if unsafe { AssignProcessToJobObject(child.job_handle(), child.process_handle()) } == 0 {
            return Err(last_error("AssignProcessToJobObject(trusted witness)"));
        }
        let mut in_job = 0;
        if unsafe { IsProcessInJob(child.process_handle(), child.job_handle(), &raw mut in_job) }
            == 0
            || in_job == 0
        {
            return Err("trusted witness process is not contained by its job".to_owned());
        }
        let previous = unsafe { ResumeThread(child.thread_handle()) };
        if previous != 1 {
            return Err(format!(
                "ResumeThread(trusted witness) returned unexpected suspend count {previous}"
            ));
        }
        child.resumed = true;
        if unsafe { WaitForSingleObject(child.process_handle(), 0) } != WAIT_TIMEOUT {
            return Err("trusted witness child exited immediately after resume".to_owned());
        }
        Ok(child)
    }

    fn validate_created_process(&self, thread_id: u32) -> Result<(), String> {
        if self.pid == 0
            || self.process_handle().is_null()
            || self.process_handle() == INVALID_HANDLE_VALUE
            || self.thread_handle().is_null()
            || self.thread_handle() == INVALID_HANDLE_VALUE
        {
            return Err("CreateProcessAsUserW returned an invalid process shape".to_owned());
        }
        if unsafe { GetProcessId(self.process_handle()) } != self.pid
            || unsafe { GetThreadId(self.thread_handle()) } != thread_id
            || unsafe { GetProcessIdOfThread(self.thread_handle()) } != self.pid
            || unsafe { WaitForSingleObject(self.process_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err("trusted witness PROCESS_INFORMATION is not self-consistent".to_owned());
        }
        let process_image = query_process_image(self.process_handle())?;
        let reopened = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(process_image)
            .map_err(|error| format!("reopen trusted witness process image failed: {error}"))?;
        if file_identity(&reopened)? != *self.image().identity() {
            return Err("trusted witness process image is not the held staged file".to_owned());
        }
        Ok(())
    }

    fn image(&self) -> &TrustedImage {
        self.image.as_ref().expect("trusted child image is present")
    }

    pub(super) fn process_handle(&self) -> HANDLE {
        self.process
            .as_ref()
            .expect("trusted child process is present")
            .0
    }

    fn thread_handle(&self) -> HANDLE {
        self.thread
            .as_ref()
            .expect("trusted child thread is present")
            .0
    }

    fn job_handle(&self) -> HANDLE {
        self.job.as_ref().expect("trusted child job is present").0
    }

    pub(super) const fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for RunningTrustedChild {
    fn drop(&mut self) {
        let process = self.process.as_ref().map_or(null_mut(), |handle| handle.0);
        if !process.is_null() && process != INVALID_HANDLE_VALUE {
            if self.resumed {
                // Closing the sole job handle kills the process tree.
                drop(self.job.take());
            } else if unsafe { WaitForSingleObject(process, 0) } == WAIT_TIMEOUT
                && unsafe { TerminateProcess(process, TERMINATION_EXIT_CODE) } == 0
                && unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0
            {
                // Recheck after the documented exit/termination race. Continuing
                // without proving death would leave an untrusted process outside
                // the capability.
                std::process::abort();
            }
            if unsafe { WaitForSingleObject(process, CHILD_TEARDOWN_TIMEOUT_MS) } != WAIT_OBJECT_0 {
                // A LocalSystem broker must never outlive an escaped child or
                // hang forever while retaining authority-bearing capabilities.
                std::process::abort();
            }
        }
        drop(self.thread.take());
        drop(self.process.take());
        drop(self.job.take());
        drop(self.image.take());
        drop(self.bootstrap.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_pipe_name_is_exact_and_bounded() {
        let name = format!("{CHILD_PIPE_PREFIX}{}", "a".repeat(64));
        assert!(valid_child_pipe_name(&name));
        assert!(!valid_child_pipe_name(&format!("{name}a")));
        assert!(!valid_child_pipe_name(&name.replace('a', "A")));
        let hello = child_hello(&name).unwrap();
        assert_eq!(&hello[..2], &[0xa2, 0x01]);
        assert!(hello[2..].iter().all(|byte| *byte == 0xaa));
    }

    #[test]
    fn random_binding_nonce_has_the_required_shape() {
        let nonce = random_hex::<32>().unwrap();
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
