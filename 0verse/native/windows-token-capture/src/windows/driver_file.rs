//! Fixed-target measurement of the installed driver image.
//!
//! This broker-side primitive accepts no service name, path, command,
//! environment value, or operation from a caller. It reads the service config
//! for the sole compiled device-open fixture, pins the exact installed disk
//! file, hashes at most 64 MiB, and retains both its handle and file identity.
//!
//! An installed-file measurement is not evidence that these bytes are loaded,
//! that a particular device object or interface is owned by them, or that they
//! implement any handler. Those are separate live-kernel claims. This module
//! never loads, starts, stops, or otherwise controls a driver service.

#![allow(
    dead_code,
    reason = "the primitive is wired by the staged broker receipt integration"
)]

use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::ptr::{null, null_mut};

use sha2::{Digest as _, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, GENERIC_READ, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_BEGIN, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_NAME_NORMALIZED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    GetFileInformationByHandle, GetFileSizeEx, GetFileType, GetFinalPathNameByHandleW,
    OPEN_EXISTING, ReadFile, SetFilePointerEx, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    SC_MANAGER_CONNECT, SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

use crate::device_open_protocol::fixed_target;

const MAX_SERVICE_CONFIG_BYTES: usize = 64 * 1024;
const MAX_PATH_U16: usize = 32_768;
const MAX_DRIVER_BYTES: u64 = 64 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, String>;

fn last_error(context: &str) -> String {
    // SAFETY: GetLastError has no preconditions and is called immediately after failure.
    let code = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {code}")
}

fn wide_null(value: &str) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = OsStr::new(value).encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) || wide.len() >= MAX_PATH_U16 {
        return Err("fixed driver service value has an invalid UTF-16 length".to_owned());
    }
    wide.push(0);
    Ok(wide)
}

struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns a successful SCM handle.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn query_fixed_service_binary_path() -> Result<String> {
    // SAFETY: null machine and database select the local active SCM database.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_error("OpenSCManagerW(fixed driver)"));
    }
    let manager = ServiceHandle(manager);
    let service_name = wide_null(fixed_target().driver_service_name)?;
    // SAFETY: manager is live and service_name is a retained NUL-terminated string.
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if service.is_null() {
        return Err(last_error("OpenServiceW(fixed driver)"));
    }
    let service = ServiceHandle(service);

    let mut required = 0_u32;
    // SAFETY: the first call intentionally obtains the bounded buffer size.
    let first = unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &raw mut required) };
    if first != 0 || required == 0 {
        return Err("QueryServiceConfigW returned an invalid sizing result".to_owned());
    }
    // SAFETY: called directly after the failed sizing call.
    let sizing_error = unsafe { GetLastError() };
    if sizing_error != ERROR_INSUFFICIENT_BUFFER && sizing_error != ERROR_MORE_DATA {
        return Err(format!(
            "QueryServiceConfigW sizing failed with Win32 error {sizing_error}"
        ));
    }
    let required = usize::try_from(required)
        .map_err(|_| "driver service config size overflowed usize".to_owned())?;
    if required < size_of::<QUERY_SERVICE_CONFIGW>() || required > MAX_SERVICE_CONFIG_BYTES {
        return Err("driver service config size is outside its bound".to_owned());
    }
    let word = size_of::<usize>();
    let mut storage = vec![0_usize; required.div_ceil(word)];
    let capacity = storage
        .len()
        .checked_mul(word)
        .ok_or_else(|| "driver service config allocation overflowed".to_owned())?;
    let mut returned_required = 0_u32;
    // SAFETY: aligned storage is writable for the advertised capacity.
    if unsafe {
        QueryServiceConfigW(
            service.0,
            storage.as_mut_ptr().cast(),
            u32::try_from(capacity).map_err(|_| "driver service config capacity overflowed u32")?,
            &raw mut returned_required,
        )
    } == 0
    {
        return Err(last_error("QueryServiceConfigW(fixed driver)"));
    }
    // SAFETY: a successful call initialized the leading config structure.
    let config = unsafe { &*storage.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    if config.dwServiceType != SERVICE_KERNEL_DRIVER {
        return Err("fixed service is not a kernel-driver service".to_owned());
    }
    let base = storage.as_ptr().cast::<u8>() as usize;
    let end = base
        .checked_add(capacity)
        .ok_or_else(|| "driver service config address overflowed".to_owned())?;
    let start = config.lpBinaryPathName as usize;
    if start < base || start >= end || !start.is_multiple_of(size_of::<u16>()) {
        return Err("driver service binary path pointer is outside its config".to_owned());
    }
    let available = (end - start) / size_of::<u16>();
    if available == 0 || available > MAX_PATH_U16 {
        return Err("driver service binary path exceeds its bound".to_owned());
    }
    // SAFETY: the pointer range was validated inside retained aligned storage.
    let units = unsafe { std::slice::from_raw_parts(config.lpBinaryPathName, available) };
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| "driver service binary path is not NUL-terminated".to_owned())?;
    if terminator == 0 {
        return Err("driver service binary path is empty".to_owned());
    }
    String::from_utf16(&units[..terminator])
        .map_err(|_| "driver service binary path is not valid UTF-16".to_owned())
}

fn windows_directory() -> Result<String> {
    let mut capacity = 260_usize;
    loop {
        if capacity > MAX_PATH_U16 {
            return Err("Windows directory exceeds its bound".to_owned());
        }
        let mut buffer = vec![0_u16; capacity];
        // SAFETY: buffer is writable for its advertised number of UTF-16 units.
        let written = unsafe {
            GetWindowsDirectoryW(
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| "Windows directory capacity overflow")?,
            )
        };
        if written == 0 {
            return Err(last_error("GetWindowsDirectoryW(driver measurement)"));
        }
        let written = usize::try_from(written)
            .map_err(|_| "Windows directory length overflowed usize".to_owned())?;
        if written < buffer.len() {
            if buffer[..written].contains(&0) {
                return Err("Windows directory contains an interior NUL".to_owned());
            }
            return String::from_utf16(&buffer[..written])
                .map_err(|_| "Windows directory is not valid UTF-16".to_owned());
        }
        capacity = written
            .checked_add(1)
            .ok_or_else(|| "Windows directory capacity overflowed".to_owned())?;
    }
}

fn canonical_installed_path(configured: &str, windows: &str) -> Result<String> {
    if configured.is_empty()
        || configured.chars().any(char::is_whitespace)
        || configured.contains(['\0', '"', '/', '*', '?'])
        || windows.contains(['\0', '"', '/', '*', '?'])
    {
        return Err("driver service binary path is not a strict argument-free path".to_owned());
    }
    let windows = windows.trim_end_matches('\\');
    if windows.len() < 3
        || windows.as_bytes().get(1) != Some(&b':')
        || windows.as_bytes().get(2) != Some(&b'\\')
    {
        return Err("Windows directory is not a canonical absolute DOS path".to_owned());
    }
    let system_root_prefix = "\\SystemRoot\\";
    let path = if configured
        .get(..system_root_prefix.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(system_root_prefix))
    {
        format!("{windows}\\{}", &configured[system_root_prefix.len()..])
    } else {
        configured.to_owned()
    };
    let required_prefix = format!("{windows}\\");
    if !path
        .get(..required_prefix.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&required_prefix))
        || path.starts_with("\\\\")
        || path.contains("\\\\")
        || path
            .split('\\')
            .any(|part| matches!(part, "." | "..") || part.is_empty())
        || !path.to_ascii_lowercase().ends_with(".sys")
    {
        return Err("driver image is not a canonical .sys path below Windows".to_owned());
    }
    Ok(path)
}

struct ProbeHandle(HANDLE);

impl Drop for ProbeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this wrapper exclusively owns the successful probe handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn reject_reparse_components(path: &str) -> Result<()> {
    let mut current = path
        .get(..3)
        .ok_or_else(|| "canonical driver path has no DOS root".to_owned())?
        .to_owned();
    let components: Vec<&str> = path[3..].split('\\').collect();
    for (index, component) in components.iter().enumerate() {
        current.push_str(component);
        let wide = wide_null(&current)?;
        // Opening the reparse point itself lets the attributes below reject it
        // instead of silently traversing it. Directory semantics are required
        // for every parent component.
        // SAFETY: wide is a retained NUL-terminated canonical component path.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateFileW(driver path component probe)"));
        }
        let probe = ProbeHandle(raw);
        let information = file_information(probe.0)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("fixed installed driver path contains a reparse point".to_owned());
        }
        let is_leaf = index + 1 == components.len();
        let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory == is_leaf {
            return Err("fixed installed driver path has an unexpected component type".to_owned());
        }
        current.push('\\');
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverFileIdentity {
    pub(crate) volume_serial_number: u32,
    pub(crate) file_index: u64,
}

/// Exact installed bytes retained for the lifetime of this measurement.
pub(crate) struct InstalledDriverFileMeasurement {
    handle: HANDLE,
    pub(crate) service_name: &'static str,
    pub(crate) canonical_path: String,
    pub(crate) final_path: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) identity: DriverFileIdentity,
}

impl Drop for InstalledDriverFileMeasurement {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: this measurement exclusively owns the pinned file handle.
            unsafe { CloseHandle(self.handle) };
        }
    }
}

fn file_information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: information is writable and handle is the retained disk-file handle.
    if unsafe { GetFileInformationByHandle(handle, &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(driver image)"));
    }
    Ok(information)
}

fn identity(information: &BY_HANDLE_FILE_INFORMATION) -> DriverFileIdentity {
    DriverFileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: u64::from(information.nFileIndexLow)
            | (u64::from(information.nFileIndexHigh) << 32),
    }
}

fn final_path(handle: HANDLE) -> Result<String> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: the first call intentionally requests the required UTF-16 count.
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, flags) };
    if required == 0 {
        return Err(last_error("GetFinalPathNameByHandleW(driver image size)"));
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "final driver path capacity overflowed".to_owned())?;
    if capacity > MAX_PATH_U16 {
        return Err("final driver path exceeds its bound".to_owned());
    }
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: buffer is writable for its advertised number of UTF-16 units.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| "final driver path capacity overflowed u32")?,
            flags,
        )
    };
    let written = usize::try_from(written)
        .map_err(|_| "final driver path length overflowed usize".to_owned())?;
    if written == 0 || written >= buffer.len() || buffer[..written].contains(&0) {
        return Err("final driver path has an invalid result length".to_owned());
    }
    let mut result = String::from_utf16(&buffer[..written])
        .map_err(|_| "final driver path is not valid UTF-16".to_owned())?;
    if result.get(..4).is_some_and(|prefix| prefix == "\\\\?\\") {
        result.drain(..4);
    }
    Ok(result)
}

fn hash_pinned_file(handle: HANDLE, expected_size: u64) -> Result<String> {
    // SAFETY: handle is a synchronous disk-file handle and zero is a valid offset.
    if unsafe { SetFilePointerEx(handle, 0, null_mut(), FILE_BEGIN) } == 0 {
        return Err(last_error("SetFilePointerEx(driver image)"));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let mut read = 0_u32;
        // SAFETY: buffer is writable and retained for this synchronous read.
        if unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).expect("fixed hash buffer fits u32"),
                &raw mut read,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error("ReadFile(driver image)"));
        }
        if read == 0 {
            break;
        }
        let read = usize::try_from(read).map_err(|_| "driver read size overflowed usize")?;
        total = total
            .checked_add(u64::try_from(read).map_err(|_| "driver read size overflowed u64")?)
            .ok_or_else(|| "driver file size overflowed".to_owned())?;
        if total > MAX_DRIVER_BYTES || total > expected_size {
            return Err("driver image changed size or exceeded 64 MiB while hashing".to_owned());
        }
        digest.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err("driver image changed size while hashing".to_owned());
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Measure and retain the fixed target's installed driver image.
///
/// This says nothing about which bytes are loaded or which code owns a device
/// interface. It performs no service control and no driver load operation.
pub(crate) fn measure_fixed_installed_driver() -> Result<InstalledDriverFileMeasurement> {
    let configured = query_fixed_service_binary_path()?;
    let canonical = canonical_installed_path(&configured, &windows_directory()?)?;
    reject_reparse_components(&canonical)?;
    let path = wide_null(&canonical)?;
    // FILE_SHARE_READ denies replacement/deletion while the measurement lives.
    // OPEN_REPARSE_POINT prevents traversal of a reparse point at the file leaf.
    // SAFETY: path is a retained NUL-terminated canonical absolute path.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(fixed installed driver)"));
    }
    let mut measurement = InstalledDriverFileMeasurement {
        handle,
        service_name: fixed_target().driver_service_name,
        canonical_path: canonical,
        final_path: String::new(),
        sha256: String::new(),
        size: 0,
        identity: DriverFileIdentity {
            volume_serial_number: 0,
            file_index: 0,
        },
    };
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err("fixed installed driver is not a disk file".to_owned());
    }
    let before = file_information(handle)?;
    if before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err("fixed installed driver is a directory or reparse point".to_owned());
    }
    let mut signed_size = 0_i64;
    // SAFETY: signed_size is writable and handle is a retained disk-file handle.
    if unsafe { GetFileSizeEx(handle, &raw mut signed_size) } == 0 {
        return Err(last_error("GetFileSizeEx(fixed installed driver)"));
    }
    let size = u64::try_from(signed_size)
        .map_err(|_| "fixed installed driver has a negative size".to_owned())?;
    if size == 0 || size > MAX_DRIVER_BYTES {
        return Err("fixed installed driver size is outside 1..=64 MiB".to_owned());
    }
    let resolved = final_path(handle)?;
    if !resolved.eq_ignore_ascii_case(&measurement.canonical_path) {
        return Err("fixed installed driver resolved through a non-canonical path".to_owned());
    }
    let sha256 = hash_pinned_file(handle, size)?;
    let after = file_information(handle)?;
    if identity(&before) != identity(&after)
        || before.nFileSizeLow != after.nFileSizeLow
        || before.nFileSizeHigh != after.nFileSizeHigh
        || before.ftLastWriteTime.dwLowDateTime != after.ftLastWriteTime.dwLowDateTime
        || before.ftLastWriteTime.dwHighDateTime != after.ftLastWriteTime.dwHighDateTime
    {
        return Err("fixed installed driver identity changed while hashing".to_owned());
    }
    let expected = fixed_target().expected_installed_driver_image_sha256;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("compiled expected driver digest is not lowercase SHA-256".to_owned());
    }
    if sha256 != expected {
        return Err(format!(
            "fixed installed driver digest differs from compiled expected digest: got {sha256}"
        ));
    }
    measurement.final_path = resolved;
    measurement.sha256 = sha256;
    measurement.size = size;
    measurement.identity = identity(&after);
    Ok(measurement)
}

#[cfg(test)]
mod tests {
    use super::canonical_installed_path;

    #[test]
    fn canonicalizes_only_system_root_or_exact_windows_root() {
        assert_eq!(
            canonical_installed_path(r"\SystemRoot\System32\drivers\fixture.sys", r"C:\Windows",)
                .unwrap(),
            r"C:\Windows\System32\drivers\fixture.sys"
        );
        assert_eq!(
            canonical_installed_path(r"c:\windows\System32\drivers\fixture.sys", r"C:\Windows\",)
                .unwrap(),
            r"c:\windows\System32\drivers\fixture.sys"
        );
    }

    #[test]
    fn rejects_arguments_aliases_traversal_and_wrong_roots() {
        for invalid in [
            r#""C:\Windows\System32\drivers\fixture.sys" --argument"#,
            r"C:\Windows\System32\drivers\fixture.sys --argument",
            r"C:\Windows\System32\drivers\..\fixture.sys",
            r"C:\Windows\System32\\drivers\fixture.sys",
            r"C:\WindowsElsewhere\System32\drivers\fixture.sys",
            r"\\?\C:\Windows\System32\drivers\fixture.sys",
            r"\SystemRoot\System32\drivers\fixture.dll",
        ] {
            assert!(
                canonical_installed_path(invalid, r"C:\Windows").is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }
}
