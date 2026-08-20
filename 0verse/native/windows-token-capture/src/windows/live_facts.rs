//! Live, OS-owned facts sampled by the native broker.
//!
//! This module deliberately accepts no request, environment, path, or command
//! input. The runner image handle remains open so the bytes whose digest is
//! authority-bound cannot be changed or deleted before the caller completes
//! the privileged operation.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt as _;
use std::ptr::{null, null_mut};

use sha2::{Digest as _, Sha256};
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, FILETIME, GENERIC_READ, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_TYPE_DISK, GetFileInformationByHandle,
    GetFileSizeEx, GetFileType, GetFinalPathNameByHandleW, OPEN_EXISTING, ReadFile,
    VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    RRF_ZEROONFAILURE, RegGetValueW,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsFullyQualified, GetComputerNameExW, GetSystemTimePreciseAsFileTime,
};

const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
const MAX_COMPUTER_NAME_U16: usize = 256;
const MAX_REGISTRY_BYTES: usize = 2 * 1024;
const MAX_MODULE_PATH_U16: usize = 32_768;
const MAX_FINAL_PATH_U16: usize = 32_768;
const MAX_RUNNER_BYTES: u64 = 256 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const MACHINE_ID_DOMAIN: &[u8] = b"0verse-windows-machine-id-v1\0";
const SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS: i32 = 90;
const CURRENT_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const CRYPTOGRAPHY_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";

type Result<T> = std::result::Result<T, String>;

/// A point-in-time set of host facts, including a pinned runner image.
pub(crate) struct LiveFacts {
    pub(crate) now_unix_seconds: i64,
    pub(crate) worker: String,
    pub(crate) build_lab_ex: String,
    #[allow(dead_code, reason = "consumed by the device-open receipt integration")]
    pub(crate) windows_ubr: u32,
    #[allow(dead_code, reason = "consumed by the device-open receipt integration")]
    pub(crate) boot_id: String,
    pub(crate) worker_machine_id: String,
    pub(crate) runner: PinnedExecutable,
}

/// The exact on-disk runner bytes and the handle preventing their replacement.
pub(crate) struct PinnedExecutable {
    handle: HANDLE,
    sha256: String,
    final_path: String,
    size: u64,
}

impl PinnedExecutable {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn final_path(&self) -> &str {
        &self.final_path
    }

    pub(crate) const fn size(&self) -> u64 {
        self.size
    }
}

impl Drop for PinnedExecutable {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: this type exclusively owns the successful file handle.
            unsafe { CloseHandle(self.handle) };
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn last_error(context: &str) -> String {
    // SAFETY: GetLastError takes no arguments and is called immediately after failure.
    let code = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {code}")
}

fn filetime_to_unix_seconds(filetime: FILETIME) -> Result<i64> {
    let ticks = u64::from(filetime.dwLowDateTime) | (u64::from(filetime.dwHighDateTime) << 32);
    let unix_ticks = ticks
        .checked_sub(FILETIME_UNIX_EPOCH)
        .ok_or_else(|| "live UTC time is before the Unix epoch".to_owned())?;
    i64::try_from(unix_ticks / FILETIME_TICKS_PER_SECOND)
        .map_err(|_| "live UTC time exceeds the supported range".to_owned())
}

pub(crate) fn now_unix_seconds() -> Result<i64> {
    let mut value = FILETIME::default();
    // SAFETY: value points to writable FILETIME storage.
    unsafe { GetSystemTimePreciseAsFileTime(&raw mut value) };
    filetime_to_unix_seconds(value)
}

fn strict_utf16(units: &[u16], label: &str) -> Result<String> {
    String::from_utf16(units).map_err(|_| format!("{label} is not valid UTF-16"))
}

fn canonical_worker(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("physical DNS FQDN is not bounded printable ASCII".to_owned());
    }
    let canonical = value.to_ascii_lowercase();
    if canonical.starts_with('.')
        || canonical.ends_with('.')
        || canonical
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err("physical DNS FQDN has an invalid label shape".to_owned());
    }
    if canonical.split('.').any(|label| {
        label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err("physical DNS FQDN contains an invalid DNS label".to_owned());
    }
    Ok(canonical)
}

fn physical_fqdn() -> Result<String> {
    let mut required = 0u32;
    // SAFETY: a null buffer is the documented size-query form.
    let first = unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsFullyQualified,
            null_mut(),
            &raw mut required,
        )
    };
    // The size query normally returns false/ERROR_MORE_DATA. Accept a nonzero
    // result only if it also supplied a useful bound.
    if first == 0 {
        // SAFETY: called immediately after the failed size query.
        let error = unsafe { GetLastError() };
        if error != ERROR_MORE_DATA {
            return Err(format!(
                "GetComputerNameExW(size) failed with Win32 error {error}"
            ));
        }
    }
    let capacity = usize::try_from(required)
        .map_err(|_| "physical DNS FQDN length overflowed usize".to_owned())?;
    if !(2..=MAX_COMPUTER_NAME_U16).contains(&capacity) {
        return Err("physical DNS FQDN length is outside the supported range".to_owned());
    }
    let mut buffer = vec![0u16; capacity];
    let mut written = required;
    // SAFETY: buffer has `written` writable UTF-16 elements.
    if unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsFullyQualified,
            buffer.as_mut_ptr(),
            &raw mut written,
        )
    } == 0
    {
        return Err(last_error("GetComputerNameExW(value)"));
    }
    let written = usize::try_from(written)
        .map_err(|_| "physical DNS FQDN result length overflowed usize".to_owned())?;
    if written == 0 || written >= buffer.len() || buffer[written] != 0 {
        return Err("physical DNS FQDN result has an invalid length or terminator".to_owned());
    }
    if buffer[..written].contains(&0) {
        return Err("physical DNS FQDN contains an interior NUL".to_owned());
    }
    canonical_worker(&strict_utf16(&buffer[..written], "physical DNS FQDN")?)
}

fn parse_registry_string(bytes: &[u8], value_type: u32, label: &str) -> Result<String> {
    if value_type != REG_SZ {
        return Err(format!("{label} is not REG_SZ"));
    }
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) || bytes.len() > MAX_REGISTRY_BYTES {
        return Err(format!("{label} has an invalid byte length"));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(format!("{label} has an invalid NUL terminator"));
    }
    let value = strict_utf16(&units[..units.len() - 1], label)?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(format!("{label} is empty or contains a control character"));
    }
    Ok(value)
}

fn registry_string(subkey: &str, name: &str, label: &str) -> Result<String> {
    let subkey = wide_null(subkey);
    let name = wide_null(name);
    let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY | RRF_ZEROONFAILURE;
    for _ in 0..3 {
        let mut value_type = 0u32;
        let mut required = 0u32;
        // SAFETY: strings are NUL-terminated and output pointers are writable.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                &raw mut value_type,
                null_mut(),
                &raw mut required,
            )
        };
        if status != 0 {
            return Err(format!(
                "RegGetValueW({label} size) failed with Win32 error {status}"
            ));
        }
        let length =
            usize::try_from(required).map_err(|_| format!("{label} length overflowed usize"))?;
        if !(2..=MAX_REGISTRY_BYTES).contains(&length) {
            return Err(format!("{label} length is outside the supported range"));
        }
        let mut bytes = vec![0u8; length];
        let mut actual = required;
        // SAFETY: bytes has `actual` writable bytes and strings remain NUL-terminated.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                &raw mut value_type,
                bytes.as_mut_ptr().cast::<c_void>(),
                &raw mut actual,
            )
        };
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != 0 {
            return Err(format!(
                "RegGetValueW({label}) failed with Win32 error {status}"
            ));
        }
        let actual = usize::try_from(actual)
            .map_err(|_| format!("{label} result length overflowed usize"))?;
        if actual > bytes.len() {
            return Err(format!("{label} result exceeds its allocated buffer"));
        }
        bytes.truncate(actual);
        return parse_registry_string(&bytes, value_type, label);
    }
    Err(format!(
        "{label} changed during every bounded registry read"
    ))
}

fn registry_dword(subkey: &str, name: &str, label: &str) -> Result<u32> {
    let subkey = wide_null(subkey);
    let name = wide_null(name);
    let flags = RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY | RRF_ZEROONFAILURE;
    let mut value_type = 0u32;
    let mut value = 0u32;
    let mut size = u32::try_from(size_of::<u32>()).expect("u32 size fits u32");
    // SAFETY: strings are NUL-terminated, value has exactly `size` writable
    // bytes, and all output pointers refer to initialized local storage.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            name.as_ptr(),
            flags,
            &raw mut value_type,
            (&raw mut value).cast::<c_void>(),
            &raw mut size,
        )
    };
    if status != 0 {
        return Err(format!(
            "RegGetValueW({label}) failed with Win32 error {status}"
        ));
    }
    if value_type != REG_DWORD || size != u32::try_from(size_of::<u32>()).unwrap() {
        return Err(format!("{label} is not an exact REG_DWORD"));
    }
    Ok(value)
}

#[repr(C)]
#[derive(Default)]
struct SystemBootEnvironmentInformation {
    boot_identifier_data1: u32,
    boot_identifier_data2: u16,
    boot_identifier_data3: u16,
    boot_identifier_data4: [u8; 8],
    firmware_type: i32,
    alignment_padding: u32,
    boot_flags: u64,
}

const _: () = assert!(size_of::<SystemBootEnvironmentInformation>() == 32);

fn canonical_boot_id(information: &SystemBootEnvironmentInformation) -> Result<String> {
    let all_zero = information.boot_identifier_data1 == 0
        && information.boot_identifier_data2 == 0
        && information.boot_identifier_data3 == 0
        && information.boot_identifier_data4 == [0; 8];
    if all_zero {
        return Err("boot environment identifier is the nil UUID".to_owned());
    }
    let tail = information.boot_identifier_data4;
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        information.boot_identifier_data1,
        information.boot_identifier_data2,
        information.boot_identifier_data3,
        tail[0],
        tail[1],
        tail[2],
        tail[3],
        tail[4],
        tail[5],
        tail[6],
        tail[7]
    ))
}

fn boot_id() -> Result<String> {
    let mut information = SystemBootEnvironmentInformation::default();
    let mut returned = 0u32;
    let size = u32::try_from(size_of::<SystemBootEnvironmentInformation>())
        .map_err(|_| "boot environment structure size overflowed u32".to_owned())?;
    // SAFETY: information points to exactly `size` writable bytes, and
    // returned points to writable u32 storage. The information class and
    // buffer shape are fixed at compile time.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS,
            (&raw mut information).cast::<c_void>(),
            size,
            &raw mut returned,
        )
    };
    if status < 0 {
        return Err(format!(
            "NtQuerySystemInformation(SystemBootEnvironmentInformation) failed with NTSTATUS {status:#010x}"
        ));
    }
    if returned != size {
        return Err(format!(
            "SystemBootEnvironmentInformation returned {returned} bytes instead of {size}"
        ));
    }
    canonical_boot_id(&information)
}

fn canonical_machine_guid(value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err("MachineGuid is not a canonical UUID".to_owned());
    }
    Ok(value)
}

fn machine_id(value: &str) -> Result<String> {
    let guid = canonical_machine_guid(value)?;
    let mut digest = Sha256::new();
    digest.update(MACHINE_ID_DOMAIN);
    digest.update(guid.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn current_module_path() -> Result<Vec<u16>> {
    let mut capacity = 260usize;
    loop {
        if capacity > MAX_MODULE_PATH_U16 {
            return Err("current module path exceeds the supported range".to_owned());
        }
        let mut buffer = vec![0u16; capacity];
        let length = u32::try_from(buffer.len())
            .map_err(|_| "module path capacity overflowed u32".to_owned())?;
        // SAFETY: null module selects the current executable; buffer is writable.
        let written = unsafe { GetModuleFileNameW(null_mut(), buffer.as_mut_ptr(), length) };
        if written == 0 {
            return Err(last_error("GetModuleFileNameW"));
        }
        let written = usize::try_from(written)
            .map_err(|_| "module path result overflowed usize".to_owned())?;
        if written < buffer.len() {
            if buffer[..written].contains(&0) {
                return Err("current module path contains an interior NUL".to_owned());
            }
            buffer.truncate(written);
            return Ok(buffer);
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| "module path capacity overflowed usize".to_owned())?;
    }
}

fn final_path(handle: HANDLE) -> Result<String> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, flags) };
    if required == 0 {
        return Err(last_error("GetFinalPathNameByHandleW(size)"));
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "final runner path length overflowed usize".to_owned())?;
    if capacity > MAX_FINAL_PATH_U16 {
        return Err("final runner path exceeds the supported range".to_owned());
    }
    let mut buffer = vec![0u16; capacity];
    // SAFETY: buffer contains capacity writable UTF-16 elements.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| "final path capacity overflowed u32")?,
            flags,
        )
    };
    let written = usize::try_from(written)
        .map_err(|_| "final runner path result overflowed usize".to_owned())?;
    if written == 0 || written >= buffer.len() || buffer[..written].contains(&0) {
        return Err("final runner path has an invalid result length".to_owned());
    }
    strict_utf16(&buffer[..written], "final runner path")
}

fn pin_current_executable() -> Result<PinnedExecutable> {
    let mut path = current_module_path()?;
    path.push(0);
    // FILE_SHARE_READ intentionally denies write and delete sharing for the
    // lifetime of PinnedExecutable.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(current executable)"));
    }
    let mut pinned = PinnedExecutable {
        handle,
        sha256: String::new(),
        final_path: String::new(),
        size: 0,
    };
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err("current executable handle is not a disk file".to_owned());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(current executable)"));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err("current executable handle refers to a directory".to_owned());
    }
    let mut signed_size = 0i64;
    if unsafe { GetFileSizeEx(handle, &raw mut signed_size) } == 0 {
        return Err(last_error("GetFileSizeEx(current executable)"));
    }
    let size = u64::try_from(signed_size)
        .map_err(|_| "current executable has a negative size".to_owned())?;
    if size == 0 || size > MAX_RUNNER_BYTES {
        return Err("current executable size is outside the supported range".to_owned());
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];
    loop {
        let mut read = 0u32;
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
            return Err(last_error("ReadFile(current executable)"));
        }
        if read == 0 {
            break;
        }
        let read = usize::try_from(read).expect("ReadFile count fits usize");
        total = total
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| "current executable read length overflowed u64".to_owned())?;
        if total > size {
            return Err("current executable grew while hashing".to_owned());
        }
        digest.update(&buffer[..read]);
    }
    if total != size {
        return Err("current executable size changed while hashing".to_owned());
    }
    pinned.size = size;
    pinned.sha256 = format!("{:x}", digest.finalize());
    pinned.final_path = final_path(handle)?;
    Ok(pinned)
}

/// Sample all live facts from fixed operating-system sources.
///
/// # Errors
///
/// Fails closed when the clock, hostname, registry, current executable path,
/// or exact executable bytes cannot be read within their fixed bounds.
pub(crate) fn sample() -> Result<LiveFacts> {
    let runner = pin_current_executable()?;
    Ok(LiveFacts {
        now_unix_seconds: now_unix_seconds()?,
        worker: physical_fqdn()?,
        build_lab_ex: registry_string(CURRENT_VERSION_KEY, "BuildLabEx", "BuildLabEx")?,
        windows_ubr: registry_dword(CURRENT_VERSION_KEY, "UBR", "UBR")?,
        boot_id: boot_id()?,
        worker_machine_id: machine_id(&registry_string(
            CRYPTOGRAPHY_KEY,
            "MachineGuid",
            "MachineGuid",
        )?)?,
        runner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn utf16_bytes(value: &[u16]) -> Vec<u8> {
        value.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    fn filetime(ticks: u64) -> FILETIME {
        let bytes = ticks.to_le_bytes();
        FILETIME {
            dwLowDateTime: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            dwHighDateTime: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    #[test]
    fn filetime_conversion_is_checked_and_truncates_subseconds() {
        let at_epoch = filetime(FILETIME_UNIX_EPOCH);
        assert_eq!(filetime_to_unix_seconds(at_epoch).unwrap(), 0);
        let ticks = FILETIME_UNIX_EPOCH + 42 * FILETIME_TICKS_PER_SECOND + 9_999_999;
        let value = filetime(ticks);
        assert_eq!(filetime_to_unix_seconds(value).unwrap(), 42);
        assert!(filetime_to_unix_seconds(FILETIME::default()).is_err());
    }

    #[test]
    fn worker_is_canonical_and_dns_shaped() {
        assert_eq!(
            canonical_worker("CANARY-01.Example.Test").unwrap(),
            "canary-01.example.test"
        );
        for invalid in [
            "",
            ".host",
            "host.",
            "bad..host",
            "-host",
            "host-",
            "bad_name",
        ] {
            assert!(canonical_worker(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn registry_strings_are_exact_and_strict() {
        let valid = utf16_bytes(&['V' as u16, 'a' as u16, 'l' as u16, 0]);
        assert_eq!(
            parse_registry_string(&valid, REG_SZ, "value").unwrap(),
            "Val"
        );
        assert!(parse_registry_string(&valid, 2, "value").is_err());
        assert!(parse_registry_string(&valid[..valid.len() - 1], REG_SZ, "value").is_err());
        assert!(
            parse_registry_string(
                &utf16_bytes(&[u16::from(b'a'), 0, u16::from(b'b'), 0]),
                REG_SZ,
                "value"
            )
            .is_err()
        );
        assert!(parse_registry_string(&utf16_bytes(&[0xd800, 0]), REG_SZ, "value").is_err());
    }

    #[test]
    fn machine_id_is_canonical_domain_separated_sha256() {
        let upper = "00112233-4455-6677-8899-AABBCCDDEEFF";
        let lower = "00112233-4455-6677-8899-aabbccddeeff";
        assert_eq!(machine_id(upper).unwrap(), machine_id(lower).unwrap());
        assert_eq!(
            machine_id(lower).unwrap(),
            "7605d7cee78c7386fdb6eb5cf8a57d4af9ffd699cb1fc45ef80d131b5a6d3af8"
        );
        assert!(machine_id("not-a-guid").is_err());
    }

    #[test]
    fn sampler_reads_stable_os_facts_and_pins_exact_runner_bytes() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first = sample().unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let live_now = u64::try_from(first.now_unix_seconds).unwrap();
        assert!(live_now + 1 >= before && live_now <= after + 1);
        assert_eq!(first.worker, first.worker.to_ascii_lowercase());
        assert!(!first.build_lab_ex.is_empty());
        assert_eq!(first.boot_id.len(), 36);
        assert_eq!(first.boot_id, first.boot_id.to_ascii_lowercase());
        assert!(
            first.worker_machine_id.len() == 64
                && first
                    .worker_machine_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(first.runner.size() > 0);
        assert_eq!(first.runner.sha256().len(), 64);
        assert!(!first.runner.final_path().is_empty());

        // A second independently opened read handle must observe the same live
        // identity and exact executable bytes while the first pin is held.
        let second = sample().unwrap();
        assert_eq!(second.worker, first.worker);
        assert_eq!(second.build_lab_ex, first.build_lab_ex);
        assert_eq!(second.windows_ubr, first.windows_ubr);
        assert_eq!(second.boot_id, first.boot_id);
        assert_eq!(second.worker_machine_id, first.worker_machine_id);
        assert_eq!(second.runner.sha256(), first.runner.sha256());
        assert_eq!(second.runner.size(), first.runner.size());
        assert_eq!(second.runner.final_path(), first.runner.final_path());
    }

    #[test]
    fn boot_id_is_canonical_and_rejects_nil_uuid() {
        let mut information = SystemBootEnvironmentInformation {
            boot_identifier_data1: 0x0011_2233,
            boot_identifier_data2: 0x4455,
            boot_identifier_data3: 0x6677,
            boot_identifier_data4: [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ..Default::default()
        };
        assert_eq!(
            canonical_boot_id(&information).unwrap(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        information.boot_identifier_data1 = 0;
        information.boot_identifier_data2 = 0;
        information.boot_identifier_data3 = 0;
        information.boot_identifier_data4 = [0; 8];
        assert!(canonical_boot_id(&information).is_err());
    }
}
