//! Fixed, capability-only device-interface observation primitives.
//!
//! This module accepts no target, path, operation, argument, or environment
//! input. It enumerates the one synthetic fixture compiled into the protocol,
//! performs exactly one query-only `CreateFileW`, and retains that handle. It
//! deliberately does not import or call `DeviceIoControl`, a driver-loading
//! API, `ReadFile`, or `WriteFile`.

#![allow(
    dead_code,
    reason = "the reviewed producer primitives are wired by the staged child/broker integration"
)]

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr::{null, null_mut};

use sha2::{Digest as _, Sha256};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, SPDRP_SERVICE,
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceInterfaceDetailW,
    SetupDiGetDeviceRegistryPropertyW,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER,
    ERROR_NO_MORE_ITEMS, ERROR_NO_SUCH_LOGON_SESSION, FILETIME, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, SYSTEMTIME,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TokenLinkedToken,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Registry::REG_SZ;
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetProcessId, GetProcessTimes,
    OpenProcessToken, OpenThreadToken,
};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;
use windows_sys::core::GUID;

use crate::device_open_protocol::{
    DeviceOpenObservation, OBSERVATION_SCHEMA, fixed_target, registry_sha256,
};
use crate::witness::WitnessTokenProfile;

const FIXED_INTERFACE_CLASS: GUID = GUID {
    data1: 0x1234_5678,
    data2: 0x1234,
    data3: 0x1234,
    data4: [0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab],
};
const MAX_INTERFACES: u32 = 256;
const MAX_DETAIL_BYTES: u32 = 64 * 1024;
const MAX_INSTANCE_U16: usize = 1024;
const MAX_SERVICE_U16: usize = 256;
const FILETIME_TICKS_PER_MILLISECOND: u64 = 10_000;
const ALLOWED_STANDARD_USER_PRIVILEGES: &[&str] = &[
    "SeChangeNotifyPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeShutdownPrivilege",
    "SeTimeZonePrivilege",
    "SeUndockPrivilege",
];

type Result<T> = std::result::Result<T, String>;

const OBJECT_BASIC_INFORMATION_CLASS: u32 = 0;
const OBJECT_TYPE_INFORMATION_CLASS: u32 = 2;
const MAX_OBJECT_TYPE_BYTES: usize = 4096;
const FILE_DATA_ACCESS_MASK: u32 = 0x0000_0001 // FILE_READ_DATA
    | 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0000_0020; // FILE_EXECUTE

#[repr(C)]
struct PublicObjectBasicInformation {
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
    reserved: [u32; 10],
}

#[repr(C)]
struct NativeUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: HANDLE,
        object_information_class: u32,
        object_information: *mut c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

fn last_error(context: &str) -> String {
    // SAFETY: GetLastError has no preconditions and is called directly after failure.
    let code = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {code}")
}

/// The query-only source device handle, with checked close and Drop fallback.
pub(crate) struct SourceDeviceHandle(HANDLE);

impl SourceDeviceHandle {
    /// Return the process-local value for the fixed child/broker protocol.
    pub(crate) fn value(&self) -> u64 {
        self.0 as usize as u64
    }

    /// Close the source explicitly and prove that the kernel accepted the
    /// close before the child acknowledges it to the broker.
    pub(crate) fn close(mut self) -> Result<()> {
        if self.0.is_null() || self.0 == INVALID_HANDLE_VALUE {
            return Err("device source handle is already invalid".to_owned());
        }
        // SAFETY: this capability exclusively owns the successful handle.
        if unsafe { CloseHandle(self.0) } == 0 {
            // Leave the value intact so Drop makes one fail-safe retry.
            return Err(last_error("CloseHandle(device source)"));
        }
        self.0 = null_mut();
        Ok(())
    }

    /// Duplicate a source handle owned by `source_process` into this process.
    ///
    /// The caller must have obtained both values from its authenticated child
    /// lifecycle. The resulting capability remains query-only because
    /// `DUPLICATE_SAME_ACCESS` cannot add access rights.
    pub(crate) fn duplicate_from_process(
        source_process: HANDLE,
        source_handle_value: u64,
    ) -> Result<Self> {
        let source_value = usize::try_from(source_handle_value)
            .map_err(|_| "device source handle value does not fit this process".to_owned())?
            as HANDLE;
        if source_process.is_null()
            || source_value.is_null()
            || source_value == INVALID_HANDLE_VALUE
        {
            return Err("device source handle identity is invalid".to_owned());
        }
        let mut duplicate = null_mut();
        // SAFETY: authenticated lifecycle code supplies a live source process and
        // handle value. Windows validates both and creates an independently owned
        // same-access handle in the current process.
        if unsafe {
            DuplicateHandle(
                source_process,
                source_value,
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last_error("DuplicateHandle(device source)"));
        }
        if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
            if !duplicate.is_null() && duplicate != INVALID_HANDLE_VALUE {
                // SAFETY: defensive close of an unexpected successful result.
                unsafe { CloseHandle(duplicate) };
            }
            return Err("DuplicateHandle returned an invalid device handle".to_owned());
        }
        let owned = Self(duplicate);
        validate_file_object_and_access(owned.0)?;
        Ok(owned)
    }
}

fn validate_file_object_and_access(handle: HANDLE) -> Result<()> {
    let basic_size = u32::try_from(size_of::<PublicObjectBasicInformation>())
        .map_err(|_| "object basic information size exceeds u32".to_owned())?;
    let mut basic = PublicObjectBasicInformation {
        attributes: 0,
        granted_access: 0,
        handle_count: 0,
        pointer_count: 0,
        reserved: [0; 10],
    };
    let mut returned = 0_u32;
    // SAFETY: basic is writable for the exact advertised structure size.
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_BASIC_INFORMATION_CLASS,
            (&raw mut basic).cast(),
            basic_size,
            &raw mut returned,
        )
    };
    if status < 0 || returned < basic_size {
        return Err(format!(
            "NtQueryObject(ObjectBasicInformation) failed with NTSTATUS {status:#x}"
        ));
    }
    if basic.granted_access & FILE_DATA_ACCESS_MASK != 0 {
        return Err("duplicated device handle has data read/write/execute access".to_owned());
    }

    let word = size_of::<usize>();
    let mut storage = vec![0_usize; MAX_OBJECT_TYPE_BYTES.div_ceil(word)];
    returned = 0;
    // SAFETY: storage is aligned, writable, and bounded; Windows returns a
    // self-contained OBJECT_TYPE_INFORMATION value in this buffer.
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_TYPE_INFORMATION_CLASS,
            storage.as_mut_ptr().cast(),
            u32::try_from(MAX_OBJECT_TYPE_BYTES)
                .map_err(|_| "object type buffer size exceeds u32".to_owned())?,
            &raw mut returned,
        )
    };
    if status < 0
        || usize::try_from(returned)
            .ok()
            .is_none_or(|length| length > MAX_OBJECT_TYPE_BYTES)
    {
        return Err(format!(
            "NtQueryObject(ObjectTypeInformation) failed with NTSTATUS {status:#x}"
        ));
    }
    let header = storage.as_ptr().cast::<NativeUnicodeString>();
    // SAFETY: successful NtQueryObject initialized the leading Unicode string.
    let name = unsafe { &*header };
    let length = usize::from(name.length);
    let base = storage.as_ptr().cast::<u8>() as usize;
    let end = base + MAX_OBJECT_TYPE_BYTES;
    let start = name.buffer as usize;
    if length == 0
        || !length.is_multiple_of(2)
        || usize::from(name.maximum_length) < length
        || start < base
        || start.checked_add(length).is_none_or(|value| value > end)
    {
        return Err("NtQueryObject returned an invalid object type name".to_owned());
    }
    // SAFETY: the validated pointer range is within the retained aligned buffer.
    let units = unsafe { std::slice::from_raw_parts(name.buffer, length / 2) };
    let object_type =
        String::from_utf16(units).map_err(|_| "object type name is not UTF-16".to_owned())?;
    if object_type != "File" {
        return Err(format!(
            "duplicated device handle has unexpected object type {object_type:?}"
        ));
    }
    Ok(())
}

impl Drop for SourceDeviceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this capability exclusively owns the successful handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Observation plus the still-live source capability that proves the open.
pub(crate) struct OpenedDeviceObservation {
    pub(crate) observation: DeviceOpenObservation,
    pub(crate) source: SourceDeviceHandle,
}

struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE as HDEVINFO {
            // SAFETY: this type exclusively owns the SetupAPI device-info set.
            unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }
}

struct EnumeratedInterface {
    path: Vec<u16>,
    path_sha256: String,
    interface_count: u32,
    selected_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryContext {
    profile: WitnessTokenProfile,
    token_id: u64,
    modified_id: u64,
    linked_token_present: bool,
}

fn filetime_u64(value: FILETIME) -> u64 {
    u64::from(value.dwLowDateTime) | (u64::from(value.dwHighDateTime) << 32)
}

fn current_filetime() -> FILETIME {
    let mut value = FILETIME::default();
    // SAFETY: value points to writable FILETIME storage.
    unsafe { GetSystemTimePreciseAsFileTime(&raw mut value) };
    value
}

fn format_filetime(value: FILETIME) -> Result<String> {
    let mut system = SYSTEMTIME::default();
    // SAFETY: both pointers reference complete initialized/writable structures.
    if unsafe { FileTimeToSystemTime(&raw const value, &raw mut system) } == 0 {
        return Err(last_error("FileTimeToSystemTime"));
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        system.wYear,
        system.wMonth,
        system.wDay,
        system.wHour,
        system.wMinute,
        system.wSecond,
        system.wMilliseconds
    ))
}

fn process_creation_filetime(process: HANDLE) -> Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the current-process pseudo handle is valid and all outputs are writable.
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(last_error("GetProcessTimes"));
    }
    let value = filetime_u64(creation);
    if value == 0 {
        return Err("GetProcessTimes returned a zero creation time".to_owned());
    }
    Ok(value)
}

fn require_no_thread_token() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: token points to writable handle storage and the pseudo handle is valid.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut token) } != 0 {
        if !token.is_null() {
            // SAFETY: successful OpenThreadToken created this handle.
            unsafe { CloseHandle(token) };
        }
        return Err("device-open worker has a thread token or active impersonation".to_owned());
    }
    // SAFETY: read immediately after OpenThreadToken failed.
    if unsafe { GetLastError() } != windows_sys::Win32::Foundation::ERROR_NO_TOKEN {
        return Err(last_error("OpenThreadToken(device-open context)"));
    }
    Ok(())
}

fn linked_token_present(token: HANDLE) -> Result<bool> {
    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut returned = 0_u32;
    let size = u32::try_from(size_of::<TOKEN_LINKED_TOKEN>())
        .map_err(|_| "TOKEN_LINKED_TOKEN size exceeds u32".to_owned())?;
    // SAFETY: linked is writable for the exact advertised structure size.
    if unsafe {
        GetTokenInformation(
            token,
            TokenLinkedToken,
            (&raw mut linked).cast::<c_void>(),
            size,
            &raw mut returned,
        )
    } != 0
    {
        if returned != size || linked.LinkedToken.is_null() {
            if !linked.LinkedToken.is_null() {
                // SAFETY: successful TokenLinkedToken created this owned handle.
                unsafe { CloseHandle(linked.LinkedToken) };
            }
            return Err("TokenLinkedToken returned an invalid result".to_owned());
        }
        // SAFETY: successful TokenLinkedToken created this owned handle.
        unsafe { CloseHandle(linked.LinkedToken) };
        return Ok(true);
    }
    // SAFETY: read immediately after GetTokenInformation failed.
    if unsafe { GetLastError() } == ERROR_NO_SUCH_LOGON_SESSION {
        Ok(false)
    } else {
        Err(last_error("GetTokenInformation(TokenLinkedToken)"))
    }
}

fn sample_primary_context() -> Result<PrimaryContext> {
    require_no_thread_token()?;
    let mut token = null_mut();
    // SAFETY: the current-process pseudo handle is valid and token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_error("OpenProcessToken(device-open context)"));
    }
    let token = super::TokenHandle(token);
    let (token_id_before, modified_id_before, _) = super::statistics(token.0)?;
    let profile = super::witness_token_profile(token.0)?;
    let linked_token_present = linked_token_present(token.0)?;
    let (token_id_after, modified_id_after, _) = super::statistics(token.0)?;
    if token_id_before != token_id_after || modified_id_before != modified_id_after {
        return Err("primary token changed while device-open facts were sampled".to_owned());
    }
    require_no_thread_token()?;
    Ok(PrimaryContext {
        profile,
        token_id: token_id_before,
        modified_id: modified_id_before,
        linked_token_present,
    })
}

fn sample_process_primary_context(process: HANDLE) -> Result<PrimaryContext> {
    if process.is_null() || process == INVALID_HANDLE_VALUE {
        return Err("device-open child process handle is invalid".to_owned());
    }
    let mut token = null_mut();
    // SAFETY: the retained exact child process handle is live and token is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_error("OpenProcessToken(device-open child)"));
    }
    let token = super::TokenHandle(token);
    let (token_id_before, modified_id_before, _) = super::statistics(token.0)?;
    let profile = super::witness_token_profile(token.0)?;
    let linked_token_present = linked_token_present(token.0)?;
    let (token_id_after, modified_id_after, _) = super::statistics(token.0)?;
    if token_id_before != token_id_after || modified_id_before != modified_id_after {
        return Err("child primary token changed while broker revalidated it".to_owned());
    }
    Ok(PrimaryContext {
        profile,
        token_id: token_id_before,
        modified_id: modified_id_before,
        linked_token_present,
    })
}

/// Revalidate the retained exact process object and its primary-token object.
pub(crate) fn revalidate_child_process(
    process: HANDLE,
    observation: &DeviceOpenObservation,
    expected_profile: &WitnessTokenProfile,
) -> Result<()> {
    // SAFETY: the caller retains the exact PROCESS_INFORMATION handle.
    if unsafe { GetProcessId(process) } != observation.process_id
        || process_creation_filetime(process)? != observation.process_creation_filetime
    {
        return Err("device-open child process identity changed".to_owned());
    }
    let current = sample_process_primary_context(process)?;
    validate_standard_user(&current)?;
    if &current.profile != expected_profile
        || current.token_id != observation.primary_token_id
        || current.modified_id != observation.primary_token_modified_id
    {
        return Err("device-open child primary-token object changed".to_owned());
    }
    Ok(())
}

fn validate_standard_user(context: &PrimaryContext) -> Result<()> {
    let profile = &context.profile;
    let enabled = profile
        .privileges
        .iter()
        .filter(|privilege| privilege.attributes & super::SE_PRIVILEGE_ENABLED != 0)
        .map(|privilege| privilege.name.as_str())
        .collect::<Vec<_>>();
    if profile.token_type != "primary"
        || profile.integrity_rid != 0x2000
        || profile.elevation_type != "default"
        || profile.elevated
        || profile.admin_group != "absent"
        || profile.app_container
        || profile.token_restricted
        || profile.restricted_sid_count != 0
        || context.linked_token_present
        || profile.privileges.iter().any(|privilege| {
            privilege.name == "SeDebugPrivilege"
                || !ALLOWED_STANDARD_USER_PRIVILEGES.contains(&privilege.name.as_str())
        })
        || !profile.lpac_supported
        || profile.less_privileged_app_container
        || enabled.is_empty()
    {
        return Err("device-open process is not a natural standard-user context".to_owned());
    }
    Ok(())
}

fn path_sha256(path: &[u16]) -> String {
    let mut digest = Sha256::new();
    for unit in path {
        digest.update(unit.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn bounded_utf16(buffer: &[u16], returned: u32, label: &str) -> Result<String> {
    let returned = usize::try_from(returned).map_err(|_| format!("{label} length overflow"))?;
    if returned == 0 || returned > buffer.len() || buffer[returned - 1] != 0 {
        return Err(format!("{label} returned an invalid terminated length"));
    }
    let text = &buffer[..returned - 1];
    if text.contains(&0) {
        return Err(format!("{label} contains an embedded NUL"));
    }
    String::from_utf16(text).map_err(|_| format!("{label} is not valid UTF-16"))
}

fn device_instance_id(set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Result<String> {
    let mut buffer = [0_u16; MAX_INSTANCE_U16];
    let mut returned = 0_u32;
    // SAFETY: set/info came from SetupAPI and the bounded buffer is writable.
    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            set,
            info,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len())
                .map_err(|_| "instance buffer size exceeds u32".to_owned())?,
            &raw mut returned,
        )
    } == 0
    {
        return Err(last_error("SetupDiGetDeviceInstanceIdW"));
    }
    bounded_utf16(&buffer, returned, "device instance ID")
}

fn device_service(set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Result<String> {
    let mut buffer = [0_u16; MAX_SERVICE_U16];
    let mut data_type = 0_u32;
    let mut returned_bytes = 0_u32;
    // SAFETY: set/info came from SetupAPI and the byte-sized bounded buffer is writable.
    if unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            info,
            SPDRP_SERVICE,
            &raw mut data_type,
            buffer.as_mut_ptr().cast::<u8>(),
            u32::try_from(size_of_val(&buffer))
                .map_err(|_| "service buffer size exceeds u32".to_owned())?,
            &raw mut returned_bytes,
        )
    } == 0
    {
        return Err(last_error(
            "SetupDiGetDeviceRegistryPropertyW(SPDRP_SERVICE)",
        ));
    }
    if data_type != REG_SZ || !returned_bytes.is_multiple_of(2) {
        return Err("SPDRP_SERVICE is not a bounded REG_SZ".to_owned());
    }
    bounded_utf16(&buffer, returned_bytes / 2, "device service name")
}

fn interface_detail(
    set: HDEVINFO,
    interface: &SP_DEVICE_INTERFACE_DATA,
) -> Result<(Vec<u16>, SP_DEVINFO_DATA)> {
    let mut required = 0_u32;
    // SAFETY: the first call intentionally asks SetupAPI for the exact byte count.
    let first = unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            set,
            interface,
            null_mut(),
            0,
            &raw mut required,
            null_mut(),
        )
    };
    // SAFETY: read immediately after the sizing call.
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error("SetupDiGetDeviceInterfaceDetailW sizing"));
    }
    let detail_header_size = u32::try_from(size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>())
        .map_err(|_| "device interface detail header size exceeds u32".to_owned())?;
    if required < detail_header_size || required > MAX_DETAIL_BYTES {
        return Err("device interface detail size is outside its fixed bound".to_owned());
    }
    let word = size_of::<usize>();
    let required_usize = usize::try_from(required)
        .map_err(|_| "device interface detail size exceeds usize".to_owned())?;
    let mut storage = vec![0_usize; required_usize.div_ceil(word)];
    let detail = storage
        .as_mut_ptr()
        .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
    // SAFETY: detail is aligned and points into storage large enough for required bytes.
    unsafe {
        (*detail).cbSize = detail_header_size;
    }
    let mut info = SP_DEVINFO_DATA {
        cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>())
            .map_err(|_| "SP_DEVINFO_DATA size exceeds u32".to_owned())?,
        ..SP_DEVINFO_DATA::default()
    };
    // SAFETY: detail storage is writable for required bytes and info is initialized.
    if unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            set,
            interface,
            detail,
            required,
            &raw mut required,
            &raw mut info,
        )
    } == 0
    {
        return Err(last_error("SetupDiGetDeviceInterfaceDetailW"));
    }
    let path_offset = offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
    let path_bytes = usize::try_from(required)
        .map_err(|_| "device interface detail size exceeds usize".to_owned())?
        .checked_sub(path_offset)
        .ok_or_else(|| "device interface detail omitted its path".to_owned())?;
    if path_bytes < 2 || !path_bytes.is_multiple_of(2) {
        return Err("device interface path has an invalid UTF-16 byte length".to_owned());
    }
    // SAFETY: path_offset/path_bytes are within the initialized detail result.
    let path_octets =
        unsafe { std::slice::from_raw_parts(detail.cast::<u8>().add(path_offset), path_bytes) };
    let units = path_octets
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let Some(nul) = units.iter().position(|unit| *unit == 0) else {
        return Err("device interface path lacks a terminator".to_owned());
    };
    if nul == 0 || units[..nul].contains(&0) {
        return Err("device interface path is empty or malformed".to_owned());
    }
    let mut path = units[..=nul].to_vec();
    path.shrink_to_fit();
    Ok((path, info))
}

fn enumerate_fixed_target() -> Result<EnumeratedInterface> {
    let target = fixed_target();
    let class_guid = FIXED_INTERFACE_CLASS;
    debug_assert_eq!(
        target.enumeration_flags,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    );
    // SAFETY: the compiled GUID is valid; all optional filters/parent handles are null.
    let set = unsafe {
        SetupDiGetClassDevsW(
            &raw const class_guid,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == INVALID_HANDLE_VALUE as HDEVINFO {
        return Err(last_error("SetupDiGetClassDevsW"));
    }
    let set = DeviceInfoSet(set);
    let mut selected: Option<(u32, Vec<u16>, String)> = None;
    let mut count = 0_u32;
    for index in 0..=MAX_INTERFACES {
        let mut interface = SP_DEVICE_INTERFACE_DATA {
            cbSize: u32::try_from(size_of::<SP_DEVICE_INTERFACE_DATA>())
                .map_err(|_| "SP_DEVICE_INTERFACE_DATA size exceeds u32".to_owned())?,
            ..SP_DEVICE_INTERFACE_DATA::default()
        };
        // SAFETY: the info set and GUID are live and interface is writable.
        if unsafe {
            SetupDiEnumDeviceInterfaces(
                set.0,
                null(),
                &raw const class_guid,
                index,
                &raw mut interface,
            )
        } == 0
        {
            // SAFETY: read immediately after SetupDiEnumDeviceInterfaces failed.
            if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(last_error("SetupDiEnumDeviceInterfaces"));
        }
        if index == MAX_INTERFACES {
            return Err("device interface enumeration exceeded 256 entries".to_owned());
        }
        count = index + 1;
        let (path, info) = interface_detail(set.0, &interface)?;
        let instance = device_instance_id(set.0, &info)?;
        let service = device_service(set.0, &info)?;
        if instance.eq_ignore_ascii_case(target.interface_instance_id)
            && service.eq_ignore_ascii_case(target.driver_service_name)
        {
            if selected.is_some() {
                return Err("fixed device target matched more than one interface".to_owned());
            }
            let digest = path_sha256(&path[..path.len() - 1]);
            selected = Some((index, path, digest));
        }
    }
    if count == 0 {
        return Err("fixed interface class has no present interfaces".to_owned());
    }
    let (selected_index, path, path_sha256) =
        selected.ok_or_else(|| "fixed device instance and service were not present".to_owned())?;
    Ok(EnumeratedInterface {
        path,
        path_sha256,
        interface_count: count,
        selected_index,
    })
}

/// Independently re-enumerate the fixed class/instance/service and bind its
/// opaque path to the child's observation digest. This performs no device open.
pub(crate) fn reenumerate_fixed_target(observation: &DeviceOpenObservation) -> Result<()> {
    let current = enumerate_fixed_target()?;
    if current.path_sha256 != observation.interface_path_sha256
        || current.interface_count != observation.interface_count
        || current.selected_index != observation.selected_interface_index
    {
        return Err("broker re-enumerated different fixed interface facts".to_owned());
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the one fixed open and its before/after evidence remain linear for auditability"
)]
fn open_with_expected_profile(
    expected_profile: Option<&WitnessTokenProfile>,
) -> Result<OpenedDeviceObservation> {
    let started = current_filetime();
    // SAFETY: GetCurrentProcess returns the current-process pseudo handle.
    let process_creation_filetime = process_creation_filetime(unsafe { GetCurrentProcess() })?;
    let before = sample_primary_context()?;
    validate_standard_user(&before)?;
    if expected_profile.is_some_and(|expected| expected != &before.profile) {
        return Err("supplied primary token facts differ from fresh complete facts".to_owned());
    }
    let selected = enumerate_fixed_target()?;
    let target = fixed_target();
    // Exactly one call. The arguments are compile-time constants matching the
    // protocol registry and grant no read, write, or IOCTL access.
    // SAFETY: selected.path is a live NUL-terminated SetupAPI path.
    let handle = unsafe {
        CreateFileW(
            selected.path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(fixed device, query-only)"));
    }
    let source = SourceDeviceHandle(handle);
    let after = sample_primary_context()?;
    if before != after {
        return Err("primary token context changed across the device open".to_owned());
    }
    let completed = current_filetime();
    let duration_ticks = filetime_u64(completed)
        .checked_sub(filetime_u64(started))
        .ok_or_else(|| "device-open observation clock moved backwards".to_owned())?;
    let duration_ms = u32::try_from(duration_ticks / FILETIME_TICKS_PER_MILLISECOND)
        .map_err(|_| "device-open observation duration overflow".to_owned())?;
    let enabled_privileges = before
        .profile
        .privileges
        .iter()
        .filter(|privilege| privilege.attributes & super::SE_PRIVILEGE_ENABLED != 0)
        .map(|privilege| privilege.name.clone())
        .collect::<Vec<_>>();
    let observation = DeviceOpenObservation {
        schema_version: OBSERVATION_SCHEMA.to_owned(),
        target_id: target.target_id.to_owned(),
        collector_registry_sha256: registry_sha256()?,
        driver_id: target.driver_id.to_owned(),
        driver_service_name: target.driver_service_name.to_owned(),
        interface_class_guid: target.interface_class_guid.to_owned(),
        interface_instance_id: target.interface_instance_id.to_owned(),
        interface_path_sha256: selected.path_sha256,
        enumeration_api: target.enumeration_api.to_owned(),
        enumeration_flags: target.enumeration_flags,
        interface_count: selected.interface_count,
        selected_interface_index: selected.selected_index,
        create_file_api: target.create_file_api.to_owned(),
        desired_access: target.desired_access,
        share_mode: target.share_mode,
        security_attributes_null: target.security_attributes_null,
        creation_disposition: target.creation_disposition,
        flags_and_attributes: target.flags_and_attributes,
        template_file_null: target.template_file_null,
        process_id: unsafe { GetCurrentProcessId() },
        process_creation_filetime,
        primary_token_id: before.token_id,
        primary_token_modified_id: before.modified_id,
        source_handle_value: source.value(),
        token_type: "TokenPrimary".to_owned(),
        thread_token_present: false,
        impersonation_active: false,
        elevation_type: "TokenElevationTypeDefault".to_owned(),
        elevated: before.profile.elevated,
        integrity_rid: before.profile.integrity_rid,
        admin_group_present: before.profile.admin_group != "absent",
        linked_token_present: before.linked_token_present,
        token_restricted: before.profile.token_restricted,
        restricted_sid_count: before.profile.restricted_sid_count,
        enabled_privileges,
        app_container: before.profile.app_container,
        debug_privilege_present: before
            .profile
            .privileges
            .iter()
            .any(|privilege| privilege.name == "SeDebugPrivilege"),
        user_sid: before.profile.user_sid,
        authentication_id: before.profile.authentication_id,
        session_id: before.profile.session_id,
        observation_started_at: format_filetime(started)?,
        observation_completed_at: format_filetime(completed)?,
        observation_duration_ms: duration_ms,
        create_file_succeeded: true,
        handle_held_during_observation: true,
        device_io_control_call_count: 0,
        driver_load_call_count: 0,
        device_handle_read_call_count: 0,
        device_handle_write_call_count: 0,
    };
    observation.validate()?;
    Ok(OpenedDeviceObservation {
        observation,
        source,
    })
}

/// Sample complete current primary-token facts and perform the one fixed open.
pub(crate) fn open_fixed_target() -> Result<OpenedDeviceObservation> {
    open_with_expected_profile(None)
}

/// Require supplied complete primary-token facts to match a fresh stable sample
/// before performing the one fixed open.
pub(crate) fn open_fixed_target_with_profile(
    profile: &WitnessTokenProfile,
) -> Result<OpenedDeviceObservation> {
    open_with_expected_profile(Some(profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_guid_and_query_only_constants_match_registry() {
        let target = fixed_target();
        assert_eq!(
            target.interface_class_guid,
            "{12345678-1234-1234-1234-1234567890ab}"
        );
        assert_eq!(
            target.enumeration_flags,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );
        assert_eq!(target.desired_access, 0);
        assert_eq!(target.share_mode, FILE_SHARE_READ | FILE_SHARE_WRITE);
        assert_eq!(target.creation_disposition, OPEN_EXISTING);
        assert_eq!(target.flags_and_attributes, FILE_ATTRIBUTE_NORMAL);
    }

    #[test]
    fn opaque_path_digest_is_utf16le_without_terminator() {
        let path = "\\\\?\\root#fixture".encode_utf16().collect::<Vec<_>>();
        let bytes = path
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(path_sha256(&path), format!("{:x}", Sha256::digest(bytes)));
    }

    #[test]
    fn fixed_opener_source_has_no_device_activity_or_driver_load_surface() {
        let source = include_str!("device_open.rs");
        for forbidden in [
            concat!("DeviceIo", "Control("),
            concat!("Read", "File("),
            concat!("Write", "File("),
            concat!("NtLoad", "Driver("),
            concat!("Start", "ServiceW("),
        ] {
            assert!(
                !source.contains(forbidden),
                "fixed opener contains forbidden API surface {forbidden}"
            );
        }
        assert_eq!(
            source.matches(concat!("        Create", "FileW(")).count(),
            1
        );
    }
}
