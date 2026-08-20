use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NO_TOKEN, GetLastError,
    HANDLE, LUID, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted, IsValidSid,
    LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    SE_PRIVILEGE_ENABLED, SECURITY_IMPERSONATION_LEVEL, SID_AND_ATTRIBUTES, SecurityImpersonation,
    SetFileSecurityW, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER,
    TokenElevation, TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
    TokenElevationTypeLimited, TokenGroups, TokenImpersonation, TokenImpersonationLevel,
    TokenIntegrityLevel, TokenIsAppContainer, TokenIsLessPrivilegedAppContainer, TokenPrimary,
    TokenPrivileges, TokenRestrictedSids, TokenSessionId, TokenStatistics, TokenType, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, OpenProcessToken,
    OpenThreadToken,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

use crate::{
    OPERATION_ID, SCHEMA_VERSION, SnapshotPairFixture, SnapshotPhase, TokenSnapshot,
    derive_token_id, operation_sha256, validate_run_nonce,
};

pub(crate) mod device_open;
pub(crate) mod driver_file;
pub(crate) mod live_facts;
pub mod pipe;
pub(crate) mod protected_store;
pub mod service;
#[cfg(feature = "ci-system-test")]
pub mod store_e2e_service;

/// Run the fixed, non-operation child handshake against a validated local pipe.
///
/// # Errors
///
/// Fails closed when the pipe name, connection, hello, or shutdown byte differs
/// from the trusted-child protocol.
pub fn run_trusted_witness_child(pipe_name: &str) -> Result<()> {
    crate::witness::child::run_client(pipe_name)
}

/// Enter the feature-gated trusted-child `LocalSystem` system-test dispatcher.
///
/// # Errors
///
/// Fails when the process is not launched by its fixed SCM service or the
/// bounded, non-operation system test cannot complete.
#[cfg(feature = "ci-system-test")]
pub fn run_trusted_child_e2e_dispatcher() -> Result<()> {
    crate::witness::ci::run_dispatcher()
}

/// Run the feature-gated Session-0 bootstrap donor protocol.
///
/// # Errors
///
/// Fails closed on an unexpected argument, control phase, identity, or pipe.
#[cfg(feature = "ci-system-test")]
pub fn run_trusted_child_e2e_donor() -> Result<()> {
    crate::witness::ci::run_donor()
}

const MAX_TOKEN_INFORMATION: u32 = 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const SECURITY_MAX_SID_SIZE: usize = 68;
const NONCE_LEDGER_DOMAIN: &[u8] = b"0verse-windows-run-nonce-ledger-v1\0";

type Result<T> = std::result::Result<T, String>;

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this type exclusively owns the successful token handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    len: usize,
}

impl AlignedBuffer {
    fn new(len: usize) -> Self {
        let word_size = size_of::<usize>();
        Self {
            words: vec![0; len.div_ceil(word_size)],
            len,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn len(&self) -> usize {
        self.len
    }
}

fn win32_error(context: &str) -> String {
    // SAFETY: GetLastError takes no arguments and has no preconditions.
    let code = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {code}")
}

fn effective_token() -> Result<(TokenHandle, &'static str)> {
    let mut handle = null_mut();
    // SAFETY: handle points to writable storage; the pseudo thread handle is valid.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut handle) } != 0 {
        return Ok((TokenHandle(handle), "thread"));
    }
    // SAFETY: called immediately after the failed OpenThreadToken call.
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(win32_error("OpenThreadToken"));
    }
    // SAFETY: handle points to writable storage; the pseudo process handle is valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) } == 0 {
        return Err(win32_error("OpenProcessToken after ERROR_NO_TOKEN"));
    }
    Ok((TokenHandle(handle), "process-fallback-no-thread-token"))
}

/// Require an unimpersonated `LocalSystem` process token for protected custody.
///
/// # Errors
///
/// Fails when a thread token exists, the process token is not primary, or its
/// user SID is not exactly the well-known `LocalSystem` SID.
pub(crate) fn require_non_impersonating_local_system() -> Result<()> {
    let mut thread_token = null_mut();
    // SAFETY: output storage and the current-thread pseudo handle are valid.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut thread_token) } != 0 {
        drop(TokenHandle(thread_token));
        return Err("protected custody refuses a thread token".to_owned());
    }
    // SAFETY: called immediately after OpenThreadToken failed.
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(win32_error("OpenThreadToken(protected custody)"));
    }

    let mut process_token = null_mut();
    // SAFETY: output storage and the current-process pseudo handle are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut process_token) } == 0 {
        return Err(win32_error("OpenProcessToken(protected custody)"));
    }
    let process_token = TokenHandle(process_token);
    let token_type: TOKEN_TYPE = fixed_information(process_token.0, TokenType)?;
    if token_type != TokenPrimary {
        return Err("protected custody process token is not primary".to_owned());
    }
    let user = token_information(process_token.0, TokenUser)?;
    // SAFETY: token_information returned a suitably aligned TOKEN_USER buffer.
    let actual = unsafe { &*user.words.as_ptr().cast::<TOKEN_USER>() }
        .User
        .Sid;
    if actual.is_null() {
        return Err("protected custody process token has no user SID".to_owned());
    }
    let mut system_sid = [0_usize; SECURITY_MAX_SID_SIZE.div_ceil(size_of::<usize>())];
    let mut system_sid_size = u32::try_from(SECURITY_MAX_SID_SIZE)
        .map_err(|_| "LocalSystem SID buffer size does not fit Win32".to_owned())?;
    // SAFETY: the aligned output is writable for SECURITY_MAX_SID_SIZE bytes.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            system_sid.as_mut_ptr().cast(),
            &raw mut system_sid_size,
        )
    } == 0
    {
        return Err(win32_error("CreateWellKnownSid(LocalSystem custody)"));
    }
    // SAFETY: both pointers identify live, validated SID buffers.
    if unsafe { EqualSid(actual, system_sid.as_mut_ptr().cast()) } == 0 {
        return Err("protected custody process token is not LocalSystem".to_owned());
    }
    Ok(())
}

pub(crate) fn current_effective_witness_profile() -> Result<crate::witness::WitnessTokenProfile> {
    let (token, _) = effective_token()?;
    witness_token_profile(token.0)
}

fn token_information(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<AlignedBuffer> {
    let mut required = 0_u32;
    // SAFETY: the first call intentionally supplies no output buffer to obtain its size.
    let first = unsafe { GetTokenInformation(handle, class, null_mut(), 0, &raw mut required) };
    if first != 0 || required == 0 {
        return Err(format!(
            "GetTokenInformation({class}) returned an invalid sizing result"
        ));
    }
    // SAFETY: called immediately after the sizing call.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(win32_error(&format!("GetTokenInformation({class}) sizing")));
    }
    if required > MAX_TOKEN_INFORMATION {
        return Err(format!(
            "GetTokenInformation({class}) requested an oversized buffer"
        ));
    }
    let mut buffer = AlignedBuffer::new(required as usize);
    let mut returned = 0_u32;
    // SAFETY: buffer has the requested writable size and remains alive for the call.
    if unsafe {
        GetTokenInformation(
            handle,
            class,
            buffer.as_mut_ptr(),
            required,
            &raw mut returned,
        )
    } == 0
    {
        return Err(win32_error(&format!("GetTokenInformation({class})")));
    }
    if returned == 0 || returned > required {
        return Err(format!(
            "GetTokenInformation({class}) returned an invalid byte count"
        ));
    }
    buffer.len = returned as usize;
    Ok(buffer)
}

fn read_value<T: Copy>(buffer: &AlignedBuffer, context: &str) -> Result<T> {
    if buffer.len() < size_of::<T>() {
        return Err(format!("{context} token information was truncated"));
    }
    // SAFETY: the length check covers T; read_unaligned avoids alignment assumptions.
    Ok(unsafe { buffer.as_ptr().cast::<T>().read_unaligned() })
}

fn fixed_information<T: Copy>(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<T> {
    let expected = u32::try_from(size_of::<T>())
        .map_err(|_| format!("GetTokenInformation({class}) fixed size overflow"))?;
    let mut value = MaybeUninit::<T>::uninit();
    let mut returned = 0_u32;
    // SAFETY: value is writable for expected bytes and is initialized only on success.
    if unsafe {
        GetTokenInformation(
            handle,
            class,
            value.as_mut_ptr().cast(),
            expected,
            &raw mut returned,
        )
    } == 0
    {
        return Err(win32_error(&format!("GetTokenInformation({class})")));
    }
    if returned != expected {
        return Err(format!(
            "GetTokenInformation({class}) returned {returned} bytes, expected {expected}"
        ));
    }
    // SAFETY: the successful API call reported that it initialized the complete object.
    Ok(unsafe { value.assume_init() })
}

fn luid_u64(luid: LUID) -> u64 {
    (u64::from(luid.HighPart.cast_unsigned()) << 32) | u64::from(luid.LowPart)
}

fn statistics(handle: HANDLE) -> Result<(u64, u64, String)> {
    let value: TOKEN_STATISTICS = fixed_information(handle, TokenStatistics)?;
    Ok((
        luid_u64(value.TokenId),
        luid_u64(value.ModifiedId),
        crate::witness::authentication_id_from_luid_parts(
            value.AuthenticationId.LowPart,
            value.AuthenticationId.HighPart,
        ),
    ))
}

fn sid_string(sid: PSID) -> Result<String> {
    // SAFETY: caller passes a SID pointer returned by the token API.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err("token API returned an invalid SID".to_owned());
    }
    let mut text = null_mut();
    // SAFETY: text points to writable pointer storage; Windows allocates the result.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(win32_error("ConvertSidToStringSidW"));
    }
    let result = (|| {
        let mut length = 0_usize;
        // SAFETY: ConvertSidToStringSidW returns a NUL-terminated allocation.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
            if length > 256 {
                return Err("SID string exceeded its bound".to_owned());
            }
        }
        // SAFETY: the loop established the initialized UTF-16 slice bounds.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| "SID string was not valid UTF-16".to_owned())
    })();
    // SAFETY: this is the allocation returned by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast()) };
    result
}

fn token_user_sid(handle: HANDLE) -> Result<String> {
    let buffer = token_information(handle, TokenUser)?;
    let user: TOKEN_USER = read_value(&buffer, "TokenUser")?;
    sid_string(user.User.Sid)
}

fn integrity_rid(handle: HANDLE) -> Result<u32> {
    let buffer = token_information(handle, TokenIntegrityLevel)?;
    let label: TOKEN_MANDATORY_LABEL = read_value(&buffer, "TokenIntegrityLevel")?;
    let sid = label.Label.Sid;
    // SAFETY: sid originates from TokenIntegrityLevel and is checked before traversal.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err("TokenIntegrityLevel returned an invalid SID".to_owned());
    }
    // SAFETY: valid SID provides a valid sub-authority-count byte.
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return Err("integrity SID has no sub-authority count".to_owned());
    }
    // SAFETY: pointer is valid for a valid SID.
    let count = u32::from(unsafe { *count_ptr });
    if count == 0 {
        return Err("integrity SID has no RID".to_owned());
    }
    // SAFETY: count - 1 is within the valid SID sub-authority array.
    let rid = unsafe { GetSidSubAuthority(sid, count - 1) };
    if rid.is_null() {
        return Err("integrity SID RID pointer was null".to_owned());
    }
    // SAFETY: pointer is valid for the selected sub-authority.
    Ok(unsafe { *rid })
}

fn elevation_type(handle: HANDLE) -> Result<&'static str> {
    let value: TOKEN_ELEVATION_TYPE = fixed_information(handle, TokenElevationType)?;
    if value == TokenElevationTypeDefault {
        Ok("default")
    } else if value == TokenElevationTypeLimited {
        Ok("limited")
    } else if value == TokenElevationTypeFull {
        Ok("full")
    } else {
        Err(format!("unknown TOKEN_ELEVATION_TYPE {value}"))
    }
}

fn elevated(handle: HANDLE) -> Result<bool> {
    let value: TOKEN_ELEVATION = fixed_information(handle, TokenElevation)?;
    match value.TokenIsElevated {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!("TokenElevation returned non-boolean value {other}")),
    }
}

fn boolean_information(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<bool> {
    let value: u32 = fixed_information(handle, class)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!(
            "token class {class} returned non-boolean value {other}"
        )),
    }
}

fn app_container(handle: HANDLE) -> Result<bool> {
    boolean_information(handle, TokenIsAppContainer)
}

fn lpac(handle: HANDLE, app_container: bool) -> Result<(bool, bool)> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: value is a writable DWORD, the documented representation for this class.
    if unsafe {
        GetTokenInformation(
            handle,
            TokenIsLessPrivilegedAppContainer,
            (&raw mut value).cast(),
            u32::try_from(size_of::<u32>()).expect("DWORD size fits u32"),
            &raw mut returned,
        )
    } == 0
    {
        // SAFETY: called immediately after GetTokenInformation failed.
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            // LPAC is an AppContainer subtype. Some Windows SKUs reject the
            // LPAC-only information class for an ordinary token, but the
            // independently sampled TokenIsAppContainer=false fact still
            // proves that this token cannot be LPAC. An AppContainer token
            // must retain the direct-query requirement and fail closed here.
            return Ok((!app_container, false));
        }
        return Err(format!(
            "GetTokenInformation(LPAC) failed with Win32 error {error}"
        ));
    }
    if returned != u32::try_from(size_of::<u32>()).expect("DWORD size fits u32") {
        return Err("LPAC token fact returned an invalid byte count".to_owned());
    }
    match value {
        0 => Ok((true, false)),
        1 => Ok((true, true)),
        other => Err(format!(
            "LPAC token fact returned non-boolean value {other}"
        )),
    }
}

fn variable_items<T: Copy>(
    buffer: &AlignedBuffer,
    offset: usize,
    count: u32,
    context: &str,
) -> Result<Vec<T>> {
    let count = usize::try_from(count).map_err(|_| format!("{context} count overflow"))?;
    let byte_count = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| offset.checked_add(bytes))
        .ok_or_else(|| format!("{context} size overflow"))?;
    if count > 4096 || byte_count > buffer.len() {
        return Err(format!("{context} array was malformed or oversized"));
    }
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: checked arithmetic and the total bounds check cover each item.
        values.push(unsafe {
            buffer
                .as_ptr()
                .add(offset + index * size_of::<T>())
                .cast::<T>()
                .read_unaligned()
        });
    }
    Ok(values)
}

fn admin_group(handle: HANDLE) -> Result<&'static str> {
    let mut admin_sid = [0_u8; SECURITY_MAX_SID_SIZE];
    let mut admin_sid_size = u32::try_from(admin_sid.len()).expect("SID size fits u32");
    // SAFETY: admin_sid is a writable buffer of the supplied size; no domain SID is needed.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            admin_sid.as_mut_ptr().cast(),
            &raw mut admin_sid_size,
        )
    } == 0
    {
        return Err(win32_error("CreateWellKnownSid(Administrators)"));
    }
    let groups_buffer = token_information(handle, TokenGroups)?;
    let group_count: u32 = read_value(&groups_buffer, "TOKEN_GROUPS count")?;
    let groups: Vec<SID_AND_ATTRIBUTES> = variable_items(
        &groups_buffer,
        offset_of!(TOKEN_GROUPS, Groups),
        group_count,
        "TOKEN_GROUPS",
    )?;
    let mut state = None;
    for group in groups {
        // SAFETY: the pointer originates from TokenGroups and is checked before comparison.
        if group.Sid.is_null() || unsafe { IsValidSid(group.Sid) } == 0 {
            return Err("TokenGroups returned an invalid SID".to_owned());
        }
        // SAFETY: both SIDs are valid OS-created SIDs; EqualSid handles their lengths.
        if unsafe { EqualSid(group.Sid, admin_sid.as_mut_ptr().cast()) } == 0 {
            continue;
        }
        if state.is_some() {
            return Err("Administrators SID appeared more than once in TokenGroups".to_owned());
        }
        state = Some(if group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
            "deny-only"
        } else if group.Attributes & SE_GROUP_ENABLED != 0 {
            "enabled"
        } else {
            return Err(
                "Administrators SID was present but neither enabled nor deny-only".to_owned(),
            );
        });
    }
    // SID pointers in each copied SID_AND_ATTRIBUTES refer into groups_buffer.
    // Keep that allocation alive until every EqualSid call has completed.
    drop(groups_buffer);
    Ok(state.unwrap_or("absent"))
}

fn restricted_sid_count(handle: HANDLE) -> Result<u32> {
    let buffer = token_information(handle, TokenRestrictedSids)?;
    let group_count: u32 = read_value(&buffer, "TokenRestrictedSids count")?;
    // Validate the claimed count and backing array even though only the count is emitted.
    let _: Vec<SID_AND_ATTRIBUTES> = variable_items(
        &buffer,
        offset_of!(TOKEN_GROUPS, Groups),
        group_count,
        "TokenRestrictedSids",
    )?;
    Ok(group_count)
}

fn witness_groups(handle: HANDLE) -> Result<Vec<crate::witness::WitnessGroupFact>> {
    let buffer = token_information(handle, TokenGroups)?;
    let group_count: u32 = read_value(&buffer, "TOKEN_GROUPS count")?;
    let groups: Vec<SID_AND_ATTRIBUTES> = variable_items(
        &buffer,
        offset_of!(TOKEN_GROUPS, Groups),
        group_count,
        "TOKEN_GROUPS",
    )?;
    let mut facts = Vec::with_capacity(groups.len());
    for group in groups {
        // SID storage remains backed by `buffer` through this loop.
        if group.Sid.is_null() || unsafe { IsValidSid(group.Sid) } == 0 {
            return Err("TokenGroups returned an invalid SID".to_owned());
        }
        facts.push(crate::witness::WitnessGroupFact {
            sid: sid_string(group.Sid)?,
            attributes: group.Attributes,
        });
    }
    facts.sort_unstable_by(|left, right| {
        left.sid
            .cmp(&right.sid)
            .then(left.attributes.cmp(&right.attributes))
    });
    if facts.windows(2).any(|pair| pair[0].sid == pair[1].sid) {
        return Err("TokenGroups returned a duplicate SID".to_owned());
    }
    Ok(facts)
}

fn privilege_name(luid: &LUID) -> Result<String> {
    let mut required = 0_u32;
    // SAFETY: first call intentionally obtains the required character count.
    let first = unsafe { LookupPrivilegeNameW(null(), luid, null_mut(), &raw mut required) };
    if first != 0 || required == 0 {
        return Err("LookupPrivilegeNameW returned an invalid sizing result".to_owned());
    }
    // SAFETY: called immediately after the sizing call.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(win32_error("LookupPrivilegeNameW sizing"));
    }
    if required > 256 {
        return Err("privilege name exceeded its bound".to_owned());
    }
    let mut text = vec![0_u16; required as usize + 1];
    let mut capacity = u32::try_from(text.len()).expect("bounded name fits u32");
    // SAFETY: text is writable for capacity UTF-16 code units.
    if unsafe { LookupPrivilegeNameW(null(), luid, text.as_mut_ptr(), &raw mut capacity) } == 0 {
        return Err(win32_error("LookupPrivilegeNameW"));
    }
    text.truncate(capacity as usize);
    String::from_utf16(&text).map_err(|_| "privilege name was invalid UTF-16".to_owned())
}

fn enabled_privileges(handle: HANDLE) -> Result<Vec<String>> {
    let buffer = token_information(handle, TokenPrivileges)?;
    let privilege_count: u32 = read_value(&buffer, "TokenPrivileges count")?;
    let privileges: Vec<LUID_AND_ATTRIBUTES> = variable_items(
        &buffer,
        offset_of!(TOKEN_PRIVILEGES, Privileges),
        privilege_count,
        "TokenPrivileges",
    )?;
    let mut names = Vec::new();
    for privilege in privileges {
        if privilege.Attributes & SE_PRIVILEGE_ENABLED != 0 {
            names.push(privilege_name(&privilege.Luid)?);
        }
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

fn witness_privileges(handle: HANDLE) -> Result<Vec<crate::witness::WitnessPrivilegeFact>> {
    let buffer = token_information(handle, TokenPrivileges)?;
    let privilege_count: u32 = read_value(&buffer, "TokenPrivileges count")?;
    let privileges: Vec<LUID_AND_ATTRIBUTES> = variable_items(
        &buffer,
        offset_of!(TOKEN_PRIVILEGES, Privileges),
        privilege_count,
        "TokenPrivileges",
    )?;
    let mut facts = Vec::with_capacity(privileges.len());
    for privilege in privileges {
        facts.push(crate::witness::WitnessPrivilegeFact {
            name: privilege_name(&privilege.Luid)?,
            attributes: privilege.Attributes,
        });
    }
    facts.sort_unstable_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.attributes.cmp(&right.attributes))
    });
    if facts.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err("TokenPrivileges returned a duplicate privilege".to_owned());
    }
    Ok(facts)
}

#[allow(
    dead_code,
    reason = "used only after the staged witness rendezvous is service-connected"
)]
pub(crate) fn validate_pipe_impersonation_token(handle: HANDLE) -> Result<()> {
    let token_type: TOKEN_TYPE = fixed_information(handle, TokenType)?;
    if token_type != TokenImpersonation {
        return Err("named-pipe donor token is not an impersonation token".to_owned());
    }
    let level: SECURITY_IMPERSONATION_LEVEL = fixed_information(handle, TokenImpersonationLevel)?;
    if level < SecurityImpersonation {
        return Err("named-pipe donor token has insufficient impersonation level".to_owned());
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "used only after the staged witness rendezvous is service-connected"
)]
pub(crate) fn witness_token_profile(handle: HANDLE) -> Result<crate::witness::WitnessTokenProfile> {
    let statistics_before: TOKEN_STATISTICS = fixed_information(handle, TokenStatistics)?;
    let token_type: TOKEN_TYPE = fixed_information(handle, TokenType)?;
    let session_id: u32 = fixed_information(handle, TokenSessionId)?;
    let app_container = app_container(handle)?;
    let (lpac_supported, less_privileged_app_container) = lpac(handle, app_container)?;
    let profile = crate::witness::WitnessTokenProfile {
        user_sid: token_user_sid(handle)?,
        session_id,
        authentication_id: crate::witness::authentication_id_from_luid_parts(
            statistics_before.AuthenticationId.LowPart,
            statistics_before.AuthenticationId.HighPart,
        ),
        token_type: if token_type == windows_sys::Win32::Security::TokenPrimary {
            "primary"
        } else if token_type == TokenImpersonation {
            "impersonation"
        } else {
            return Err(format!("token has unknown TOKEN_TYPE {token_type}"));
        },
        integrity_rid: integrity_rid(handle)?,
        elevation_type: elevation_type(handle)?,
        elevated: elevated(handle)?,
        admin_group: admin_group(handle)?,
        app_container,
        // SAFETY: the handle is a live queryable token. The API has no
        // failure sentinel distinct from FALSE.
        token_restricted: unsafe { IsTokenRestricted(handle) } != 0,
        restricted_sid_count: restricted_sid_count(handle)?,
        groups: witness_groups(handle)?,
        privileges: witness_privileges(handle)?,
        lpac_supported,
        less_privileged_app_container,
    };
    let statistics_after: TOKEN_STATISTICS = fixed_information(handle, TokenStatistics)?;
    if statistics_before.TokenId.LowPart != statistics_after.TokenId.LowPart
        || statistics_before.TokenId.HighPart != statistics_after.TokenId.HighPart
        || statistics_before.ModifiedId.LowPart != statistics_after.ModifiedId.LowPart
        || statistics_before.ModifiedId.HighPart != statistics_after.ModifiedId.HighPart
    {
        return Err("witness token changed while its complete profile was sampled".to_owned());
    }
    Ok(profile)
}

fn capture_snapshot(run_nonce: &str, phase: SnapshotPhase) -> Result<TokenSnapshot> {
    let (token, source) = effective_token()?;
    let (token_id_before, modified_id_before, authentication_id_before) = statistics(token.0)?;
    let session_id_before: u32 = fixed_information(token.0, TokenSessionId)?;
    let user_sid = token_user_sid(token.0)?;
    let integrity_rid = integrity_rid(token.0)?;
    let elevation_type = elevation_type(token.0)?;
    let elevated = elevated(token.0)?;
    let admin_group = admin_group(token.0)?;
    let app_container = app_container(token.0)?;
    let (lpac_supported, less_privileged_app_container) = lpac(token.0, app_container)?;
    let restricted_sid_count = restricted_sid_count(token.0)?;
    let enabled_privileges = enabled_privileges(token.0)?;
    let session_id_after: u32 = fixed_information(token.0, TokenSessionId)?;
    let (token_id_after, modified_id_after, authentication_id_after) = statistics(token.0)?;
    if token_id_before != token_id_after
        || modified_id_before != modified_id_after
        || session_id_before != session_id_after
        || authentication_id_before != authentication_id_after
    {
        return Err("effective token changed while its facts were captured".to_owned());
    }
    Ok(TokenSnapshot {
        token_id: derive_token_id(run_nonce, phase, token_id_before),
        user_sid,
        integrity_rid,
        elevation_type,
        elevated,
        admin_group,
        app_container,
        restricted_sid_count,
        enabled_privileges,
        token_source: source,
        statistics_token_id_before: token_id_before,
        statistics_token_id_after: token_id_after,
        modified_id_before,
        modified_id_after,
        lpac_supported,
        less_privileged_app_container,
        session_id: session_id_before,
        authentication_id: authentication_id_before,
    })
}

pub(crate) fn random_identifier() -> Result<String> {
    let mut random = [0_u8; 24];
    // SAFETY: random is a valid writable buffer and the system-preferred provider needs no handle.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            u32::try_from(random.len()).expect("random size fits u32"),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!("BCryptGenRandom failed with NTSTATUS {status:#x}"));
    }
    Ok(URL_SAFE_NO_PAD.encode(random))
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn known_program_data() -> Result<PathBuf> {
    let mut raw = null_mut();
    // SAFETY: raw is writable pointer storage and FOLDERID_ProgramData is a valid known-folder ID.
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
    let path = (|| {
        let mut length = 0_usize;
        // SAFETY: SHGetKnownFolderPath returns a NUL-terminated task allocation.
        while unsafe { *raw.add(length) } != 0 {
            length += 1;
            if length > 32_768 {
                return Err("ProgramData path exceeded its bound".to_owned());
            }
        }
        // SAFETY: the loop established initialized UTF-16 slice bounds.
        Ok(PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(raw, length)
        })))
    })();
    // SAFETY: raw is the task allocation returned by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

fn protect_path(path: &Path, current_user_sid: &str) -> Result<()> {
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{current_user_sid})");
    let sddl_wide = wide_null(OsStr::new(&sddl));
    let mut descriptor = null_mut();
    // SAFETY: sddl_wide is NUL-terminated and descriptor is writable pointer storage.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(win32_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    let path_wide = wide_null(path.as_os_str());
    // SAFETY: path is NUL-terminated and descriptor remains allocated for the call.
    let result = unsafe {
        SetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    // SAFETY: descriptor is the local allocation returned by the conversion API.
    unsafe { LocalFree(descriptor.cast()) };
    if result == 0 {
        return Err(win32_error("SetFileSecurityW"));
    }
    Ok(())
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "ledger path is a reparse point: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "ledger path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn ledger_root(current_user_sid: &str) -> Result<PathBuf> {
    let mut path = known_program_data()?;
    for component in ["0verse", "windows-token-capture", "nonces"] {
        path.push(component);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
        }
        reject_reparse_point(&path)?;
        protect_path(&path, current_user_sid)?;
    }
    Ok(path)
}

fn consume_run_nonce(run_nonce: &str) -> Result<()> {
    let (token, _) = effective_token()?;
    let current_user_sid = token_user_sid(token.0)?;
    let root = ledger_root(&current_user_sid)?;
    let mut digest = Sha256::new();
    digest.update(NONCE_LEDGER_DOMAIN);
    digest.update(run_nonce.as_bytes());
    let name = format!("{:x}.used", digest.finalize());
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "run nonce has already been consumed".to_owned()
            } else {
                format!("cannot atomically consume run nonce: {error}")
            }
        })?;
    file.write_all(b"consumed\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot durably record consumed run nonce: {error}"))?;
    protect_path(&path, &current_user_sid)?;
    Ok(())
}

fn parse_arguments() -> Result<String> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut run_nonce = None;
    let mut operation = None;
    while let Some(argument) = arguments.next() {
        let argument = argument
            .to_str()
            .ok_or_else(|| "arguments must be valid Unicode".to_owned())?;
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        let value = value
            .to_str()
            .ok_or_else(|| format!("{argument} value must be valid Unicode"))?;
        match argument {
            "--run-nonce" if run_nonce.is_none() => run_nonce = Some(value.to_owned()),
            "--operation" if operation.is_none() => operation = Some(value.to_owned()),
            "--run-nonce" | "--operation" => {
                return Err(format!("duplicate argument: {argument}"));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let run_nonce = run_nonce.ok_or_else(|| "--run-nonce is required".to_owned())?;
    validate_run_nonce(&run_nonce).map_err(str::to_owned)?;
    if operation.as_deref() != Some(OPERATION_ID) {
        return Err(format!(
            "--operation must be the fixed harmless operation {OPERATION_ID}"
        ));
    }
    Ok(run_nonce)
}

fn execute_fixed_operation() {
    // This is the complete compile-time operation registry. It intentionally has no
    // external command, path, callback, script, payload, or dynamic loading surface.
    match OPERATION_ID {
        "fixture.control.noop" => std::hint::black_box(()),
        _ => unreachable!("the compile-time operation registry is exhaustive"),
    }
}

/// Run one fixed, harmless token-capture fixture and write JSON to stdout.
///
/// # Errors
///
/// Fails closed on invalid arguments, nonce replay, ACL failure, unstable token
/// facts, thread migration, unavailable Windows APIs, or JSON output failure.
pub fn run() -> Result<()> {
    let run_nonce = parse_arguments()?;
    consume_run_nonce(&run_nonce)?;
    let capture_nonce = random_identifier()?;
    if capture_nonce == run_nonce {
        return Err("capture and run nonce domains collided".to_owned());
    }
    // SAFETY: these calls have no arguments or preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    let process_instance_id = format!("p{process_id}-{}", random_identifier()?);
    // SAFETY: this call has no arguments or preconditions.
    let thread_id_before = unsafe { GetCurrentThreadId() };
    let start_token = capture_snapshot(&run_nonce, SnapshotPhase::Start)?;
    execute_fixed_operation();
    // SAFETY: this call has no arguments or preconditions.
    let thread_id_after_operation = unsafe { GetCurrentThreadId() };
    if thread_id_before != thread_id_after_operation {
        return Err("operation did not remain on the capture OS thread".to_owned());
    }
    let finish_token = capture_snapshot(&run_nonce, SnapshotPhase::Finish)?;
    // SAFETY: this call has no arguments or preconditions.
    let thread_id_after = unsafe { GetCurrentThreadId() };
    if thread_id_before != thread_id_after {
        return Err("before/after token snapshots came from different OS threads".to_owned());
    }
    let recorded_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_millis();
    let fixture = SnapshotPairFixture {
        schema_version: SCHEMA_VERSION,
        operation_id: OPERATION_ID,
        operation_sha256: operation_sha256(),
        run_nonce,
        capture_nonce,
        process_instance_id,
        recorded_at_unix_ms,
        thread_id_before,
        thread_id_after,
        start_token,
        finish_token,
        claim_eligible: false,
        fixture: true,
        replay_protection: "user-scoped-best-effort",
        weaponization: false,
        auto_disclosure: false,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &fixture)
        .map_err(|error| format!("cannot serialize fixture JSON: {error}"))?;
    println!();
    Ok(())
}
