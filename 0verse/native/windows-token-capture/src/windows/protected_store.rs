#![allow(
    dead_code,
    reason = "protected substrate remains unreachable until device-open broker activation"
)]

//! Handle-validated SYSTEM-only filesystem substrate for broker stores.
//!
//! This module creates no trust roots. Installers must provision the exact
//! directories and fixed leaves before a broker starts.

use std::ffi::{OsStr, OsString, c_void};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid,
    GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FindClose, FindFirstFileW, FindNextFileW, FlushFileBuffers,
    GetDriveTypeW, GetFileInformationByHandle, GetVolumeInformationByHandleW, OPEN_EXISTING,
    READ_CONTROL, ReadFile, WIN32_FIND_DATAW, WriteFile,
};
#[cfg(feature = "ci-system-test")]
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DeleteFileW, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, RemoveDirectoryW,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use zeroize::Zeroizing;

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ROOT_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)";
const FILE_SDDL: &str = "O:SYG:SYD:P(A;;FA;;;SY)";

pub(crate) struct ExclusiveLock(OwnedHandle);

pub(crate) struct ProtectedStore {
    root: PathBuf,
    _ancestor_handles: Vec<OwnedHandle>,
    _root_handle: OwnedHandle,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            // SAFETY: this object exclusively owns the successful handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct OwnedDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: descriptor is a LocalAlloc allocation returned by Win32.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct OwnedFindHandle(HANDLE);

impl Drop for OwnedFindHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this object exclusively owns the successful find handle.
            unsafe { FindClose(self.0) };
        }
    }
}

impl ProtectedStore {
    pub(crate) fn open(root_leaf: &str) -> Result<Self, String> {
        validate_leaf_name(root_leaf)?;
        let mut root = known_program_data()?;
        validate_fixed_drive(&root)?;
        let program_data = open_existing(
            &root,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_shape(&program_data, true, 0, 0)?;

        root.push("0verse");
        let company_root = open_existing(
            &root,
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_shape(&company_root, true, 0, 0)?;

        root.push(root_leaf);
        let root_handle = open_existing(
            &root,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&root_handle, true, 0, 0, ROOT_SDDL)?;
        validate_volume(&root_handle)?;
        Ok(Self {
            root,
            _ancestor_handles: vec![program_data, company_root],
            _root_handle: root_handle,
        })
    }

    pub(crate) fn entries(&self) -> Result<Vec<String>, String> {
        enumerate_directory(&self.root)
    }

    pub(crate) fn read_leaf(
        &self,
        name: &str,
        minimum: u64,
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        validate_leaf_name(name)?;
        let handle = open_existing(
            &self.root.join(name),
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let information = validate_handle(&handle, false, minimum, maximum, FILE_SDDL)?;
        read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh)
    }

    /// Read one leaf from a sibling protected root while this store keeps the
    /// validated company ancestor pinned against replacement.
    pub(crate) fn read_sibling_leaf(
        &self,
        root_leaf: &str,
        name: &str,
        minimum: u64,
        maximum: u64,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        validate_leaf_name(root_leaf)?;
        let company = self
            .root
            .parent()
            .ok_or_else(|| "protected store has no company ancestor".to_owned())?;
        let root = company.join(root_leaf);
        let root_handle = open_existing(
            &root,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&root_handle, true, 0, 0, ROOT_SDDL)?;
        validate_volume(&root_handle)?;
        let sibling = Self {
            root,
            _ancestor_handles: Vec::new(),
            _root_handle: root_handle,
        };
        sibling.read_leaf(name, minimum, maximum)
    }

    pub(crate) fn read_optional_leaf(
        &self,
        name: &str,
        minimum: u64,
        maximum: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        validate_leaf_name(name)?;
        let Some(handle) = open_existing_optional(
            &self.root.join(name),
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?
        else {
            return Ok(None);
        };
        let information = validate_handle(&handle, false, minimum, maximum, FILE_SDDL)?;
        read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh).map(Some)
    }

    pub(crate) fn lock(&self, name: &str) -> Result<ExclusiveLock, String> {
        validate_leaf_name(name)?;
        let handle = open_existing(
            &self.root.join(name),
            GENERIC_READ | READ_CONTROL,
            0,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_handle(&handle, false, 0, 0, FILE_SDDL)?;
        Ok(ExclusiveLock(handle))
    }

    pub(crate) fn create_immutable(
        &self,
        name: &str,
        record: &[u8],
        maximum: u64,
        label: &str,
    ) -> Result<(), String> {
        validate_leaf_name(name)?;
        let exact = u64::try_from(record.len())
            .map_err(|_| format!("{label} length does not fit its durable bound"))?;
        if exact == 0 || exact > maximum {
            return Err(format!("{label} exceeds its durable bound"));
        }
        let descriptor = descriptor_from_sddl(FILE_SDDL)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| "SECURITY_ATTRIBUTES size does not fit Win32".to_owned())?,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path = wide_null(self.root.join(name).as_os_str());
        // SAFETY: path and security descriptor are live and NUL-terminated.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE | READ_CONTROL,
                0,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: called immediately after CreateFileW failed.
            let error = unsafe { GetLastError() };
            if matches!(error, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
                return Err(format!("{label} has already been reserved"));
            }
            return Err(format!("cannot reserve {label}: Win32 error {error}"));
        }
        let handle = OwnedHandle(raw);
        // Creation burns the identity. A subsequent error deliberately leaves
        // a torn immutable leaf that recovery rejects.
        validate_handle(&handle, false, 0, maximum, FILE_SDDL)?;
        write_all(&handle, record)?;
        validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
        // SAFETY: handle is a writable synchronous disk-file handle.
        if unsafe { FlushFileBuffers(handle.0) } == 0 {
            return Err(win32_error("FlushFileBuffers(protected store)"));
        }
        Ok(())
    }
}

#[cfg(feature = "ci-system-test")]
fn ci_program_data_path() -> Result<PathBuf, String> {
    known_program_data()
}

#[cfg(feature = "ci-system-test")]
fn ci_path_exists(path: &Path) -> bool {
    let path = wide_null(path.as_os_str());
    // SAFETY: path is NUL-terminated.
    (unsafe { GetFileAttributesW(path.as_ptr()) }) != INVALID_FILE_ATTRIBUTES
}

#[cfg(feature = "ci-system-test")]
fn ci_create_system_directory(path: &Path) -> Result<(), String> {
    let descriptor = descriptor_from_sddl(ROOT_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| "SECURITY_ATTRIBUTES size does not fit Win32".to_owned())?,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_null(path.as_os_str());
    // SAFETY: path and descriptor are valid and live for the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(win32_error("CreateDirectoryW(protected-store CI)"));
    }
    let handle = open_existing(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_handle(&handle, true, 0, 0, ROOT_SDDL)?;
    Ok(())
}

#[cfg(feature = "ci-system-test")]
fn ci_create_system_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let descriptor = descriptor_from_sddl(FILE_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| "SECURITY_ATTRIBUTES size does not fit Win32".to_owned())?,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_null(path.as_os_str());
    // SAFETY: path and descriptor are valid and live for the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(win32_error("CreateFileW(protected-store CI leaf)"));
    }
    let handle = OwnedHandle(raw);
    let exact = u64::try_from(bytes.len()).map_err(|_| "CI leaf size overflow".to_owned())?;
    validate_handle(&handle, false, 0, exact, FILE_SDDL)?;
    write_all(&handle, bytes)?;
    // SAFETY: handle is a writable synchronous disk-file handle.
    if unsafe { FlushFileBuffers(handle.0) } == 0 {
        return Err(win32_error("FlushFileBuffers(protected-store CI leaf)"));
    }
    validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
    Ok(())
}

#[cfg(feature = "ci-system-test")]
fn ci_validate_system_file(path: &Path, expected: &[u8]) -> Result<(), String> {
    let handle = open_existing(
        path,
        GENERIC_READ | READ_CONTROL,
        0,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    let exact =
        u64::try_from(expected.len()).map_err(|_| "CI expected size overflow".to_owned())?;
    let information = validate_handle(&handle, false, exact, exact, FILE_SDDL)?;
    let actual = read_exact(&handle, information.nFileSizeLow, information.nFileSizeHigh)?;
    if actual.as_slice() != expected {
        return Err("protected-store CI marker content differs".to_owned());
    }
    Ok(())
}

#[cfg(feature = "ci-system-test")]
fn ci_delete_system_file(path: &Path, maximum: u64) -> Result<(), String> {
    let handle = open_existing(
        path,
        GENERIC_READ | READ_CONTROL,
        0,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_handle(&handle, false, 0, maximum, FILE_SDDL)?;
    drop(handle);
    let wide = wide_null(path.as_os_str());
    // SAFETY: the path was handle-validated immediately before deletion.
    if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
        return Err(win32_error("DeleteFileW(protected-store CI)"));
    }
    Ok(())
}

#[cfg(feature = "ci-system-test")]
fn ci_remove_system_directory(path: &Path) -> Result<(), String> {
    let handle = open_existing(
        path,
        GENERIC_READ | READ_CONTROL,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_handle(&handle, true, 0, 0, ROOT_SDDL)?;
    drop(handle);
    let wide = wide_null(path.as_os_str());
    // SAFETY: the path was handle-validated immediately before removal.
    if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
        return Err(win32_error("RemoveDirectoryW(protected-store CI)"));
    }
    Ok(())
}

#[cfg(feature = "ci-system-test")]
fn ci_entries(path: &Path) -> Result<Vec<String>, String> {
    enumerate_directory(path)
}

#[cfg(feature = "ci-system-test")]
const DEVICE_CI_CONTROL: &str = "0verse-windows-device-store-e2e-control";
#[cfg(feature = "ci-system-test")]
const DEVICE_ROOT: &str = "windows-device-open-broker";
#[cfg(feature = "ci-system-test")]
const DEVICE_POLICY: &str = "device_open.allowed_signers";
#[cfg(feature = "ci-system-test")]
const DEVICE_KEY: &str = "device_open_ed25519";
#[cfg(feature = "ci-system-test")]
const DEVICE_LOCK: &str = "ledger.lock";
#[cfg(feature = "ci-system-test")]
const DEVICE_CI_SENTINEL: &str = "owned-by-device-store-ci";
#[cfg(feature = "ci-system-test")]
const DEVICE_CI_SENTINEL_SCHEMA: &str = "0verse.windows-device-store-ci-owner/v2";
#[cfg(feature = "ci-system-test")]
const DEVICE_CI_PHASE_ONE: &str = "phase-one.complete";
#[cfg(feature = "ci-system-test")]
const DEVICE_CI_PHASE_TWO: &str = "phase-two.complete";

/// Opaque owner for the one fixed device-store CI namespace.
///
/// No arbitrary path crosses this feature-gated API.
#[cfg(feature = "ci-system-test")]
pub(crate) struct DeviceOpenCiOwner {
    control: PathBuf,
    root: PathBuf,
}

#[cfg(feature = "ci-system-test")]
#[derive(Clone, Copy)]
pub(crate) enum DeviceOpenCiFixture {
    SameAsCapture,
    DistinctDevice,
}

#[cfg(feature = "ci-system-test")]
impl DeviceOpenCiFixture {
    fn material(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::SameAsCapture => (
                include_bytes!("../../../../tests/fixtures/windows-token-sshsig/allowed_signers"),
                include_bytes!("../../../../tests/fixtures/windows-token-sshsig/test-only-key"),
            ),
            Self::DistinctDevice => (
                include_bytes!(
                    "../../../../tests/fixtures/windows-device-open-sshsig/allowed_signers"
                ),
                include_bytes!(
                    "../../../../tests/fixtures/windows-device-open-sshsig/test-only-key"
                ),
            ),
        }
    }
}

#[cfg(feature = "ci-system-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CiRootIdentity {
    volume_serial: u32,
    file_id: u64,
}

#[cfg(feature = "ci-system-test")]
impl DeviceOpenCiOwner {
    pub(crate) fn open_or_provision(fixture: DeviceOpenCiFixture) -> Result<Self, String> {
        let program_data = ci_program_data_path()?;
        let owner = Self {
            control: program_data.join(DEVICE_CI_CONTROL),
            root: program_data.join("0verse").join(DEVICE_ROOT),
        };
        if ci_path_exists(&owner.control) {
            owner.require_root_binding()?;
            return Ok(owner);
        }
        if ci_path_exists(&owner.root) {
            return Err("device-store CI root exists without its ownership sentinel".to_owned());
        }
        ci_create_system_directory(&owner.control)?;
        // The root is provisioned before its binding sentinel. A crash before
        // the final create leaves an unowned namespace that every later open
        // and cleanup refuses rather than guessing ownership.
        owner.provision_root(fixture)?;
        owner.create_root_binding()?;
        Ok(owner)
    }

    pub(crate) fn replace_root(&self, fixture: DeviceOpenCiFixture) -> Result<(), String> {
        self.require_root_binding()?;
        self.remove_root()?;
        ci_delete_system_file(&self.control.join(DEVICE_CI_SENTINEL), 4096)?;
        self.provision_root(fixture)?;
        self.create_root_binding()
    }

    pub(crate) fn phase_one_exists(&self) -> bool {
        ci_path_exists(&self.control.join(DEVICE_CI_PHASE_ONE))
    }

    pub(crate) fn phase_two_exists(&self) -> bool {
        ci_path_exists(&self.control.join(DEVICE_CI_PHASE_TWO))
    }

    pub(crate) fn require_phase_one(&self) -> Result<(), String> {
        ci_validate_system_file(&self.control.join(DEVICE_CI_PHASE_ONE), b"phase-one\n")
    }

    pub(crate) fn require_phase_two(&self) -> Result<(), String> {
        ci_validate_system_file(&self.control.join(DEVICE_CI_PHASE_TWO), b"phase-two\n")
    }

    pub(crate) fn mark_phase_one(&self) -> Result<(), String> {
        ci_create_system_file(&self.control.join(DEVICE_CI_PHASE_ONE), b"phase-one\n")
    }

    pub(crate) fn mark_phase_two(&self) -> Result<(), String> {
        ci_create_system_file(&self.control.join(DEVICE_CI_PHASE_TWO), b"phase-two\n")
    }

    pub(crate) fn cleanup(&self) -> Result<(), String> {
        self.require_root_binding()?;
        self.remove_root()?;
        let entries = ci_entries(&self.control)?;
        if entries.iter().any(|name| {
            !matches!(
                name.as_str(),
                DEVICE_CI_SENTINEL | DEVICE_CI_PHASE_ONE | DEVICE_CI_PHASE_TWO
            )
        }) {
            return Err("device-store CI control contains an unknown entry".to_owned());
        }
        for name in entries {
            ci_delete_system_file(&self.control.join(name), 4096)?;
        }
        ci_remove_system_directory(&self.control)
    }

    fn provision_root(&self, fixture: DeviceOpenCiFixture) -> Result<(), String> {
        let (policy, key) = fixture.material();
        ci_create_system_directory(&self.root)?;
        for (name, bytes) in [
            (DEVICE_POLICY, policy),
            (DEVICE_KEY, key),
            (DEVICE_LOCK, b"" as &[u8]),
        ] {
            ci_create_system_file(&self.root.join(name), bytes)?;
        }
        Ok(())
    }

    fn remove_root(&self) -> Result<(), String> {
        if !ci_path_exists(&self.root) {
            return Ok(());
        }
        let entries = ci_entries(&self.root)?;
        if entries.iter().any(|name| !is_device_store_entry(name)) {
            return Err("device-store CI root contains an unknown entry".to_owned());
        }
        for name in entries {
            ci_delete_system_file(&self.root.join(name), 2 * 1024 * 1024)?;
        }
        ci_remove_system_directory(&self.root)
    }

    fn create_root_binding(&self) -> Result<(), String> {
        let identity = ci_root_identity(&self.root)?;
        ci_create_system_file(
            &self.control.join(DEVICE_CI_SENTINEL),
            &ci_root_binding_bytes(identity),
        )
    }

    fn require_root_binding(&self) -> Result<CiRootIdentity, String> {
        if !ci_path_exists(&self.root) {
            return Err("device-store CI binding exists without its root".to_owned());
        }
        let identity = ci_root_identity(&self.root)?;
        ci_validate_system_file(
            &self.control.join(DEVICE_CI_SENTINEL),
            &ci_root_binding_bytes(identity),
        )
        .map_err(|error| format!("device-store CI root ownership binding is invalid: {error}"))?;
        Ok(identity)
    }
}

#[cfg(feature = "ci-system-test")]
fn ci_root_identity(path: &Path) -> Result<CiRootIdentity, String> {
    let handle = open_existing(
        path,
        GENERIC_READ | READ_CONTROL,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    let information = validate_handle(&handle, true, 0, 0, ROOT_SDDL)?;
    let file_id =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    if information.dwVolumeSerialNumber == 0 || file_id == 0 {
        return Err("device-store CI root has an invalid filesystem identity".to_owned());
    }
    Ok(CiRootIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_id,
    })
}

#[cfg(feature = "ci-system-test")]
fn ci_root_binding_bytes(identity: CiRootIdentity) -> Vec<u8> {
    format!(
        "{DEVICE_CI_SENTINEL_SCHEMA}\nvolume_serial={:08x}\nfile_id={:016x}\n",
        identity.volume_serial, identity.file_id
    )
    .into_bytes()
}

#[cfg(feature = "ci-system-test")]
fn is_device_store_entry(name: &str) -> bool {
    if matches!(name, DEVICE_POLICY | DEVICE_KEY | DEVICE_LOCK) {
        return true;
    }
    let digest = name
        .strip_prefix("receipt-")
        .or_else(|| name.strip_prefix("boundary-"))
        .or_else(|| name.strip_prefix("transcript-"))
        .and_then(|rest| rest.strip_suffix(".reserved"))
        .or_else(|| {
            name.strip_prefix("completion-")
                .and_then(|rest| rest.strip_suffix(".json"))
        });
    digest.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_leaf_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('.')
        || name.ends_with('.')
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err("protected-store leaf name is unsafe".to_owned());
    }
    Ok(())
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn known_program_data() -> Result<PathBuf, String> {
    let mut raw = null_mut();
    // SAFETY: folder ID is static and raw is writable task-allocation storage.
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
        // SAFETY: the API returned a NUL-terminated task allocation.
        while unsafe { *raw.add(length) } != 0 {
            length += 1;
            if length > 32_000 {
                return Err("ProgramData path exceeds its bound".to_owned());
            }
        }
        // SAFETY: the loop established the initialized UTF-16 slice length.
        Ok(PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(raw, length)
        })))
    })();
    // SAFETY: raw is the task allocation returned by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

fn validate_fixed_drive(path: &Path) -> Result<(), String> {
    let root = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) => format!("{}:\\", char::from(letter)),
            Prefix::VerbatimDisk(letter) => format!(r"\\?\{}:\", char::from(letter)),
            _ => return Err("protected store must not use UNC or device paths".to_owned()),
        },
        _ => return Err("protected store path has no local drive prefix".to_owned()),
    };
    let root = wide_null(OsStr::new(&root));
    // SAFETY: root is a NUL-terminated drive-root path.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err("protected store must reside on a fixed local drive".to_owned());
    }
    Ok(())
}

fn validate_volume(handle: &OwnedHandle) -> Result<(), String> {
    let mut volume_name = [0_u16; 64];
    let mut filesystem_name = [0_u16; 64];
    let volume_name_length = u32::try_from(volume_name.len())
        .map_err(|_| "volume-name bound does not fit Win32".to_owned())?;
    let filesystem_name_length = u32::try_from(filesystem_name.len())
        .map_err(|_| "filesystem-name bound does not fit Win32".to_owned())?;
    let mut serial = 0;
    let mut component_length = 0;
    let mut flags = 0;
    // SAFETY: output arrays and scalar pointers are writable for supplied sizes.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle.0,
            volume_name.as_mut_ptr(),
            volume_name_length,
            &raw mut serial,
            &raw mut component_length,
            &raw mut flags,
            filesystem_name.as_mut_ptr(),
            filesystem_name_length,
        )
    } == 0
        || flags & FILE_PERSISTENT_ACLS == 0
    {
        return Err("protected-store volume lacks persistent ACL support".to_owned());
    }
    Ok(())
}

fn open_existing(path: &Path, access: u32, share: u32, flags: u32) -> Result<OwnedHandle, String> {
    let path = wide_null(path.as_os_str());
    // SAFETY: path is NUL-terminated; no security attributes are used for open.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(win32_error("CreateFileW(protected store)"));
    }
    Ok(OwnedHandle(handle))
}

fn open_existing_optional(
    path: &Path,
    access: u32,
    share: u32,
    flags: u32,
) -> Result<Option<OwnedHandle>, String> {
    let path = wide_null(path.as_os_str());
    // SAFETY: path is NUL-terminated; no security attributes are used for open.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: read immediately after CreateFileW failed.
        let error = unsafe { GetLastError() };
        if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        return Err(format!(
            "CreateFileW(optional protected-store leaf) failed with Win32 error {error}"
        ));
    }
    Ok(Some(OwnedHandle(handle)))
}

fn enumerate_directory(path: &Path) -> Result<Vec<String>, String> {
    let pattern = wide_null(path.join("*").as_os_str());
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: pattern is NUL-terminated and data is writable for the exact structure.
    let raw = unsafe { FindFirstFileW(pattern.as_ptr(), &raw mut data) };
    if raw == INVALID_HANDLE_VALUE {
        // SAFETY: read immediately after failed enumeration.
        if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
            return Ok(Vec::new());
        }
        return Err(win32_error("FindFirstFileW(protected store)"));
    }
    let find = OwnedFindHandle(raw);
    let mut names = Vec::new();
    loop {
        let length = data
            .cFileName
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| "protected-store entry name is not NUL-terminated".to_owned())?;
        let name = String::from_utf16(&data.cFileName[..length])
            .map_err(|_| "protected-store entry name is not valid UTF-16".to_owned())?;
        if name != "." && name != ".." {
            names.push(name);
        }
        // SAFETY: find is a live search handle and data remains writable.
        if unsafe { FindNextFileW(find.0, &raw mut data) } == 0 {
            // SAFETY: read immediately after the failed enumeration call.
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                return Err(format!(
                    "FindNextFileW(protected store) failed with Win32 error {error}"
                ));
            }
            break;
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn descriptor_from_sddl(sddl: &str) -> Result<OwnedDescriptor, String> {
    let sddl = wide_null(OsStr::new(sddl));
    let mut descriptor = null_mut();
    // SAFETY: SDDL is NUL-terminated and descriptor storage is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(win32_error(
            "ConvertStringSecurityDescriptor(protected store)",
        ));
    }
    Ok(OwnedDescriptor(descriptor))
}

fn validate_handle(
    handle: &OwnedHandle,
    directory: bool,
    minimum: u64,
    maximum: u64,
    expected_sddl: &str,
) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let information = validate_shape(handle, directory, minimum, maximum)?;
    validate_security(handle, expected_sddl)?;
    Ok(information)
}

fn validate_shape(
    handle: &OwnedHandle,
    directory: bool,
    minimum: u64,
    maximum: u64,
) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: information is writable for the exact structure size.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut information) } == 0 {
        return Err(win32_error("GetFileInformationByHandle(protected store)"));
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let unsafe_attributes = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_COMPRESSED
        | FILE_ATTRIBUTE_ENCRYPTED
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_SPARSE_FILE;
    if information.dwFileAttributes & unsafe_attributes != 0
        || is_directory != directory
        || (!directory && information.nNumberOfLinks != 1)
    {
        return Err("protected-store handle type, reparse, or link count is unsafe".to_owned());
    }
    let size = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if !directory && (size < minimum || size > maximum) {
        return Err("protected-store file size is outside its exact bound".to_owned());
    }
    Ok(information)
}

fn validate_security(handle: &OwnedHandle, expected_sddl: &str) -> Result<(), String> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: output pointers are writable; descriptor owns the returned allocation.
    let result = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if result != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor is the GetSecurityInfo LocalAlloc result.
            unsafe { LocalFree(descriptor) };
        }
        return Err(format!(
            "GetSecurityInfo(protected store) failed or returned NULL: {result}"
        ));
    }
    let actual = OwnedDescriptor(descriptor);
    let expected = descriptor_from_sddl(expected_sddl)?;
    compare_descriptors(actual.0, expected.0)
}

fn compare_descriptors(
    actual: PSECURITY_DESCRIPTOR,
    expected: PSECURITY_DESCRIPTOR,
) -> Result<(), String> {
    let (actual_owner, actual_dacl, actual_control) = descriptor_parts(actual)?;
    let (expected_owner, expected_dacl, expected_control) = descriptor_parts(expected)?;
    // SAFETY: descriptor_parts established both owner SID pointers.
    if unsafe { EqualSid(actual_owner, expected_owner) } == 0
        || actual_control & SE_DACL_PROTECTED == 0
        || expected_control & SE_DACL_PROTECTED == 0
    {
        return Err("protected-store owner or DACL protection is invalid".to_owned());
    }
    let actual_size = acl_size(actual_dacl)?;
    let expected_size = acl_size(expected_dacl)?;
    if actual_size != expected_size {
        return Err("protected-store DACL size differs from SYSTEM-only policy".to_owned());
    }
    // SAFETY: GetAclInformation verified both ACL byte lengths.
    let actual_bytes =
        unsafe { std::slice::from_raw_parts(actual_dacl.cast::<u8>(), actual_size as usize) };
    // SAFETY: GetAclInformation verified both ACL byte lengths.
    let expected_bytes =
        unsafe { std::slice::from_raw_parts(expected_dacl.cast::<u8>(), expected_size as usize) };
    if actual_bytes != expected_bytes {
        return Err("protected-store DACL is not the exact SYSTEM-only policy".to_owned());
    }
    Ok(())
}

fn descriptor_parts(
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(PSID, *mut ACL, SECURITY_DESCRIPTOR_CONTROL), String> {
    let mut owner = null_mut();
    let mut owner_defaulted = 0;
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = null_mut();
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor is valid for the duration of these calls and outputs are writable.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
        } == 0
        || unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
            == 0
        || owner.is_null()
        || dacl_present == 0
        || dacl.is_null()
        || owner_defaulted != 0
        || dacl_defaulted != 0
    {
        return Err("protected-store security descriptor is malformed or defaulted".to_owned());
    }
    Ok((owner, dacl, control))
}

fn acl_size(acl: *mut ACL) -> Result<u32, String> {
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: ACL pointer came from a validated descriptor and output is writable.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(win32_error("GetAclInformation(protected store)"));
    }
    if information.AclBytesInUse < u32::try_from(size_of::<ACL>()).expect("ACL size fits u32") {
        return Err("protected-store DACL byte count is invalid".to_owned());
    }
    Ok(information.AclBytesInUse)
}

fn read_exact(
    handle: &OwnedHandle,
    size_low: u32,
    size_high: u32,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let size = (u64::from(size_high) << 32) | u64::from(size_low);
    let size = usize::try_from(size).map_err(|_| "protected-store size overflow".to_owned())?;
    let mut bytes = Zeroizing::new(vec![0_u8; size]);
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk = u32::try_from(bytes.len() - offset).unwrap_or(u32::MAX);
        let mut read = 0;
        // SAFETY: the remaining vector slice is writable for chunk bytes.
        if unsafe {
            ReadFile(
                handle.0,
                bytes[offset..].as_mut_ptr(),
                chunk,
                &raw mut read,
                null_mut(),
            )
        } == 0
            || read == 0
        {
            return Err(win32_error("ReadFile(protected store)"));
        }
        offset += usize::try_from(read).map_err(|_| "protected-store read overflow".to_owned())?;
    }
    let mut extra = 0_u8;
    let mut read = 0;
    // SAFETY: extra is writable for one byte and the handle is synchronous.
    if unsafe { ReadFile(handle.0, &raw mut extra, 1, &raw mut read, null_mut()) } == 0 || read != 0
    {
        return Err("protected-store file changed size during its held-handle read".to_owned());
    }
    Ok(bytes)
}

fn write_all(handle: &OwnedHandle, bytes: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk = u32::try_from(bytes.len() - offset).unwrap_or(u32::MAX);
        let mut written = 0;
        // SAFETY: the remaining slice is readable for chunk bytes.
        if unsafe {
            WriteFile(
                handle.0,
                bytes[offset..].as_ptr(),
                chunk,
                &raw mut written,
                null_mut(),
            )
        } == 0
            || written == 0
        {
            return Err(win32_error("WriteFile(protected store)"));
        }
        offset += usize::try_from(written)
            .map_err(|_| "protected-store write count overflow".to_owned())?;
    }
    Ok(())
}

fn win32_error(context: &str) -> String {
    // SAFETY: reads the calling thread's last-error value.
    format!("{context} failed with Win32 error {}", unsafe {
        GetLastError()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bounded_leaf_names() {
        for name in [
            "device_open.allowed_signers",
            "device_open_ed25519",
            "ledger.lock",
            "receipt-0123456789abcdef.reserved",
        ] {
            validate_leaf_name(name).unwrap();
        }
        for name in ["", ".", "..", "../key", "Key", "a\\b", "a/b", "a:"] {
            assert!(validate_leaf_name(name).is_err());
        }
    }

    #[test]
    fn remote_and_device_roots_are_rejected_before_open() {
        assert!(validate_fixed_drive(Path::new(r"\\server\share\store")).is_err());
        assert!(validate_fixed_drive(Path::new(r"\\.\C:\store")).is_err());
    }
}
