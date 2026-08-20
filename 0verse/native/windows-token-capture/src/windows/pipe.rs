use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    PIPE_WAIT,
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const PIPE_BUFFER_BYTES: u32 = 1024 * 1024;
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)";

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            // SAFETY: this object exclusively owns the successful pipe handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn create_validation_pipe(name: &str) -> Result<OwnedHandle, String> {
    let descriptor_text = wide_null(OsStr::new(PIPE_SDDL));
    let mut descriptor = null_mut();
    // SAFETY: the SDDL is NUL-terminated and descriptor is writable pointer storage.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(super::win32_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(pipe)",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits u32"),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide_null(OsStr::new(name));
    // SAFETY: name and security descriptor remain live for the call. The API
    // copies the descriptor into the new kernel object before returning.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &raw const attributes,
        )
    };
    // SAFETY: descriptor is the LocalAlloc allocation returned by the converter.
    unsafe { LocalFree(descriptor) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(super::win32_error("CreateNamedPipeW"));
    }
    Ok(OwnedHandle(handle))
}

/// Exercise only the local, ACL-gated named-pipe construction boundary.
///
/// This does not connect a client, execute an operation, or emit capture data.
/// It exists so hosted Windows CI compiles and creates the exact A1 kernel
/// object while the privileged A2 service remains intentionally unavailable.
///
/// # Errors
///
/// Returns an error if Windows rejects the security descriptor or pipe creation.
pub fn console_self_test() -> Result<(), String> {
    let facts = super::live_facts::sample()?;
    if facts.now_unix_seconds <= 0
        || facts.worker.is_empty()
        || facts.build_lab_ex.is_empty()
        || facts.worker_machine_id.len() != 64
        || facts.runner.sha256().len() != 64
        || facts.runner.final_path().is_empty()
        || facts.runner.size() == 0
    {
        return Err("live Windows fact sampler returned an invalid shape".to_owned());
    }
    let name = format!(
        r"\\.\pipe\0verse.windows-token-broker.a1.{}",
        std::process::id()
    );
    let pipe = create_validation_pipe(&name)?;
    drop(pipe);
    drop(facts);
    Ok(())
}

#[must_use]
pub const fn maximum_frame_bytes() -> u32 {
    PIPE_BUFFER_BYTES
}
