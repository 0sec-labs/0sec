//! Feature-gated one-shot SCM harness for hosted Windows CI.
//!
//! This module is not part of the production broker. Both services accept no
//! material or paths: they exercise and clean only the internally fixed test
//! namespace while running as `LocalSystem`.

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

const E2E_SERVICE_NAME: &str = "0verseWindowsStoreE2E";
const CLEANUP_SERVICE_NAME: &str = "0verseWindowsStoreCleanup";
const FAILURE_CODE: u32 = 1;
const E2E_DIAGNOSTIC: &str = "0verse-windows-store-e2e-error.txt";
const CLEANUP_DIAGNOSTIC: &str = "0verse-windows-store-cleanup-error.txt";

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

unsafe extern "system" fn control_handler(
    _control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    NO_ERROR
}

fn report_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: 0,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: service_exit_code,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: the handle was returned by SCM and status lives through the call.
    unsafe { SetServiceStatus(handle, &raw const status) };
}

fn finish(handle: SERVICE_STATUS_HANDLE, succeeded: bool) {
    if succeeded {
        report_status(handle, SERVICE_STOPPED, NO_ERROR, 0);
    } else {
        report_status(
            handle,
            SERVICE_STOPPED,
            ERROR_SERVICE_SPECIFIC_ERROR,
            FAILURE_CODE,
        );
    }
}

fn record_diagnostic(name: &str, error: &str) {
    let Some(program_data) = std::env::var_os("ProgramData") else {
        return;
    };
    let path = PathBuf::from(program_data).join(name);
    let bounded: String = error.chars().take(4096).collect();
    // This is a feature-gated, non-secret CI diagnostic outside the trust
    // namespace. CREATE_NEW avoids following or overwriting a prepositioned
    // filesystem object. The runner removes it in `finally`; failure is harmless.
    if let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(path) {
        let _ = file.write_all(bounded.as_bytes());
        let _ = file.sync_all();
    }
}

unsafe extern "system" fn e2e_service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide_null(E2E_SERVICE_NAME);
    // SAFETY: the name is NUL-terminated and callback ABI is exact.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null_mut()) };
    if handle.is_null() {
        return;
    }
    report_status(handle, SERVICE_START_PENDING, NO_ERROR, 0);
    report_status(handle, SERVICE_RUNNING, NO_ERROR, 0);
    match crate::service_store::run_ci_system_test_phase()
        .and_then(|_| crate::device_open_store::run_ci_system_test_phase())
    {
        Ok(()) => finish(handle, true),
        Err(error) => {
            record_diagnostic(E2E_DIAGNOSTIC, &error);
            finish(handle, false);
        }
    }
}

unsafe extern "system" fn cleanup_service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide_null(CLEANUP_SERVICE_NAME);
    // SAFETY: the name is NUL-terminated and callback ABI is exact.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null_mut()) };
    if handle.is_null() {
        return;
    }
    report_status(handle, SERVICE_START_PENDING, NO_ERROR, 0);
    report_status(handle, SERVICE_RUNNING, NO_ERROR, 0);
    let device = crate::device_open_store::cleanup_ci_system_test();
    let capture = crate::service_store::cleanup_ci_system_test();
    let cleanup = match (device, capture) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(device), Ok(())) => Err(format!("device cleanup failed: {device}")),
        (Ok(()), Err(capture)) => Err(format!("capture cleanup failed: {capture}")),
        (Err(device), Err(capture)) => Err(format!(
            "device cleanup failed: {device}; capture cleanup failed: {capture}"
        )),
    };
    match cleanup {
        Ok(()) => finish(handle, true),
        Err(error) => {
            record_diagnostic(CLEANUP_DIAGNOSTIC, &error);
            finish(handle, false);
        }
    }
}

fn run_dispatcher(
    service_name: &str,
    service_main: unsafe extern "system" fn(u32, *mut *mut u16),
) -> Result<(), String> {
    let mut name = wide_null(service_name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table has a terminal zero entry and remains alive for the call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(super::win32_error(
            "StartServiceCtrlDispatcherW(CI store service)",
        ));
    }
    Ok(())
}

/// Enter the feature-gated lifecycle test service dispatcher.
///
/// # Errors
///
/// Returns an error when the process was not started by the expected SCM service.
pub fn run_e2e_dispatcher() -> Result<(), String> {
    run_dispatcher(E2E_SERVICE_NAME, e2e_service_main)
}

/// Enter the feature-gated exact cleanup service dispatcher.
///
/// # Errors
///
/// Returns an error when the process was not started by the expected SCM service.
pub fn run_cleanup_dispatcher() -> Result<(), String> {
    run_dispatcher(CLEANUP_SERVICE_NAME, cleanup_service_main)
}
