use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

const SERVICE_NAME: &str = "0verseWindowsTokenBroker";
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP {
        STOP_REQUESTED.store(true, Ordering::Release);
    }
    NO_ERROR
}

fn report_status(handle: SERVICE_STATUS_HANDLE, state: u32, accepted: u32, exit_code: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: the status handle was returned by the SCM and `status` lives for the call.
    unsafe { SetServiceStatus(handle, &raw const status) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let service_name = wide_null(SERVICE_NAME);
    // SAFETY: the service name is NUL-terminated and the callback has the required ABI.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(service_name.as_ptr(), Some(control_handler), null_mut())
    };
    if handle.is_null() {
        return;
    }
    report_status(handle, SERVICE_START_PENDING, 0, NO_ERROR);
    report_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, NO_ERROR);

    // A1 establishes the SCM boundary but intentionally cannot execute an
    // operation or emit evidence. A2 replaces this fail-closed stop with the
    // authority-verifying broker loop as one atomic security change.
    let _ = STOP_REQUESTED.load(Ordering::Acquire);
    report_status(handle, SERVICE_STOPPED, 0, ERROR_CALL_NOT_IMPLEMENTED);
}

/// Enter the Windows Service Control Manager dispatcher.
///
/// # Errors
///
/// Returns an error when the process was not launched by the SCM or dispatcher
/// registration fails.
pub fn run_dispatcher() -> Result<(), String> {
    let mut service_name = wide_null(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table is terminated by a zero entry and remains alive for the call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(super::win32_error("StartServiceCtrlDispatcherW"));
    }
    Ok(())
}

#[must_use]
pub const fn service_name() -> &'static str {
    SERVICE_NAME
}
