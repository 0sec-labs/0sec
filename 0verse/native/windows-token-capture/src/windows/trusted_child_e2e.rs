//! Feature-gated, non-claim trusted-child system test.
//!
//! A fresh non-admin scheduled-task process supplies the bootstrap token. The
//! `LocalSystem` service exercises the production rendezvous, exact child launch,
//! process-object binding, one fixed neutral control no-op, and cleanup code,
//! but cannot bind authority, reserve or execute a production operation, load
//! signing material, or emit vulnerability evidence.

use std::ffi::{OsStr, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_SPECIFIC_ERROR, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    NO_ERROR,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LsaFreeReturnBuffer, LsaGetLogonSessionData, SECURITY_LOGON_SESSION_DATA, SECURITY_LOGON_TYPE,
};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FlushFileBuffers, OPEN_EXISTING, WriteFile,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetProcessId, OpenProcessToken,
};

use super::child;
use super::rendezvous::{AcceptOutcome, WitnessRendezvous};
use super::{ExpectedWitnessIdentity, OwnedKernelHandle, WitnessRendezvousSpec};

const SERVICE_NAME: &str = "0verseWindowsTrustedChildE2E";
const ROOT_NAME: &str = "0verse-trusted-child-e2e";
const CONFIG_NAME: &str = "config.json";
const FACTS_NAME: &str = "facts.json";
const DONOR_ERROR_NAME: &str = "donor-error.json";
const RECEIPT_NAME: &str = "receipt.json";
const ERROR_NAME: &str = "error.txt";
const MAX_CONTROL_BYTES: u64 = 4096;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const CAMPAIGN_SHA256: &str = "81be4d1c8f47b462d16d0dfbb6e2b9f698e5a34fb2fc0a2da547b0810e869f4a";
const ACCEPTANCE_SHA256: &str = "e709ee03377c9f6f2d580d2a24f470bfb01f8d2cd9334b64139cfe3053d5cf55";

type Result<T> = std::result::Result<T, String>;

fn last_error(context: &str) -> String {
    let error = unsafe { GetLastError() };
    format!("{context} failed with Win32 error {error}")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    expected_user_sid: String,
    run_nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DonorFacts {
    nonce: String,
    user_sid: String,
    session_id: u32,
    authentication_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DonorError {
    message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandFile {
    nonce: String,
    phase: u8,
    kind: String,
    pipe_name: Option<String>,
}

#[derive(Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "exact safety booleans are the neutral CI receipt wire contract"
)]
struct Receipt<'a> {
    schema: &'static str,
    subject_sid: &'a str,
    session_id: u32,
    authentication_id: &'a str,
    broker_sha256: &'a str,
    child_pid: u32,
    child_binding_sha256: &'a str,
    adapter_operation_sha256: &'a str,
    adapter_input_sha256: &'a str,
    adapter_output_sha256: &'a str,
    start_profile_sha256: &'a str,
    finish_profile_sha256: &'a str,
    thread_id_start: u32,
    thread_id_finish: u32,
    bootstrap_authenticated: bool,
    invalid_hello_rejected: bool,
    wrong_process_rejected: bool,
    exact_child_authenticated: bool,
    child_profile_equal: bool,
    local_system_service: bool,
    batch_logon: bool,
    graceful_shutdown: bool,
    stage_removed: bool,
    control_noop_executed: bool,
    single_request_path_used: bool,
    same_thread: bool,
    token_profile_equal: bool,
    claim_eligible: bool,
    claim_created: bool,
    authority_verified: bool,
    authority_bound: bool,
    reservation_performed: bool,
    operation_reserved: bool,
    operation_executed: bool,
    signing_key_loaded: bool,
    evidence_signed: bool,
    weaponization: bool,
    auto_disclosure: bool,
    human_report_gate: bool,
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) || wide.len() > 32_767 {
        return Err("trusted-child E2E value contains NUL or exceeds its bound".to_owned());
    }
    wide.push(0);
    Ok(wide)
}

fn root() -> Result<PathBuf> {
    let program_data =
        std::env::var_os("ProgramData").ok_or_else(|| "ProgramData is unavailable".to_owned())?;
    Ok(PathBuf::from(program_data).join(ROOT_NAME))
}

fn validate_e2e_nonce(value: &str) -> Result<()> {
    crate::validate_run_nonce(value).map_err(str::to_owned)?;
    if value.len() != 64 {
        return Err("trusted-child E2E run nonce must contain exactly 64 characters".to_owned());
    }
    Ok(())
}

fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("read {} metadata failed: {error}", path.display()))?;
    if metadata.len() == 0 || metadata.len() > MAX_CONTROL_BYTES || !metadata.is_file() {
        return Err(format!(
            "{} has an invalid control-file shape",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| "control-file size does not fit usize")?,
    );
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("read {} failed: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_slice(&bounded_read(path)?)
        .map_err(|error| format!("parse {} failed: {error}", path.display()))
}

fn create_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("serialize JSON failed: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err("trusted-child E2E JSON exceeds its bound".to_owned());
    }
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("create {} failed: {error}", temporary.display()))?;
    let write_result = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write {} failed: {error}", temporary.display()));
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "publish {} as {} failed: {error}",
            temporary.display(),
            path.display()
        ));
    }
    Ok(())
}

fn wait_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        match fs::metadata(path) {
            Ok(_) => return read_json(path),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(format!(
                    "read {} metadata failed while waiting: {error}",
                    path.display()
                ));
            }
        }
    }
}

fn wait_donor_facts(root: &Path) -> Result<DonorFacts> {
    let facts_path = root.join("from-donor").join(FACTS_NAME);
    let error_path = root.join("from-donor").join(DONOR_ERROR_NAME);
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        match fs::metadata(&error_path) {
            Ok(_) => {
                let diagnostic: DonorError = read_json(&error_path)?;
                return Err(format!(
                    "trusted-child E2E donor failed: {}",
                    diagnostic.message
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "read {} metadata failed while waiting: {error}",
                    error_path.display()
                ));
            }
        }
        match fs::metadata(&facts_path) {
            Ok(_) => return read_json(&facts_path),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(format!(
                    "read {} metadata failed while waiting: {error}",
                    facts_path.display()
                ));
            }
        }
    }
}

fn command_path(root: &Path, phase: u8) -> PathBuf {
    root.join("to-donor").join(format!("phase-{phase}.json"))
}

fn publish_command(
    root: &Path,
    nonce: &str,
    phase: u8,
    kind: &str,
    pipe_name: Option<&str>,
) -> Result<()> {
    create_json(
        &command_path(root, phase),
        &CommandFile {
            nonce: nonce.to_owned(),
            phase,
            kind: kind.to_owned(),
            pipe_name: pipe_name.map(str::to_owned),
        },
    )
}

fn validate_command(command: &CommandFile, nonce: &str, phase: u8, kind: &str) -> Result<()> {
    if command.nonce != nonce || command.phase != phase || command.kind != kind {
        return Err(format!(
            "trusted-child E2E phase {phase} command is invalid"
        ));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .map_err(|error| format!("open broker image {} failed: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read broker image failed: {error}"))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > 64 * 1024 * 1024 {
            return Err("broker image exceeds the trusted-child bound".to_owned());
        }
        digest.update(&buffer[..read]);
    }
    if total == 0 {
        return Err("broker image is empty".to_owned());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sibling_broker() -> Result<PathBuf> {
    let current = std::env::current_exe()
        .map_err(|error| format!("resolve E2E service image failed: {error}"))?;
    let parent = current
        .parent()
        .ok_or_else(|| "E2E service image has no parent directory".to_owned())?;
    Ok(parent.join("windows-token-broker.exe"))
}

fn stop_event() -> Result<OwnedKernelHandle> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(last_error("CreateEventW(trusted-child E2E)"));
    }
    Ok(OwnedKernelHandle(event))
}

fn bootstrap_spec(
    nonce: &str,
    suffix: &str,
    expected: &ExpectedWitnessIdentity,
) -> Result<WitnessRendezvousSpec> {
    WitnessRendezvousSpec::new(
        CAMPAIGN_SHA256,
        ACCEPTANCE_SHA256,
        "control",
        1,
        &format!("{suffix}_{nonce}"),
        expected.user_sid(),
        expected.session_id(),
        expected.authentication_id(),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the linear negative/bootstrap/child lifecycle remains visible for auditability"
)]
fn run_service_test() -> Result<()> {
    let service_profile = current_process_profile()?;
    if service_profile.user_sid != "S-1-5-18"
        || service_profile.session_id != 0
        || service_profile.token_type != "primary"
    {
        return Err("trusted-child E2E service is not LocalSystem in Session 0".to_owned());
    }
    let root = root()?;
    let config: Config = read_json(&root.join(CONFIG_NAME))?;
    validate_e2e_nonce(&config.run_nonce)?;
    let facts = wait_donor_facts(&root)?;
    if facts.nonce != config.run_nonce
        || facts.user_sid != config.expected_user_sid
        || facts.session_id != 0
    {
        return Err("scheduled-task donor facts differ from trusted CI configuration".to_owned());
    }
    let expected =
        ExpectedWitnessIdentity::new(&facts.user_sid, facts.session_id, &facts.authentication_id)?;
    let stop = stop_event()?;

    let bad = WitnessRendezvous::prepare(bootstrap_spec(
        &config.run_nonce,
        "ci_bad_hello",
        &expected,
    )?)?;
    publish_command(
        &root,
        &config.run_nonce,
        1,
        "invalid-hello",
        Some(bad.name()),
    )?;
    let bad_result = unsafe { bad.accept(stop.0) };
    if !matches!(bad_result, Err(ref error) if error == "witness hello is invalid") {
        return Err("invalid bootstrap hello was not rejected exactly".to_owned());
    }

    let bootstrap_rendezvous = WitnessRendezvous::prepare(bootstrap_spec(
        &config.run_nonce,
        "ci_bootstrap",
        &expected,
    )?)?;
    publish_command(
        &root,
        &config.run_nonce,
        2,
        "bootstrap",
        Some(bootstrap_rendezvous.name()),
    )?;
    let bootstrap = match unsafe { bootstrap_rendezvous.accept(stop.0) }? {
        AcceptOutcome::Authenticated(token) => *token,
        AcceptOutcome::Stopped => return Err("bootstrap authentication was stopped".to_owned()),
        AcceptOutcome::TimedOut => {
            return Err("bootstrap authentication timed out".to_owned());
        }
    };
    let broker = sibling_broker()?;
    let broker_sha256 = hash_file(&broker)?;

    let child_spec = WitnessRendezvousSpec::new_child(
        bootstrap.rendezvous_binding_sha256(),
        &broker_sha256,
        &"7".repeat(64),
        &expected,
    )?;
    let wrong_process = WitnessRendezvous::prepare(child_spec)?;
    publish_command(
        &root,
        &config.run_nonce,
        3,
        "wrong-process",
        Some(wrong_process.name()),
    )?;
    let expected_pid = unsafe { GetProcessId(bootstrap.bootstrap_process.0) };
    let wrong_result =
        unsafe { wrong_process.accept_exact(stop.0, expected_pid, bootstrap.bootstrap_process.0) };
    if !matches!(wrong_result, Err(ref error) if error == "trusted child pipe was opened by the wrong process ID")
    {
        return Err("wrong trusted-child process was not rejected exactly".to_owned());
    }

    let mut pinned =
        unsafe { child::create_and_authenticate(bootstrap, &broker, &broker_sha256, stop.0) }?;
    if pinned.sha256() != broker_sha256 {
        return Err("pinned trusted-child hash changed".to_owned());
    }
    let capability = pinned
        .trusted_child
        .take()
        .ok_or_else(|| "trusted-child capability is missing".to_owned())?;
    let shutdown = capability.ci_execute_noop_and_shutdown(&config.run_nonce, stop.0)?;
    let execution = &shutdown.execution;
    publish_command(&root, &config.run_nonce, 4, "release", None)?;

    create_json(
        &root.join(RECEIPT_NAME),
        &Receipt {
            schema: "0verse-windows-trusted-child-e2e-receipt-v2",
            subject_sid: &facts.user_sid,
            session_id: facts.session_id,
            authentication_id: &facts.authentication_id,
            broker_sha256: &broker_sha256,
            child_pid: shutdown.pid,
            child_binding_sha256: &shutdown.binding_sha256,
            adapter_operation_sha256: &execution.adapter_result.operation_sha256,
            adapter_input_sha256: &execution.adapter_result.input_sha256,
            adapter_output_sha256: &execution.adapter_result.output_sha256,
            start_profile_sha256: &execution.start_profile_sha256,
            finish_profile_sha256: &execution.finish_profile_sha256,
            thread_id_start: execution.thread_id_start,
            thread_id_finish: execution.thread_id_finish,
            bootstrap_authenticated: true,
            invalid_hello_rejected: true,
            wrong_process_rejected: true,
            exact_child_authenticated: true,
            child_profile_equal: true,
            local_system_service: true,
            batch_logon: true,
            graceful_shutdown: true,
            stage_removed: true,
            control_noop_executed: true,
            single_request_path_used: true,
            same_thread: execution.same_thread,
            token_profile_equal: execution.token_profile_equal,
            claim_eligible: false,
            claim_created: false,
            authority_verified: false,
            authority_bound: false,
            reservation_performed: false,
            operation_reserved: false,
            operation_executed: false,
            signing_key_loaded: false,
            evidence_signed: false,
            weaponization: false,
            auto_disclosure: false,
            human_report_gate: true,
        },
    )
}

fn write_pipe(pipe_name: &str, bytes: &[u8], flush: bool) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 64 {
        return Err("trusted-child E2E pipe message has an invalid size".to_owned());
    }
    let name = wide_null(OsStr::new(pipe_name))?;
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(E2E donor pipe)"));
    }
    let pipe = OwnedKernelHandle(raw);
    let mut written = 0u32;
    if unsafe {
        WriteFile(
            pipe.0,
            bytes.as_ptr(),
            u32::try_from(bytes.len()).expect("bounded message size fits u32"),
            &raw mut written,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("WriteFile(E2E donor pipe)"));
    }
    if written as usize != bytes.len() {
        return Err("trusted-child E2E donor pipe write was incomplete".to_owned());
    }
    if flush && unsafe { FlushFileBuffers(pipe.0) } == 0 {
        return Err("trusted-child E2E donor pipe flush failed".to_owned());
    }
    Ok(())
}

fn current_process_profile() -> Result<super::WitnessTokenProfile> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_error("OpenProcessToken(E2E donor)"));
    }
    let token = OwnedKernelHandle(token);
    crate::windows::witness_token_profile(token.0)
}

fn current_standard_user_batch_profile() -> Result<super::WitnessTokenProfile> {
    let profile = current_process_profile()?;
    if profile.token_type != "primary" || profile.session_id != 0 {
        return Err("E2E donor is not a primary Session-0 process".to_owned());
    }
    let expected = ExpectedWitnessIdentity::new(
        &profile.user_sid,
        profile.session_id,
        &profile.authentication_id,
    )?;
    profile
        .validate_primary_standard_user(&expected)
        .map_err(|error| {
            let diagnostic = serde_json::to_string(&profile)
                .unwrap_or_else(|serialize_error| format!("<serialize failed: {serialize_error}>"));
            format!("{error}: profile={diagnostic}")
        })?;
    let authentication_id = u64::from_str_radix(&profile.authentication_id, 16)
        .map_err(|_| "E2E donor authentication LUID is invalid".to_owned())?;
    let authentication_id = authentication_id.to_le_bytes();
    let luid = windows_sys::Win32::Foundation::LUID {
        LowPart: u32::from_le_bytes(
            authentication_id[..4]
                .try_into()
                .expect("LUID low part has four bytes"),
        ),
        HighPart: i32::from_le_bytes(
            authentication_id[4..]
                .try_into()
                .expect("LUID high part has four bytes"),
        ),
    };
    let mut data: *mut SECURITY_LOGON_SESSION_DATA = null_mut();
    let status = unsafe { LsaGetLogonSessionData(&raw const luid, &raw mut data) };
    if status != 0 || data.is_null() {
        return Err(format!(
            "LsaGetLogonSessionData(E2E donor) failed with NTSTATUS {status:#x}"
        ));
    }
    let logon_type = unsafe { (*data).LogonType };
    let logon_session = unsafe { (*data).Session };
    let free_status = unsafe { LsaFreeReturnBuffer(data.cast()) };
    if free_status != 0 {
        return Err(format!(
            "LsaFreeReturnBuffer(E2E donor) failed with NTSTATUS {free_status:#x}"
        ));
    }
    if logon_type != SECURITY_LOGON_TYPE::Batch.0 as u32 || logon_session != 0 {
        return Err("E2E donor is not an LSA Batch logon in Session 0".to_owned());
    }
    Ok(profile)
}

fn run_primary_donor() -> Result<()> {
    let root = root()?;
    let config: Config = read_json(&root.join(CONFIG_NAME))?;
    validate_e2e_nonce(&config.run_nonce)?;
    let profile = current_standard_user_batch_profile()?;
    if profile.user_sid != config.expected_user_sid {
        return Err("E2E donor SID differs from its fixed configuration".to_owned());
    }
    create_json(
        &root.join("from-donor").join(FACTS_NAME),
        &DonorFacts {
            nonce: config.run_nonce.clone(),
            user_sid: profile.user_sid,
            session_id: profile.session_id,
            authentication_id: profile.authentication_id,
        },
    )?;

    let phase1: CommandFile = wait_json(&command_path(&root, 1))?;
    validate_command(&phase1, &config.run_nonce, 1, "invalid-hello")?;
    // The server intentionally rejects this byte and may close immediately
    // after reading it, so a client-side flush would race that expected close.
    write_pipe(
        phase1
            .pipe_name
            .as_deref()
            .ok_or_else(|| "phase 1 pipe is missing".to_owned())?,
        &[0xff],
        false,
    )?;

    let phase2: CommandFile = wait_json(&command_path(&root, 2))?;
    validate_command(&phase2, &config.run_nonce, 2, "bootstrap")?;
    write_pipe(
        phase2
            .pipe_name
            .as_deref()
            .ok_or_else(|| "phase 2 pipe is missing".to_owned())?,
        &[0xa1],
        true,
    )?;

    let phase3: CommandFile = wait_json(&command_path(&root, 3))?;
    validate_command(&phase3, &config.run_nonce, 3, "wrong-process")?;
    let pipe = phase3
        .pipe_name
        .as_deref()
        .ok_or_else(|| "phase 3 pipe is missing".to_owned())?;
    let status = Command::new(sibling_broker()?)
        .arg("--trusted-witness-child")
        .arg(pipe)
        .status()
        .map_err(|error| format!("launch wrong-process child failed: {error}"))?;
    if status.success() {
        return Err("wrong-process child unexpectedly completed its handshake".to_owned());
    }

    let phase4: CommandFile = wait_json(&command_path(&root, 4))?;
    validate_command(&phase4, &config.run_nonce, 4, "release")?;
    if phase4.pipe_name.is_some() {
        return Err("release command unexpectedly contains a pipe".to_owned());
    }
    Ok(())
}

/// Run the exact feature-gated donor mode selected by the command line.
pub(crate) fn run_donor() -> Result<()> {
    let result = if std::env::args_os().len() == 1 {
        run_primary_donor()
    } else {
        Err("trusted-child E2E donor accepts no arguments".to_owned())
    };
    if let Err(error) = &result
        && let Ok(root) = root()
    {
        let message: String = error.chars().take(3072).collect();
        let _ = create_json(
            &root.join("from-donor").join(DONOR_ERROR_NAME),
            &DonorError { message },
        );
    }
    result
}

unsafe extern "system" fn control_handler(
    _control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    NO_ERROR
}

fn report_status(handle: SERVICE_STATUS_HANDLE, state: u32, win32: u32, specific: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: 0,
        dwWin32ExitCode: win32,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe { SetServiceStatus(handle, &raw const status) };
}

fn record_error(error: &str) {
    if let Ok(root) = root() {
        let bounded: String = error.chars().take(4096).collect();
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(ERROR_NAME))
            .and_then(|mut file| file.write_all(bounded.as_bytes()));
    }
}

fn service_error_with_donor_diagnostic(error: &str) -> String {
    let Ok(root) = root() else {
        return error.to_owned();
    };
    let donor_error_path = root.join("from-donor").join(DONOR_ERROR_NAME);
    let Ok(diagnostic) = read_json::<DonorError>(&donor_error_path) else {
        return error.to_owned();
    };
    format!("{error}; donor diagnostic: {}", diagnostic.message)
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null_mut()) };
    if handle.is_null() {
        return;
    }
    report_status(handle, SERVICE_START_PENDING, NO_ERROR, 0);
    report_status(handle, SERVICE_RUNNING, NO_ERROR, 0);
    match run_service_test() {
        Ok(()) => report_status(handle, SERVICE_STOPPED, NO_ERROR, 0),
        Err(error) => {
            record_error(&service_error_with_donor_diagnostic(&error));
            report_status(handle, SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1);
        }
    }
}

/// Enter the fixed SCM dispatcher for the feature-gated system test.
pub(crate) fn run_dispatcher() -> Result<()> {
    let mut name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(last_error("StartServiceCtrlDispatcherW(trusted-child E2E)"));
    }
    Ok(())
}
