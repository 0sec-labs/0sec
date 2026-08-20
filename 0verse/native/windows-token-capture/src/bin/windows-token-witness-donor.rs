#[cfg(windows)]
fn main() {
    if let Err(error) = zeroverse_windows_token_capture::windows::run_trusted_child_e2e_donor() {
        eprintln!("trusted-child CI donor failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the trusted-child CI donor is supported only on Windows");
    std::process::exit(1);
}
