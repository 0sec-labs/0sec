#[cfg(windows)]
fn main() {
    if let Err(error) = zeroverse_windows_token_capture::windows::run() {
        eprintln!("windows token capture fixture failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows token capture fixture is supported only on Windows");
    std::process::exit(1);
}
