#[cfg(windows)]
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("the trusted-child CI service accepts no arguments");
        std::process::exit(2);
    }
    if let Err(error) = zeroverse_windows_token_capture::windows::run_trusted_child_e2e_dispatcher()
    {
        eprintln!("trusted-child CI dispatcher failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the trusted-child CI service is supported only on Windows");
    std::process::exit(1);
}
