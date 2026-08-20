#[cfg(windows)]
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("the CI LocalSystem cleanup service accepts no arguments");
        std::process::exit(2);
    }
    if let Err(error) =
        zeroverse_windows_token_capture::windows::store_e2e_service::run_cleanup_dispatcher()
    {
        eprintln!("Windows store cleanup dispatcher failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the CI LocalSystem cleanup service is supported only on Windows");
    std::process::exit(1);
}
