#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--console-self-test") if args.len() == 2 => {
            zeroverse_windows_token_capture::windows::pipe::console_self_test()
        }
        Some("--trusted-witness-child") if args.len() == 3 => {
            zeroverse_windows_token_capture::windows::run_trusted_witness_child(&args[2])
        }
        None => zeroverse_windows_token_capture::windows::service::run_dispatcher(),
        _ => Err(
            "usage: windows-token-broker [--console-self-test | --trusted-witness-child PIPE]"
                .to_owned(),
        ),
    };
    if let Err(error) = result {
        eprintln!("Windows token broker boundary failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows token broker is supported only on Windows");
    std::process::exit(1);
}
