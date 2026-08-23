use std::{env, path::PathBuf};
fn main() {
    let mut a = env::args().skip(1);
    if a.next().as_deref() != Some("--shim") {
        eprintln!("zcode-supervisor-shim: --shim required");
        std::process::exit(2);
    }
    let control = PathBuf::from(a.next().unwrap());
    let state = PathBuf::from(a.next().unwrap());
    let program = a.next().unwrap();
    let args: Vec<String> = a.collect();
    let fd: i32 = env::var("ZCODE_SHIM_HANDSHAKE_FD")
        .unwrap()
        .parse()
        .unwrap();
    if let Err(error) = zcode_supervisor::shim::run(fd, &control, &state, &program, &args) {
        eprintln!("zcode-supervisor-shim: {error}");
        std::process::exit(1);
    }
}
