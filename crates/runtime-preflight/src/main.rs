use std::time::Duration;
fn main() {
    let result =
        runtime_preflight::run_from_env(Duration::from_secs(2)).expect("preflight read failed");
    println!(
        "{}",
        serde_json::to_string(&result).expect("preflight serialization failed")
    );
}
