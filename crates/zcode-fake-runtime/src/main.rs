use std::io::{self, BufRead, Write};
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let mut out = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let id = v.get("id").cloned().unwrap_or(serde_json::Value::from(1));
        if mode == "malformed" {
            writeln!(out, "{{").unwrap();
            out.write_all(b"{\"method\":\"future/event\",\"params\":{\"raw\":true}}\n")
                .unwrap();
            out.flush().unwrap();
            break;
        } else if mode == "out-of-order" {
            out.write_all(b"{\"method\":\"turn/completed\",\"params\":{}}\n")
                .unwrap();
            out.write_all(b"{\"method\":\"turn/started\",\"params\":{}}\n")
                .unwrap();
            out.flush().unwrap();
            break;
        } else if mode == "interleaved" {
            writeln!(out, r#"{{"method":"turn/started","params":{{}}}}"#).unwrap();
            writeln!(
                out,
                r#"{{"method":"permission/request","params":{{"request_id":"p1"}}}}"#
            )
            .unwrap();
            writeln!(out, r#"{{"id":{},"result":{{"ok":true}}}}"#, id).unwrap();
            writeln!(out, r#"{{"method":"turn/completed","params":{{}}}}"#).unwrap();
            out.flush().unwrap();
        } else {
            writeln!(out, r#"{{"id":{},"result":{{"ok":true}}}}"#, id).unwrap();
            out.flush().unwrap();
        }
    }
}
