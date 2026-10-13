//! Runs gateway / network debugging commands in the background and streams
//! the exact command line plus its output into the console log.

use std::process::Command;
use std::time::Duration;

use crate::state::{lock, LogKind, SharedRef};

/// How to judge a finished command.
#[derive(Clone, Copy)]
pub enum Expect {
    Success,
    /// The command is expected to FAIL (e.g. "robot must be unreachable").
    Failure,
}

pub fn ssh_args(target: &str, remote: &str) -> Vec<String> {
    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, remote]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Host part of an ssh target like `ubuntu@192.168.1.60`.
pub fn host_of(target: &str) -> &str {
    target.rsplit('@').next().unwrap_or(target)
}

pub fn display(argv: &[String]) -> String {
    argv.iter()
        .map(|a| if a.contains(' ') { format!("'{a}'") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn run(shared: &SharedRef, label: &str, argv: Vec<String>, expect: Expect) {
    let shared = shared.clone();
    let label = label.to_string();
    lock(&shared).push_log(LogKind::Cmd, format!("$ {}", display(&argv)));
    std::thread::spawn(move || {
        let result = Command::new(&argv[0]).args(&argv[1..]).output();
        let mut s = lock(&shared);
        match result {
            Err(e) => s.push_log(LogKind::Fail, format!("{label}: could not run {}: {e}", argv[0])),
            Ok(out) => {
                let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
                if !text.trim().is_empty() {
                    s.push_log(LogKind::Out, text.trim_end().to_string());
                }
                let ok = match expect {
                    Expect::Success => out.status.success(),
                    Expect::Failure => !out.status.success(),
                };
                let verdict = match (expect, ok) {
                    (Expect::Success, true) => format!("PASS {label}"),
                    (Expect::Success, false) => format!("FAIL {label} (exit {})", out.status.code().unwrap_or(-1)),
                    (Expect::Failure, true) => format!("PASS {label} (command failed as it should)"),
                    (Expect::Failure, false) => format!("FAIL {label}: command succeeded but must not"),
                };
                s.push_log(if ok { LogKind::Pass } else { LogKind::Fail }, verdict);
            }
        }
    });
}

/// Poll `f` until it returns Some or the timeout passes.
pub fn wait_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = std::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if std::time::Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
