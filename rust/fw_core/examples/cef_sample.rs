//! Print sample SIEM lines (CEF and JSON) for the docs.
//!   cargo run -p fw_core --example cef_sample
use fw_core::firewall::*;
use fw_core::siem::{syslog_frame, to_cef};

fn main() {
    let inc = Incident {
        time: 1_791_900_000.25,
        attack: UNAUTHORIZED_PUBLISHER.into(),
        severity: "WARN".into(),
        action: DROPPED.into(),
        count: 11,
        detail: "command from a publisher that is not allowlisted".into(),
        source: "intruder".into(),
        mode: ARMED.into(),
    };
    let cef = to_cef(&inc, "nanopi-r5s", "0.3.0", 1_791_900_000_250);
    println!("{}", syslog_frame(&inc, "2026-10-14T06:40:00.250Z", "nanopi-r5s", &cef));
    println!("{}", inc.to_json());
}
