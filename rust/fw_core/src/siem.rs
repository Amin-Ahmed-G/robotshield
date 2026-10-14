//! SIEM output formats for incidents.
//!
//! - CEF (Common Event Format): read natively by Splunk, Microsoft Sentinel,
//!   IBM QRadar and ArcSight.
//! - RFC 5424 syslog framing around either CEF or the JSON incident line.

use crate::firewall::Incident;
use crate::mitre;

/// CEF severity (0-10) for an incident.
pub fn cef_severity(inc: &Incident) -> u8 {
    match (inc.severity.as_str(), inc.action.as_str()) {
        (_, _) if inc.attack == crate::firewall::LOCKDOWN_ENTERED => 9,
        ("ERROR", _) => 8,
        (_, "DROPPED") => 6,
        (_, "CLAMPED") => 4,
        _ => 5,
    }
}

/// Syslog severity (RFC 5424): 3 error, 4 warning, 6 informational.
pub fn syslog_severity(inc: &Incident) -> u8 {
    match inc.severity.as_str() {
        "ERROR" => 3,
        "WARN" => 4,
        _ => 6,
    }
}

fn esc_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn esc_ext(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\r', "\\r").replace('\n', "\\n")
}

/// One CEF:0 line. `time_ms` is the event time in Unix milliseconds.
pub fn to_cef(inc: &Incident, host: &str, version: &str, time_ms: i64) -> String {
    let mut ext = vec![
        format!("rt={time_ms}"),
        format!("dvchost={}", esc_ext(host)),
        format!("act={}", esc_ext(&inc.action)),
        format!("cnt={}", inc.count),
        format!("msg={}", esc_ext(&inc.summary())),
        format!("cs1Label=firewallMode cs1={}", esc_ext(&inc.mode)),
    ];
    if !inc.source.is_empty() {
        ext.push(format!("suser={}", esc_ext(&inc.source)));
    }
    if let Some(t) = mitre::technique(&inc.attack) {
        ext.push(format!("cs2Label=mitreTechniqueId cs2={}", t.id));
        ext.push(format!("cs3Label=mitreTechnique cs3={}", esc_ext(t.name)));
        ext.push(format!("cs4Label=mitreTactic cs4={}", esc_ext(t.tactic)));
        ext.push(format!("cs5Label=mitreFramework cs5={}", esc_ext(mitre::ATTACK_VERSION)));
    }
    format!(
        "CEF:0|RoboShield|robot_firewall|{}|{}|{}|{}|{}",
        esc_header(version),
        esc_header(&inc.attack),
        esc_header(&inc.detail),
        cef_severity(inc),
        ext.join(" ")
    )
}

/// RFC 5424 syslog message (facility local4) carrying `msg`.
/// `timestamp` must be RFC 3339, e.g. 2026-10-14T12:30:00.123Z.
pub fn syslog_frame(inc: &Incident, timestamp: &str, host: &str, msg: &str) -> String {
    let pri = 20 * 8 + syslog_severity(inc) as u16;
    let host = if host.is_empty() { "-" } else { host };
    format!("<{pri}>1 {timestamp} {host} robot_firewall - {} - {msg}", inc.attack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::*;

    fn inc(attack: &str, action: &str, detail: &str) -> Incident {
        Incident {
            time: 1.0,
            attack: attack.into(),
            severity: "WARN".into(),
            action: action.into(),
            count: 3,
            detail: detail.into(),
            source: "intruder".into(),
            mode: ARMED.into(),
        }
    }

    #[test]
    fn cef_has_header_and_mitre_fields() {
        let line = to_cef(&inc(UNAUTHORIZED_PUBLISHER, DROPPED, "not allowlisted"), "nanopi", "0.3.0", 1_700_000_000_000);
        assert!(line.starts_with("CEF:0|RoboShield|robot_firewall|0.3.0|UNAUTHORIZED_PUBLISHER|not allowlisted|6|"));
        assert!(line.contains("cs2Label=mitreTechniqueId cs2=T1692.001"));
        assert!(line.contains("cs4Label=mitreTactic cs4=Impair Process Control"));
        assert!(line.contains("suser=intruder"));
        assert!(line.contains("cnt=3"));
    }

    #[test]
    fn cef_escapes_header_and_extension() {
        let line = to_cef(&inc(MALFORMED, DROPPED, "a|b\\c"), "h", "1", 0);
        assert!(line.contains("|a\\|b\\\\c|"), "{line}");
        let line = to_cef(&inc(MALFORMED, DROPPED, "x=1\nnext"), "h", "1", 0);
        assert!(line.contains("msg=MALFORMED: x\\=1\\nnext"), "{line}");
        assert!(!line.contains('\n'));
    }

    #[test]
    fn untagged_incidents_have_no_mitre_fields() {
        let line = to_cef(&inc(LOCKDOWN_ENTERED, ALERTED, "20 incidents"), "h", "1", 0);
        assert!(!line.contains("mitreTechniqueId"));
        assert!(line.contains("|9|"), "lockdown is high severity: {line}");
    }

    #[test]
    fn syslog_framing() {
        let mut i = inc(FLOOD, DROPPED, "rate");
        let f = syslog_frame(&i, "2026-10-14T12:00:00.000Z", "nanopi", "MSG");
        assert_eq!(f, "<164>1 2026-10-14T12:00:00.000Z nanopi robot_firewall - FLOOD - MSG");
        i.severity = "ERROR".into();
        assert!(syslog_frame(&i, "t", "", "m").starts_with("<163>1 t - robot_firewall"));
    }
}
