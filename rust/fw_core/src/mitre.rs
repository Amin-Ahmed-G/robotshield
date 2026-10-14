//! MITRE ATT&CK for ICS tags for firewall incidents.
//!
//! Verified against the official STIX data (ics-attack collection v20).
//! T0855 / T0856 were revoked in that release; their replacements are
//! T1692.001 Command Message and T1692.002 Reporting Message.

use crate::firewall::*;

pub const ATTACK_VERSION: &str = "ATT&CK for ICS v20";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    /// Primary tactic for this detection.
    pub tactic: &'static str,
}

const COMMAND_MESSAGE: Technique =
    Technique { id: "T1692.001", name: "Command Message", tactic: "Impair Process Control" };

/// Technique for an incident type; `None` for firewall responses (LOCKDOWN,
/// BLOCKED_IN_LOCKDOWN) and internal bookkeeping.
pub fn technique(attack: &str) -> Option<Technique> {
    Some(match attack {
        MALFORMED | INVALID_VALUE | LIMIT_VIOLATION | STEP_JUMP | REPLAY | UNAUTHORIZED_PUBLISHER => COMMAND_MESSAGE,
        FLOOD => Technique { id: "T0814", name: "Denial of Service", tactic: "Inhibit Response Function" },
        ROGUE_DEVICE => Technique { id: "T0848", name: "Rogue Master", tactic: "Initial Access" },
        STATE_SPOOFING => Technique { id: "T1692.002", name: "Reporting Message", tactic: "Evasion" },
        STATE_GUARD => Technique { id: "T0880", name: "Loss of Safety", tactic: "Impact" },
        STATE_STALE => Technique { id: "T0815", name: "Denial of View", tactic: "Impact" },
        NETWORK_PROBE => Technique { id: "T0846", name: "Remote System Discovery", tactic: "Discovery" },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_attack_type_is_tagged() {
        for attack in [MALFORMED, INVALID_VALUE, LIMIT_VIOLATION, STEP_JUMP, REPLAY, UNAUTHORIZED_PUBLISHER,
                       FLOOD, ROGUE_DEVICE, STATE_SPOOFING, STATE_GUARD, STATE_STALE, NETWORK_PROBE] {
            assert!(technique(attack).is_some(), "{attack} has no MITRE tag");
        }
    }

    #[test]
    fn responses_are_not_tagged() {
        for t in [LOCKDOWN_ENTERED, BLOCKED_IN_LOCKDOWN, UNIDENTIFIED_PUBLISHER, "REARM"] {
            assert!(technique(t).is_none(), "{t}");
        }
    }

    #[test]
    fn known_mappings() {
        assert_eq!(technique(FLOOD).unwrap().id, "T0814");
        assert_eq!(technique(ROGUE_DEVICE).unwrap().id, "T0848");
        assert_eq!(technique(STATE_SPOOFING).unwrap().id, "T1692.002");
        assert_eq!(technique(UNAUTHORIZED_PUBLISHER).unwrap().tactic, "Impair Process Control");
    }
}
