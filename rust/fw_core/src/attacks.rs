//! Legitimate commander trajectory and attack transforms used by the console
//! to exercise the firewall.

use std::f64::consts::PI;

use crate::firewall::Command;

/// (mode, what it does, what the firewall should do)
pub const ATTACK_MODES: [(&str, &str, &str); 9] = [
    ("none", "legitimate traffic only", "FORWARDED"),
    ("overreach", "commander aims past the position limits", "CLAMPED"),
    ("overspeed", "velocity far above limit", "CLAMPED"),
    ("spike", "sudden position jump", "STEP_JUMP -> LOCKDOWN"),
    ("nan", "NaN position", "INVALID_VALUE -> LOCKDOWN"),
    ("flood", "many copies per tick", "FLOOD -> LOCKDOWN"),
    ("unknown_joint", "extra joint name", "MALFORMED -> LOCKDOWN"),
    ("replay", "5 s old timestamp", "REPLAY -> LOCKDOWN"),
    ("spoof", "second, non-allowlisted publisher", "UNAUTHORIZED_PUBLISHER -> LOCKDOWN"),
];

pub fn is_attack_mode(mode: &str) -> bool {
    ATTACK_MODES.iter().any(|(m, _, _)| *m == mode)
}

/// Smooth reference trajectory with a phase offset per joint.
pub fn sine_targets(t: f64, n_joints: usize, amplitude: f64, freq_hz: f64) -> Vec<f64> {
    (0..n_joints)
        .map(|i| amplitude * (2.0 * PI * freq_hz * t + i as f64 * PI / 4.0).sin())
        .collect()
}

/// Move each joint from current toward target by at most max_delta.
pub fn step_toward(current: &[f64], target: &[f64], max_delta: f64) -> Vec<f64> {
    current.iter().zip(target).map(|(c, t)| c + (t - c).clamp(-max_delta, max_delta)).collect()
}

/// Messages to publish this tick for an attack mode. `spoof` and `overreach`
/// are handled by the caller (extra publisher / larger amplitude).
pub fn apply_attack(mode: &str, msg: &Command, joint_index: usize, magnitude: f64,
                    flood_copies: usize) -> Vec<Command> {
    assert!(is_attack_mode(mode), "unknown attack mode {mode:?}");
    let j = joint_index % msg.names.len().max(1);
    let mut out = msg.clone();
    match mode {
        "overspeed" => {
            if out.velocity.is_empty() {
                out.velocity = vec![0.0; out.names.len()];
            }
            out.velocity[j] = magnitude * 2.0;
        }
        "spike" => out.position[j] += magnitude,
        "nan" => out.position[j] = f64::NAN,
        "unknown_joint" => {
            out.names.push("joint_99".into());
            out.position.push(0.0);
            if !out.velocity.is_empty() {
                out.velocity.push(0.0);
            }
        }
        "replay" => out.stamp = msg.stamp.map(|s| s - 5.0),
        "flood" => {
            return (0..flood_copies)
                .map(|k| Command { stamp: msg.stamp.map(|s| s + k as f64 * 1e-6), ..out.clone() })
                .collect();
        }
        _ => {}
    }
    vec![out]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Command {
        Command {
            names: vec!["a".into(), "b".into()],
            position: vec![0.1, 0.2],
            velocity: vec![0.0, 0.0],
            stamp: Some(100.0),
            ..Default::default()
        }
    }

    #[test]
    fn trajectory_helpers() {
        assert!(sine_targets(1.3, 4, 0.8, 0.2).iter().all(|v| v.abs() <= 0.8));
        let s = step_toward(&[0.0, 1.0], &[5.0, 0.95], 0.1);
        assert!((s[0] - 0.1).abs() < 1e-12 && (s[1] - 0.95).abs() < 1e-12);
    }

    #[test]
    fn every_mode_produces_messages() {
        for (mode, _, _) in ATTACK_MODES {
            assert!(!apply_attack(mode, &base(), 0, 3.0, 40).is_empty(), "{mode}");
        }
    }

    #[test]
    fn transforms() {
        assert!((apply_attack("spike", &base(), 1, 3.0, 1)[0].position[1] - 3.2).abs() < 1e-12);
        assert!(apply_attack("nan", &base(), 0, 3.0, 1)[0].position[0].is_nan());
        assert!(apply_attack("unknown_joint", &base(), 0, 3.0, 1)[0].names.contains(&"joint_99".to_string()));
        assert_eq!(apply_attack("replay", &base(), 0, 3.0, 1)[0].stamp, Some(95.0));
        assert_eq!(apply_attack("overspeed", &base(), 0, 3.0, 1)[0].velocity[0], 6.0);
        let flood = apply_attack("flood", &base(), 0, 3.0, 10);
        assert_eq!(flood.len(), 10);
        assert!(flood.windows(2).all(|w| w[1].stamp > w[0].stamp));
    }

    #[test]
    #[should_panic]
    fn unknown_mode_rejected() {
        apply_attack("bogus", &base(), 0, 3.0, 1);
    }
}
