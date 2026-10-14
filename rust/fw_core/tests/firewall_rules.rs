//! Port of test/test_firewall_rules.py: one test per rule plus lockdown logic.

use std::collections::HashMap;

use fw_core::firewall::*;
use fw_core::JointLimits;

fn names() -> Vec<String> {
    vec!["j1".into(), "j2".into()]
}

fn make(f: impl FnOnce(&mut FirewallConfig)) -> CommandFirewall {
    let mut cfg = FirewallConfig::new(names());
    cfg.limits = names()
        .into_iter()
        .map(|n| (n, JointLimits { position_min: -1.0, position_max: 1.0, velocity: 1.0, effort: 10.0 }))
        .collect::<HashMap<_, _>>();
    cfg.lockdown_threshold = 5;
    cfg.start_locked = false;
    f(&mut cfg);
    CommandFirewall::new(cfg)
}

fn cmd(pos: &[f64], t: f64) -> Command {
    Command { names: names(), position: pos.to_vec(), stamp: Some(t), source: "laptop".into(), ..Default::default() }
}

fn first_attack(v: &Verdict) -> &str {
    &v.incidents[0].attack
}

#[test]
fn valid_command_forwarded() {
    let mut f = make(|_| {});
    let v = f.inspect(&cmd(&[0.1, 0.1], 10.0), 10.0);
    assert_eq!(v.action, FORWARDED);
    assert_eq!(v.command.unwrap().position, vec![0.1, 0.1]);
    assert!(v.incidents.is_empty());
}

#[test]
fn reorders_to_configured_joint_order() {
    let mut f = make(|_| {});
    let c = Command { names: vec!["j2".into(), "j1".into()], ..cmd(&[0.2, 0.1], 10.0) };
    let out = f.inspect(&c, 10.0).command.unwrap();
    assert_eq!(out.names, names());
    assert_eq!(out.position, vec![0.1, 0.2]);
}

#[test]
fn malformed_dropped() {
    let cases: [(&[&str], &[f64], &str); 4] = [
        (&["j1", "j2", "j9"], &[0.0, 0.0, 0.0], "unknown"),
        (&["j1"], &[0.0], "missing"),
        (&["j1", "j1"], &[0.0, 0.0], "duplicate"),
        (&["j1", "j2"], &[0.0], "positions"),
    ];
    for (n, pos, why) in cases {
        let mut f = make(|_| {});
        let c = Command { names: n.iter().map(|s| s.to_string()).collect(), ..cmd(pos, 1.0) };
        let v = f.inspect(&c, 1.0);
        assert_eq!(v.action, DROPPED);
        assert_eq!(first_attack(&v), MALFORMED);
        assert!(v.incidents[0].detail.contains(why), "{why}");
    }
}

#[test]
fn missing_stamp_is_malformed() {
    let mut f = make(|_| {});
    let v = f.inspect(&Command { stamp: Some(0.0), ..cmd(&[0.0, 0.0], 1.0) }, 1.0);
    assert_eq!(first_attack(&v), MALFORMED);
}

#[test]
fn nan_and_inf_dropped() {
    let mut f = make(|_| {});
    assert_eq!(first_attack(&f.inspect(&cmd(&[f64::NAN, 0.0], 1.0), 1.0)), INVALID_VALUE);
    let c = Command { velocity: vec![f64::INFINITY, 0.0], ..cmd(&[0.0, 0.0], 1.1) };
    assert_eq!(f.inspect(&c, 1.1).action, DROPPED);
}

#[test]
fn position_clamped_by_default() {
    let mut f = make(|c| c.max_step = 10.0);
    let v = f.inspect(&cmd(&[1.5, -3.0], 1.0), 1.0);
    assert_eq!(v.action, CLAMPED);
    assert_eq!(v.command.unwrap().position, vec![1.0, -1.0]);
    assert_eq!(v.incidents[0].attack, LIMIT_VIOLATION);
}

#[test]
fn velocity_clamped() {
    let mut f = make(|_| {});
    let v = f.inspect(&Command { velocity: vec![5.0, -0.5], ..cmd(&[0.0, 0.0], 1.0) }, 1.0);
    assert_eq!(v.action, CLAMPED);
    assert_eq!(v.command.unwrap().velocity, vec![1.0, -0.5]);
}

#[test]
fn clamps_do_not_escalate_to_lockdown() {
    let mut f = make(|c| c.lockdown_threshold = 3);
    for i in 0..10 {
        let t = 1.0 + i as f64 * 0.05;
        let v = f.inspect(&Command { velocity: vec![5.0, 0.0], ..cmd(&[0.0, 0.0], t) }, t);
        assert_eq!(v.action, CLAMPED);
    }
    assert_eq!(f.mode, ARMED);
    assert_eq!(f.clamped, 10);
}

#[test]
fn limit_action_drop() {
    let mut f = make(|c| {
        c.limit_action = "drop".into();
        c.max_step = 10.0;
    });
    assert_eq!(f.inspect(&cmd(&[1.5, 0.0], 1.0), 1.0).action, DROPPED);
}

#[test]
fn step_jump_dropped_against_last_accepted() {
    let mut f = make(|_| {});
    f.inspect(&cmd(&[0.0, 0.0], 1.0), 1.0);
    let v = f.inspect(&cmd(&[0.5, 0.0], 1.05), 1.05);
    assert_eq!(v.action, DROPPED);
    assert_eq!(first_attack(&v), STEP_JUMP);
    assert_eq!(f.inspect(&cmd(&[0.15, 0.0], 1.1), 1.1).action, FORWARDED);
}

#[test]
fn step_uses_robot_state_when_no_command_yet() {
    let mut f = make(|_| {});
    f.observe_state(&names(), &[0.8, 0.0], 1.0);
    assert_eq!(first_attack(&f.inspect(&cmd(&[0.0, 0.0], 1.0), 1.0)), STEP_JUMP);
}

#[test]
fn replay_stale_future_and_nonmonotonic() {
    let mut f = make(|_| {});
    let at = |pos: [f64; 2], stamp: f64| Command { stamp: Some(stamp), ..cmd(&pos, stamp) };
    assert_eq!(first_attack(&f.inspect(&at([0.0, 0.0], 5.0), 10.0)), REPLAY);
    assert_eq!(f.inspect(&at([0.0, 0.0], 11.0), 10.0).action, DROPPED);
    assert_eq!(f.inspect(&at([0.0, 0.0], 10.0), 10.0).action, FORWARDED);
    assert_eq!(f.inspect(&at([0.0, 0.0], 9.9), 10.1).action, DROPPED);
}

#[test]
fn flood_triggers_drops_then_lockdown() {
    let mut f = make(|c| c.lockdown_threshold = 5);
    let verdicts: Vec<Verdict> = (0..30).map(|i| f.inspect(&cmd(&[0.0, 0.0], 1.0 + i as f64 * 1e-6), 1.0)).collect();
    assert!(verdicts[..10].iter().all(|v| v.action == FORWARDED));
    assert!(verdicts[10..].iter().all(|v| v.action == DROPPED));
    let attacks: Vec<&str> = verdicts.iter().flat_map(|v| v.incidents.iter().map(|i| i.attack.as_str())).collect();
    assert!(attacks.contains(&FLOOD) && attacks.contains(&LOCKDOWN_ENTERED));
    assert_eq!(f.mode, LOCKDOWN);
}

#[test]
fn incident_reports_are_rate_limited_and_flushed() {
    let mut f = make(|c| c.lockdown_threshold = 1000);
    let mut reports = Vec::new();
    for i in 0..10 {
        let t = 1.0 + i as f64 * 0.01;
        reports.extend(f.inspect(&cmd(&[f64::NAN, 0.0], t), t).incidents);
    }
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].count, 1);
    let flushed = f.flush(2.5);
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].count, 9);
    assert_eq!(f.counters[INVALID_VALUE], 10);
}

#[test]
fn lockdown_blocks_everything_and_rearm_needs_fresh_safe_state() {
    let mut f = make(|c| c.start_locked = true);
    assert_eq!(f.mode, LOCKDOWN);
    let blocked = f.inspect(&cmd(&[0.0, 0.0], 1.0), 1.0);
    assert_eq!(blocked.action, DROPPED);
    assert!(blocked.incidents.is_empty());
    assert_eq!(f.counters[BLOCKED_IN_LOCKDOWN], 1);
    let (ok, msg) = f.rearm(1.0);
    assert!(!ok && msg.contains("no fresh"));
    f.observe_state(&names(), &[0.3, 0.0], 1.0);
    assert!(f.rearm(1.1).0);
    assert_eq!(f.mode, ARMED);
    assert_eq!(f.inspect(&cmd(&[0.35, 0.0], 1.2), 1.2).action, FORWARDED);
    assert_eq!(f.inspect(&cmd(&[0.0, 0.0], 1.3), 1.3).action, DROPPED);
}

#[test]
fn rearm_refused_when_robot_outside_limits() {
    let mut f = make(|c| {
        c.start_locked = true;
        c.state_margin = 1.0;
    });
    f.observe_state(&names(), &[1.2, 0.0], 1.0);
    let (ok, msg) = f.rearm(1.0);
    assert!(!ok && msg.contains("outside limits"));
}

#[test]
fn state_guard_is_critical() {
    let mut f = make(|_| {});
    let attacks: Vec<String> = f.observe_state(&names(), &[1.5, 0.0], 1.0).into_iter().map(|i| i.attack).collect();
    assert_eq!(attacks, vec![STATE_GUARD.to_string(), LOCKDOWN_ENTERED.to_string()]);
    assert_eq!(f.mode, LOCKDOWN);
}

#[test]
fn external_alerts() {
    let mut f = make(|_| {});
    f.report_external(UNAUTHORIZED_PUBLISHER, "/evil", 1.0, "", false);
    assert_eq!(f.mode, ARMED);
    let incidents = f.report_external(ROGUE_DEVICE, "2 publishers", 1.1, "", true);
    assert_eq!(f.mode, LOCKDOWN);
    assert!(incidents.last().unwrap().summary().contains("LOCKDOWN"));
}

#[test]
fn hold_command_uses_last_accepted_with_zero_velocity() {
    let mut f = make(|_| {});
    assert!(f.hold_command(1.0).is_none());
    f.inspect(&cmd(&[0.1, 0.2], 1.0), 1.0);
    let hold = f.hold_command(2.0).unwrap();
    assert_eq!(hold.position, vec![0.1, 0.2]);
    assert_eq!(hold.velocity, vec![0.0, 0.0]);
}

#[test]
fn summary_and_json() {
    let inc = Incident {
        time: 1.0,
        attack: FLOOD.into(),
        severity: "WARN".into(),
        action: DROPPED.into(),
        count: 812,
        detail: "850 Hz exceeds 50 Hz limit".into(),
        source: "attacker".into(),
        mode: LOCKDOWN.into(),
    };
    let text = inc.summary();
    assert!(text.starts_with("FLOOD: 850 Hz") && text.contains("812 msg(s) dropped"));
    assert!(text.ends_with("robot holding last safe pose"));
    let json: serde_json::Value = serde_json::from_str(&inc.to_json()).unwrap();
    assert_eq!(json["summary"], text);
    assert_eq!(json["count"], 812);
    assert_eq!(json["mitre_technique_id"], "T0814");
    assert_eq!(json["mitre_tactic"], "Inhibit Response Function");
}

#[test]
fn unauthorized_publisher_dropped_per_message() {
    let mut f = make(|_| {});
    let evil = Command { source: "intruder".into(), ..cmd(&[0.0, 0.0], 1.0) };
    let v = f.inspect_from(&evil, 1.0, false);
    assert_eq!(v.action, DROPPED);
    assert_eq!(first_attack(&v), UNAUTHORIZED_PUBLISHER);
    assert_eq!(v.incidents[0].source, "intruder");
    // A persistent intruder cannot force a lockdown; legit traffic keeps flowing.
    for i in 1..100 {
        let t = 1.0 + i as f64 * 0.001;
        f.inspect_from(&Command { stamp: Some(t), ..evil.clone() }, t, false);
    }
    assert_eq!(f.mode, ARMED);
    assert_eq!(f.inspect(&cmd(&[0.05, 0.0], 1.2), 1.2).action, FORWARDED);
}

#[test]
fn unidentified_publisher_dropped_silently() {
    let mut f = make(|_| {});
    let v = f.drop_unidentified(1.0);
    assert_eq!(v.action, DROPPED);
    assert!(v.incidents.is_empty());
    assert_eq!(f.counters[UNIDENTIFIED_PUBLISHER], 1);
    assert_eq!(f.mode, ARMED);
}
