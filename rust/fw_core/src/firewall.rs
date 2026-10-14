//! Application-layer rule engine for the robot command firewall.
//!
//! Every joint command from the untrusted network goes through
//! [`CommandFirewall::inspect`], which forwards it (possibly clamped) or drops
//! it and returns any incidents to report. Repeated incidents escalate to
//! LOCKDOWN: all input is dropped and the robot is held at its last safe pose
//! until an operator re-arms.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::limits::{Field, JointLimits};
use crate::rate::{RateTracker, TokenBucket};

// Modes
pub const ARMED: &str = "ARMED";
pub const LOCKDOWN: &str = "LOCKDOWN";

// Verdict actions
pub const FORWARDED: &str = "FORWARDED";
pub const CLAMPED: &str = "CLAMPED";
pub const DROPPED: &str = "DROPPED";
pub const ALERTED: &str = "ALERTED";

// Attack / incident types (strings are the wire format on /firewall/events)
pub const MALFORMED: &str = "MALFORMED";
pub const INVALID_VALUE: &str = "INVALID_VALUE";
pub const LIMIT_VIOLATION: &str = "LIMIT_VIOLATION";
pub const STEP_JUMP: &str = "STEP_JUMP";
pub const FLOOD: &str = "FLOOD";
pub const REPLAY: &str = "REPLAY";
pub const UNAUTHORIZED_PUBLISHER: &str = "UNAUTHORIZED_PUBLISHER";
pub const ROGUE_DEVICE: &str = "ROGUE_DEVICE_ON_ROBOT_LAN";
/// Extra publishers on the robot's state topic: someone faking telemetry.
pub const STATE_SPOOFING: &str = "STATE_SPOOFING";
pub const STATE_GUARD: &str = "STATE_GUARD";
pub const STATE_STALE: &str = "STATE_STALE";
pub const NETWORK_PROBE: &str = "NETWORK_PROBE";
pub const BLOCKED_IN_LOCKDOWN: &str = "BLOCKED_IN_LOCKDOWN";
/// Sender not yet mapped to a ROS node (discovery race); counted, not reported.
pub const UNIDENTIFIED_PUBLISHER: &str = "UNIDENTIFIED_PUBLISHER";
pub const LOCKDOWN_ENTERED: &str = "LOCKDOWN";

fn is_critical(attack: &str) -> bool {
    matches!(attack, ROGUE_DEVICE | STATE_SPOOFING | STATE_GUARD | LOCKDOWN_ENTERED)
}

/// Transport-independent joint command (maps to sensor_msgs/JointState).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Command {
    pub names: Vec<String>,
    pub position: Vec<f64>,
    pub velocity: Vec<f64>,
    pub effort: Vec<f64>,
    /// Header stamp in seconds; `None`/0 means unstamped.
    pub stamp: Option<f64>,
    pub source: String,
}

impl Command {
    pub fn values(&self, field: Field) -> &[f64] {
        match field {
            Field::Position => &self.position,
            Field::Velocity => &self.velocity,
            Field::Effort => &self.effort,
        }
    }

    fn values_mut(&mut self, field: Field) -> &mut Vec<f64> {
        match field {
            Field::Position => &mut self.position,
            Field::Velocity => &mut self.velocity,
            Field::Effort => &mut self.effort,
        }
    }

    fn has_stamp(&self) -> bool {
        self.stamp.is_some_and(|s| s != 0.0)
    }
}

/// One reportable security/safety event (possibly aggregating many messages).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Incident {
    pub time: f64,
    pub attack: String,
    pub severity: String,
    pub action: String,
    pub count: u64,
    pub detail: String,
    pub source: String,
    pub mode: String,
}

impl Incident {
    pub fn summary(&self) -> String {
        let mut text = format!("{}: {}", self.attack, self.detail);
        if !self.source.is_empty() {
            text += &format!(" (source: {})", self.source);
        }
        if self.action == DROPPED || self.action == CLAMPED {
            text += &format!("; {} msg(s) {}", self.count, self.action.to_lowercase());
        }
        if self.mode == LOCKDOWN {
            text += " -> LOCKDOWN, robot holding last safe pose";
        }
        text
    }

    /// JSON line for the incident log and SIEM (same fields as the Python
    /// version). MITRE ATT&CK for ICS fields are flat for easy SIEM mapping.
    pub fn to_json(&self) -> String {
        let mut value = serde_json::to_value(self).expect("incident serializes");
        value["summary"] = serde_json::Value::String(self.summary());
        if let Some(t) = crate::mitre::technique(&self.attack) {
            value["mitre_technique_id"] = t.id.into();
            value["mitre_technique"] = t.name.into();
            value["mitre_tactic"] = t.tactic.into();
            value["mitre_framework"] = crate::mitre::ATTACK_VERSION.into();
        }
        value.to_string()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub action: &'static str,
    pub command: Option<Command>,
    pub incidents: Vec<Incident>,
}

#[derive(Clone, Debug)]
pub struct FirewallConfig {
    pub joint_names: Vec<String>,
    pub limits: HashMap<String, JointLimits>,
    pub max_step: f64,
    pub max_rate_hz: f64,
    pub burst: f64,
    pub max_age_s: f64,
    pub max_future_s: f64,
    pub require_stamp: bool,
    /// "clamp" or "drop".
    pub limit_action: String,
    pub lockdown_threshold: usize,
    pub lockdown_window_s: f64,
    pub report_interval_s: f64,
    pub state_margin: f64,
    pub state_timeout_s: f64,
    pub start_locked: bool,
}

impl FirewallConfig {
    pub fn new(joint_names: Vec<String>) -> Self {
        Self {
            joint_names,
            limits: HashMap::new(),
            max_step: 0.2,
            max_rate_hz: 50.0,
            burst: 10.0,
            max_age_s: 0.5,
            max_future_s: 0.2,
            require_stamp: true,
            limit_action: "clamp".into(),
            lockdown_threshold: 20,
            lockdown_window_s: 2.0,
            report_interval_s: 1.0,
            state_margin: 0.05,
            state_timeout_s: 0.5,
            start_locked: true,
        }
    }
}

/// Status snapshot published as JSON on /firewall/status.
#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub mode: String,
    pub lockdown_reason: String,
    pub lockdown_since: Option<f64>,
    pub forwarded: u64,
    pub clamped: u64,
    pub dropped: u64,
    pub input_rate_hz: f64,
    pub robot_state_fresh: bool,
    pub counters: BTreeMap<String, u64>,
}

/// Stateful rule engine; not thread safe (callers hold a lock).
pub struct CommandFirewall {
    pub cfg: FirewallConfig,
    pub mode: &'static str,
    pub lockdown_reason: String,
    pub lockdown_since: Option<f64>,
    bucket: TokenBucket,
    input_rate: RateTracker,
    pub counters: BTreeMap<String, u64>,
    pub forwarded: u64,
    pub clamped: u64,
    pub dropped: u64,
    pub last_accepted: Option<Vec<f64>>,
    last_stamp: Option<f64>,
    pub state: Option<HashMap<String, f64>>,
    state_time: Option<f64>,
    recent: VecDeque<f64>,
    pending: HashMap<String, u64>,
    pending_meta: HashMap<String, (String, String, String)>,
    last_report: HashMap<String, f64>,
}

impl CommandFirewall {
    pub fn new(mut cfg: FirewallConfig) -> Self {
        for name in &cfg.joint_names {
            cfg.limits.entry(name.clone()).or_default();
        }
        let locked = cfg.start_locked;
        Self {
            bucket: TokenBucket::new(cfg.max_rate_hz, cfg.burst),
            cfg,
            mode: if locked { LOCKDOWN } else { ARMED },
            lockdown_reason: if locked { "startup: waiting for operator re-arm".into() } else { String::new() },
            lockdown_since: None,
            input_rate: RateTracker::new(1.0),
            counters: BTreeMap::new(),
            forwarded: 0,
            clamped: 0,
            dropped: 0,
            last_accepted: None,
            last_stamp: None,
            state: None,
            state_time: None,
            recent: VecDeque::new(),
            pending: HashMap::new(),
            pending_meta: HashMap::new(),
            last_report: HashMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Incident bookkeeping
    // ------------------------------------------------------------------
    #[allow(clippy::too_many_arguments)]
    fn record(&mut self, attack: &str, detail: &str, action: &str, now: f64, source: &str,
              escalate: bool, critical: bool, report: bool) -> Vec<Incident> {
        let mut incidents = Vec::new();
        *self.counters.entry(attack.into()).or_insert(0) += 1;
        if !report {
            return incidents;
        }
        *self.pending.entry(attack.into()).or_insert(0) += 1;
        self.pending_meta.insert(attack.into(), (detail.into(), action.into(), source.into()));

        let due = self.last_report.get(attack).is_none_or(|last| now - last >= self.cfg.report_interval_s);
        if due {
            incidents.push(self.emit(attack, now));
        }

        if self.mode == ARMED {
            if critical {
                incidents.push(self.enter_lockdown(format!("{attack}: {detail}"), now));
            } else if escalate {
                self.recent.push_back(now);
                while self.recent.front().is_some_and(|t| now - t > self.cfg.lockdown_window_s) {
                    self.recent.pop_front();
                }
                if self.recent.len() >= self.cfg.lockdown_threshold {
                    let reason = format!("{} incidents in {:.1}s (latest: {attack})",
                                         self.recent.len(), self.cfg.lockdown_window_s);
                    incidents.push(self.enter_lockdown(reason, now));
                }
            }
        }
        incidents
    }

    fn emit(&mut self, attack: &str, now: f64) -> Incident {
        let (detail, action, source) = self.pending_meta.get(attack).cloned().unwrap_or_default();
        let count = self.pending.remove(attack).unwrap_or(0);
        self.last_report.insert(attack.into(), now);
        Incident {
            time: now,
            attack: attack.into(),
            severity: if is_critical(attack) { "ERROR" } else { "WARN" }.into(),
            action,
            count,
            detail,
            source,
            mode: self.mode.into(),
        }
    }

    /// Report aggregated counts that were held back by rate limiting.
    pub fn flush(&mut self, now: f64) -> Vec<Incident> {
        let mut due: Vec<String> = self
            .pending
            .iter()
            .filter(|(a, n)| **n > 0 && self.last_report.get(*a).is_none_or(|t| now - t >= self.cfg.report_interval_s))
            .map(|(a, _)| a.clone())
            .collect();
        due.sort();
        due.iter().map(|a| self.emit(a, now)).collect()
    }

    fn enter_lockdown(&mut self, reason: String, now: f64) -> Incident {
        self.mode = LOCKDOWN;
        self.lockdown_reason = reason.clone();
        self.lockdown_since = Some(now);
        *self.counters.entry(LOCKDOWN_ENTERED.into()).or_insert(0) += 1;
        Incident {
            time: now,
            attack: LOCKDOWN_ENTERED.into(),
            severity: "ERROR".into(),
            action: ALERTED.into(),
            count: 1,
            detail: reason,
            source: String::new(),
            mode: LOCKDOWN.into(),
        }
    }

    fn drop_cmd(&mut self, attack: &str, detail: &str, now: f64, source: &str,
                escalate: bool, report: bool) -> Verdict {
        self.dropped += 1;
        let incidents = self.record(attack, detail, DROPPED, now, source, escalate, false, report);
        Verdict { action: DROPPED, command: None, incidents }
    }

    // ------------------------------------------------------------------
    // Command inspection
    // ------------------------------------------------------------------
    pub fn inspect(&mut self, cmd: &Command, now: f64) -> Verdict {
        self.inspect_from(cmd, now, true)
    }

    /// Like [`Self::inspect`], for gateways that can attribute each message to
    /// its publisher: `authorized == false` drops it as UNAUTHORIZED_PUBLISHER.
    pub fn inspect_from(&mut self, cmd: &Command, now: f64, authorized: bool) -> Verdict {
        self.input_rate.tick(now);
        let src = cmd.source.as_str();

        if self.mode == LOCKDOWN {
            // Counted in status only; the LOCKDOWN incident already explains why.
            return self.drop_cmd(BLOCKED_IN_LOCKDOWN, "input blocked during lockdown", now, src, false, false);
        }
        if !authorized {
            // Dropped individually, so it cannot affect the robot; not escalating
            // keeps an intruder from locking out the legitimate operator.
            return self.drop_cmd(UNAUTHORIZED_PUBLISHER, "command from a publisher that is not allowlisted",
                                 now, src, false, true);
        }
        if !self.bucket.allow(now) {
            let detail = format!("rate limit exceeded ({:.0} Hz sustained, burst {:.0}); measured {:.0} msgs in the last 1 s",
                                 self.cfg.max_rate_hz, self.cfg.burst, self.input_rate.rate_hz(now));
            return self.drop_cmd(FLOOD, &detail, now, src, true, true);
        }
        if let Some(problem) = self.schema_problem(cmd) {
            return self.drop_cmd(MALFORMED, &problem, now, src, true, true);
        }
        for field in Field::ALL {
            for (name, value) in cmd.names.iter().zip(cmd.values(field)) {
                if !value.is_finite() {
                    let detail = format!("{name}.{} = {value}", field.as_str());
                    return self.drop_cmd(INVALID_VALUE, &detail, now, src, true, true);
                }
            }
        }
        if let Some(problem) = self.replay_problem(cmd, now) {
            return self.drop_cmd(REPLAY, &problem, now, src, true, true);
        }

        let mut ordered = self.reorder(cmd);

        if let Some(reference) = self.reference_positions() {
            for ((name, new), old) in ordered.names.iter().zip(&ordered.position).zip(&reference) {
                if (new - old).abs() > self.cfg.max_step {
                    let detail = format!("{name} jumped {:+.3} rad (max step {} rad)", new - old, self.cfg.max_step);
                    return self.drop_cmd(STEP_JUMP, &detail, now, src, true, true);
                }
            }
        }

        let mut violations = Vec::new();
        for field in Field::ALL {
            let names = ordered.names.clone();
            let values = ordered.values_mut(field);
            for (i, name) in names.iter().enumerate().take(values.len()) {
                let limits = self.cfg.limits[name];
                if limits.violates(field, values[i]) {
                    violations.push(format!("{name}.{}={:.3}", field.as_str(), values[i]));
                    values[i] = limits.clamp(field, values[i]);
                }
            }
        }

        let mut incidents = Vec::new();
        let mut action = FORWARDED;
        if !violations.is_empty() {
            let detail = format!("outside limits: {}", violations.join(", "));
            if self.cfg.limit_action == "drop" {
                return self.drop_cmd(LIMIT_VIOLATION, &detail, now, src, true, true);
            }
            // A clamped command is safe to forward, so it does not escalate.
            action = CLAMPED;
            self.clamped += 1;
            incidents = self.record(LIMIT_VIOLATION, &detail, CLAMPED, now, src, false, false, true);
        }

        self.forwarded += 1;
        self.last_accepted = Some(ordered.position.clone());
        if cmd.has_stamp() {
            self.last_stamp = cmd.stamp;
        }
        Verdict { action, command: Some(ordered), incidents }
    }

    /// Drop a command whose publisher is not identified yet (DDS delivered data
    /// before ROS node info). Fail-closed but silent: counted in status only.
    pub fn drop_unidentified(&mut self, now: f64) -> Verdict {
        self.input_rate.tick(now);
        self.drop_cmd(UNIDENTIFIED_PUBLISHER, "publisher not identified yet", now, "", false, false)
    }

    fn schema_problem(&self, cmd: &Command) -> Option<String> {
        let unique: HashSet<&String> = cmd.names.iter().collect();
        if unique.len() != cmd.names.len() {
            return Some("duplicate joint names".into());
        }
        let unknown: Vec<&str> = cmd.names.iter().filter(|n| !self.cfg.joint_names.contains(n)).map(String::as_str).collect();
        if !unknown.is_empty() {
            return Some(format!("unknown joint(s): {}", unknown.join(", ")));
        }
        let missing: Vec<&str> = self.cfg.joint_names.iter().filter(|n| !cmd.names.contains(n)).map(String::as_str).collect();
        if !missing.is_empty() {
            return Some(format!("missing joint(s): {}", missing.join(", ")));
        }
        if cmd.position.len() != cmd.names.len() {
            return Some(format!("{} names but {} positions", cmd.names.len(), cmd.position.len()));
        }
        for field in [Field::Velocity, Field::Effort] {
            let n = cmd.values(field).len();
            if n != 0 && n != cmd.names.len() {
                return Some(format!("{} names but {n} {} values", cmd.names.len(), field.as_str()));
            }
        }
        if self.cfg.require_stamp && !cmd.has_stamp() {
            return Some("missing header stamp".into());
        }
        None
    }

    fn replay_problem(&self, cmd: &Command, now: f64) -> Option<String> {
        let stamp = cmd.stamp.filter(|s| *s != 0.0)?;
        let age = now - stamp;
        if age > self.cfg.max_age_s {
            return Some(format!("stale command, stamped {age:.2}s ago (max {}s)", self.cfg.max_age_s));
        }
        if -age > self.cfg.max_future_s {
            return Some(format!("command stamped {:.2}s in the future", -age));
        }
        if self.last_stamp.is_some_and(|last| stamp <= last) {
            return Some("timestamp not newer than last accepted command".into());
        }
        None
    }

    fn reorder(&self, cmd: &Command) -> Command {
        let index: HashMap<&String, usize> = cmd.names.iter().enumerate().map(|(i, n)| (n, i)).collect();
        let pick = |values: &[f64]| -> Vec<f64> {
            if values.is_empty() {
                Vec::new()
            } else {
                self.cfg.joint_names.iter().map(|n| values[index[n]]).collect()
            }
        };
        Command {
            names: self.cfg.joint_names.clone(),
            position: pick(&cmd.position),
            velocity: pick(&cmd.velocity),
            effort: pick(&cmd.effort),
            stamp: cmd.stamp,
            source: cmd.source.clone(),
        }
    }

    fn reference_positions(&self) -> Option<Vec<f64>> {
        if let Some(last) = &self.last_accepted {
            return Some(last.clone());
        }
        let state = self.state.as_ref()?;
        self.cfg.joint_names.iter().map(|n| state.get(n).copied()).collect()
    }

    // ------------------------------------------------------------------
    // Robot state, external alerts, lockdown control
    // ------------------------------------------------------------------

    /// Feed robot joint_states; lock down if the robot is out of bounds.
    pub fn observe_state(&mut self, names: &[String], positions: &[f64], now: f64) -> Vec<Incident> {
        let state: HashMap<String, f64> = names.iter().cloned().zip(positions.iter().copied()).collect();
        let mut bad = Vec::new();
        for name in names {
            let Some(limits) = self.cfg.limits.get(name) else { continue };
            let pos = state[name];
            if !pos.is_finite()
                || pos < limits.position_min - self.cfg.state_margin
                || pos > limits.position_max + self.cfg.state_margin
            {
                bad.push(format!("{name}={pos:.3}"));
            }
        }
        self.state = Some(state);
        self.state_time = Some(now);
        if bad.is_empty() {
            return Vec::new();
        }
        let detail = format!("robot state outside limits: {}", bad.join(", "));
        self.record(STATE_GUARD, &detail, ALERTED, now, "robot", false, true, true)
    }

    pub fn state_fresh(&self, now: f64) -> bool {
        self.state_time.is_some_and(|t| now - t <= self.cfg.state_timeout_s)
    }

    /// Record an alert detected outside inspect() (graph watch, nftables).
    pub fn report_external(&mut self, attack: &str, detail: &str, now: f64, source: &str,
                           critical: bool) -> Vec<Incident> {
        self.record(attack, detail, ALERTED, now, source, !critical, critical, true)
    }

    pub fn rearm(&mut self, now: f64) -> (bool, String) {
        if self.mode == ARMED {
            return (true, "already armed".into());
        }
        if !self.state_fresh(now) {
            return (false, "refused: no fresh robot joint_states".into());
        }
        let state = self.state.as_ref().expect("fresh state exists");
        let missing: Vec<&str> = self.cfg.joint_names.iter().filter(|n| !state.contains_key(*n)).map(String::as_str).collect();
        if !missing.is_empty() {
            return (false, format!("refused: robot state missing {}", missing.join(", ")));
        }
        for name in &self.cfg.joint_names {
            if self.cfg.limits[name].violates(Field::Position, state[name]) {
                return (false, format!("refused: {name} at {:.3} is outside limits", state[name]));
            }
        }
        let pose: Vec<f64> = self.cfg.joint_names.iter().map(|n| state[n]).collect();
        self.mode = ARMED;
        self.lockdown_reason.clear();
        self.lockdown_since = None;
        self.last_accepted = Some(pose);
        self.last_stamp = None;
        self.recent.clear();
        self.bucket.reset();
        (true, "armed: forwarding commands from current robot pose".into())
    }

    /// Command that keeps the robot where it is (used during LOCKDOWN).
    pub fn hold_command(&self, now: f64) -> Option<Command> {
        let pos = self.reference_positions()?;
        Some(Command {
            names: self.cfg.joint_names.clone(),
            velocity: vec![0.0; pos.len()],
            position: pos,
            effort: Vec::new(),
            stamp: Some(now),
            source: "firewall".into(),
        })
    }

    pub fn reset_counters(&mut self) {
        self.counters.clear();
        self.forwarded = 0;
        self.clamped = 0;
        self.dropped = 0;
        self.pending.clear();
        self.last_report.clear();
    }

    pub fn status(&mut self, now: f64) -> Status {
        Status {
            mode: self.mode.into(),
            lockdown_reason: self.lockdown_reason.clone(),
            lockdown_since: self.lockdown_since,
            forwarded: self.forwarded,
            clamped: self.clamped,
            dropped: self.dropped,
            input_rate_hz: (self.input_rate.rate_hz(now) * 10.0).round() / 10.0,
            robot_state_fresh: self.state_fresh(now),
            counters: self.counters.clone(),
        }
    }
}
