//! State shared between the UI thread, the ROS executor and worker threads.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use fw_core::rate::RateTracker;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// The command that was run (shown as `$ cmd`).
    Cmd,
    Out,
    Pass,
    Fail,
    Info,
}

pub struct LogLine {
    pub when: String,
    pub kind: LogKind,
    pub text: String,
}

pub struct EventRow {
    pub when: String,
    /// DiagnosticStatus level: 0 OK, 1 WARN, 2 ERROR.
    pub level: u8,
    pub attack: String,
    pub message: String,
    /// FORWARDED / CLAMPED / DROPPED / ALERTED ('' for REARM etc.)
    pub action: String,
    pub source: String,
    pub count: String,
    /// MITRE ATT&CK for ICS technique id / name / tactic ('' if untagged).
    pub mitre_id: String,
    pub mitre_name: String,
    pub mitre_tactic: String,
}

#[derive(Clone, PartialEq)]
pub enum TestResult {
    Pending,
    Running,
    Pass(String),
    Fail(String),
}

pub struct TestRow {
    pub mode: &'static str,
    pub expected: &'static str,
    pub result: TestResult,
}

pub struct Shared {
    pub started: Instant,
    // Firewall
    pub status: Option<serde_json::Value>,
    pub status_at: Option<Instant>,
    /// Local minus gateway clock at the last status message, in seconds.
    pub clock_skew_s: Option<f64>,
    pub events: Vec<EventRow>,
    // Commander / attacks
    pub commander_on: bool,
    pub attack: String,
    pub attack_since: Instant,
    pub attack_duration_s: f64,
    pub attack_joint: usize,
    pub attack_magnitude: f64,
    pub flood_copies: usize,
    pub sent: u64,
    // Robot state relayed by the gateway
    pub joint_names: Vec<String>,
    pub robot_pose: Option<Vec<f64>>,
    pub robot_velocity: Vec<f64>,
    pub max_abs_position: f64,
    pub state_rate: RateTracker,
    pub status_rate: RateTracker,
    pub events_rate: RateTracker,
    // Self-test
    pub selftest: Vec<TestRow>,
    pub selftest_running: bool,
    // Console output
    pub log: Vec<LogLine>,
    // Chart history (t = seconds since console start)
    /// Robot joint positions, decimated to ~20 Hz, last HISTORY_S seconds.
    pub pose_history: VecDeque<(f64, Vec<f64>)>,
    /// (t, forwarded msgs/s, dropped msgs/s) from successive status messages.
    pub traffic_history: VecDeque<(f64, f64, f64)>,
    last_counts: Option<(f64, f64, f64)>,
}

/// Seconds of history shown in the live charts.
pub const HISTORY_S: f64 = 30.0;

impl Shared {
    pub fn new(joint_names: Vec<String>) -> Self {
        Self {
            started: Instant::now(),
            status: None,
            status_at: None,
            clock_skew_s: None,
            events: Vec::new(),
            commander_on: false,
            attack: "none".into(),
            attack_since: Instant::now(),
            attack_duration_s: 0.0,
            attack_joint: 0,
            attack_magnitude: 3.0,
            flood_copies: 40,
            sent: 0,
            joint_names,
            robot_pose: None,
            robot_velocity: Vec::new(),
            max_abs_position: 0.0,
            state_rate: RateTracker::new(2.0),
            status_rate: RateTracker::new(5.0),
            events_rate: RateTracker::new(5.0),
            selftest: Vec::new(),
            selftest_running: false,
            log: Vec::new(),
            pose_history: VecDeque::new(),
            traffic_history: VecDeque::new(),
            last_counts: None,
        }
    }

    pub fn record_pose(&mut self, t: f64, pose: &[f64]) {
        if self.pose_history.back().is_some_and(|(last, _)| t - last < 0.05) {
            return;
        }
        self.pose_history.push_back((t, pose.to_vec()));
        while self.pose_history.front().is_some_and(|(t0, _)| t - t0 > HISTORY_S) {
            self.pose_history.pop_front();
        }
    }

    /// Turn cumulative forwarded/dropped counters into per-second rates.
    pub fn record_counts(&mut self, t: f64, forwarded: f64, dropped: f64) {
        if let Some((t0, f0, d0)) = self.last_counts {
            let dt = t - t0;
            if dt > 0.2 {
                // Counters reset (Reset button / gateway restart) -> treat as zero.
                let fr = ((forwarded - f0) / dt).max(0.0);
                let dr = ((dropped - d0) / dt).max(0.0);
                self.traffic_history.push_back((t, fr, dr));
            } else {
                return;
            }
        }
        self.last_counts = Some((t, forwarded, dropped));
        while self.traffic_history.front().is_some_and(|(t0, _, _)| t - t0 > HISTORY_S) {
            self.traffic_history.pop_front();
        }
    }

    /// Seconds since the console started (monotonic), for rate trackers.
    pub fn t(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    pub fn mode(&self) -> Option<String> {
        self.status.as_ref()?.get("mode")?.as_str().map(String::from)
    }

    pub fn push_log(&mut self, kind: LogKind, text: impl Into<String>) {
        let text = text.into();
        for line in text.lines() {
            self.log.push(LogLine { when: now_hms(), kind, text: line.to_string() });
        }
        let excess = self.log.len().saturating_sub(2000);
        self.log.drain(..excess);
    }

    pub fn set_attack(&mut self, mode: &str) {
        if self.attack != mode {
            self.attack = mode.to_string();
            self.attack_since = Instant::now();
            self.push_log(LogKind::Info, format!("attack mode -> {mode}"));
        }
    }
}

pub type SharedRef = Arc<Mutex<Shared>>;

pub fn lock(shared: &SharedRef) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn now_hms() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
