//! ROS 2 side of the console (untrusted / laptop domain): listens to the
//! firewall, runs the commander and attacks, calls the firewall services and
//! answers graph inspection buttons.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diagnostic_msgs::msg::DiagnosticStatus;
use fw_core::attacks::{apply_attack, sine_targets, step_toward};
use fw_core::Command;
use rclrs::*;
use sensor_msgs::msg::JointState;
use std_msgs::msg::String as StringMsg;
use std_srvs::srv::{Trigger, Trigger_Request, Trigger_Response};

use crate::shell::wait_until;
use crate::state::{lock, now_hms, EventRow, LogKind, SharedRef, TestResult, TestRow};

pub const COMMANDER_NODE: &str = "attack_sim_node";

/// Simulated intruder node and its publisher, alive only during `spoof`.
type Intruder = Arc<Mutex<Option<(Node, Publisher<JointState>)>>>;
const COMMAND_TOPIC: &str = "joint_commands";

/// (attack mode, incident the firewall must report, max seconds to wait)
pub const SELF_TEST: [(&str, &str, f64); 8] = [
    ("overspeed", "LIMIT_VIOLATION", 6.0),
    ("overreach", "LIMIT_VIOLATION", 15.0),
    ("spike", "STEP_JUMP", 6.0),
    ("nan", "INVALID_VALUE", 6.0),
    ("unknown_joint", "MALFORMED", 6.0),
    ("replay", "REPLAY", 6.0),
    ("flood", "FLOOD", 6.0),
    ("spoof", "UNAUTHORIZED_PUBLISHER", 8.0),
];

fn stamp(t: f64) -> builtin_interfaces::msg::Time {
    let sec = t.floor();
    builtin_interfaces::msg::Time { sec: sec as i32, nanosec: ((t - sec) * 1e9) as u32 }
}

fn wall_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn to_msg(cmd: &Command) -> JointState {
    let mut msg = JointState::default();
    msg.header.stamp = stamp(cmd.stamp.unwrap_or(0.0));
    msg.name = cmd.names.clone();
    msg.position = cmd.position.clone();
    msg.velocity = cmd.velocity.clone();
    msg
}

pub struct RosLink {
    pub domain: usize,
    pub shared: SharedRef,
    console: Node,
    exec_commands: Arc<ExecutorCommands>,
    rearm_client: Client<Trigger>,
    reset_client: Client<Trigger>,
    _keep: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
}

impl RosLink {
    pub fn start(domain: usize, shared: SharedRef) -> Result<Arc<Self>, RclrsError> {
        let ctx = Context::new(["firewall_console".to_string()], InitOptions::new().with_domain_id(Some(domain)))?;
        let mut executor = ctx.create_basic_executor();
        let console = executor.create_node("firewall_console")?;
        let commander = executor.create_node(COMMANDER_NODE)?;
        let exec_commands = executor.commands().clone();

        let mut keep: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

        let s = shared.clone();
        keep.push(Box::new(console.create_subscription::<DiagnosticStatus, _>(
            "/firewall/events".keep_last(100),
            move |m: DiagnosticStatus| {
                let attack = m.values.iter().find(|kv| kv.key == "attack").map(|kv| kv.value.clone()).unwrap_or_default();
                let mut s = lock(&s);
                let t = s.t();
                s.events_rate.tick(t);
                s.events.push(EventRow { when: now_hms(), level: m.level, attack, message: m.message });
                let excess = s.events.len().saturating_sub(1000);
                s.events.drain(..excess);
            },
        )?));

        let s = shared.clone();
        keep.push(Box::new(console.create_subscription::<StringMsg, _>("/firewall/status", move |m: StringMsg| {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&m.data) else { return };
            let mut s = lock(&s);
            let t = s.t();
            s.status_rate.tick(t);
            s.clock_skew_s = json.get("time").and_then(|v| v.as_f64()).map(|g| wall_now() - g);
            s.status = Some(json);
            s.status_at = Some(Instant::now());
        })?));

        let s = shared.clone();
        keep.push(Box::new(console.create_subscription::<JointState, _>("joint_states", move |m: JointState| {
            let mut s = lock(&s);
            let t = s.t();
            s.state_rate.tick(t);
            let index: std::collections::HashMap<&String, usize> = m.name.iter().enumerate().map(|(i, n)| (n, i)).collect();
            let names = s.joint_names.clone();
            if names.iter().all(|n| index.contains_key(n) && index[n] < m.position.len()) {
                let pose: Vec<f64> = names.iter().map(|n| m.position[index[n]]).collect();
                let peak = pose.iter().fold(0.0_f64, |a, p| a.max(p.abs()));
                s.max_abs_position = s.max_abs_position.max(peak);
                s.robot_velocity = names.iter().filter_map(|n| m.velocity.get(index[n]).copied()).collect();
                s.robot_pose = Some(pose);
            }
        })?));

        // Commander: legitimate sine trajectory near the robot pose, plus the
        // selected attack. Publishes as "attack_sim_node" so it matches the
        // gateway allowlist in the default params.
        let cmd_pub = commander.create_publisher::<JointState>(COMMAND_TOPIC)?;
        let s = shared.clone();
        let spawner = exec_commands.clone();
        let intruder: Intruder = Arc::new(Mutex::new(None));
        let t0 = wall_now();
        keep.push(Box::new(commander.create_timer_repeating(Duration::from_millis(50), move || {
            let mut s = lock(&s);
            if s.attack != "none" && s.attack_duration_s > 0.0
                && s.attack_since.elapsed().as_secs_f64() > s.attack_duration_s
            {
                s.set_attack("none");
            }
            let spoof = s.commander_on && s.attack == "spoof";
            let mut intruder = intruder.lock().unwrap();
            if spoof && intruder.is_none() {
                if let Ok(node) = spawner.create_node("intruder") {
                    if let Ok(p) = node.create_publisher::<JointState>(COMMAND_TOPIC) {
                        *intruder = Some((node, p));
                    }
                }
            } else if !spoof && intruder.is_some() {
                *intruder = None;
            }
            if !s.commander_on {
                return;
            }
            let Some(pose) = s.robot_pose.clone() else { return };
            let now = wall_now();
            let amplitude = if s.attack == "overreach" { 1.5 } else { 0.8 };
            let target = sine_targets(now - t0, pose.len(), amplitude, 0.1);
            let base = Command {
                names: s.joint_names.clone(),
                position: step_toward(&pose, &target, 0.08),
                velocity: vec![0.0; pose.len()],
                effort: Vec::new(),
                stamp: Some(now),
                source: String::new(),
            };
            for cmd in apply_attack(&s.attack, &base, s.attack_joint, s.attack_magnitude, s.flood_copies) {
                if cmd_pub.publish(to_msg(&cmd)).is_ok() {
                    s.sent += 1;
                }
            }
            if let Some((_, p)) = intruder.as_ref() {
                // Legit-looking commands from a node that is not allowlisted.
                let _ = p.publish(to_msg(&base));
            }
        })?));

        let rearm_client = console.create_client::<Trigger>("/firewall/rearm")?;
        let reset_client = console.create_client::<Trigger>("/firewall/reset")?;
        keep.push(Box::new(commander));

        std::thread::spawn(move || {
            let errors = executor.spin(SpinOptions::default());
            if !errors.is_empty() {
                eprintln!("ROS executor stopped: {errors:?}");
            }
        });

        Ok(Arc::new(Self { domain, shared, console, exec_commands, rearm_client, reset_client, _keep: Mutex::new(keep) }))
    }

    pub fn shutdown(&self) {
        self.exec_commands.halt_spinning();
    }

    // ------------------------------------------------------------------
    // Firewall services
    // ------------------------------------------------------------------

    /// Blocking service call; returns (success, message).
    fn call_trigger(&self, client: &Client<Trigger>) -> Result<(bool, String), String> {
        if !client.service_is_ready().unwrap_or(false) {
            return Err("service not available (firewall unreachable or not authenticated)".into());
        }
        let mut promise: Promise<Trigger_Response> =
            client.call(Trigger_Request::default()).map_err(|e| e.to_string())?;
        wait_until(Duration::from_secs(5), || promise.try_recv().ok().flatten())
            .map(|r| (r.success, r.message))
            .ok_or_else(|| "no response within 5 s".into())
    }

    pub fn rearm_blocking(&self) -> Result<(bool, String), String> {
        self.call_trigger(&self.rearm_client)
    }

    pub fn trigger(self: &Arc<Self>, which: &'static str) {
        let me = self.clone();
        lock(&self.shared).push_log(LogKind::Cmd, format!("$ ros2 service call /firewall/{which} std_srvs/srv/Trigger"));
        std::thread::spawn(move || {
            let client = if which == "rearm" { &me.rearm_client } else { &me.reset_client };
            let result = me.call_trigger(client);
            let mut s = lock(&me.shared);
            match result {
                Ok((true, msg)) => s.push_log(LogKind::Pass, format!("{which}: {msg}")),
                Ok((false, msg)) => s.push_log(LogKind::Fail, format!("{which}: {msg}")),
                Err(e) => s.push_log(LogKind::Fail, format!("{which}: {e}")),
            }
        });
    }

    // ------------------------------------------------------------------
    // ROS inspection buttons
    // ------------------------------------------------------------------

    pub fn list_nodes(&self) {
        let result = self.console.get_node_names_with_enclaves();
        let mut s = lock(&self.shared);
        s.push_log(LogKind::Cmd, format!("$ ros2 node list   (domain {})", self.domain));
        match result {
            Ok(nodes) => {
                for (n, enclave) in nodes {
                    let ns = if n.namespace == "/" { String::new() } else { n.namespace.clone() };
                    s.push_log(LogKind::Out, format!("{ns}/{}   enclave: {enclave}", n.name));
                }
            }
            Err(e) => s.push_log(LogKind::Fail, e.to_string()),
        }
    }

    pub fn list_topics(&self) {
        let result = self.console.get_topic_names_and_types();
        let mut s = lock(&self.shared);
        s.push_log(LogKind::Cmd, "$ ros2 topic list -t");
        match result {
            Ok(map) => {
                let mut topics: Vec<_> = map.into_iter().collect();
                topics.sort();
                for (topic, types) in topics {
                    s.push_log(LogKind::Out, format!("{topic}  [{}]", types.join(", ")));
                }
            }
            Err(e) => s.push_log(LogKind::Fail, e.to_string()),
        }
    }

    pub fn command_publishers(&self) {
        let result = self.console.get_publishers_info_by_topic(&format!("/{COMMAND_TOPIC}"));
        let mut s = lock(&self.shared);
        s.push_log(LogKind::Cmd, format!("$ ros2 topic info /{COMMAND_TOPIC} -v"));
        match result {
            Ok(infos) if infos.is_empty() => s.push_log(LogKind::Info, "no publishers"),
            Ok(infos) => {
                for i in infos {
                    let gid: String = i.endpoint_gid.iter().take(8).map(|b| format!("{b:02x}")).collect();
                    let tag = match i.node_name.as_str() {
                        COMMANDER_NODE => "  (this console, allowlisted)",
                        "intruder" => "  (simulated intruder)",
                        _ => "",
                    };
                    let ns = i.node_namespace.trim_end_matches('/');
                    s.push_log(LogKind::Out, format!("publisher {ns}/{}  gid {gid}..{tag}", i.node_name));
                }
            }
            Err(e) => s.push_log(LogKind::Fail, e.to_string()),
        }
    }

    pub fn topic_rates(&self) {
        let mut s = lock(&self.shared);
        let t = s.t();
        let lines = [
            ("joint_states (relayed by gateway)", s.state_rate.rate_hz(t), s.state_rate.age_s(t)),
            ("/firewall/status", s.status_rate.rate_hz(t), s.status_rate.age_s(t)),
            ("/firewall/events", s.events_rate.rate_hz(t), s.events_rate.age_s(t)),
        ];
        s.push_log(LogKind::Cmd, "$ ros2 topic hz joint_states /firewall/status /firewall/events");
        for (name, rate, age) in lines {
            let age = if age.is_finite() { format!("{age:.2}s ago") } else { "never".into() };
            s.push_log(LogKind::Out, format!("{name:36} {rate:6.1} Hz   last {age}"));
        }
    }

    pub fn latest_state(&self) {
        let mut s = lock(&self.shared);
        s.push_log(LogKind::Cmd, "$ ros2 topic echo --once joint_states");
        match s.robot_pose.clone() {
            None => s.push_log(LogKind::Fail, "no joint_states received from the gateway"),
            Some(pose) => {
                let names = s.joint_names.clone();
                let vel = s.robot_velocity.clone();
                for (i, n) in names.iter().enumerate() {
                    let v = vel.get(i).map_or(String::from("-"), |v| format!("{v:+.3}"));
                    s.push_log(LogKind::Out, format!("{n:10} position {:+.4} rad   velocity {v} rad/s", pose[i]));
                }
                let peak = s.max_abs_position;
                s.push_log(LogKind::Info, format!("max |position| seen since start: {peak:.4} rad"));
            }
        }
    }

    pub fn clock_check(&self) {
        let mut s = lock(&self.shared);
        s.push_log(LogKind::Cmd, "$ compare laptop clock with gateway clock (/firewall/status time)");
        let max_age = 0.5;
        match s.clock_skew_s {
            None => s.push_log(LogKind::Fail, "no gateway time yet (firewall unreachable, or an older gateway without status.time)"),
            Some(skew) if skew.abs() < max_age / 2.0 => {
                s.push_log(LogKind::Pass, format!("PASS clock skew {:+.3} s (replay window {max_age} s)", skew))
            }
            Some(skew) => s.push_log(LogKind::Fail, format!(
                "FAIL clock skew {:+.3} s: commands will be rejected as REPLAY; run `chronyc tracking` on both machines",
                skew
            )),
        }
    }

    // ------------------------------------------------------------------
    // Self-test: run every attack and check the firewall reports it
    // ------------------------------------------------------------------

    pub fn run_self_test(self: &Arc<Self>) {
        {
            let mut s = lock(&self.shared);
            if s.selftest_running {
                return;
            }
            s.selftest_running = true;
            s.selftest = SELF_TEST
                .iter()
                .map(|(mode, expected, _)| TestRow { mode, expected, result: TestResult::Pending })
                .collect();
            s.max_abs_position = 0.0;
            s.commander_on = true;
            s.attack_duration_s = 0.0;
            s.push_log(LogKind::Info, "self-test started: every attack must be detected and the robot must stay within limits");
        }
        let me = self.clone();
        std::thread::spawn(move || {
            for (i, (mode, expected, timeout)) in SELF_TEST.iter().enumerate() {
                lock(&me.shared).selftest[i].result = TestResult::Running;
                let result = me.self_test_one(mode, expected, *timeout);
                let mut s = lock(&me.shared);
                s.set_attack("none");
                let line = match &result {
                    TestResult::Pass(m) => (LogKind::Pass, format!("PASS {mode}: {m}")),
                    TestResult::Fail(m) => (LogKind::Fail, format!("FAIL {mode}: {m}")),
                    _ => (LogKind::Info, String::new()),
                };
                s.push_log(line.0, line.1);
                s.selftest[i].result = result;
                drop(s);
                std::thread::sleep(Duration::from_millis(1500));
            }
            let _ = me.rearm_blocking();
            let mut s = lock(&me.shared);
            let passed = s.selftest.iter().filter(|r| matches!(r.result, TestResult::Pass(_))).count();
            let peak = s.max_abs_position;
            let limit = 1.0 + 0.05;
            let kind = if passed == SELF_TEST.len() && peak <= limit { LogKind::Pass } else { LogKind::Fail };
            s.push_log(kind, format!(
                "self-test: {passed}/{} attacks detected; robot max |position| {peak:.3} rad (default limit 1.0)",
                SELF_TEST.len()
            ));
            s.selftest_running = false;
        });
    }

    fn self_test_one(&self, mode: &str, expected: &str, timeout_s: f64) -> TestResult {
        // 1. Make sure the firewall is ARMED.
        let armed = wait_until(Duration::from_secs(8), || match self.rearm_blocking() {
            Ok((true, _)) => Some(()),
            _ => {
                std::thread::sleep(Duration::from_millis(500));
                None
            }
        });
        if armed.is_none() {
            let why = self.rearm_blocking().map(|(_, m)| m).unwrap_or_else(|e| e);
            return TestResult::Fail(format!("could not arm firewall: {why}"));
        }
        // Let the commander settle so the legit stream is flowing.
        std::thread::sleep(Duration::from_millis(700));
        // 2. Launch the attack and wait for the matching incident.
        let marker = {
            let mut s = lock(&self.shared);
            let marker = s.events.len();
            s.set_attack(mode);
            marker
        };
        let started = Instant::now();
        let seen = wait_until(Duration::from_secs_f64(timeout_s), || {
            let s = lock(&self.shared);
            s.events[marker.min(s.events.len())..].iter().find(|e| e.attack == expected).map(|e| e.message.clone())
        });
        lock(&self.shared).set_attack("none");
        match seen {
            Some(msg) => TestResult::Pass(format!("{:.1}s: {msg}", started.elapsed().as_secs_f64())),
            None => {
                let hint = if mode == "spoof" { " (is allowed_publishers set on the gateway?)" } else { "" };
                TestResult::Fail(format!("no {expected} incident within {timeout_s:.0}s{hint}"))
            }
        }
    }
}
