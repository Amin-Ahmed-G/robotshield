//! End-to-end tests: run the real `robot_firewall` binary between two DDS
//! domains, with the test acting as both the laptop (untrusted) and the robot
//! (trusted). The only way a command can reach the robot is through the binary.

use std::process::{Child, Command as Process, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diagnostic_msgs::msg::DiagnosticStatus;
use rclrs::*;
use sensor_msgs::msg::JointState;
use std_srvs::srv::{Trigger, Trigger_Request, Trigger_Response};

const JOINTS: [&str; 2] = ["joint_1", "joint_2"];

fn wait_for(timeout_s: f64, mut predicate: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(timeout_s);
    while Instant::now() < end {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn stamp(t: f64) -> builtin_interfaces::msg::Time {
    let sec = t.floor();
    builtin_interfaces::msg::Time { sec: sec as i32, nanosec: ((t - sec) * 1e9) as u32 }
}

struct Bench {
    firewall: Child,
    laptop_ctx: Context,
    laptop: Node,
    robot_ctx: Context,
    cmd_pub: Publisher<JointState>,
    rearm_client: Client<Trigger>,
    events: Arc<Mutex<Vec<DiagnosticStatus>>>,
    received: Arc<Mutex<Vec<JointState>>>,
    executors: Vec<Arc<ExecutorCommands>>,
    _keep: Vec<Box<dyn std::any::Any>>,
}

impl Bench {
    fn start(untrusted: usize, trusted: usize) -> Bench {
        Self::start_with(untrusted, trusted, &[])
    }

    fn start_with(untrusted: usize, trusted: usize, extra: &[String]) -> Bench {
        std::env::set_var("ROS_AUTOMATIC_DISCOVERY_RANGE", "LOCALHOST");
        std::env::set_var("ROS_SECURITY_ENABLE", "false");
        let log = std::env::temp_dir().join(format!("robot_fw_test_{untrusted}.jsonl"));
        let firewall = Process::new(env!("CARGO_BIN_EXE_robot_firewall"))
            .args(["--untrusted-domain", &untrusted.to_string(), "--trusted-domain", &trusted.to_string()])
            .args(["--set", &format!("joint_names={JOINTS:?}").replace('"', "")])
            .args(["--set", "lockdown_threshold=5", "--set", "allowed_publishers=[laptop]"])
            .args(["--set", "watch_period_s=0.2", "--set", &format!("incident_log_path={}", log.display())])
            .args(extra.iter().flat_map(|kv| ["--set".to_string(), kv.clone()]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start robot_firewall");

        let laptop_ctx = Context::new(["test".to_string()], InitOptions::new().with_domain_id(Some(untrusted))).unwrap();
        let robot_ctx = Context::new(["test".to_string()], InitOptions::new().with_domain_id(Some(trusted))).unwrap();
        let mut laptop_exec = laptop_ctx.create_basic_executor();
        let mut robot_exec = robot_ctx.create_basic_executor();
        let laptop = laptop_exec.create_node("laptop").unwrap();
        let robot = robot_exec.create_node("robot").unwrap();

        let cmd_pub = laptop.create_publisher::<JointState>("joint_commands").unwrap();
        let rearm_client = laptop.create_client::<Trigger>("/firewall/rearm").unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = events.clone();
        let events_sub = laptop
            .create_subscription::<DiagnosticStatus, _>("/firewall/events".keep_last(100), move |m: DiagnosticStatus| {
                e.lock().unwrap().push(m)
            })
            .unwrap();

        let state_pub = robot.create_publisher::<JointState>("joint_states").unwrap();
        let clock = robot.get_clock();
        let state_timer = robot
            .create_timer_repeating(Duration::from_millis(20), move || {
                let mut msg = JointState::default();
                msg.header.stamp = stamp(clock.now().nsec as f64 * 1e-9);
                msg.name = JOINTS.iter().map(|s| s.to_string()).collect();
                msg.position = vec![0.0, 0.0];
                let _ = state_pub.publish(msg);
            })
            .unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let r = received.clone();
        let cmd_sub = robot
            .create_subscription::<JointState, _>("joint_commands".keep_last(200), move |m: JointState| {
                r.lock().unwrap().push(m)
            })
            .unwrap();

        let executors = vec![laptop_exec.commands().clone(), robot_exec.commands().clone()];
        std::thread::spawn(move || laptop_exec.spin(SpinOptions::default()));
        std::thread::spawn(move || robot_exec.spin(SpinOptions::default()));

        let bench = Bench {
            firewall,
            laptop_ctx,
            laptop,
            robot_ctx,
            cmd_pub,
            rearm_client,
            events,
            received,
            executors,
            _keep: vec![Box::new(events_sub), Box::new(state_timer), Box::new(cmd_sub)],
        };
        assert!(
            wait_for(15.0, || bench.cmd_pub.get_subscription_count().unwrap_or(0) > 0
                && bench.rearm_client.service_is_ready().unwrap_or(false)),
            "firewall did not come up"
        );
        bench
    }

    fn now(&self) -> f64 {
        self.laptop.get_clock().now().nsec as f64 * 1e-9
    }

    fn send_named(&self, names: &[&str], position: &[f64], stamp_s: f64) {
        let mut msg = JointState::default();
        msg.header.stamp = stamp(stamp_s);
        msg.name = names.iter().map(|s| s.to_string()).collect();
        msg.position = position.to_vec();
        self.cmd_pub.publish(msg).unwrap();
    }

    fn send(&self, position: &[f64]) {
        self.send_named(&JOINTS, position, self.now());
    }

    fn rearm(&self) -> Trigger_Response {
        let mut promise: Promise<Trigger_Response> = self.rearm_client.call(Trigger_Request::default()).unwrap();
        let mut out = None;
        assert!(wait_for(5.0, || {
            if let Ok(Some(r)) = promise.try_recv() {
                out = Some(r);
            }
            out.is_some()
        }));
        out.unwrap()
    }

    /// Rearm once the firewall has seen fresh robot state.
    fn arm(&self) {
        assert!(wait_for(10.0, || self.rearm().success), "rearm refused");
        std::thread::sleep(Duration::from_millis(100));
        self.received.lock().unwrap().clear();
    }

    fn attacks(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .flat_map(|e| e.values.iter().filter(|kv| kv.key == "attack").map(|kv| kv.value.clone()))
            .collect()
    }

    fn event_with(&self, attack: &str, key: &str) -> Option<String> {
        self.events.lock().unwrap().iter().find_map(|e| {
            let is = e.values.iter().any(|kv| kv.key == "attack" && kv.value == attack);
            is.then(|| e.values.iter().find(|kv| kv.key == key).map(|kv| kv.value.clone())).flatten()
        })
    }

    fn forwarded_positions(&self) -> Vec<f64> {
        self.received.lock().unwrap().iter().flat_map(|m| m.position.clone()).collect()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = self.firewall.kill();
        let _ = self.firewall.wait();
        for exec in &self.executors {
            exec.halt_spinning();
        }
        let _ = (&self.laptop_ctx, &self.robot_ctx);
    }
}

#[test]
fn starts_locked_then_forwards_after_rearm() {
    let b = Bench::start(61, 62);
    b.send(&[0.05, 0.0]);
    std::thread::sleep(Duration::from_millis(300));
    // Only hold commands (robot pose 0.0) reach the robot while locked.
    assert!(b.forwarded_positions().iter().all(|p| *p == 0.0));
    b.arm();
    b.send(&[0.1, 0.0]);
    assert!(wait_for(5.0, || b.forwarded_positions().contains(&0.1)));
}

#[test]
fn unsafe_commands_never_reach_robot() {
    let b = Bench::start(63, 64);
    b.arm();
    b.send(&[5.0, 0.0]); // step jump
    std::thread::sleep(Duration::from_millis(50));
    b.send(&[f64::NAN, 0.0]); // NaN
    std::thread::sleep(Duration::from_millis(50));
    b.send_named(&["joint_1", "joint_2", "joint_99"], &[0.0, 0.0, 0.0], b.now()); // unknown joint
    std::thread::sleep(Duration::from_millis(50));
    b.send_named(&JOINTS, &[0.0, 0.0], b.now() - 10.0); // replay
    assert!(wait_for(5.0, || {
        let a = b.attacks();
        ["STEP_JUMP", "INVALID_VALUE", "MALFORMED", "REPLAY"].iter().all(|x| a.iter().any(|y| y == x))
    }), "attacks seen: {:?}", b.attacks());
    assert!(b.forwarded_positions().iter().all(|p| p.is_finite() && p.abs() <= 1.0));
}

#[test]
fn flood_triggers_lockdown() {
    let b = Bench::start(65, 66);
    b.arm();
    let base = b.now();
    for i in 0..200 {
        b.send_named(&JOINTS, &[0.0, 0.0], base + i as f64 * 1e-4);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(wait_for(5.0, || b.attacks().iter().any(|a| a == "LOCKDOWN")), "{:?}", b.attacks());
    assert!(b.attacks().iter().any(|a| a == "FLOOD"));
}

#[test]
fn rogue_publisher_on_robot_lan_locks_down() {
    let b = Bench::start(67, 68);
    b.arm();
    let exec = b.robot_ctx.create_basic_executor();
    let rogue = exec.create_node("rogue").unwrap();
    let _pub = rogue.create_publisher::<JointState>("joint_commands").unwrap();
    assert!(wait_for(5.0, || b.attacks().iter().any(|a| a == "ROGUE_DEVICE_ON_ROBOT_LAN")));
    assert!(wait_for(2.0, || b.attacks().iter().any(|a| a == "LOCKDOWN")));
}

#[test]
fn unauthorized_publisher_dropped_while_operator_keeps_control() {
    let b = Bench::start(69, 70);
    b.arm();
    let exec = b.laptop_ctx.create_basic_executor();
    let intruder = exec.create_node("intruder").unwrap();
    let evil_pub = intruder.create_publisher::<JointState>("joint_commands").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    for i in 0..40 {
        let mut msg = JointState::default();
        msg.header.stamp = stamp(b.now());
        msg.name = JOINTS.iter().map(|s| s.to_string()).collect();
        msg.position = vec![0.05, 0.0];
        evil_pub.publish(msg).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        if i % 4 == 0 {
            b.send(&[0.1, 0.0]);
        }
    }
    assert!(wait_for(5.0, || b.event_with("UNAUTHORIZED_PUBLISHER", "source").is_some()));
    assert_eq!(b.event_with("UNAUTHORIZED_PUBLISHER", "source").unwrap(), "intruder");
    let positions = b.forwarded_positions();
    assert!(!positions.contains(&0.05), "intruder command reached the robot");
    assert!(positions.contains(&0.1), "operator commands were blocked");
    assert!(!b.attacks().iter().any(|a| a == "LOCKDOWN"), "intruder forced a lockdown");
}

#[test]
fn incidents_stream_to_siem_as_cef_with_mitre_tags() {
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let port = collector.local_addr().unwrap().port();
    let b = Bench::start_with(59, 60, &[format!("siem_syslog=udp://127.0.0.1:{port}"), "siem_format=cef".into()]);
    b.arm();
    b.send(&[f64::NAN, 0.0]);
    let mut got = String::new();
    assert!(wait_for(5.0, || {
        let mut buf = [0u8; 4096];
        if let Ok(n) = collector.recv(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            if msg.contains("INVALID_VALUE") {
                got = msg;
            }
        }
        !got.is_empty()
    }), "no SIEM datagram received");
    assert!(got.starts_with("<164>1 "), "RFC 5424 local4.warning frame: {got}");
    assert!(got.contains("CEF:0|RoboShield|robot_firewall|"), "{got}");
    assert!(got.contains("cs2Label=mitreTechniqueId cs2=T1692.001"), "{got}");
    assert!(got.contains("cs4Label=mitreTactic cs4=Impair Process Control"), "{got}");
    // The ROS event carries the same tag for the console.
    assert!(wait_for(2.0, || b.event_with("INVALID_VALUE", "mitre_technique_id").as_deref() == Some("T1692.001")));
}
