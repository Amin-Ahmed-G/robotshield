//! Robot command firewall: bridges an untrusted ROS 2 domain (WiFi, laptop) and
//! a trusted one (Ethernet, robot) inside one process, and is the only path
//! between them.
//!
//! ```text
//!   untrusted  joint_commands --> [fw_core rules] --> trusted joint_commands
//!   trusted    joint_states   --> state guard     --> untrusted joint_states
//! ```
//!
//! Incidents go to /firewall/events (DiagnosticStatus), a JSONL log, and are
//! summarised on /diagnostics and /firewall/status. /firewall/rearm and
//! /firewall/reset (std_srvs/Trigger) are served on the untrusted side.
//!
//! Unlike the Python gateway, every incoming command is attributed to its
//! publisher (RMW GID -> node name), so messages from non-allowlisted
//! publishers are dropped individually.

mod config;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use diagnostic_msgs::msg::{DiagnosticArray, DiagnosticStatus, KeyValue};
use fw_core::firewall::{self as fw, Command, CommandFirewall, Incident};
use rclrs::*;
use sensor_msgs::msg::JointState;
use std_msgs::msg::{Float64MultiArray, String as StringMsg};
use std_srvs::srv::{Trigger, Trigger_Request, Trigger_Response};

use config::Params;

/// Name rmw reports for an endpoint whose ROS node info has not arrived yet.
const NODE_NAME_UNKNOWN: &str = "_NODE_NAME_UNKNOWN_";

/// (first message time per unidentified GID, last graph refresh for them)
type Unidentified = (HashMap<[u8; 16], Instant>, Option<Instant>);

#[derive(Parser, Debug)]
#[command(version, about = "Two-domain ROS 2 robot command firewall")]
struct Args {
    /// ROS domain of the laptop / WiFi side.
    #[arg(long, env = "FIREWALL_UNTRUSTED_DOMAIN", default_value_t = 10)]
    untrusted_domain: usize,
    /// ROS domain of the robot / Ethernet side.
    #[arg(long, env = "FIREWALL_TRUSTED_DOMAIN", default_value_t = 20)]
    trusted_domain: usize,
    /// SROS2 enclave for the untrusted side (needs ROS_SECURITY_KEYSTORE).
    #[arg(long, env = "FIREWALL_ENCLAVE", default_value = "")]
    enclave: String,
    /// SROS2 enclave for the robot side (default: unsecured).
    #[arg(long, default_value = "")]
    trusted_enclave: String,
    /// Parameters YAML (same file as the Python firewall_node).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override a parameter, e.g. --set incident_log_path=/var/log/x.jsonl
    #[arg(long = "set", value_name = "KEY=VALUE")]
    overrides: Vec<String>,
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Minimal systemd notify (READY=1 / WATCHDOG=1) without extra dependencies.
fn sd_notify(state: &str) {
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let addr = if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        SocketAddr::from_abstract_name(name.as_bytes())
    } else {
        SocketAddr::from_pathname(&path)
    };
    if let Ok(addr) = addr {
        let _ = sock.send_to_addr(state.as_bytes(), &addr);
    }
}

/// Create a context on `domain`, with DDS-Security only if `enclave` is set.
/// rcl reads ROS_SECURITY_ENABLE at init time, so it can differ per context.
fn init_context(domain: usize, enclave: &str) -> Result<Context, String> {
    let mut args = vec!["robot_firewall".to_string()];
    if enclave.is_empty() {
        std::env::set_var("ROS_SECURITY_ENABLE", "false");
    } else {
        if std::env::var("ROS_SECURITY_KEYSTORE").map_or(true, |k| k.is_empty()) {
            return Err(format!("enclave {enclave} requested but ROS_SECURITY_KEYSTORE is unset"));
        }
        std::env::set_var("ROS_SECURITY_ENABLE", "true");
        if std::env::var("ROS_SECURITY_STRATEGY").is_err() {
            std::env::set_var("ROS_SECURITY_STRATEGY", "Enforce");
        }
        args.extend(["--ros-args".into(), "--enclave".into(), enclave.into()]);
    }
    Context::new(args, InitOptions::new().with_domain_id(Some(domain)))
        .map_err(|e| format!("init domain {domain}: {e}"))
}

fn fq(topic: &str) -> String {
    if topic.starts_with('/') { topic.to_string() } else { format!("/{topic}") }
}

fn now_s(node: &Node) -> f64 {
    node.get_clock().now().nsec as f64 * 1e-9
}

fn stamp_s(t: &builtin_interfaces::msg::Time) -> f64 {
    t.sec as f64 + t.nanosec as f64 * 1e-9
}

fn to_stamp(t: f64) -> builtin_interfaces::msg::Time {
    let sec = t.floor();
    builtin_interfaces::msg::Time { sec: sec as i32, nanosec: ((t - sec) * 1e9) as u32 }
}

fn gid_key(data: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let n = data.len().min(16);
    key[..n].copy_from_slice(&data[..n]);
    key
}

fn kv(key: &str, value: impl ToString) -> KeyValue {
    KeyValue { key: key.into(), value: value.to_string() }
}

fn level_of(severity: &str) -> u8 {
    match severity {
        "ERROR" => DiagnosticStatus::ERROR,
        "WARN" => DiagnosticStatus::WARN,
        _ => DiagnosticStatus::OK,
    }
}

fn joint_state_to_command(msg: &JointState, source: String) -> Command {
    Command {
        names: msg.name.clone(),
        position: msg.position.clone(),
        velocity: msg.velocity.clone(),
        effort: msg.effort.clone(),
        stamp: Some(stamp_s(&msg.header.stamp)),
        source,
    }
}

fn command_to_joint_state(cmd: &Command) -> JointState {
    let mut msg = JointState::default();
    msg.header.stamp = to_stamp(cmd.stamp.unwrap_or(0.0));
    msg.name = cmd.names.clone();
    msg.position = cmd.position.clone();
    msg.velocity = cmd.velocity.clone();
    msg.effort = cmd.effort.clone();
    msg
}

enum RobotPublisher {
    JointState(Publisher<JointState>),
    Array(Publisher<Float64MultiArray>),
}

impl RobotPublisher {
    fn publish(&self, cmd: &Command) {
        let result = match self {
            RobotPublisher::JointState(p) => p.publish(command_to_joint_state(cmd)),
            RobotPublisher::Array(p) => {
                p.publish(Float64MultiArray { data: cmd.position.clone(), ..Default::default() })
            }
        };
        if let Err(e) = result {
            eprintln!("robot publish failed: {e}");
        }
    }
}

// ----------------------------------------------------------------------------
// Firewall state shared by the two executor threads
// ----------------------------------------------------------------------------

struct Firewall {
    params: Params,
    domains: (usize, usize),
    core: Mutex<CommandFirewall>,
    untrusted: Node,
    trusted: Node,
    robot_pub: RobotPublisher,
    state_relay: Publisher<JointState>,
    events_pub: Publisher<DiagnosticStatus>,
    diag_pub: Publisher<DiagnosticArray>,
    status_pub: Publisher<StringMsg>,
    incident_log: PathBuf,
    /// RMW GID of each publisher on the untrusted command topic -> node name.
    publishers: Mutex<HashMap<[u8; 16], String>>,
    /// When each not-yet-identified GID first sent a message, and when the
    /// graph was last re-queried for it.
    unidentified: Mutex<Unidentified>,
    watch: Mutex<WatchState>,
    alive: Mutex<[Instant; 2]>,
}

#[derive(Default)]
struct WatchState {
    reported_unauthorized: Vec<[u8; 16]>,
    nft_last: HashMap<String, u64>,
    state_was_fresh: bool,
}

impl Firewall {
    fn now(&self) -> f64 {
        now_s(&self.untrusted)
    }

    fn report(&self, incidents: Vec<Incident>) {
        if incidents.is_empty() {
            return;
        }
        let mut log = OpenOptions::new().create(true).append(true).open(&self.incident_log);
        for inc in incidents {
            let summary = inc.summary();
            if inc.severity == "ERROR" {
                log_error!(self.untrusted.logger(), "{summary}");
            } else {
                log_warn!(self.untrusted.logger(), "{summary}");
            }
            let status = DiagnosticStatus {
                level: level_of(&inc.severity),
                name: format!("robot_firewall: {}", inc.attack),
                message: summary,
                hardware_id: self.params.hardware_id.clone(),
                values: vec![
                    kv("attack", &inc.attack),
                    kv("action", &inc.action),
                    kv("count", inc.count),
                    kv("source", &inc.source),
                    kv("mode", &inc.mode),
                    kv("time", format!("{:.3}", inc.time)),
                    kv("detail", &inc.detail),
                ],
            };
            let _ = self.events_pub.publish(status);
            match log.as_mut() {
                Ok(f) => {
                    let _ = writeln!(f, "{}", inc.to_json());
                }
                Err(e) => log_error!(self.untrusted.logger(), "cannot write incident log: {e}"),
            }
        }
    }

    /// Resolve the publisher of a message to a node name. DDS can deliver
    /// data before ROS node info for that endpoint arrives, so unknown GIDs
    /// trigger a (rate-limited) graph refresh and are never cached as known.
    fn publisher_name(&self, gid: [u8; 16]) -> Option<String> {
        let known = |map: &HashMap<[u8; 16], String>| {
            map.get(&gid).filter(|n| n.as_str() != NODE_NAME_UNKNOWN).cloned()
        };
        if let Some(name) = known(&self.publishers.lock().unwrap()) {
            return Some(name);
        }
        let due = {
            let mut unidentified = self.unidentified.lock().unwrap();
            let due = unidentified.1.is_none_or(|t| t.elapsed() >= Duration::from_millis(100));
            if due {
                unidentified.1 = Some(Instant::now());
            }
            due
        };
        if due {
            self.refresh_publishers();
        }
        known(&self.publishers.lock().unwrap())
    }

    fn refresh_publishers(&self) {
        let topic = fq(&self.params.command_topic);
        if let Ok(infos) = self.untrusted.get_publishers_info_by_topic(&topic) {
            *self.publishers.lock().unwrap() =
                infos.into_iter().map(|i| (i.endpoint_gid, i.node_name)).collect();
        }
    }

    fn on_command(&self, msg: JointState, info: MessageInfo) {
        let now = self.now();
        let gid = gid_key(&info.publisher_gid.data);
        let name = if self.params.allowed_publishers.is_empty() { None } else { self.publisher_name(gid) };
        if !self.params.allowed_publishers.is_empty() && name.is_none() {
            // Grace period for new publishers whose node info is still in flight:
            // drop (fail-closed) without raising an intrusion alarm.
            let first_seen = *self.unidentified.lock().unwrap().0.entry(gid).or_insert_with(Instant::now);
            if first_seen.elapsed() < Duration::from_secs(2) {
                let verdict = self.core.lock().unwrap().drop_unidentified(now);
                self.report(verdict.incidents);
                return;
            }
        } else {
            self.unidentified.lock().unwrap().0.remove(&gid);
        }
        let authorized = self.params.allowed_publishers.is_empty()
            || name.as_ref().is_some_and(|n| self.params.allowed_publishers.contains(n));
        let source = name.unwrap_or_else(|| "unidentified publisher (no ROS node info)".into());
        let cmd = joint_state_to_command(&msg, source);
        let verdict = {
            let mut core = self.core.lock().unwrap();
            let v = core.inspect_from(&cmd, now, authorized);
            if let Some(out) = &v.command {
                self.robot_pub.publish(out);
            }
            v
        };
        self.report(verdict.incidents);
    }

    fn on_state(&self, msg: JointState) {
        let incidents = self.core.lock().unwrap().observe_state(&msg.name, &msg.position, self.now());
        let _ = self.state_relay.publish(msg);
        self.report(incidents);
    }

    fn hold_tick(&self) {
        self.alive.lock().unwrap()[0] = Instant::now();
        let core = self.core.lock().unwrap();
        if core.mode == fw::LOCKDOWN {
            if let Some(hold) = core.hold_command(self.now()) {
                self.robot_pub.publish(&hold);
            }
        }
    }

    fn on_rearm(&self) -> Trigger_Response {
        let (was_armed, ok, message, mode) = {
            let mut core = self.core.lock().unwrap();
            let was_armed = core.mode == fw::ARMED;
            let (ok, message) = core.rearm(self.now());
            (was_armed, ok, message, core.mode)
        };
        if was_armed {
            // No state change: answer the caller, but keep the incident feed quiet.
            return Trigger_Response { success: ok, message };
        }
        log_warn!(self.untrusted.logger(), "Re-arm requested: {message}");
        let _ = self.events_pub.publish(DiagnosticStatus {
            level: if ok { DiagnosticStatus::OK } else { DiagnosticStatus::WARN },
            name: "robot_firewall: REARM".into(),
            message: message.clone(),
            hardware_id: self.params.hardware_id.clone(),
            values: vec![kv("attack", "REARM"), kv("mode", mode), kv("time", format!("{:.3}", self.now()))],
        });
        Trigger_Response { success: ok, message }
    }

    fn on_reset(&self) -> Trigger_Response {
        self.core.lock().unwrap().reset_counters();
        self.watch.lock().unwrap().reported_unauthorized.clear();
        Trigger_Response { success: true, message: "counters reset".into() }
    }

    fn watch_tick(&self) {
        self.alive.lock().unwrap()[1] = Instant::now();
        let now = self.now();
        let mut incidents = Vec::new();
        self.refresh_publishers();
        incidents.extend(self.check_robot_lan(now));
        incidents.extend(self.check_untrusted_publishers(now));
        incidents.extend(self.check_state_freshness(now));
        incidents.extend(self.check_nft_counters(now));
        let status = {
            let mut core = self.core.lock().unwrap();
            incidents.extend(core.flush(now));
            core.status(now)
        };
        self.report(incidents);
        self.publish_status(status);
        let alive = self.alive.lock().unwrap();
        if alive.iter().all(|t| t.elapsed() < Duration::from_secs(5)) {
            sd_notify("WATCHDOG=1");
        }
    }

    fn check_robot_lan(&self, now: f64) -> Vec<Incident> {
        let mut out = Vec::new();
        let out_topic = fq(&self.params.output_topic);
        let state_topic = fq(&self.params.state_topic);
        let out_pubs = self.trusted.count_publishers(&out_topic).unwrap_or(0);
        let mut core = self.core.lock().unwrap();
        if out_pubs > 1 {
            out.extend(core.report_external(
                fw::ROGUE_DEVICE,
                &format!("{} extra publisher(s) on robot {out_topic}", out_pubs - 1),
                now, "robot LAN", true));
        }
        let state_pubs = self.trusted.count_publishers(&state_topic).unwrap_or(0);
        if state_pubs > self.params.expected_state_publishers {
            out.extend(core.report_external(
                fw::ROGUE_DEVICE,
                &format!("{state_pubs} publishers on robot {state_topic} (expected {}); possible state spoofing",
                         self.params.expected_state_publishers),
                now, "robot LAN", true));
        }
        out
    }

    fn check_untrusted_publishers(&self, now: f64) -> Vec<Incident> {
        if self.params.allowed_publishers.is_empty() {
            return Vec::new();
        }
        let publishers = self.publishers.lock().unwrap().clone();
        let mut watch = self.watch.lock().unwrap();
        let mut core = self.core.lock().unwrap();
        let mut out = Vec::new();
        for (gid, name) in publishers {
            if name == NODE_NAME_UNKNOWN {
                continue; // node info not discovered yet; judged per message
            }
            if self.params.allowed_publishers.contains(&name) || watch.reported_unauthorized.contains(&gid) {
                continue;
            }
            watch.reported_unauthorized.push(gid);
            let detail = format!("node \"{name}\" publishing on {} is not allowlisted; its messages are dropped",
                                 self.params.command_topic);
            out.extend(core.report_external(fw::UNAUTHORIZED_PUBLISHER, &detail, now, &name,
                                            self.params.unauthorized_lockdown));
        }
        out
    }

    fn check_state_freshness(&self, now: f64) -> Vec<Incident> {
        let mut core = self.core.lock().unwrap();
        let fresh = core.state_fresh(now);
        let mut watch = self.watch.lock().unwrap();
        let out = if watch.state_was_fresh && !fresh {
            let detail = format!("no robot {} for more than {}s (robot link down?)",
                                 self.params.state_topic, self.params.state_timeout_s);
            core.report_external(fw::STATE_STALE, &detail, now, "robot", false)
        } else {
            Vec::new()
        };
        watch.state_was_fresh = fresh;
        out
    }

    fn check_nft_counters(&self, now: f64) -> Vec<Incident> {
        if self.params.nft_counters_file.is_empty() {
            return Vec::new();
        }
        let Ok(text) = std::fs::read_to_string(&self.params.nft_counters_file) else { return Vec::new() };
        let Ok(counters) = serde_json::from_str::<HashMap<String, u64>>(&text) else { return Vec::new() };
        let mut watch = self.watch.lock().unwrap();
        let mut core = self.core.lock().unwrap();
        let mut out = Vec::new();
        for (name, packets) in counters {
            let last = *watch.nft_last.get(&name).unwrap_or(&packets);
            watch.nft_last.insert(name.clone(), packets);
            if packets > last {
                let detail = format!("{} packet(s) blocked by nftables rule \"{name}\"", packets - last);
                out.extend(core.report_external(fw::NETWORK_PROBE, &detail, now, &name, false));
            }
        }
        out
    }

    fn publish_status(&self, status: fw_core::Status) {
        let mut json = serde_json::to_value(&status).expect("status serializes");
        json["domains"] = serde_json::json!({"untrusted": self.domains.0, "trusted": self.domains.1});
        json["time"] = serde_json::json!(self.now());
        json["implementation"] = serde_json::json!("rust");
        let _ = self.status_pub.publish(StringMsg { data: json.to_string() });

        let locked = status.mode == fw::LOCKDOWN;
        let mut values = vec![
            kv("mode", &status.mode),
            kv("forwarded", status.forwarded),
            kv("clamped", status.clamped),
            kv("dropped", status.dropped),
            kv("input_rate_hz", status.input_rate_hz),
            kv("robot_state_fresh", status.robot_state_fresh),
        ];
        values.extend(status.counters.iter().map(|(k, v)| kv(&format!("count.{k}"), v)));
        let mut array = DiagnosticArray::default();
        array.header.stamp = to_stamp(self.now());
        array.status.push(DiagnosticStatus {
            level: if locked { DiagnosticStatus::ERROR } else { DiagnosticStatus::OK },
            name: "robot_firewall: state".into(),
            message: if locked { status.lockdown_reason.clone() } else { "armed, forwarding".into() },
            hardware_id: self.params.hardware_id.clone(),
            values,
        });
        let _ = self.diag_pub.publish(array);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    if args.untrusted_domain == args.trusted_domain {
        return Err("untrusted and trusted domains must differ".into());
    }
    let mut params = Params::load(args.config.as_deref(), &args.overrides)?;
    if params.hardware_id.is_empty() {
        params.hardware_id = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_else(|_| "robot_firewall".into());
    }
    let incident_log = if params.incident_log_path.is_empty() {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".ros/robot_firewall/incidents.jsonl")
    } else {
        PathBuf::from(&params.incident_log_path)
    };
    if let Some(dir) = incident_log.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }

    let trusted_ctx = init_context(args.trusted_domain, &args.trusted_enclave)?;
    let untrusted_ctx = init_context(args.untrusted_domain, &args.enclave)?;
    let mut trusted_exec = trusted_ctx.create_basic_executor();
    let mut untrusted_exec = untrusted_ctx.create_basic_executor();
    let err = |e: RclrsError| e.to_string();

    // Parameter services are disabled: config comes only from the gateway's files.
    let trusted = trusted_exec
        .create_node("firewall_gateway".start_parameter_services(false))
        .map_err(err)?;
    let untrusted = untrusted_exec
        .create_node("firewall".start_parameter_services(false))
        .map_err(err)?;

    let robot_pub = match params.output_type.as_str() {
        "joint_state" => RobotPublisher::JointState(trusted.create_publisher(params.output_topic.as_str()).map_err(err)?),
        _ => RobotPublisher::Array(trusted.create_publisher(params.output_topic.as_str()).map_err(err)?),
    };
    let fw = Arc::new(Firewall {
        core: Mutex::new(CommandFirewall::new(params.firewall_config())),
        domains: (args.untrusted_domain, args.trusted_domain),
        robot_pub,
        state_relay: untrusted.create_publisher(params.state_topic.as_str()).map_err(err)?,
        events_pub: untrusted.create_publisher("/firewall/events".keep_last(50)).map_err(err)?,
        diag_pub: untrusted.create_publisher("/diagnostics").map_err(err)?,
        status_pub: untrusted.create_publisher("/firewall/status").map_err(err)?,
        incident_log,
        publishers: Mutex::new(HashMap::new()),
        unidentified: Mutex::new((HashMap::new(), None)),
        watch: Mutex::new(WatchState::default()),
        alive: Mutex::new([Instant::now(); 2]),
        untrusted: untrusted.clone(),
        trusted: trusted.clone(),
        params,
    });

    let f = fw.clone();
    let _state_sub = trusted
        .create_subscription::<JointState, _>(fw.params.state_topic.as_str(), move |msg: JointState| f.on_state(msg))
        .map_err(err)?;
    let f = fw.clone();
    let _hold_timer = trusted
        .create_timer_repeating(Duration::from_secs_f64(1.0 / fw.params.hold_rate_hz), move || f.hold_tick())
        .map_err(err)?;

    let f = fw.clone();
    // Deep queue so bursts reach the rate limiter instead of being discarded by DDS.
    let _cmd_sub = untrusted
        .create_subscription::<JointState, _>(
            fw.params.command_topic.as_str().keep_last(fw.params.input_queue_depth),
            move |msg: JointState, info: MessageInfo| f.on_command(msg, info),
        )
        .map_err(err)?;
    let f = fw.clone();
    let _rearm = untrusted
        .create_service::<Trigger, _>("/firewall/rearm", move |_req: Trigger_Request| f.on_rearm())
        .map_err(err)?;
    let f = fw.clone();
    let _reset = untrusted
        .create_service::<Trigger, _>("/firewall/reset", move |_req: Trigger_Request| f.on_reset())
        .map_err(err)?;
    let f = fw.clone();
    let _watch_timer = untrusted
        .create_timer_repeating(Duration::from_secs_f64(fw.params.watch_period_s), move || f.watch_tick())
        .map_err(err)?;

    {
        let core = fw.core.lock().unwrap();
        log_info!(
            fw.untrusted.logger(),
            "Robot firewall (Rust) up: untrusted domain {} -> trusted domain {}, joints={:?}, mode={}, \
             allowlist={:?}, incident log {}",
            args.untrusted_domain, args.trusted_domain, core.cfg.joint_names, core.mode,
            fw.params.allowed_publishers, fw.incident_log.display()
        );
    }

    let trusted_thread = std::thread::spawn(move || trusted_exec.spin(SpinOptions::default()));
    sd_notify("READY=1");
    let errors = untrusted_exec.spin(SpinOptions::default());
    let _ = trusted_thread.join();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("executor errors: {errors:?}"))
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("robot_firewall: {e}");
        std::process::exit(1);
    }
}
