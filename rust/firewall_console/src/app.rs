//! egui window: every firewall debugging command as a button. Hovering a
//! button shows the equivalent CLI command; running it prints that command
//! and its output in the console panel.

use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use fw_core::attacks::ATTACK_MODES;

use crate::ros::RosLink;
use crate::shell::{self, Expect};
use crate::state::{lock, LogKind, TestResult};

const RED: Color32 = Color32::from_rgb(0xe0, 0x4f, 0x4f);
const AMBER: Color32 = Color32::from_rgb(0xe0, 0xa0, 0x30);
const GREEN: Color32 = Color32::from_rgb(0x3f, 0xb9, 0x50);
const DIM: Color32 = Color32::from_rgb(0x90, 0x90, 0x98);
const CMD: Color32 = Color32::from_rgb(0x6c, 0xb6, 0xff);

pub struct ConsoleApp {
    ros: Arc<RosLink>,
    gateway: String,
    robot_ip: String,
    confirm_restart: bool,
    feed_filter: String,
}

impl ConsoleApp {
    pub fn new(ros: Arc<RosLink>, gateway: String, robot_ip: String) -> Self {
        Self { ros, gateway, robot_ip, confirm_restart: false, feed_filter: String::new() }
    }

    fn ssh(&self, label: &str, remote: &str, expect: Expect) {
        if self.gateway.trim().is_empty() {
            lock(&self.ros.shared).push_log(LogKind::Fail, "set the gateway ssh target first (e.g. ubuntu@192.168.1.60)");
            return;
        }
        shell::run(&self.ros.shared, label, shell::ssh_args(self.gateway.trim(), remote), expect);
    }

    fn ping(&self, label: &str, host: &str, expect: Expect) {
        let argv = ["ping", "-c", "3", "-W", "1", host].iter().map(|s| s.to_string()).collect();
        shell::run(&self.ros.shared, label, argv, expect);
    }

    // ------------------------------------------------------------------
    // Panels
    // ------------------------------------------------------------------

    fn header(&mut self, ui: &mut egui::Ui) {
        let s = lock(&self.ros.shared);
        let age = s.status_at.map(|t| t.elapsed().as_secs_f64());
        ui.horizontal(|ui| {
            ui.heading("Robot Firewall Console");
            ui.separator();
            match (age, s.mode()) {
                (Some(a), Some(mode)) if a < 3.0 => {
                    let (color, text) = if mode == "LOCKDOWN" { (RED, "LOCKDOWN") } else { (GREEN, "ARMED") };
                    ui.label(RichText::new(format!(" {text} ")).strong().color(Color32::WHITE).background_color(color));
                    if mode == "LOCKDOWN" {
                        let reason = s.status.as_ref().and_then(|j| j["lockdown_reason"].as_str()).unwrap_or("");
                        ui.label(RichText::new(reason).color(RED));
                    } else {
                        ui.label(RichText::new("forwarding commands").color(GREEN));
                    }
                }
                _ => {
                    ui.label(RichText::new(" FIREWALL UNREACHABLE ").strong().color(Color32::WHITE).background_color(RED));
                    ui.label(RichText::new("no /firewall/status - check WiFi, domain, SROS2 env, service").color(DIM));
                }
            }
        });
        ui.horizontal(|ui| {
            let implementation = s.status.as_ref().and_then(|j| j["implementation"].as_str()).unwrap_or("?");
            ui.label(RichText::new(format!("domain {}  |  gateway: {implementation}", self.ros.domain)).color(DIM));
            if let Some(skew) = s.clock_skew_s {
                let color = if skew.abs() < 0.25 { DIM } else { RED };
                ui.label(RichText::new(format!("|  clock skew {skew:+.3}s")).color(color));
            }
            if let Some(j) = &s.status {
                ui.label(RichText::new(format!(
                    "|  in {} Hz  forwarded {}  clamped {}  dropped {}  robot state {}",
                    j["input_rate_hz"], j["forwarded"], j["clamped"], j["dropped"],
                    if j["robot_state_fresh"].as_bool() == Some(true) { "ok" } else { "STALE" }
                )).color(DIM));
            }
        });
    }

    fn firewall_controls(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firewall");
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("Re-arm").strong()).fill(GREEN.gamma_multiply(0.35)))
                .on_hover_text("ros2 service call /firewall/rearm std_srvs/srv/Trigger\nRefused unless robot state is fresh and within limits.")
                .clicked()
            {
                self.ros.trigger("rearm");
            }
            if ui.button("Reset counters").on_hover_text("ros2 service call /firewall/reset std_srvs/srv/Trigger").clicked() {
                self.ros.trigger("reset");
            }
        });
    }

    /// Per-incident counters; kept at the bottom so they never shift buttons.
    fn counters(&mut self, ui: &mut egui::Ui) {
        ui.heading("Counters");
        let s = lock(&self.ros.shared);
        match s.status.as_ref().and_then(|j| j["counters"].as_object()) {
            Some(counters) if !counters.is_empty() => {
                egui::Grid::new("counters").striped(true).show(ui, |ui| {
                    for (k, v) in counters {
                        ui.label(k);
                        ui.label(v.to_string());
                        ui.end_row();
                    }
                });
            }
            _ => {
                ui.label(RichText::new("(none)").color(DIM));
            }
        }
    }

    fn commander(&mut self, ui: &mut egui::Ui) {
        ui.heading("Commander & attacks");
        let mut s = lock(&self.ros.shared);
        ui.horizontal(|ui| {
            let label = if s.commander_on { "Stop commander" } else { "Start commander" };
            if ui.toggle_value(&mut s.commander_on, label)
                .on_hover_text("ros2 run monitor_py attack_sim_node\nSends a smooth, legitimate trajectory that starts at the robot's pose.")
                .changed()
            {
                let on = s.commander_on;
                s.push_log(LogKind::Info, if on { "commander started (node attack_sim_node)" } else { "commander stopped" });
            }
            ui.label(RichText::new(format!("{} sent", s.sent)).color(DIM));
        });
        if s.commander_on && s.robot_pose.is_none() {
            ui.label(RichText::new("waiting for joint_states from the gateway...").color(AMBER));
        }
        ui.add_space(4.0);
        egui::Grid::new("attacks").num_columns(2).spacing([6.0, 4.0]).show(ui, |ui| {
            for (i, (mode, what, outcome)) in ATTACK_MODES.iter().enumerate() {
                let active = s.attack == *mode;
                let text = if *mode == "none" { "Stop attack".to_string() } else { mode.to_string() };
                let mut button = egui::Button::new(if active { RichText::new(&text).strong() } else { RichText::new(&text) })
                    .min_size(egui::vec2(140.0, 0.0));
                if active && *mode != "none" {
                    button = button.fill(RED.gamma_multiply(0.5));
                }
                let hover = format!("ros2 param set /attack_sim_node attack_mode {mode}\n{what}\nExpected: {outcome}");
                if ui.add_enabled(s.commander_on || *mode == "none", button).on_hover_text(hover).clicked() {
                    s.set_attack(mode);
                }
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("auto-stop after");
            ui.add(egui::DragValue::new(&mut s.attack_duration_s).range(0.0..=60.0).speed(0.5).suffix(" s"))
                .on_hover_text("0 = until stopped");
            ui.label("joint");
            let max_joint = s.joint_names.len().saturating_sub(1);
            ui.add(egui::DragValue::new(&mut s.attack_joint).range(0..=max_joint));
        });
        ui.horizontal(|ui| {
            ui.label("magnitude");
            ui.add(egui::DragValue::new(&mut s.attack_magnitude).range(0.1..=10.0).speed(0.1));
            ui.label("flood copies");
            ui.add(egui::DragValue::new(&mut s.flood_copies).range(2..=500));
        });
    }

    fn self_test(&mut self, ui: &mut egui::Ui) {
        ui.heading("Self-test");
        let running = lock(&self.ros.shared).selftest_running;
        if ui.add_enabled(!running, egui::Button::new(if running { "Running..." } else { "Run full self-test" }))
            .on_hover_text("Re-arms, runs every attack, checks the expected incident is reported and that the robot stayed within limits.")
            .clicked()
        {
            self.ros.run_self_test();
        }
        let s = lock(&self.ros.shared);
        egui::Grid::new("selftest").striped(true).show(ui, |ui| {
            for row in &s.selftest {
                ui.label(row.mode);
                ui.label(RichText::new(row.expected).color(DIM));
                let (text, color, tip) = match &row.result {
                    TestResult::Pending => ("-".to_string(), DIM, String::new()),
                    TestResult::Running => ("running".to_string(), AMBER, String::new()),
                    TestResult::Pass(m) => ("PASS".to_string(), GREEN, m.clone()),
                    TestResult::Fail(m) => ("FAIL".to_string(), RED, m.clone()),
                };
                let r = ui.label(RichText::new(text).strong().color(color));
                if !tip.is_empty() {
                    r.on_hover_text(tip);
                }
                ui.end_row();
            }
        });
    }

    fn inspection_buttons(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("ROS").strong());
            if ui.button("Nodes").on_hover_text("ros2 node list").clicked() {
                self.ros.list_nodes();
            }
            if ui.button("Topics").on_hover_text("ros2 topic list -t").clicked() {
                self.ros.list_topics();
            }
            if ui.button("Command publishers").on_hover_text("ros2 topic info /joint_commands -v").clicked() {
                self.ros.command_publishers();
            }
            if ui.button("Topic rates").on_hover_text("ros2 topic hz joint_states / /firewall/status / /firewall/events").clicked() {
                self.ros.topic_rates();
            }
            if ui.button("Robot state").on_hover_text("ros2 topic echo --once joint_states").clicked() {
                self.ros.latest_state();
            }
            if ui.button("Clock skew").on_hover_text("Compare laptop time with the gateway's (replay window is 0.5 s)").clicked() {
                self.ros.clock_check();
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Gateway").strong());
            ui.add(egui::TextEdit::singleline(&mut self.gateway).hint_text("user@nanopi-ip").desired_width(150.0));
            ui.label("robot IP");
            ui.add(egui::TextEdit::singleline(&mut self.robot_ip).desired_width(110.0));
        });
        ui.horizontal_wrapped(|ui| {
            let host = shell::host_of(self.gateway.trim()).to_string();
            if ui.button("Ping gateway").on_hover_text(format!("ping -c 3 -W 1 {host}")).clicked() {
                if host.is_empty() {
                    lock(&self.ros.shared).push_log(LogKind::Fail, "set the gateway ssh target first");
                } else {
                    self.ping("gateway reachable", &host, Expect::Success);
                }
            }
            let robot = self.robot_ip.trim().to_string();
            if ui.button("Robot NOT reachable")
                .on_hover_text(format!("ping -c 3 -W 1 {robot}\nPASS when this FAILS: nothing may route from the laptop to the robot."))
                .clicked()
            {
                self.ping("robot isolated from laptop", &robot, Expect::Failure);
            }
            if ui.button("Service status").on_hover_text("ssh <gateway> systemctl status robot-firewall").clicked() {
                self.ssh("firewall service status", "systemctl status robot-firewall robot-firewall-counters --no-pager -n 10", Expect::Success);
            }
            if ui.button("Journal").on_hover_text("ssh <gateway> journalctl -u robot-firewall -n 40").clicked() {
                self.ssh("firewall journal", "journalctl -u robot-firewall -n 40 --no-pager", Expect::Success);
            }
            if ui.button("nft counters").on_hover_text("ssh <gateway> sudo -n nft list counters table inet robot_fw").clicked() {
                self.ssh("nftables counters", "sudo -n nft list counters table inet robot_fw", Expect::Success);
            }
            if ui.button("Incident log").on_hover_text("ssh <gateway> tail -n 20 /var/log/robot_firewall/incidents.jsonl").clicked() {
                self.ssh("incident log", "tail -n 20 /var/log/robot_firewall/incidents.jsonl", Expect::Success);
            }
            if ui.button("Forwarding off").on_hover_text("ssh <gateway> sysctl net.ipv4.ip_forward  (must be 0)").clicked() {
                self.ssh("ip forwarding disabled", "test \"$(sysctl -n net.ipv4.ip_forward)\" = 0 && echo ip_forward=0", Expect::Success);
            }
            if ui.add(egui::Button::new(RichText::new("Restart firewall").color(RED)))
                .on_hover_text("ssh <gateway> sudo -n systemctl restart robot-firewall\nThe firewall comes back in LOCKDOWN.")
                .clicked()
            {
                self.confirm_restart = true;
            }
        });
    }

    fn incident_feed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Incident feed");
            ui.add(egui::TextEdit::singleline(&mut self.feed_filter).hint_text("filter").desired_width(120.0));
            if ui.small_button("Clear").clicked() {
                lock(&self.ros.shared).events.clear();
            }
        });
        let s = lock(&self.ros.shared);
        let filter = self.feed_filter.to_lowercase();
        egui::ScrollArea::vertical().id_salt("feed").stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            if s.events.is_empty() {
                ui.label(RichText::new("(no incidents yet)").color(DIM));
            }
            for e in s.events.iter().filter(|e| filter.is_empty() || e.message.to_lowercase().contains(&filter)) {
                let color = match e.level {
                    2 => RED,
                    1 => AMBER,
                    _ => GREEN,
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&e.when).monospace().color(DIM));
                    ui.label(RichText::new(&e.message).monospace().color(color));
                });
            }
        });
    }

    fn console_log(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Console");
            if ui.small_button("Clear").clicked() {
                lock(&self.ros.shared).log.clear();
            }
            if ui.small_button("Copy all").clicked() {
                let text: String = lock(&self.ros.shared).log.iter().map(|l| format!("{} {}\n", l.when, l.text)).collect();
                ui.ctx().copy_text(text);
            }
        });
        let s = lock(&self.ros.shared);
        egui::ScrollArea::vertical().id_salt("log").stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            for l in &s.log {
                let color = match l.kind {
                    LogKind::Cmd => CMD,
                    LogKind::Pass => GREEN,
                    LogKind::Fail => RED,
                    LogKind::Info => AMBER,
                    LogKind::Out => ui.visuals().text_color(),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&l.when).monospace().color(DIM));
                    ui.label(RichText::new(&l.text).monospace().color(color));
                });
            }
        });
    }

    fn restart_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_restart {
            return;
        }
        egui::Window::new("Restart firewall service?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("The robot holds position while the gateway restarts.");
                ui.label("The firewall comes back in LOCKDOWN and must be re-armed.");
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Restart").color(RED)).clicked() {
                        self.ssh("restart firewall", "sudo -n systemctl restart robot-firewall", Expect::Success);
                        self.confirm_restart = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_restart = false;
                    }
                });
            });
    }
}

impl eframe::App for ConsoleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("header").show(ui, |ui| self.header(ui));
        egui::Panel::left("controls").resizable(true).default_size(360.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.firewall_controls(ui);
                ui.separator();
                self.commander(ui);
                ui.separator();
                self.self_test(ui);
                ui.separator();
                self.counters(ui);
            });
        });
        egui::Panel::bottom("console").resizable(true).default_size(300.0).show(ui, |ui| {
            self.inspection_buttons(ui);
            ui.separator();
            self.console_log(ui);
        });
        egui::CentralPanel::default().show(ui, |ui| self.incident_feed(ui));
        let ctx = ui.ctx().clone();
        self.restart_dialog(&ctx);
        ctx.request_repaint_after(Duration::from_millis(200));
    }

    fn on_exit(&mut self) {
        lock(&self.ros.shared).commander_on = false;
        self.ros.shutdown();
    }
}
