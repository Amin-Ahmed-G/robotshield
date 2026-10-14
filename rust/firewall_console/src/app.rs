//! Robot firewall console: a monitoring-style dashboard where every debugging
//! command is a button. Hovering a button shows the equivalent CLI command;
//! running it prints that command and its output in the console panel.

use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke};
use egui_plot::{HLine, Line, LineStyle, Plot, PlotPoints};
use fw_core::attacks::ATTACK_MODES;

use crate::ros::{RosLink, SELF_TEST};
use crate::shell::{self, Expect};
use crate::state::{lock, LogKind, TestResult, HISTORY_S};
use crate::theme::{self, *};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Incidents,
    Diagnostics,
}

pub struct ConsoleApp {
    ros: Arc<RosLink>,
    gateway: String,
    robot_ip: String,
    confirm_restart: bool,
    feed_filter: String,
    tab: Tab,
}

impl ConsoleApp {
    pub fn new(ctx: &egui::Context, ros: Arc<RosLink>, gateway: String, robot_ip: String) -> Self {
        theme::apply(ctx);
        Self { ros, gateway, robot_ip, confirm_restart: false, feed_filter: String::new(), tab: Tab::Incidents }
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
    // Top bar and status bar
    // ------------------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let s = lock(&self.ros.shared);
        let connected = s.status_at.is_some_and(|t| t.elapsed().as_secs_f64() < 3.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("RoboShield").size(19.0).strong().color(ACCENT));
            ui.label(RichText::new("Robot Firewall Console").size(15.0).color(TEXT2));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(4.0);
                ui.label(RichText::new(chrono::Local::now().format("%H:%M:%S").to_string()).monospace().color(MUTED));
                ui.separator();
                if let Some(skew) = s.clock_skew_s {
                    let color = if skew.abs() < 0.25 { TEXT2 } else { CRIT };
                    ui.label(RichText::new(format!("clock skew {skew:+.3}s")).color(color))
                        .on_hover_text("Laptop minus gateway clock. Replay protection needs |skew| < 0.25 s.");
                    ui.separator();
                }
                match s.status.as_ref().and_then(|j| j.get("secure")).and_then(|v| v.as_bool()) {
                    Some(true) => chip(ui, "SROS2 ENFORCED", GOOD),
                    Some(false) => chip(ui, "SROS2 OFF", WARN),
                    None => chip(ui, "SROS2 ?", MUTED),
                }
                .on_hover_text("DDS-Security on the laptop side of the gateway");
                let implementation = s.status.as_ref().and_then(|j| j["implementation"].as_str()).unwrap_or("?");
                ui.label(RichText::new(format!("gateway: {implementation}")).color(TEXT2));
                ui.label(RichText::new(format!("domain {}", self.ros.domain)).color(TEXT2));
                ui.separator();
                if connected {
                    dot_label(ui, GOOD, "Connected");
                } else {
                    dot_label(ui, CRIT, "Gateway unreachable");
                }
            });
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let mut s = lock(&self.ros.shared);
        let t = s.t();
        let events = s.events.len();
        let last = s.events.last().map(|e| format!("{}  {}", e.when, e.attack)).unwrap_or_else(|| "none".into());
        let state_hz = s.state_rate.rate_hz(t);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("RoboShield v{}", env!("CARGO_PKG_VERSION"))).small().color(MUTED));
            ui.separator();
            ui.label(RichText::new(format!("{events} incidents  ·  last: {last}")).small().color(MUTED));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(format!("robot state {state_hz:.0} Hz  ·  {} commands sent", s.sent)).small().color(MUTED));
            });
        });
    }

    // ------------------------------------------------------------------
    // Left column: control cards
    // ------------------------------------------------------------------

    fn firewall_card(&mut self, ui: &mut egui::Ui) {
        card(ui, "Firewall", |ui| {
            let (mode, reason, fresh, peak) = {
                let s = lock(&self.ros.shared);
                let connected = s.status_at.is_some_and(|t| t.elapsed().as_secs_f64() < 3.0);
                let mode = if connected { s.mode().unwrap_or_default() } else { "UNREACHABLE".into() };
                let reason = s.status.as_ref().and_then(|j| j["lockdown_reason"].as_str()).unwrap_or("").to_string();
                let fresh = s.status.as_ref().and_then(|j| j["robot_state_fresh"].as_bool()).unwrap_or(false);
                (mode, reason, fresh, s.max_abs_position)
            };
            ui.horizontal(|ui| {
                let color = match mode.as_str() {
                    "ARMED" => GOOD,
                    "LOCKDOWN" => CRIT,
                    _ => MUTED,
                };
                chip(ui, &mode, color);
                ui.label(RichText::new(if mode == "ARMED" { "forwarding commands" } else { "" }).color(TEXT2));
            });
            if mode == "LOCKDOWN" && !reason.is_empty() {
                ui.label(RichText::new(reason).small().color(CRIT));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let rearm = egui::Button::new(RichText::new("Re-arm").strong().color(Color32::WHITE)).fill(ACCENT);
                if ui.add(rearm)
                    .on_hover_text("ros2 service call /firewall/rearm std_srvs/srv/Trigger\nRefused unless robot state is fresh and within limits.")
                    .clicked()
                {
                    self.ros.trigger("rearm");
                }
                if ui.button("Reset counters").on_hover_text("ros2 service call /firewall/reset std_srvs/srv/Trigger").clicked() {
                    self.ros.trigger("reset");
                }
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                dot_label(ui, if fresh { GOOD } else { CRIT }, if fresh { "robot state live" } else { "robot state stale" });
                ui.label(RichText::new(format!("max |pos| {peak:.3} rad")).small().color(MUTED));
            });
        });
    }

    fn attack_card(&mut self, ui: &mut egui::Ui) {
        card(ui, "Attack simulator", |ui| {
            let mut s = lock(&self.ros.shared);
            ui.horizontal(|ui| {
                let (label, fill) = if s.commander_on { ("Stop commander", CARD_HI) } else { ("Start commander", ACCENT) };
                let button = egui::Button::new(RichText::new(label).strong().color(Color32::WHITE)).fill(fill);
                if ui.add(button)
                    .on_hover_text("ros2 run monitor_py attack_sim_node\nSmooth, legitimate trajectory that starts at the robot's pose.")
                    .clicked()
                {
                    s.commander_on = !s.commander_on;
                    let on = s.commander_on;
                    s.push_log(LogKind::Info, if on { "commander started (node attack_sim_node)" } else { "commander stopped" });
                }
                if s.commander_on && s.robot_pose.is_none() {
                    ui.label(RichText::new("waiting for robot state").small().color(WARN));
                }
            });
            ui.add_space(4.0);
            let width = (ui.available_width() - 8.0) / 2.0;
            egui::Grid::new("attacks").num_columns(2).spacing([8.0, 6.0]).striped(false).show(ui, |ui| {
                for (i, (mode, what, outcome)) in ATTACK_MODES.iter().enumerate().skip(1) {
                    let active = s.attack == *mode;
                    let mut b = egui::Button::new(RichText::new(*mode).color(if active { Color32::WHITE } else { TEXT }))
                        .min_size(egui::vec2(width, 28.0));
                    if active {
                        b = b.fill(CRIT.gamma_multiply(0.8));
                    }
                    let hover = format!("ros2 param set /attack_sim_node attack_mode {mode}\n{what}\nExpected: {outcome}");
                    if ui.add_enabled(s.commander_on, b).on_hover_text(hover).clicked() {
                        s.set_attack(mode);
                    }
                    if i % 2 == 0 {
                        ui.end_row();
                    }
                }
            });
            ui.add_space(4.0);
            let stop = egui::Button::new("Stop attack").min_size(egui::vec2(ui.available_width(), 28.0));
            if ui.add_enabled(s.attack != "none", stop).clicked() {
                s.set_attack("none");
            }
            egui::CollapsingHeader::new(RichText::new("Attack parameters").color(TEXT2)).show(ui, |ui| {
                egui::Grid::new("attack_params").num_columns(2).show(ui, |ui| {
                    ui.label("auto-stop after");
                    ui.add(egui::DragValue::new(&mut s.attack_duration_s).range(0.0..=60.0).speed(0.5).suffix(" s"))
                        .on_hover_text("0 = until stopped");
                    ui.end_row();
                    ui.label("target joint");
                    let max_joint = s.joint_names.len().saturating_sub(1);
                    ui.add(egui::DragValue::new(&mut s.attack_joint).range(0..=max_joint));
                    ui.end_row();
                    ui.label("magnitude");
                    ui.add(egui::DragValue::new(&mut s.attack_magnitude).range(0.1..=10.0).speed(0.1));
                    ui.end_row();
                    ui.label("flood copies / tick");
                    ui.add(egui::DragValue::new(&mut s.flood_copies).range(2..=500));
                    ui.end_row();
                });
            });
        });
    }

    fn selftest_card(&mut self, ui: &mut egui::Ui) {
        card(ui, "Self-test", |ui| {
            let running = lock(&self.ros.shared).selftest_running;
            let label = if running { "Running…" } else { "Run full self-test" };
            let b = egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
                .fill(if running { CARD_HI } else { ACCENT })
                .min_size(egui::vec2(ui.available_width(), 30.0));
            if ui.add_enabled(!running, b)
                .on_hover_text("Re-arms, fires every attack, checks the expected incident is reported and that the robot stayed within limits.")
                .clicked()
            {
                self.ros.run_self_test();
            }
            let s = lock(&self.ros.shared);
            if s.selftest.is_empty() {
                ui.label(RichText::new(format!("{} attack types, about 20 s", SELF_TEST.len())).small().color(MUTED));
                return;
            }
            let done = s.selftest.iter().filter(|r| matches!(r.result, TestResult::Pass(_) | TestResult::Fail(_))).count();
            let passed = s.selftest.iter().filter(|r| matches!(r.result, TestResult::Pass(_))).count();
            ui.add(egui::ProgressBar::new(done as f32 / s.selftest.len() as f32)
                .text(format!("{passed} / {} passed", s.selftest.len()))
                .fill(if passed == done { GOOD.gamma_multiply(0.7) } else { CRIT.gamma_multiply(0.7) }));
            let name_w = ui.available_width() - 90.0;
            egui::Grid::new("selftest").num_columns(2).spacing([8.0, 4.0]).striped(true).min_col_width(70.0).show(ui, |ui| {
                for row in &s.selftest {
                    ui.add_sized([name_w, 22.0], egui::Label::new(RichText::new(row.mode).color(TEXT2)))
                        .on_hover_text(row.expected);
                    let (text, color, tip) = match &row.result {
                        TestResult::Pending => ("—", MUTED, String::new()),
                        TestResult::Running => ("RUNNING", WARN, String::new()),
                        TestResult::Pass(m) => ("PASS", GOOD, m.clone()),
                        TestResult::Fail(m) => ("FAIL", CRIT, m.clone()),
                    };
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let r = if text == "—" { ui.label(RichText::new(text).color(color)) } else { chip(ui, text, color) };
                        if !tip.is_empty() {
                            r.on_hover_text(tip);
                        }
                    });
                    ui.end_row();
                }
            });
        });
    }

    // ------------------------------------------------------------------
    // Central area: KPIs, charts, tabs
    // ------------------------------------------------------------------

    fn kpis(&mut self, ui: &mut egui::Ui) {
        let s = lock(&self.ros.shared);
        let j = s.status.clone().unwrap_or_default();
        let num = |k: &str| j.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let connected = s.status_at.is_some_and(|t| t.elapsed().as_secs_f64() < 3.0);
        let mode = if connected { s.mode().unwrap_or_else(|| "—".into()) } else { "OFFLINE".into() };
        let mode_color = match mode.as_str() {
            "ARMED" => GOOD,
            "LOCKDOWN" => CRIT,
            _ => MUTED,
        };
        let passed = s.selftest.iter().filter(|r| matches!(r.result, TestResult::Pass(_))).count();
        let selftest = if s.selftest.is_empty() { "—".to_string() } else { format!("{passed}/{}", s.selftest.len()) };
        let blocked_types = j.get("counters").and_then(|c| c.as_object()).map_or(0, |c| {
            c.keys().filter(|k| !matches!(k.as_str(), "BLOCKED_IN_LOCKDOWN" | "LOCKDOWN" | "UNIDENTIFIED_PUBLISHER")).count()
        });
        drop(s);
        let tiles: [(&str, String, Color32, String); 6] = [
            ("Mode", mode.clone(), mode_color, if mode == "LOCKDOWN" { "robot held at safe pose".into() } else { "firewall state".into() }),
            ("Input rate", format!("{:.0} Hz", num("input_rate_hz")), TEXT, "commands from laptop".into()),
            ("Forwarded", format!("{:.0}", num("forwarded")), TEXT, "reached the robot".into()),
            ("Clamped", format!("{:.0}", num("clamped")), if num("clamped") > 0.0 { WARN } else { TEXT }, "limited to safe range".into()),
            ("Dropped", format!("{:.0}", num("dropped")), if num("dropped") > 0.0 { CRIT } else { TEXT }, format!("{blocked_types} attack types seen")),
            ("Self-test", selftest, if passed > 0 { GOOD } else { TEXT }, "attacks caught".into()),
        ];
        let gap = 10.0;
        let w = ((ui.available_width() - gap * (tiles.len() as f32 - 1.0)) / tiles.len() as f32).floor();
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (caption, value, color, sub) in tiles {
                kpi(ui, w, caption, &value, color, &sub);
            }
        });
    }

    fn charts(&mut self, ui: &mut egui::Ui) {
        let s = lock(&self.ros.shared);
        let now = s.t();
        let names = s.joint_names.clone();
        let mut joints: Vec<Vec<[f64; 2]>> = vec![Vec::new(); names.len()];
        for (t, pose) in &s.pose_history {
            for (j, p) in pose.iter().enumerate().take(names.len()) {
                joints[j].push([t - now, *p]);
            }
        }
        let mut limits: Vec<f64> = s.status.as_ref().and_then(|j| j.get("limits")).and_then(|l| l.as_object())
            .map(|m| m.values().filter_map(|v| v.as_array()).flatten().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();
        limits.sort_by(|a, b| a.partial_cmp(b).unwrap());
        limits.dedup_by(|a, b| (*a - *b).abs() < 1e-9);
        let fwd: Vec<[f64; 2]> = s.traffic_history.iter().map(|(t, f, _)| [t - now, *f]).collect();
        let drop_: Vec<[f64; 2]> = s.traffic_history.iter().map(|(t, _, d)| [t - now, *d]).collect();
        drop(s);

        let gap = 10.0;
        let w = ((ui.available_width() - gap) / 2.0).floor();
        let h = 200.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            ui.allocate_ui_with_layout(egui::vec2(w, h + 56.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(w);
                card(ui, "Robot joint positions (rad) vs limits", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (j, name) in names.iter().enumerate() {
                            dot_label(ui, SERIES[j % SERIES.len()], name.clone());
                        }
                        dot_label(ui, CRIT, "limit");
                    });
                    Plot::new("pose_plot")
                        .height(h)
                        .allow_drag(false).allow_zoom(false).allow_scroll(false).allow_boxed_zoom(false)
                        .include_x(-HISTORY_S).include_x(0.0)
                        .include_y(-1.2).include_y(1.2)
                        .show_background(false)
                        .show_grid([false, true])
                        .x_axis_label("seconds ago")
                        .y_axis_min_width(32.0)
                        .show(ui, |p| {
                            for lim in &limits {
                                p.hline(HLine::new("limit", *lim).color(CRIT.gamma_multiply(0.85)).width(1.2)
                                    .style(LineStyle::Dashed { length: 8.0 }));
                            }
                            for (j, pts) in joints.into_iter().enumerate() {
                                let color = SERIES[j % SERIES.len()];
                                p.line(Line::new(names[j].clone(), PlotPoints::from(pts)).color(color).width(2.0));
                            }
                        });
                });
            });
            ui.allocate_ui_with_layout(egui::vec2(w, h + 56.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(w);
                card(ui, "Command traffic (msgs/s)", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        dot_label(ui, FORWARDED, "forwarded to robot");
                        dot_label(ui, BLOCKED, "dropped by firewall");
                    });
                    Plot::new("traffic_plot")
                        .height(h)
                        .allow_drag(false).allow_zoom(false).allow_scroll(false).allow_boxed_zoom(false)
                        .include_x(-HISTORY_S).include_x(0.0)
                        .include_y(0.0).include_y(30.0)
                        .show_background(false)
                        .show_grid([false, true])
                        .x_axis_label("seconds ago")
                        .y_axis_min_width(32.0)
                        .show(ui, |p| {
                            p.line(Line::new("forwarded to robot", PlotPoints::from(fwd)).color(FORWARDED).width(2.0));
                            p.line(Line::new("dropped", PlotPoints::from(drop_)).color(BLOCKED).width(2.0));
                        });
                });
            });
        });
    }

    fn tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (tab, label) in [(Tab::Incidents, "Incidents"), (Tab::Diagnostics, "Diagnostics & console")] {
                let selected = self.tab == tab;
                let text = RichText::new(label).strong().color(if selected { TEXT } else { MUTED });
                if ui.add(egui::Button::new(text).fill(if selected { CARD_HI } else { Color32::TRANSPARENT })
                    .stroke(if selected { Stroke::new(1.0, BORDER) } else { Stroke::NONE }))
                    .clicked()
                {
                    self.tab = tab;
                }
            }
        });
        ui.add_space(4.0);
        match self.tab {
            Tab::Incidents => self.incident_table(ui),
            Tab::Diagnostics => self.diagnostics(ui),
        }
    }

    fn incident_table(&mut self, ui: &mut egui::Ui) {
        card(ui, "", |ui| {
            let count = lock(&self.ros.shared).events.len();
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{count} incidents")).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Clear").clicked() {
                        lock(&self.ros.shared).events.clear();
                    }
                    ui.add(egui::TextEdit::singleline(&mut self.feed_filter).hint_text("filter…").desired_width(180.0));
                });
            });
            ui.add_space(4.0);
            let s = lock(&self.ros.shared);
            let filter = self.feed_filter.to_lowercase();
            let rows: Vec<_> = s.events.iter().rev()
                .filter(|e| filter.is_empty() || e.message.to_lowercase().contains(&filter))
                .take(200).collect();
            if rows.is_empty() {
                ui.add_space(10.0);
                ui.label(RichText::new("No incidents yet. Start the commander and fire an attack, or run the self-test.").color(MUTED));
                ui.add_space(10.0);
                return;
            }
            // Fixed columns, then DETAIL takes whatever width is left.
            const COLS: [(&str, f32); 6] =
                [("TIME", 74.0), ("SEVERITY", 90.0), ("TYPE", 180.0), ("MITRE ATT&CK", 96.0), ("ACTION", 110.0), ("SOURCE", 120.0)];
            let gap = 10.0;
            let fixed: f32 = COLS.iter().map(|(_, w)| w + gap).sum();
            let detail_w = (ui.available_width() - fixed - 16.0).max(120.0);
            let row_h = 26.0;
            let cell = |ui: &mut egui::Ui, w: f32, add: &mut dyn FnMut(&mut egui::Ui)| {
                ui.allocate_ui_with_layout(egui::vec2(w, row_h), Layout::left_to_right(Align::Center), |ui| {
                    ui.set_width(w);
                    add(ui);
                });
            };
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for (h, w) in COLS {
                    cell(ui, w, &mut |ui| { ui.label(RichText::new(h).size(11.0).strong().color(MUTED)); });
                }
                cell(ui, detail_w, &mut |ui| { ui.label(RichText::new("DETAIL").size(11.0).strong().color(MUTED)); });
            });
            ui.separator();
            egui::ScrollArea::vertical().id_salt("incidents").auto_shrink([false, false]).show(ui, |ui| {
                for (i, e) in rows.into_iter().enumerate() {
                    let (sev, color) = severity(e.level);
                    let action_color = match e.action.as_str() {
                        "DROPPED" => CRIT,
                        "CLAMPED" => WARN,
                        "" => MUTED,
                        _ => TEXT2,
                    };
                    let action = if e.action.is_empty() {
                        "—".to_string()
                    } else if e.count.is_empty() || e.count == "1" {
                        e.action.clone()
                    } else {
                        format!("{} ×{}", e.action, e.count)
                    };
                    let detail = e.message.split_once(": ").map_or(e.message.as_str(), |(_, d)| d).to_string();
                    let fill = if i % 2 == 0 { CARD_HI.gamma_multiply(0.55) } else { Color32::TRANSPARENT };
                    egui::Frame::new().fill(fill).corner_radius(egui::CornerRadius::same(5)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = gap;
                            cell(ui, COLS[0].1, &mut |ui| { ui.label(RichText::new(&e.when).monospace().color(TEXT2)); });
                            cell(ui, COLS[1].1, &mut |ui| { chip(ui, sev, color); });
                            cell(ui, COLS[2].1, &mut |ui| { ui.add(egui::Label::new(RichText::new(&e.attack).strong()).truncate()); });
                            cell(ui, COLS[3].1, &mut |ui| {
                                if e.mitre_id.is_empty() {
                                    ui.label(RichText::new("—").color(MUTED));
                                } else {
                                    chip(ui, &e.mitre_id, ACCENT).on_hover_text(format!(
                                        "MITRE ATT&CK for ICS\n{} {}\nTactic: {}", e.mitre_id, e.mitre_name, e.mitre_tactic));
                                }
                            });
                            cell(ui, COLS[4].1, &mut |ui| { ui.label(RichText::new(&action).color(action_color)); });
                            cell(ui, COLS[5].1, &mut |ui| {
                                ui.add(egui::Label::new(RichText::new(if e.source.is_empty() { "—" } else { &e.source }).color(TEXT2)).truncate());
                            });
                            cell(ui, detail_w, &mut |ui| {
                                ui.add(egui::Label::new(RichText::new(&detail).color(TEXT2)).truncate()).on_hover_text(&e.message);
                            });
                        });
                    });
                }
            });
        });
    }

    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        let left_w = 380.0;
        ui.horizontal_top(|ui| {
            ui.allocate_ui(egui::vec2(left_w, ui.available_height()), |ui| {
                ui.vertical(|ui| {
                    card(ui, "ROS graph", |ui| self.ros_buttons(ui));
                    ui.add_space(8.0);
                    card(ui, "Gateway & network", |ui| self.gateway_buttons(ui));
                });
            });
            ui.add_space(8.0);
            ui.vertical(|ui| card(ui, "Console output", |ui| self.console_log(ui)));
        });
    }

    fn ros_buttons(&mut self, ui: &mut egui::Ui) {
        let w = (ui.available_width() - 8.0) / 2.0;
        let size = egui::vec2(w, 28.0);
        egui::Grid::new("ros_buttons").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            if ui.add(egui::Button::new("Nodes").min_size(size)).on_hover_text("ros2 node list (with SROS2 enclaves)").clicked() {
                self.ros.list_nodes();
            }
            if ui.add(egui::Button::new("Topics").min_size(size)).on_hover_text("ros2 topic list -t").clicked() {
                self.ros.list_topics();
            }
            ui.end_row();
            if ui.add(egui::Button::new("Command publishers").min_size(size)).on_hover_text("ros2 topic info /joint_commands -v").clicked() {
                self.ros.command_publishers();
            }
            if ui.add(egui::Button::new("Topic rates").min_size(size)).on_hover_text("ros2 topic hz on joint_states, /firewall/status, /firewall/events").clicked() {
                self.ros.topic_rates();
            }
            ui.end_row();
            if ui.add(egui::Button::new("Robot state").min_size(size)).on_hover_text("ros2 topic echo --once joint_states").clicked() {
                self.ros.latest_state();
            }
            if ui.add(egui::Button::new("Clock skew").min_size(size)).on_hover_text("Compare laptop time with the gateway's (replay window 0.5 s)").clicked() {
                self.ros.clock_check();
            }
            ui.end_row();
        });
    }

    fn gateway_buttons(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("gateway_inputs").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label(RichText::new("SSH target").color(TEXT2));
            ui.add(egui::TextEdit::singleline(&mut self.gateway).hint_text("user@nanopi-ip").desired_width(f32::INFINITY));
            ui.end_row();
            ui.label(RichText::new("Robot IP").color(TEXT2));
            ui.add(egui::TextEdit::singleline(&mut self.robot_ip).desired_width(f32::INFINITY));
            ui.end_row();
        });
        ui.add_space(4.0);
        let w = (ui.available_width() - 8.0) / 2.0;
        let size = egui::vec2(w, 28.0);
        let host = shell::host_of(self.gateway.trim()).to_string();
        let robot = self.robot_ip.trim().to_string();
        egui::Grid::new("gateway_buttons").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            if ui.add(egui::Button::new("Ping gateway").min_size(size)).on_hover_text(format!("ping -c 3 -W 1 {host}")).clicked() {
                if host.is_empty() {
                    lock(&self.ros.shared).push_log(LogKind::Fail, "set the gateway ssh target first");
                } else {
                    self.ping("gateway reachable", &host, Expect::Success);
                }
            }
            if ui.add(egui::Button::new("Robot NOT reachable").min_size(size))
                .on_hover_text(format!("ping -c 3 -W 1 {robot}\nPASS when this FAILS: nothing may route from the laptop to the robot."))
                .clicked()
            {
                self.ping("robot isolated from laptop", &robot, Expect::Failure);
            }
            ui.end_row();
            if ui.add(egui::Button::new("Service status").min_size(size)).on_hover_text("ssh <gateway> systemctl status robot-firewall").clicked() {
                self.ssh("firewall service status", "systemctl status robot-firewall robot-firewall-counters --no-pager -n 10", Expect::Success);
            }
            if ui.add(egui::Button::new("Journal").min_size(size)).on_hover_text("ssh <gateway> journalctl -u robot-firewall -n 40").clicked() {
                self.ssh("firewall journal", "journalctl -u robot-firewall -n 40 --no-pager", Expect::Success);
            }
            ui.end_row();
            if ui.add(egui::Button::new("nft counters").min_size(size)).on_hover_text("ssh <gateway> sudo -n nft list counters table inet robot_fw").clicked() {
                self.ssh("nftables counters", "sudo -n nft list counters table inet robot_fw", Expect::Success);
            }
            if ui.add(egui::Button::new("Incident log").min_size(size)).on_hover_text("ssh <gateway> tail -n 20 /var/log/robot_firewall/incidents.jsonl").clicked() {
                self.ssh("incident log", "tail -n 20 /var/log/robot_firewall/incidents.jsonl", Expect::Success);
            }
            ui.end_row();
            if ui.add(egui::Button::new("Forwarding off").min_size(size)).on_hover_text("ssh <gateway> sysctl net.ipv4.ip_forward  (must be 0)").clicked() {
                self.ssh("ip forwarding disabled", "test \"$(sysctl -n net.ipv4.ip_forward)\" = 0 && echo ip_forward=0", Expect::Success);
            }
            if ui.add(egui::Button::new(RichText::new("Restart firewall").color(CRIT)).min_size(size))
                .on_hover_text("ssh <gateway> sudo -n systemctl restart robot-firewall\nThe firewall comes back in LOCKDOWN.")
                .clicked()
            {
                self.confirm_restart = true;
            }
            ui.end_row();
        });
    }

    fn console_log(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Every command shows the CLI equivalent").small().color(MUTED));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Clear").clicked() {
                    lock(&self.ros.shared).log.clear();
                }
                if ui.small_button("Copy all").clicked() {
                    let text: String = lock(&self.ros.shared).log.iter().map(|l| format!("{} {}\n", l.when, l.text)).collect();
                    ui.ctx().copy_text(text);
                }
            });
        });
        let s = lock(&self.ros.shared);
        egui::Frame::new().fill(BG).corner_radius(egui::CornerRadius::same(6)).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("log").stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                if s.log.is_empty() {
                    ui.label(RichText::new("$ _").monospace().color(MUTED));
                }
                for l in &s.log {
                    let color = match l.kind {
                        LogKind::Cmd => ACCENT,
                        LogKind::Pass => GOOD,
                        LogKind::Fail => CRIT,
                        LogKind::Info => WARN,
                        LogKind::Out => TEXT2,
                    };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&l.when).monospace().color(MUTED));
                        ui.label(RichText::new(&l.text).monospace().color(color));
                    });
                }
            });
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
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Restart").strong().color(Color32::WHITE)).fill(CRIT)).clicked() {
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
        let bar = egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(12, 8));
        egui::Panel::top("top_bar").frame(bar).show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("status_bar").frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(12, 4)))
            .show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("controls").resizable(false).default_size(330.0)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(12)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.firewall_card(ui);
                    ui.add_space(10.0);
                    self.attack_card(ui);
                    ui.add_space(10.0);
                    self.selftest_card(ui);
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(12)))
            .show(ui, |ui| {
                self.kpis(ui);
                ui.add_space(10.0);
                self.charts(ui);
                ui.add_space(10.0);
                self.tabs(ui);
            });
        let ctx = ui.ctx().clone();
        self.restart_dialog(&ctx);
        ctx.request_repaint_after(Duration::from_millis(100));
    }

    fn on_exit(&mut self) {
        lock(&self.ros.shared).commander_on = false;
        self.ros.shutdown();
    }
}
