//! Robot firewall console: a desktop GUI for the laptop side with every
//! debugging command as a button (firewall control, attacks and self-test,
//! ROS inspection, gateway/network checks).
//!
//! Security settings come from the environment exactly like any ROS 2 program:
//! `source deploy/nanopi/sros2/laptop_env.sh ~/robot_fw_keystore 10` first.

mod app;
mod ros;
mod shell;
mod state;

use std::sync::{Arc, Mutex};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "Robot firewall console")]
struct Args {
    /// ROS domain of the laptop/WiFi side (defaults to $ROS_DOMAIN_ID, else 10).
    #[arg(long, env = "ROS_DOMAIN_ID", default_value_t = 10)]
    domain: usize,
    /// ssh target of the gateway for the network buttons, e.g. ubuntu@192.168.1.60
    #[arg(long, env = "FIREWALL_GATEWAY", default_value = "")]
    gateway: String,
    /// Robot IP on the isolated LAN (must NOT be reachable from the laptop).
    #[arg(long, env = "FIREWALL_ROBOT_IP", default_value = "192.168.50.2")]
    robot_ip: String,
    /// Joint names, in order (must match the gateway's joint_names).
    #[arg(long, value_delimiter = ',', default_value = "joint_1,joint_2,joint_3,joint_4")]
    joints: Vec<String>,
    /// Run the attack self-test without opening a window; exit 0 if all pass.
    #[arg(long)]
    selftest: bool,
    /// UI scale factor (e.g. 1.5 for HiDPI screens or crisp screenshots).
    #[arg(long, default_value_t = 1.0)]
    zoom: f32,
}

/// Headless self-test: prints the console log to stdout as it runs.
fn run_headless_selftest(ros: std::sync::Arc<ros::RosLink>) -> ! {
    let shared = ros.shared.clone();
    let got_state = shell::wait_until(std::time::Duration::from_secs(15), || {
        state::lock(&shared).robot_pose.is_some().then_some(())
    });
    if got_state.is_none() {
        eprintln!("no joint_states from the gateway within 15 s");
        std::process::exit(2);
    }
    ros.run_self_test();
    let mut printed = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let s = state::lock(&shared);
        for line in &s.log[printed.min(s.log.len())..] {
            println!("{} {}", line.when, line.text);
        }
        printed = s.log.len();
        if !s.selftest_running {
            let all_pass = s.selftest.iter().all(|r| matches!(r.result, state::TestResult::Pass(_)));
            let ok = all_pass && s.max_abs_position <= 1.05;
            drop(s);
            ros.shutdown();
            std::process::exit(if ok { 0 } else { 1 });
        }
    }
}

fn main() -> eframe::Result {
    let args = Args::parse();
    let shared = Arc::new(Mutex::new(state::Shared::new(args.joints.clone())));
    let ros = match ros::RosLink::start(args.domain, shared) {
        Ok(ros) => ros,
        Err(e) => {
            eprintln!("firewall_console: ROS init failed on domain {}: {e}", args.domain);
            std::process::exit(1);
        }
    };
    if args.selftest {
        run_headless_selftest(ros);
    }
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Robot Firewall Console")
            .with_inner_size([1280.0 * args.zoom, 820.0 * args.zoom])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Robot Firewall Console",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_zoom_factor(args.zoom);
            Ok(Box::new(app::ConsoleApp::new(ros, args.gateway, args.robot_ip)))
        }),
    )
}
