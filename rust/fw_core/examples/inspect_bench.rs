//! Micro-benchmark: time per `CommandFirewall::inspect` call for a valid
//! 6-joint command (the common path: every rule runs, command is forwarded).
//! Prints JSON with percentiles in nanoseconds.
//!   cargo run --release -p fw_core --example inspect_bench

use std::collections::HashMap;
use std::time::Instant;

use fw_core::{Command, CommandFirewall, FirewallConfig, JointLimits};

fn main() {
    let names: Vec<String> = (1..=6).map(|i| format!("joint_{i}")).collect();
    let mut cfg = FirewallConfig::new(names.clone());
    cfg.limits = names
        .iter()
        .map(|n| (n.clone(), JointLimits { position_min: -1.0, position_max: 1.0, velocity: 1.0, effort: 10.0 }))
        .collect::<HashMap<_, _>>();
    cfg.start_locked = false;
    cfg.max_rate_hz = 1e12; // measure rule cost, not the rate limiter
    cfg.burst = 1e12;
    let mut fw = CommandFirewall::new(cfg);

    let n = 1_000_000;
    let mut samples = Vec::with_capacity(n);
    let mut t = 1000.0;
    for i in 0..n + 10_000 {
        t += 1e-4;
        let x = 0.5 * ((i as f64) * 1e-3).sin();
        let cmd = Command {
            names: names.clone(),
            position: vec![x; 6],
            velocity: vec![0.1; 6],
            effort: Vec::new(),
            stamp: Some(t),
            source: "bench".into(),
        };
        let start = Instant::now();
        let v = fw.inspect(&cmd, t);
        let dt = start.elapsed().as_nanos() as f64;
        std::hint::black_box(v);
        if i >= 10_000 {
            samples.push(dt);
        }
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| samples[((samples.len() as f64 - 1.0) * p) as usize];
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!(
        "{{\"impl\":\"rust\",\"n\":{},\"mean_ns\":{mean:.1},\"p50_ns\":{},\"p90_ns\":{},\"p99_ns\":{},\"p999_ns\":{}}}",
        samples.len(), pct(0.5), pct(0.9), pct(0.99), pct(0.999)
    );
}
