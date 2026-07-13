use roboshield_core::config::SecurityPolicy;
use roboshield_core::parser;
use roboshield_core::detector::DetectionEngine;
use std::time::Instant;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================");
    println!("RoboShield Micro-Benchmark Execution");
    println!("=========================================");

    // Create a mock policy configuration
    let policy_content = r#"
        allowed_guid_prefixes = [
            "01:0f:a5:bc:de:f0:12:34:56:78:90:ab"
        ]
        [topic_publishers]
        "/cmd_vel" = ["01:0f:a5:bc:de:f0:12:34:56:78:90:ab"]
        [frequency_limits]
        "/cmd_vel" = { min_hz = 1.0, max_hz = 60.0 }
    "#;

    let temp_policy_path = "temp_policy.toml";
    fs::write(temp_policy_path, policy_content)?;

    let policy = SecurityPolicy::load_from_file(temp_policy_path)?;
    let mut detector = DetectionEngine::new(policy);

    // Clean up temporary file immediately after loading
    let _ = fs::remove_file(temp_policy_path);

    // 1. Build a mock RTPS DATA packet (/cmd_vel)
    let mut mock_payload = Vec::new();
    mock_payload.extend_from_slice(b"RTPS");
    mock_payload.extend_from_slice(&[2, 3, 0x01, 0x0f]);
    let auth_guid = [0x01, 0x0f, 0xa5, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab];
    mock_payload.extend_from_slice(&auth_guid);

    // Add submessage DATA representing topic /cmd_vel
    mock_payload.push(0x15); // ID
    mock_payload.push(0x05); // Flags (LE, Data present)
    mock_payload.extend_from_slice(&[44, 0x00]); // length (44 bytes payload)
    
    mock_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extra flags, inline qos
    mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0xc1]); // reader
    mock_payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writer
    mock_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq = 1
    mock_payload.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE

    // PID_TOPIC_NAME = 0x0005, Len=13
    mock_payload.extend_from_slice(&[0x05, 0x00, 0x0d, 0x00]); 
    mock_payload.extend_from_slice(&[0x09, 0x00, 0x00, 0x00]); // Str length = 9 (including null)
    mock_payload.extend_from_slice(b"/cmd_vel\0"); // topic name + null
    mock_payload.extend_from_slice(&[0x00, 0x00, 0x00]); // alignment padding
    mock_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL

    // Warmup iterations
    println!("Warming up CPU cache...");
    for _ in 0..10_000 {
        let msg = parser::parse_rtps_packet(&mock_payload)?;
        let _ = detector.analyze_message(&msg);
    }

    // Benchmark Run
    const ITERATIONS: u32 = 200_000;
    println!("Running benchmark with {} iterations...", ITERATIONS);
    
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let msg = parser::parse_rtps_packet(&mock_payload)?;
        let _ = detector.analyze_message(&msg);
    }
    let duration = start.elapsed();

    let total_secs = duration.as_secs_f64();
    let avg_ns = (total_secs / ITERATIONS as f64) * 1_000_000_000.0;
    let avg_us = avg_ns / 1_000.0;
    let throughput = ITERATIONS as f64 / total_secs;

    println!("-----------------------------------------");
    println!("Benchmark Results (Release Target):");
    println!("Total Execution Time : {:.4} seconds", total_secs);
    println!("Average Packet Delay : {:.2} ns ({:.3} μs)", avg_ns, avg_us);
    println!("Throughput Capacity  : {:.2} packets/sec", throughput);
    println!("=========================================");

    Ok(())
}
