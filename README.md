# RoboShield: Real-Time RTPS Security Watchdog

RoboShield is an embedded, lightweight Network Intrusion Detection System (NIDS) and inline packet filter designed specifically for ROS 2 (RTPS/DDS) networks. It runs out-of-band on dedicated network appliances (such as the NanoPi R2S) to monitor, detect, and mitigate cyber-physical threats without requiring modifications to the robot's onboard firmware or ROS 2 software stack.

Developed as part of security research targeting publications in **IEEE RAS / ICRA / NDSS**, RoboShield focuses on sub-millisecond packet inspection latency to remain compatible with strict real-time robotic control loops.

---

## Key Features

- **Zero-Trust Network Discovery**: Performs out-of-band topology scanning. Compares discovered DDS Participant GUID prefixes against a strict security policy.
- **Topic-to-Node Access Control**: Maps RTPS `DATA` submessages to their source GUIDs. Detects and flags unauthorized nodes attempting to publish to sensitive topics (e.g. `/cmd_vel` spoofing).
- **Rate-Based DoS & Flood Detection**: Employs sliding-window frequency tracking to detect message floods, telemetry denial-of-service, or faulty/compromised sensors exceeding safety limits.
- **Low-Latency Passive Tap & Inline filtering**:
  - **Passive mode**: Uses `libpcap` to monitor traffic from a network mirror port.
  - **Inline mode**: Directs traffic using Linux `iptables` and `NFQUEUE` to drop/accept packets in-path.
- **SIEM Integration**: Appends structured JSON security alerts suitable for ingestion by central logging tools (Splunk, ElasticSearch, or local syslog).

---

## Repository Structure

```
roboshield/
├── config/
│   └── policies.toml        # TOML file defining whitelisted GUIDs and topic frequency rules
├── roboshield-core/          # The NIDS daemon and packet dissector binary
│   ├── src/
│   │   ├── main.rs          # Sniffer loop orchestration
│   │   ├── parser.rs        # Hand-rolled, endianness-aware RTPS parser
│   │   ├── detector.rs      # Rule-based signature matching engine
│   │   ├── config.rs        # TOML policy loader
│   │   └── logger.rs        # High-performance JSON alerts logger
│   └── Cargo.toml
├── roboshield-simulator/     # Synthetic RTPS packet generator and security injector
│   ├── src/
│   │   ├── main.rs          # Traffic mode controller
│   │   └── rtps_builder.rs  # Manual RTPS packet serializer
│   └── Cargo.toml
└── THREAT_MODEL.md          # ROS 2 RTPS security vulnerability and threat landscape analysis
```

---

## Getting Started

### Prerequisites

You need the Rust toolchain installed. Additionally, RoboShield relies on `libpcap` for network captures.

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential
```

### Build

Compile the workspace in release mode:
```bash
cargo build --release
```

---

## Running the Security Watchdog

### 1. Configure Policies
Edit `config/policies.toml` to list allowed node GUID prefixes and topic frequency rules:

```toml
allowed_guid_prefixes = [
    "01:0f:a5:bc:de:f0:12:34:56:78:90:ab"
]

[topic_publishers]
"/cmd_vel" = ["01:0f:a5:bc:de:f0:12:34:56:78:90:ab"]

[frequency_limits]
"/cmd_vel" = { min_hz = 1.0, max_hz = 60.0 }
```

### 2. Live Capture Mode
Run the watchdog on a specific network interface (e.g. `eth0` or `lo`):
```bash
# Sudo privileges are required for raw packet capture
sudo ./target/release/roboshield-core --interface lo --config config/policies.toml
```

### 3. PCAP Replay Mode
Inspect pre-recorded pcap files:
```bash
./target/release/roboshield-core --pcap sample_traffic.pcap --config config/policies.toml
```

---

## Evaluating Threat Detection (Simulation)

RoboShield includes a traffic simulator to evaluate detection efficacy under simulated attack scenarios.

### Normal Operation Baseline
Generates compliant, authorized RTPS traffic at 10Hz to verify that no alerts are triggered:
```bash
./target/release/roboshield-simulator --mode normal --port 7412
```

### Attack Scenario 1: Topic Flood / Denial of Service
Injects high-frequency `/cmd_vel` commands (>100Hz) to test rate limit triggers:
```bash
./target/release/roboshield-simulator --mode flood --port 7412
```

### Attack Scenario 2: Rogue Node Injection & Spoofing
Injects traffic using an unauthorized node GUID prefix not listed in the whitelist:
```bash
./target/release/roboshield-simulator --mode spoof --port 7412
```
Look at the output console of `roboshield-core` or inspect `alerts.json` to verify that NIDS alerts are captured.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
