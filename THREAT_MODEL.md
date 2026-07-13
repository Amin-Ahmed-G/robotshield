# RoboShield Threat Model and Attack Surface Analysis

This document outlines the threat model, vulnerability classes, and attack scenarios considered by the RoboShield RTPS Security Watchdog, specifically targeting ROS 2 deployments on embedded network appliances like the NanoPi R2S.

---

## 1. ROS 2 / RTPS Security Landscape

ROS 2 uses RTPS (Real-Time Publish-Subscribe) as the underlying wire protocol, typically running over UDP/IP. While ROS 2 supports SROS2 (DDS-Security), many production and academic deployments disable security due to CPU limitations, key management complexity, or legacy interoperability.

This leaves the RTPS network open to several attack vectors:
1. **Unencrypted RTPS UDP traffic**: Easy to intercept, read, and spoof.
2. **Anonymous Node Discovery (SPDP/SEDP)**: Nodes join the network and claim GUIDs without validation.
3. **No message rate validation**: A rogue node or compromised sensor can flood topics (e.g. `/cmd_vel`) to execute a Denial of Service (DoS) or hijack actuator control.

---

## 2. Threat Classification & Anomalies

RoboShield detects and logs the following network threats:

### T1: Discovery Abuse & Rogue Node Join
* **Vector**: An attacker injects SPDP (Simple Participant Discovery Protocol) packets to advertise a malicious node or impersonate an existing node GUID.
* **Impact**: The malicious node can establish subscriptions to sensitive telemetry or publish unauthorized commands.
* **Detection**: Whitelist check on participant GUID Prefixes and node names.

### T2: Topic Spoofing (Unauthorized Publishing)
* **Vector**: An attacker publishes `DATA` submessages under a critical topic name (e.g. `/cmd_vel` or `/joint_states`) using an arbitrary or spoofed GUID.
* **Impact**: Hijacking of robot actuator controls or spoofing sensor reading diagnostics.
* **Detection**: Map-based verification: matching the publisher's GUID prefix in the RTPS header against authorized publishers declared in the policy.

### T3: Message Flooding / Denial of Service (DoS)
* **Vector**: High-frequency transmission of `DATA` packets to consume CPU/network resources.
* **Impact**: Delayed message execution, packet loss, or failure of real-time control loops (e.g., causing motor controllers to trip).
* **Detection**: Sliding-window frequency estimation. If the measured message rate exceeds `max_hz` defined for that topic, flag as an anomaly.

### T4: Protocol Malformation & Exploit Injections
* **Vector**: Injected RTPS packets containing malformed headers, invalid submessage lengths, or out-of-order submessage segments.
* **Impact**: Crashing the DDS middleware deserialization routines (buffer overflow/denial of service on target nodes).
* **Detection**: Parser-level constraint verification (e.g. validating packet bounds, checking submessage lengths against remaining payload size).

---

## 3. Mitigation Strategies

RoboShield deploys a two-fold mitigation architecture:
- **Phase 1-2 (Passive)**: Tap mode (via mirror port or local loopback using `libpcap`). Detects anomalies and generates structured JSON alerts for external SIEM engines.
- **Phase 3-4 (Inline)**: Bridge mode (using Linux `iptables` and `NFQUEUE`). Inspects RTPS packets in-path, dropping unauthorized or malformed frames before they reach the local DDS middleware stack.
