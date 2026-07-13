# ROS 2 Discourse & LinkedIn Publication References

This directory contains pre-drafted posts to announce **RoboShield** on community platforms. 

---

## 1. ROS 2 Discourse Announcement

*Recommended Category: **Security** or **Next-Gen ROS***

### Title:
`RoboShield: A Low-Latency Out-of-Band RTPS Watchdog and Firewall in Rust`

### Body:
```markdown
Hello ROS Community,

I’d like to share **RoboShield**, an open-source, lightweight security watchdog and inline packet-level firewall built in Rust, designed specifically to inspect and mitigate RTPS network attacks on ROS 2 networks.

* **GitHub Repository**: https://github.com/Amin-Ahmed-G/robotshield

### Why RoboShield?
While SROS2 (DDS-Security) provides excellent cryptographic access control, it introduces significant CPU and latency overhead, which can be prohibitive for resource-constrained controllers or high-frequency real-time loops. RoboShield is designed to run **out-of-band** on a transparent dual-ethernet bridge (such as a NanoPi R2S), requiring zero configuration or modifications to the robot's onboard nodes.

### Current Features
* **Zero-Trust Discovery Validation**: Scans SPDP/SEDP packets and matches participant GUID prefixes against a strict TOML policy.
* **Topic Spoofing Detection**: Maps RTPS `DATA` submessages to their source GUIDs and blocks unauthorized publishers from commanding topics (like `/cmd_vel`).
* **Sliding-Window Hz Tracking**: High-performance, low-memory frequency tracking to detect message floods or faulty sensor anomalies.
* **Low Processing Overhead**: Written in zero-allocation Rust, micro-benchmarks on RTPS CDR payloads show an average processing latency of just **1.36 microseconds**, allowing it to support high-speed real-time control loops with virtually zero jitter.

I’d love to hear your feedback on the architecture, particularly regarding the inline `NFQUEUE` routing strategies and handling complex RTPS ParameterLists.

Best regards,
Amin Ahmed G
```

---

## 2. LinkedIn Post

### Post Text:
```text
🚀 I'm excited to share my latest project, **RoboShield**: a low-latency, out-of-band security watchdog and firewall for ROS 2 (RTPS/DDS) networks written in Rust.

Most ROS 2 networks run in plain-text over UDP. While standard cryptographic security profiles (SROS2) exist, they are often disabled on embedded controllers due to heavy CPU and latency overhead.

I built RoboShield to solve this out-of-band, allowing it to sit transparently on a physical hardware bridge (like a NanoPi R2S) and inspect packets without modifying the robot's internal code.

**Key Technical Details:**
* **Zero-Allocation Rust Parser**: Built an endianness-aware RTPS dissector that parses raw UDP byte packets on the fly.
* **Rate-Based DoS Defense**: Created stateful sliding-window frequency trackers to catch message flooding and unauthorized publisher injection.
* **Microsecond-Level Performance**: Leveraged Rust's zero-cost abstractions to achieve a packet processing delay of just 1.36 microseconds (over 734,000 packets/sec throughput capacity), keeping it fully compatible with real-time control loops.

Working on this project gave me deep experience with systems-level networking, raw serialization formats (CDR/ParameterList), and low-latency systems programming.

Check out the code, threat model, and evaluation benchmarks on my GitHub:
👉 https://github.com/Amin-Ahmed-G/robotshield

#robotics #ros2 #rust #systems #cybersecurity #embedded #cplusplus
```
