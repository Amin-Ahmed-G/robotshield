# ROS Discourse post: RoboShield v2

- **Where:** https://discourse.openrobotics.org/c/projects/10 (Projects)
- **Tags:** `ros2` `jazzy` `security` `safety` `rust`
- **When:** Monday to Wednesday, so it can make Friday's "ROS News for the Week"
- **Attach:** `docs/announcements/roboshield_v2_selftest.gif` where marked, and
  `docs/perf_attack_timeline.png` where marked

---

## Title

RoboShield: an inline command firewall for ROS 2 robots (Rust, SROS2, ~0.5 ms overhead)

## Body

Hi all,

Most ROS 2 robots I've worked with trust every message on the network. Anything that can publish to `/joint_commands` can move the arm: a buggy script, a typo, or someone else on the WiFi. SROS2 helps with *who* can talk, but nothing checks *what* they say before the robot acts on it.

So I built **RoboShield**, a small gateway (a NanoPi in my setup) that sits between the network and the robot and is the only path to it. Every command is inspected, then forwarded, clamped, dropped, or the robot is locked down and held at its last safe pose.

**Repo:** https://github.com/Amin-Ahmed-G/robotshield (MIT)

[GIF: roboshield_v2_selftest.gif, the console firing 8 attack types at the live firewall]

### How it works

- **Two ROS domains, one bridge.** The laptop is on domain 10 (WiFi), the robot on domain 20 (its own Ethernet cable). One process joins both via two contexts. With `ip_forward=0` and a default-drop nftables ruleset, nothing else can reach the robot.
- **SROS2 on the WiFi side only.** rcl reads `ROS_SECURITY_ENABLE` per context at init, so the laptop side enforces DDS-Security while the robot side stays plain, for robots that can't run SROS2.
- **Command rules:** schema and joint names, NaN/inf, per-joint position/velocity/effort limits (clamped), step jumps, token-bucket rate limiting, and stale or replayed stamps. Repeated incidents trigger LOCKDOWN until an operator re-arms. It also boots locked.
- **Per-message publisher check.** Each message's `publisher_gid` is matched to a node name, so a spoofing node's messages are dropped one by one while the real operator keeps control.
- **Robot side:** a rogue commander or fake `joint_states` publisher on the robot LAN raises an alert and locks down.
- **SIEM-ready:** incidents are tagged with MITRE ATT&CK for ICS (v20, e.g. T1692.001 Command Message, T0814 Denial of Service) and can stream as CEF or JSON syslog to Splunk, Sentinel or Elastic.

### Numbers (laptop, Ryzen 7 7435HS, Jazzy, Fast DDS; NanoPi numbers next)

| | |
|---|---|
| Rule check per 6-joint command | 1.37 µs median (Rust), 9.5 µs (Python version) |
| End-to-end latency added | +0.5 ms median; 1000/1000 commands delivered |
| Attack self-test | 8/8 detected, also with SROS2 enforced and a cert-less publisher spamming |
| 600 msg/s flood → lockdown | ~10 ms |

[Image: perf_attack_timeline.png. An overreach attack gets clamped at the limit, then a flood triggers lockdown; the robot never leaves its safe range.]

The benchmark scripts and raw data are in `bench/`.

### Try it (one machine, simulated robot)

```bash
sudo apt install ros-jazzy-test-msgs   # rclrs 0.7 links against it
git clone https://github.com/Amin-Ahmed-G/robotshield && cd robotshield
colcon build --packages-select monitor_py && source install/setup.bash
(cd rust && ./build.sh --release)

ROS_DOMAIN_ID=20 ros2 run monitor_py robot_sim_node                                  # terminal 1
rust/target/release/robot_firewall --config src/monitor_py/config/firewall_params.yaml # terminal 2
ROS_DOMAIN_ID=10 rust/target/release/firewall_console                                # terminal 3: "Run full self-test"
```

NanoPi deployment (nftables, SROS2 keystore, systemd watchdog) is in `deploy/nanopi/`.

### Things I hit that might help others

- **rclrs on Jazzy binaries:** the shipped message crates use `rosidl_runtime_rs` 0.6, so rclrs **0.7.0** works and 0.8 doesn't (yet) with them.
- **`TopicEndpointInfo` in rclrs has no `endpoint_gid`.** I vendored a one-field patch to map publisher GIDs to node names.
- **Discovery race:** a publisher's data can arrive before its node info, so it shows as `_NODE_NAME_UNKNOWN_`. The gateway fails closed with a 2 s grace period before raising an alarm.

### Where I'd love feedback

1. Would an `endpoint_gid` field on `TopicEndpointInfo` be welcome in rclrs? Happy to open a PR.
2. Any interest in exposing `publisher_gid` in rclpy's message info? My Python gateway can't attribute messages without it.
3. With Fast DDS, what's the cleanest way to pin each participant in one process to its own interface? I currently rely on nftables.
4. Does the MITRE mapping make sense to people doing OT security on robots?

This pairs nicely with tools like `ros2_fault_injection`: that one tests how your stack handles bad inputs, and this one keeps them from reaching the robot in the field.

A note on v1: my earlier post described inline blocking, but v1 shipped as an alert-only packet watchdog. v2 is where enforcement actually lives.

It's not a certified safety system, so keep your hardware e-stop. I'd really appreciate thoughts on the threat model and the lockdown behaviour.

Thanks,
Amin
