# Rust robot firewall

| Crate | What |
|---|---|
| `fw_core` | The rule engine (limits, step, rate, replay, schema, lockdown). Pure Rust, no ROS. |
| `robot_firewall` | Gateway binary for the NanoPi. Bridges the WiFi and robot ROS domains, the same way `firewall_node.py` does. |
| `firewall_console` | Desktop GUI for the laptop. Every debugging command is a button. |
| `vendor/rclrs` | rclrs 0.7.0 with a one-line patch that exposes endpoint GIDs (see `PATCH.md`). |

The Rust gateway works like the Python one. It uses the same topics, services,
JSON formats and `firewall_params.yaml`, so the dashboard, deploy scripts and
config work with either. It adds one thing the Python version can't do: it
identifies the **publisher of every message** and drops commands from
non-allowlisted nodes one by one, so the real operator keeps control during a
spoofing attack.

## SIEM export and MITRE ATT&CK for ICS

Every incident carries its MITRE ATT&CK for ICS v20 technique and tactic. The
gateway can stream incidents as CEF or JSON over syslog/UDP to Splunk,
Sentinel, QRadar, ArcSight or Elastic (`--set siem_syslog=udp://host:514`).
See [docs/SIEM.md](../docs/SIEM.md) for the mapping, sample lines and
collector configs.

## Build

```bash
sudo apt install ros-jazzy-test-msgs      # rclrs links against it (once)
./build.sh --release                      # everything
./build.sh --release -p robot_firewall    # NanoPi: gateway only
./build.sh --release -p firewall_console  # laptop: GUI only
```

Needs Rust ≥ 1.85 (from rustup) and ROS 2 Jazzy in `/opt/ros/jazzy`. The message
crates come from the Jazzy packages (`/opt/ros/jazzy/share/*/rust`).

## Run

Gateway, reading the same params file as the Python node:
```bash
target/release/robot_firewall --untrusted-domain 10 --trusted-domain 20 \
    --config ../src/monitor_py/config/firewall_params.yaml [--enclave /firewall] [--set key=value ...]
```

Console on the laptop, with the SROS2 environment loaded:
```bash
source ../deploy/nanopi/sros2/laptop_env.sh ~/robot_fw_keystore 10
target/release/firewall_console --gateway ubuntu@<nanopi-ip>
target/release/firewall_console --selftest   # headless: exit 0 if all attacks are caught
```

![Firewall console dashboard](../docs/dashboard.png)

Console buttons (hover over any of them to see the equivalent CLI command):
- **Firewall:** Re-arm, Reset counters, live ARMED/LOCKDOWN state, traffic and incident counters.
- **Commander & attacks:** a legitimate commander, one button per attack, and **Run full self-test**.
- **ROS:** Nodes (with SROS2 enclave), Topics, Command publishers, Topic rates, Robot state, Clock skew.
- **Gateway** (over ssh): Ping gateway, Robot NOT reachable, Service status, Journal,
  nft counters, Incident log, Forwarding off, Restart firewall (asks for confirmation).

## Tests

```bash
source /opt/ros/jazzy/setup.bash && cargo test --workspace
```
This runs 30 rule-engine tests, 3 config tests (including the shared YAML file),
and 5 end-to-end tests. The end-to-end tests start the real `robot_firewall`
binary between two DDS domains and check that unsafe commands never reach the
robot, that floods and rogue devices trigger lockdown, and that an intruder's
messages are dropped while the operator's still get through.
