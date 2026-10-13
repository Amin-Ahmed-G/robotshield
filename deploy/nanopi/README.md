# Robot firewall on a NanoPi

The NanoPi sits between your laptop and the robot:

```
Laptop  ~~~ WiFi (wlan0) ~~~  NanoPi  ──── Ethernet (eth0) ────  Robot
ROS domain 10                 firewall_node                    ROS domain 20
untrusted                     (only bridge)                    192.168.50.2, isolated
```

The robot sits on a cable that only the NanoPi can reach, and it listens on a
different ROS domain from the laptop. Only `firewall_node` joins both domains.
Every command from the laptop is inspected there. It is either forwarded,
clamped, or dropped, or the firewall locks down. Each incident is reported to
the laptop over WiFi: what the attack was and what the firewall did about it.

## Protection layers

| Layer | What | Where |
|---|---|---|
| 1. Isolation | No IP forwarding and a default-drop `forward` chain. The robot subnet has no route to it. IPv6 is off. | `templates/99-robot-firewall.conf.in`, `nftables.conf.in` |
| 2. Allowlists | WiFi side accepts only `LAPTOP_IP`, and only SSH plus RTPS ports for domain 10. Robot side accepts only `ROBOT_IP`, and only RTPS for domain 20. Everything else is counted, logged and dropped. Output is default-drop too. | `templates/nftables.conf.in` |
| 3. Authentication | SROS2 / DDS-Security on the WiFi domain. Participants without a certificate from your CA cannot discover or talk to the firewall. | `sros2/` |
| 4. Command inspection | Schema, NaN/inf, joint limits (clamp), step jumps, rate limiting, replay/stale stamps, unauthorized publishers, rogue devices on the robot LAN, and robot-state guard. Escalates to **LOCKDOWN**. | `monitor_py/firewall_rules.py`, `firewall_node.py` |

Fail-safe behavior:
- The firewall **boots in LOCKDOWN** and only forwards after an operator re-arms it.
- If the firewall process dies, systemd restarts it (with a watchdog) and it comes back locked.
- The robot must hold position when commands stop. `robot_sim_node` shows the expected behavior (`command_timeout_s`).
- **Keep a hardware e-stop.** This is a security layer, not a certified safety system.

## Hardware

- An **arm64** NanoPi: R2S, R4S, R5S, R6S, NEO3 or similar. ROS 2 Jazzy has no
  32-bit ARM (armhf) binaries, so the R1, NEO and other armv7 boards will not work.
- A **USB WiFi adapter** with a mainline Linux driver, if the board has no WiFi.
- An Ethernet cable from the NanoPi to the robot. Don't connect the robot to any other network.

## Bring-up

**1. Flash** Ubuntu 24.04 (noble) arm64 to the NanoPi. Armbian and FriendlyElec
both ship noble images. Boot it, connect it to your WiFi, and SSH in from the laptop.

**2. Create the keystore on the laptop.** The CA private keys stay on the laptop:
```bash
./deploy/nanopi/sros2/make_keystore.sh ~/robot_fw_keystore 10
scp ~/robot_fw_keystore-gateway.tgz nanopi:
```

**3. Configure.** On the NanoPi, in a checkout of this repo:
```bash
cp deploy/nanopi/firewall.env.example deploy/nanopi/firewall.env
nano deploy/nanopi/firewall.env     # interfaces, LAPTOP_IP, ROBOT_IP, domains
```
Give the laptop a fixed IP or a DHCP reservation. It is the only WiFi address
the NanoPi will accept traffic from. Check interface names with `ip -br link`.

**4. Install.** The Rust gateway is the default (`FIREWALL_IMPL=rust` in
`firewall.env`). It needs Rust ≥ 1.85 for your user on the NanoPi:
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`. To use the Python
gateway instead, set `FIREWALL_IMPL=python`.
```bash
sudo ./deploy/nanopi/setup_nanopi.sh --keystore ~/robot_fw_keystore-gateway.tgz --with-netplan
```
The script refuses to run over SSH from any address other than `LAPTOP_IP`,
so you can't lock yourself out. `--with-netplan` writes the static robot-LAN
address and the WiFi config. Apply it with `sudo netplan apply` from the console.

**5. Robot.** Set the robot's address to `ROBOT_IP/24` with no gateway,
`ROS_DOMAIN_ID=20`, and the command topic and type from
`/etc/robot_firewall/firewall_params.yaml` (`output_topic`, `output_type`).
Then set the joint names and limits in that file for your robot and run
`sudo systemctl restart robot-firewall`.

**6. Laptop.** Use the GUI console (`rust/`, build it with `./build.sh --release -p firewall_console`):
```bash
source deploy/nanopi/sros2/laptop_env.sh ~/robot_fw_keystore 10
rust/target/release/firewall_console --gateway <you>@<nanopi-ip>
```
Setup installs a sudoers rule so the console's *nft counters* and *Restart firewall*
buttons work over ssh without a password prompt. The same checks from the CLI:
```bash
ros2 run monitor_py firewall_dashboard                      # live view
ros2 service call /firewall/rearm std_srvs/srv/Trigger      # arm
ros2 run monitor_py attack_sim_node                         # commander / attacks
ros2 param set /attack_sim_node attack_mode flood           # try an attack
```
Re-arming is refused unless the robot's state is fresh and within limits.

## Verify on the real hardware

From the laptop:
- `ping 192.168.50.2` fails, because nothing routes to the robot.
- `nmap -sU -p 9900-10149 <nanopi>` and `nmap <nanopi>` show only SSH and the domain-10 RTPS ports.
- Run a ROS node **without** `laptop_env.sh`, with `ROS_DOMAIN_ID=10`, publishing
  `joint_commands`. It never shows up on the firewall, and the robot never moves.
- Cycle every `attack_mode`. The dashboard shows each attack and the action taken.

On the robot LAN:
- Plug a second machine into the robot switch and publish on `joint_commands`
  with `ROS_DOMAIN_ID=20`. You should see `ROGUE_DEVICE_ON_ROBOT_LAN` followed by LOCKDOWN.

On the NanoPi:
- `sudo nft list counters` should match the `NETWORK_PROBE` events on the dashboard.
- `journalctl -u robot-firewall -f` shows the live log. Incidents are in `/var/log/robot_firewall/incidents.jsonl`.
- `sudo systemctl kill -s KILL robot-firewall`: the robot holds, the service restarts, and the dashboard shows LOCKDOWN.

## Limits to know about

- **Clocks must be synced.** Replay protection rejects commands stamped more than
  `max_age_s` (0.5 s) away from the gateway clock. The setup installs chrony. If
  every command shows up as `REPLAY`, check `chronyc tracking` on both machines.
- **Default SROS2 permissions are per domain, not per topic.** Anyone holding a
  `/laptop` certificate can publish any topic on domain 10. Command inspection
  still applies. For least privilege, generate enclaves from a policy file
  (`ros2 security generate_artifacts -p policy.xml`).
- **`allowed_publishers` matches on node names.** Node names can be spoofed, so
  this check only complements SROS2 and cannot replace it. The Rust gateway drops
  unauthorized messages one by one. rclpy on Jazzy does not expose the sender of
  each message, so the Python gateway triggers LOCKDOWN instead.
- **The robot LAN is unauthenticated** by default, because many robots can't do SROS2.
  It is protected physically (one cable) and by rogue-publisher detection. If your
  robot supports SROS2, pass `--trusted-enclave` to `firewall_node`.
- The RMW is **Fast DDS** (the Jazzy default). The in-process two-domain bridge
  and per-context security were tested with it.
