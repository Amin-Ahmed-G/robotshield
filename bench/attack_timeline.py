"""
Record a live attack timeline through the Rust gateway.

  0-4 s    legitimate sine commander
  4-12 s   OVERREACH: commander aims at 1.5 rad, limit is 1.0
  12-15 s  legitimate
  15-17 s  FLOOD: ~600 msgs/s
  17-22 s  legitimate commander keeps sending (firewall is in LOCKDOWN)

Records commanded joint_1, actual robot joint_1 (robot domain), msgs sent,
msgs forwarded to the robot, and firewall incidents.
Writes bench/results/timeline.json. Run from the repo root.
"""
import json
import math
import os
from pathlib import Path
import subprocess
import threading
import time

import rclpy
from rclpy.context import Context
from rclpy.executors import SingleThreadedExecutor
from builtin_interfaces.msg import Time
from diagnostic_msgs.msg import DiagnosticStatus
from sensor_msgs.msg import JointState
from std_srvs.srv import Trigger

JOINTS = ['joint_1', 'joint_2', 'joint_3', 'joint_4']
U, T = 87, 88


def stamp(ns):
    return Time(sec=ns // 1_000_000_000, nanosec=ns % 1_000_000_000)


def main():
    os.environ['ROS_AUTOMATIC_DISCOVERY_RANGE'] = 'LOCALHOST'
    Path('bench/results').mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ROS_DOMAIN_ID=str(T))
    robot_proc = subprocess.Popen(
        ['install/monitor_py/lib/monitor_py/robot_sim_node', '--ros-args', '-p', 'max_velocity:=1.5'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fw_proc = subprocess.Popen(
        ['rust/target/release/robot_firewall', '--untrusted-domain', str(U), '--trusted-domain', str(T),
         '--config', 'src/monitor_py/config/firewall_params.yaml', '--set', 'incident_log_path=/dev/null'],
        stdout=open('bench/results/gateway_timeline.log', 'w'), stderr=subprocess.STDOUT)

    lctx, rctx = Context(), Context()
    rclpy.init(context=lctx, domain_id=U)
    rclpy.init(context=rctx, domain_id=T)
    laptop = rclpy.create_node('attack_sim_node', context=lctx)
    probe = rclpy.create_node('probe', context=rctx)
    pub = laptop.create_publisher(JointState, 'joint_commands', 10)
    rearm = laptop.create_client(Trigger, '/firewall/rearm')

    t0 = [None]
    lock = threading.Lock()
    rec = {'commanded': [], 'robot': [], 'sent': [], 'forwarded': [], 'held': [], 'events': []}
    pose = [None]

    def rel():
        return time.monotonic() - t0[0] if t0[0] else None

    def on_state(msg):
        if 'joint_1' in msg.name:
            pose[0] = list(msg.position)
            t = rel()
            if t is not None:
                with lock:
                    rec['robot'].append((t, msg.position[msg.name.index('joint_1')]))

    def on_forwarded(msg):
        t = rel()
        if t is None:
            return
        with lock:
            (rec['held'] if msg.velocity else rec['forwarded']).append(t)

    def on_event(msg):
        t = rel()
        attack = next((kv.value for kv in msg.values if kv.key == 'attack'), '')
        if t is not None:
            with lock:
                rec['events'].append((t, attack, msg.message))

    probe.create_subscription(JointState, 'joint_states', on_state, 50)
    probe.create_subscription(JointState, 'joint_commands', on_forwarded, 1000)
    laptop.create_subscription(DiagnosticStatus, '/firewall/events', on_event, 100)

    exes = []
    for node, ctx in ((laptop, lctx), (probe, rctx)):
        ex = SingleThreadedExecutor(context=ctx)
        ex.add_node(node)
        threading.Thread(target=ex.spin, daemon=True).start()
        exes.append(ex)

    assert rearm.wait_for_service(timeout_sec=20)
    deadline = time.time() + 20
    armed = False
    while not armed and time.time() < deadline:
        if pose[0] is not None:
            fut = rearm.call_async(Trigger.Request())
            while not fut.done():
                time.sleep(0.02)
            armed = fut.result().success
        time.sleep(0.2)
    assert armed

    t0[0] = time.monotonic()
    while (t := rel()) < 22.0:
        cur = pose[0]
        flood = 15.0 <= t < 17.0
        amplitude = 1.5 if 4.0 <= t < 12.0 else 0.8
        target = [amplitude * math.sin(2 * math.pi * 0.25 * t + i * math.pi / 4) for i in range(4)]
        cmd = [c + max(-0.08, min(0.08, g - c)) for c, g in zip(cur, target)]
        copies = 30 if flood else 1
        for _ in range(copies):
            msg = JointState(name=JOINTS, position=cmd)
            msg.header.stamp = stamp(time.time_ns())
            pub.publish(msg)
        with lock:
            rec['commanded'].append((t, target[0]))
            rec['sent'].extend([t] * copies)
        time.sleep(0.05)

    time.sleep(0.5)
    for ex in exes:
        ex.shutdown()
    fw_proc.terminate()
    robot_proc.terminate()
    Path('bench/results/timeline.json').write_text(json.dumps(rec))
    print(json.dumps({k: len(v) for k, v in rec.items()}))
    for ev in rec['events']:
        print(f'{ev[0]:6.2f}s {ev[1]}')
    for ctx in (lctx, rctx):
        rclpy.try_shutdown(context=ctx)


if __name__ == '__main__':
    main()
