"""
End-to-end latency added by the firewall gateway.

Sends stamped JointState commands from an untrusted-domain node to a
robot-domain subscriber, either directly (same domain, no firewall) or through
the Rust / Python gateway, and records receive_time - send_stamp per message.

  python3 bench/gateway_latency.py {direct|rust|python} [--count 1000] [--rate 40]

Run from the repo root with ROS 2 Jazzy + install/ sourced and the Rust
gateway built in release mode. Writes bench/results/latency_<mode>.json.
"""
import argparse
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
from sensor_msgs.msg import JointState
from std_srvs.srv import Trigger

JOINTS = ['joint_1', 'joint_2', 'joint_3', 'joint_4']
DOMAINS = {'direct': (82, 82), 'rust': (83, 84), 'python': (85, 86)}


def stamp_from_ns(ns):
    from builtin_interfaces.msg import Time
    return Time(sec=ns // 1_000_000_000, nanosec=ns % 1_000_000_000)


def start_gateway(mode, untrusted, trusted):
    log = open(f'bench/results/gateway_{mode}.log', 'w')
    if mode == 'rust':
        cmd = ['rust/target/release/robot_firewall', '--untrusted-domain', str(untrusted),
               '--trusted-domain', str(trusted), '--set', 'incident_log_path=/dev/null']
    else:
        cmd = ['install/monitor_py/lib/monitor_py/firewall_node', '--untrusted-domain',
               str(untrusted), '--trusted-domain', str(trusted), '--ros-args',
               '-p', 'incident_log_path:=/dev/null']
    return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=DOMAINS)
    ap.add_argument('--count', type=int, default=1000)
    ap.add_argument('--rate', type=float, default=40.0)
    args = ap.parse_args()
    os.environ['ROS_AUTOMATIC_DISCOVERY_RANGE'] = 'LOCALHOST'
    Path('bench/results').mkdir(parents=True, exist_ok=True)
    untrusted, trusted = DOMAINS[args.mode]

    gateway = None if args.mode == 'direct' else start_gateway(args.mode, untrusted, trusted)

    lctx, rctx = Context(), Context()
    rclpy.init(context=lctx, domain_id=untrusted)
    rclpy.init(context=rctx, domain_id=trusted)
    laptop = rclpy.create_node('attack_sim_node', context=lctx)
    robot = rclpy.create_node('robot', context=rctx)
    pub = laptop.create_publisher(JointState, 'joint_commands', 10)
    rearm = laptop.create_client(Trigger, '/firewall/rearm')

    latencies = []
    lock = threading.Lock()

    def on_cmd(msg):
        now = time.time_ns()
        if msg.velocity:  # hold commands from the gateway carry zero velocity; ours carry none
            return
        sent = msg.header.stamp.sec * 1_000_000_000 + msg.header.stamp.nanosec
        with lock:
            latencies.append((now - sent) / 1000.0)

    robot.create_subscription(JointState, 'joint_commands', on_cmd, 100)
    state_pub = robot.create_publisher(JointState, 'joint_states', 10)

    def publish_state():
        msg = JointState(name=JOINTS, position=[0.0] * 4)
        msg.header.stamp = stamp_from_ns(time.time_ns())
        state_pub.publish(msg)

    robot.create_timer(0.02, publish_state)
    executors = []
    for node, ctx in ((laptop, lctx), (robot, rctx)):
        ex = SingleThreadedExecutor(context=ctx)
        ex.add_node(node)
        threading.Thread(target=ex.spin, daemon=True).start()
        executors.append(ex)

    deadline = time.time() + 20
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.1)
    if gateway:
        assert rearm.wait_for_service(timeout_sec=15), 'gateway did not come up'
        armed = False
        while not armed and time.time() < deadline + 10:
            fut = rearm.call_async(Trigger.Request())
            while not fut.done():
                time.sleep(0.02)
            armed = fut.result().success
            time.sleep(0.2)
        assert armed, 'could not re-arm gateway'
    time.sleep(1.0)

    period = 1.0 / args.rate
    next_t = time.perf_counter()
    for i in range(args.count):
        x = 0.05 * math.sin(i * 0.05)
        msg = JointState(name=JOINTS, position=[x] * 4)
        msg.header.stamp = stamp_from_ns(time.time_ns())
        pub.publish(msg)
        next_t += period
        time.sleep(max(0.0, next_t - time.perf_counter()))
    time.sleep(1.0)

    for ex in executors:
        ex.shutdown()
    if gateway:
        gateway.terminate()
        gateway.wait(timeout=10)
    with lock:
        data = sorted(latencies)
    result = {'mode': args.mode, 'sent': args.count, 'received': len(data), 'latency_us': data}
    Path(f'bench/results/latency_{args.mode}.json').write_text(json.dumps(result))

    def pct(p):
        return data[int((len(data) - 1) * p)]
    print(json.dumps({'mode': args.mode, 'sent': args.count, 'received': len(data),
                      'p50_us': round(pct(0.5), 1), 'p95_us': round(pct(0.95), 1),
                      'p99_us': round(pct(0.99), 1), 'max_us': round(data[-1], 1)}))
    for ctx in (lctx, rctx):
        rclpy.try_shutdown(context=ctx)


if __name__ == '__main__':
    main()
