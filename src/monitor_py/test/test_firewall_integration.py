"""
End-to-end test of firewall_node on two real DDS domains in one process.

Laptop side (untrusted) and robot side (trusted) are separate rclpy contexts
on different domain IDs, so the only way a command can reach the robot is
through the firewall.
"""

import math
import os
import threading
import time

from diagnostic_msgs.msg import DiagnosticStatus
from monitor_py.firewall_node import init_context, RobotFirewall
from monitor_py.ros_conv import sec_to_stamp
import pytest
import rclpy
from rclpy.executors import SingleThreadedExecutor
from sensor_msgs.msg import JointState
from std_srvs.srv import Trigger

UNTRUSTED, TRUSTED = 91, 92
JOINTS = ['joint_1', 'joint_2']


def wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class Bench:

    def __init__(self, tmp_path):
        os.environ['ROS_AUTOMATIC_DISCOVERY_RANGE'] = 'LOCALHOST'
        params = ['--ros-args',
                  '-p', f'joint_names:={JOINTS}',
                  '-p', 'lockdown_threshold:=5',
                  '-p', 'allowed_publishers:=[laptop]',
                  '-p', 'watch_period_s:=0.2',
                  '-p', f'incident_log_path:={tmp_path}/incidents.jsonl']
        self.trusted_ctx = init_context(TRUSTED, '', ['test'] + params)
        self.untrusted_ctx = init_context(UNTRUSTED, '', ['test'])
        self.fw = RobotFirewall(self.untrusted_ctx, self.trusted_ctx, UNTRUSTED, TRUSTED)

        self.laptop_ctx = init_context(UNTRUSTED, '', ['test'])
        self.robot_ctx = init_context(TRUSTED, '', ['test'])
        self.laptop = rclpy.create_node('laptop', context=self.laptop_ctx)
        self.robot = rclpy.create_node('robot', context=self.robot_ctx)

        self.cmd_pub = self.laptop.create_publisher(JointState, 'joint_commands', 10)
        self.rearm_client = self.laptop.create_client(Trigger, '/firewall/rearm')
        self.events = []
        self.laptop.create_subscription(
            DiagnosticStatus, '/firewall/events', self.events.append, 50)
        self.state_pub = self.robot.create_publisher(JointState, 'joint_states', 10)
        self.received = []
        self.robot.create_subscription(
            JointState, 'joint_commands', self.received.append, 50)
        self.robot.create_timer(0.02, self._publish_state)

        self.executors = []
        for node, ctx in ((self.fw.trusted, self.trusted_ctx),
                          (self.fw.untrusted, self.untrusted_ctx),
                          (self.laptop, self.laptop_ctx), (self.robot, self.robot_ctx)):
            ex = SingleThreadedExecutor(context=ctx)
            ex.add_node(node)
            threading.Thread(target=ex.spin, daemon=True).start()
            self.executors.append(ex)
        assert wait_for(lambda: self.cmd_pub.get_subscription_count() > 0 and
                        self.rearm_client.service_is_ready(), 10.0)

    def _publish_state(self):
        msg = JointState(name=JOINTS, position=[0.0, 0.0])
        msg.header.stamp = self.robot.get_clock().now().to_msg()
        self.state_pub.publish(msg)

    def now(self):
        return self.laptop.get_clock().now().nanoseconds * 1e-9

    def send(self, position, names=JOINTS, stamp=None):
        msg = JointState(name=list(names), position=[float(p) for p in position])
        msg.header.stamp = sec_to_stamp(self.now() if stamp is None else stamp)
        self.cmd_pub.publish(msg)

    def rearm(self):
        future = self.rearm_client.call_async(Trigger.Request())
        assert wait_for(future.done)
        return future.result()

    def attacks(self):
        return [kv.value for e in self.events for kv in e.values if kv.key == 'attack']

    def forwarded_positions(self):
        return [p for m in self.received if m.header.stamp.sec != 0 for p in m.position]

    def close(self):
        for ex in self.executors:
            ex.shutdown()
        self.fw.destroy()
        self.laptop.destroy_node()
        self.robot.destroy_node()
        for ctx in (self.trusted_ctx, self.untrusted_ctx, self.laptop_ctx, self.robot_ctx):
            rclpy.try_shutdown(context=ctx)


@pytest.fixture
def bench(tmp_path):
    b = Bench(tmp_path)
    yield b
    b.close()


def test_starts_locked_then_forwards_after_rearm(bench):
    assert wait_for(lambda: bench.fw.core.state_fresh(bench.now()))
    bench.send([0.05, 0.0])
    time.sleep(0.3)
    # Only hold commands (at the robot pose, zero velocity) reach the robot.
    assert all(p == 0.0 for p in bench.forwarded_positions())

    assert bench.rearm().success
    bench.received.clear()
    bench.send([0.1, 0.0])
    assert wait_for(lambda: 0.1 in bench.forwarded_positions())


def test_unsafe_commands_never_reach_robot(bench):
    assert wait_for(lambda: bench.fw.core.state_fresh(bench.now()))
    assert bench.rearm().success
    bench.received.clear()

    bench.send([5.0, 0.0])            # step jump
    time.sleep(0.05)
    bench.send([math.nan, 0.0])       # NaN
    time.sleep(0.05)
    bench.send([0.0, 0.0, 0.0], names=JOINTS + ['joint_99'])  # unknown joint
    time.sleep(0.05)
    bench.send([0.0, 0.0], stamp=bench.now() - 10.0)  # replay
    assert wait_for(lambda: {'STEP_JUMP', 'INVALID_VALUE', 'MALFORMED', 'REPLAY'}
                    <= set(bench.attacks()))
    positions = bench.forwarded_positions()
    assert all(math.isfinite(p) and abs(p) <= 1.0 for p in positions)
    assert 'STEP_JUMP' in bench.fw.incident_log.read_text()


def test_flood_triggers_lockdown(bench):
    assert wait_for(lambda: bench.fw.core.state_fresh(bench.now()))
    assert bench.rearm().success
    base = bench.now()
    for i in range(200):  # ~1 kHz
        bench.send([0.0, 0.0], stamp=base + i * 1e-4)
        time.sleep(0.001)
    assert wait_for(lambda: 'LOCKDOWN' in bench.attacks())
    assert 'FLOOD' in bench.attacks()
    assert bench.fw.core.mode == 'LOCKDOWN'


def test_rogue_publisher_on_robot_lan_locks_down(bench):
    assert wait_for(lambda: bench.fw.core.state_fresh(bench.now()))
    assert bench.rearm().success
    rogue = rclpy.create_node('rogue', context=bench.robot_ctx)
    rogue.create_publisher(JointState, 'joint_commands', 10)
    try:
        assert wait_for(lambda: 'ROGUE_DEVICE_ON_ROBOT_LAN' in bench.attacks())
        assert bench.fw.core.mode == 'LOCKDOWN'
    finally:
        rogue.destroy_node()


def test_unauthorized_publisher_on_untrusted_side_locks_down(bench):
    assert wait_for(lambda: bench.fw.core.state_fresh(bench.now()))
    assert bench.rearm().success
    intruder = rclpy.create_node('intruder', context=bench.laptop_ctx)
    intruder.create_publisher(JointState, 'joint_commands', 10)
    try:
        assert wait_for(lambda: 'UNAUTHORIZED_PUBLISHER' in bench.attacks())
        assert bench.fw.core.mode == 'LOCKDOWN'
    finally:
        intruder.destroy_node()
