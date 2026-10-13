#!/usr/bin/env python3
"""
Simulated robot that follows joint commands and holds on timeout.

Stand-in for the robot on the trusted LAN. Follows position commands on
joint_commands with a per-joint velocity cap and publishes joint_states.
If commands stop arriving for command_timeout_s it holds its current pose,
which is the fail-safe the firewall relies on when it goes down.
Part of ros2_monitor_suite.
"""

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from sensor_msgs.msg import JointState
from std_msgs.msg import Float64MultiArray


class RobotSimNode(Node):
    """Simulated N-DOF arm with first-order position tracking."""

    def __init__(self):
        super().__init__('robot_sim_node')

        self.declare_parameter('publish_rate_hz', 50.0)
        self.declare_parameter('joint_names', ['joint_1', 'joint_2', 'joint_3', 'joint_4'])
        self.declare_parameter('max_velocity', 1.5)
        self.declare_parameter('command_timeout_s', 0.5)
        self.declare_parameter('command_type', 'joint_state')

        rate = self.get_parameter('publish_rate_hz').value
        self.joint_names = list(self.get_parameter('joint_names').value)
        self.max_velocity = self.get_parameter('max_velocity').value
        self.command_timeout_s = self.get_parameter('command_timeout_s').value
        command_type = self.get_parameter('command_type').value

        n = len(self.joint_names)
        self.position = [0.0] * n
        self.velocity = [0.0] * n
        self.target = [0.0] * n
        self.last_command_time = None
        self._holding = True
        self._dt = 1.0 / rate

        if command_type == 'float64_multi_array':
            self.create_subscription(Float64MultiArray, 'joint_commands', self._on_array, 10)
        else:
            self.create_subscription(JointState, 'joint_commands', self._on_joint_state, 10)
        self.publisher_ = self.create_publisher(JointState, 'joint_states', 10)
        self.timer = self.create_timer(self._dt, self._timer_callback)

        self.get_logger().info(
            f'RobotSimNode started: {n} joints @ {rate} Hz, '
            f'max_velocity={self.max_velocity} rad/s, timeout={self.command_timeout_s}s')

    def _now(self) -> float:
        return self.get_clock().now().nanoseconds * 1e-9

    def _on_joint_state(self, msg: JointState):
        index = {name: i for i, name in enumerate(msg.name)}
        for j, name in enumerate(self.joint_names):
            i = index.get(name)
            if i is not None and i < len(msg.position):
                self.target[j] = msg.position[i]
        self.last_command_time = self._now()

    def _on_array(self, msg: Float64MultiArray):
        for j, value in enumerate(msg.data[:len(self.target)]):
            self.target[j] = value
        self.last_command_time = self._now()

    def _timer_callback(self):
        stale = self.last_command_time is None or \
            self._now() - self.last_command_time > self.command_timeout_s
        if stale != self._holding:
            self._holding = stale
            if stale:
                self.get_logger().warn('Command timeout: holding current pose')
            else:
                self.get_logger().info('Receiving commands')
        if stale:
            self.target = list(self.position)

        max_step = self.max_velocity * self._dt
        for j in range(len(self.position)):
            delta = max(-max_step, min(max_step, self.target[j] - self.position[j]))
            self.position[j] += delta
            self.velocity[j] = delta / self._dt

        msg = JointState()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.name = self.joint_names
        msg.position = list(self.position)
        msg.velocity = list(self.velocity)
        self.publisher_.publish(msg)


def main(args=None):
    rclpy.init(args=args)
    node = RobotSimNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
