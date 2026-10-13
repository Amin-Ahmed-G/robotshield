#!/usr/bin/env python3
"""
Laptop-side commander that can switch live into attacks on the firewall.

Runs on the laptop (untrusted side). Publishes legitimate joint commands that
track a sine trajectory while staying close to the robot's reported pose, and
can switch live into an attack to exercise the firewall:

  ros2 param set /attack_sim_node attack_mode flood

Modes: none, overreach, overspeed, spike, nan, flood, unknown_joint, replay,
spoof. With attack_duration_s > 0 the mode reverts to 'none' automatically.
Part of ros2_monitor_suite.
"""

from monitor_py.attacks import apply_attack, ATTACK_MODES, CommandMsg, sine_targets, step_toward
from monitor_py.ros_conv import sec_to_stamp
from rcl_interfaces.msg import SetParametersResult
import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.parameter import Parameter
from sensor_msgs.msg import JointState


class AttackSimNode(Node):

    def __init__(self):
        super().__init__('attack_sim_node')

        self.declare_parameter('joint_names', ['joint_1', 'joint_2', 'joint_3', 'joint_4'])
        self.declare_parameter('publish_rate_hz', 20.0)
        self.declare_parameter('amplitude', 0.8)
        self.declare_parameter('overreach_amplitude', 1.5)
        self.declare_parameter('frequency_hz', 0.1)
        self.declare_parameter('max_command_step', 0.08)
        self.declare_parameter('attack_mode', 'none')
        self.declare_parameter('attack_joint', 0)
        self.declare_parameter('attack_magnitude', 3.0)
        self.declare_parameter('attack_duration_s', 0.0)
        self.declare_parameter('flood_copies', 40)

        self.joint_names = list(self.get_parameter('joint_names').value)
        rate = self.get_parameter('publish_rate_hz').value
        self.add_on_set_parameters_callback(self._validate)

        self.cmd_pub = self.create_publisher(JointState, 'joint_commands', 10)
        self.create_subscription(JointState, 'joint_states', self._on_state, 10)
        self.state = None
        self.mode = 'none'
        self.mode_since = 0.0
        self.t0 = self._now()
        self.intruder = None
        self.intruder_pub = None
        self.create_timer(1.0 / rate, self._tick)

        self.get_logger().info(
            f'AttackSimNode started @ {rate} Hz. Switch attacks with: '
            f'ros2 param set /attack_sim_node attack_mode <{"|".join(ATTACK_MODES)}>')

    def _now(self) -> float:
        return self.get_clock().now().nanoseconds * 1e-9

    def _validate(self, params):
        for param in params:
            if param.name == 'attack_mode' and param.value not in ATTACK_MODES:
                return SetParametersResult(
                    successful=False, reason=f'attack_mode must be one of {ATTACK_MODES}')
        return SetParametersResult(successful=True)

    def _on_state(self, msg: JointState):
        index = {n: i for i, n in enumerate(msg.name)}
        if all(n in index for n in self.joint_names):
            self.state = [msg.position[index[n]] for n in self.joint_names]

    def _update_mode(self, now):
        mode = self.get_parameter('attack_mode').value
        duration = self.get_parameter('attack_duration_s').value
        if mode != 'none' and duration > 0 and now - self.mode_since > duration \
                and mode == self.mode:
            self.set_parameters([Parameter('attack_mode', value='none')])
            mode = 'none'
        if mode != self.mode:
            self.get_logger().warn(f'attack_mode: {self.mode} -> {mode}')
            self.mode, self.mode_since = mode, now
            self._set_intruder(mode == 'spoof')

    def _set_intruder(self, enabled):
        if enabled and self.intruder is None:
            self.intruder = rclpy.create_node('intruder', context=self.context)
            self.intruder_pub = self.intruder.create_publisher(JointState, 'joint_commands', 10)
        elif not enabled and self.intruder is not None:
            self.intruder.destroy_node()
            self.intruder = self.intruder_pub = None

    def _tick(self):
        now = self._now()
        self._update_mode(now)
        if self.state is None:
            return  # wait for the robot pose so commands start where the robot is

        amplitude = self.get_parameter(
            'overreach_amplitude' if self.mode == 'overreach' else 'amplitude').value
        target = sine_targets(now - self.t0, len(self.joint_names), amplitude,
                              self.get_parameter('frequency_hz').value)
        position = step_toward(self.state, target,
                               self.get_parameter('max_command_step').value)
        base = CommandMsg(list(self.joint_names), position,
                          [0.0] * len(position), now)

        for msg in apply_attack(
                self.mode, base,
                self.get_parameter('attack_joint').value,
                self.get_parameter('attack_magnitude').value,
                self.get_parameter('flood_copies').value):
            self.cmd_pub.publish(self._to_msg(msg))

        if self.intruder_pub is not None:
            # Legit-looking commands from a node that is not allowlisted.
            self.intruder_pub.publish(self._to_msg(base))

    @staticmethod
    def _to_msg(cmd: CommandMsg) -> JointState:
        msg = JointState()
        msg.header.stamp = sec_to_stamp(cmd.stamp)
        msg.name = cmd.names
        msg.position = [float(v) for v in cmd.position]
        msg.velocity = [float(v) for v in cmd.velocity]
        return msg


def main(args=None):
    rclpy.init(args=args)
    node = AttackSimNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
