#!/usr/bin/env python3
"""
Joint state monitor with limits, rate watchdog and diagnostics.

Subscribes to /joint_states and checks every joint's position, velocity and
effort against per-joint limits (with debounce and hysteresis), and watches
the topic's rate and staleness. Logs only on state transitions, publishes
/diagnostics for rqt_robot_monitor, and one DiagnosticStatus per transition
on ~/alerts. ~/reset (std_srvs/Trigger) clears all latched state.
Part of ros2_monitor_suite.
"""

from diagnostic_msgs.msg import DiagnosticArray, DiagnosticStatus
from monitor_py.checks import FAULT, INVALID, JointHealth, OK
from monitor_py.rate_tracker import RateTracker
from monitor_py.ros_conv import declare_joint_limits, declare_limit_defaults, key_values
import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from sensor_msgs.msg import JointState
from std_srvs.srv import Trigger

STATE_LEVEL = {OK: DiagnosticStatus.OK, FAULT: DiagnosticStatus.WARN,
               INVALID: DiagnosticStatus.ERROR}


class JointMonitorNode(Node):
    """Monitors JointState messages and reports limit and topic health."""

    def __init__(self):
        super().__init__('joint_monitor_node')

        self.limit_defaults = declare_limit_defaults(self)
        self.declare_parameter('hysteresis_ratio', 0.05)
        self.declare_parameter('debounce_count', 3)
        self.declare_parameter('expected_rate_hz', 10.0)
        self.declare_parameter('min_rate_ratio', 0.8)
        self.declare_parameter('stale_timeout_s', 0.5)
        self.declare_parameter('diagnostics_period_s', 1.0)

        self.hysteresis_ratio = self.get_parameter('hysteresis_ratio').value
        self.debounce_count = self.get_parameter('debounce_count').value
        self.expected_rate_hz = self.get_parameter('expected_rate_hz').value
        self.min_rate_ratio = self.get_parameter('min_rate_ratio').value
        self.stale_timeout_s = self.get_parameter('stale_timeout_s').value
        period = self.get_parameter('diagnostics_period_s').value

        self.joints = {}
        self.rate = RateTracker(window_s=2.0)
        self.topic_state = 'NO_DATA'
        self._malformed_logged = False

        self.subscription = self.create_subscription(
            JointState, 'joint_states', self._listener_callback, 10)
        self.diag_pub = self.create_publisher(DiagnosticArray, '/diagnostics', 10)
        self.alert_pub = self.create_publisher(DiagnosticStatus, '~/alerts', 10)
        self.create_service(Trigger, '~/reset', self._on_reset)
        self.create_timer(period, self._watchdog)

        self.get_logger().info(
            f'JointMonitorNode started: default limits {self.limit_defaults}, '
            f'expected {self.expected_rate_hz} Hz')

    def _now(self) -> float:
        return self.get_clock().now().nanoseconds * 1e-9

    def _joint(self, name) -> JointHealth:
        if name not in self.joints:
            limits = declare_joint_limits(self, name, self.limit_defaults)
            self.joints[name] = JointHealth(name, limits, self.hysteresis_ratio,
                                            self.debounce_count)
        return self.joints[name]

    def _alert(self, level, name, message, **values):
        self.alert_pub.publish(DiagnosticStatus(
            level=level, name=name, message=message, values=key_values(**values)))

    def _listener_callback(self, msg: JointState):
        self.rate.tick(self._now())
        n = len(msg.name)
        if any(len(arr) not in (0, n) for arr in (msg.position, msg.velocity, msg.effort)):
            if not self._malformed_logged:
                self.get_logger().warn(
                    f'Malformed JointState: {n} names, {len(msg.position)} positions, '
                    f'{len(msg.velocity)} velocities, {len(msg.effort)} efforts')
                self._malformed_logged = True
            return

        for i, name in enumerate(msg.name):
            health = self._joint(name)
            events = health.update(
                msg.position[i] if msg.position else None,
                msg.velocity[i] if msg.velocity else None,
                msg.effort[i] if msg.effort else None)
            for event in events:
                text = event.describe()
                if event.new_state == OK:
                    self.get_logger().info(text)
                else:
                    self.get_logger().warn(text)
                self._alert(STATE_LEVEL[event.new_state], f'joint_monitor: {name}', text,
                            field=event.field, state=event.new_state,
                            value=f'{event.value:.4f}')

    def _watchdog(self):
        now = self._now()
        age = self.rate.age_s(now)
        rate = self.rate.rate_hz(now)
        if age > self.stale_timeout_s:
            state = 'STALE'
        elif rate < self.expected_rate_hz * self.min_rate_ratio:
            state = 'SLOW'
        else:
            state = 'OK'

        if state != self.topic_state:
            text = f'joint_states topic {self.topic_state} -> {state} ' \
                   f'(rate {rate:.1f} Hz, age {age:.2f}s)'
            if state == 'OK':
                self.get_logger().info(text)
            else:
                self.get_logger().warn(text)
            level = DiagnosticStatus.OK if state == 'OK' else DiagnosticStatus.WARN
            self._alert(level, 'joint_monitor: topic', text, state=state)
            self.topic_state = state

        array = DiagnosticArray()
        array.header.stamp = self.get_clock().now().to_msg()
        array.status.append(DiagnosticStatus(
            level=DiagnosticStatus.OK if state == 'OK' else DiagnosticStatus.WARN,
            name='joint_monitor: topic', message=state,
            values=key_values(rate_hz=f'{rate:.1f}', age_s=f'{age:.2f}',
                              total=self.rate.total)))
        for name, health in self.joints.items():
            worst = health.worst_state()
            checkers = health.checkers
            array.status.append(DiagnosticStatus(
                level=STATE_LEVEL[worst], name=f'joint_monitor: {name}', message=worst,
                values=key_values(
                    breach_count=health.breach_count,
                    **{f'{f}': c.last_value for f, c in checkers.items()},
                    **{f'{f}_peak': f'{c.peak:.4f}' for f, c in checkers.items()})))
        self.diag_pub.publish(array)

    def _on_reset(self, request, response):
        for health in self.joints.values():
            health.reset()
        self.rate.reset()
        self.topic_state = 'NO_DATA'
        self._malformed_logged = False
        response.success = True
        response.message = f'reset {len(self.joints)} joint(s)'
        self.get_logger().info(response.message)
        return response


def main(args=None):
    rclpy.init(args=args)
    node = JointMonitorNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
