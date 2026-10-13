#!/usr/bin/env python3
"""
Laptop-side terminal dashboard for the robot firewall.

Shows the current mode, traffic
counters, per-attack counters and a live incident feed describing each attack
and what the firewall did about it.

  ros2 run monitor_py firewall_dashboard            # full-screen view
  ros2 run monitor_py firewall_dashboard --ros-args -p plain:=true   # log lines
Part of ros2_monitor_suite.
"""

from collections import deque
import datetime
import json
import time

from diagnostic_msgs.msg import DiagnosticStatus
import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from std_msgs.msg import String

RED, YELLOW, GREEN, BOLD, DIM, RESET = (
    '\033[31m', '\033[33m', '\033[32m', '\033[1m', '\033[2m', '\033[0m')
LEVEL_COLOR = {DiagnosticStatus.OK: GREEN, DiagnosticStatus.WARN: YELLOW,
               DiagnosticStatus.ERROR: RED}


class FirewallDashboard(Node):

    def __init__(self):
        super().__init__('firewall_dashboard')
        self.declare_parameter('plain', False)
        self.declare_parameter('max_events', 15)
        self.declare_parameter('status_timeout_s', 3.0)
        self.plain = self.get_parameter('plain').value
        self.timeout = self.get_parameter('status_timeout_s').value
        self.events = deque(maxlen=self.get_parameter('max_events').value)
        self.status = None
        self.status_time = None
        self.create_subscription(DiagnosticStatus, '/firewall/events', self._on_event, 50)
        self.create_subscription(String, '/firewall/status', self._on_status, 10)
        if not self.plain:
            self.create_timer(0.5, self._draw)
        else:
            self.get_logger().info('Listening on /firewall/events')

    def _on_event(self, msg: DiagnosticStatus):
        stamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.events.appendleft((stamp, msg.level, msg.message))
        if self.plain:
            level = {DiagnosticStatus.OK: 'OK', DiagnosticStatus.WARN: 'WARN',
                     DiagnosticStatus.ERROR: 'ERROR'}.get(msg.level, 'INFO')
            print(f'{stamp} [{level}] {msg.message}', flush=True)

    def _on_status(self, msg: String):
        try:
            self.status = json.loads(msg.data)
            self.status_time = time.monotonic()
        except ValueError:
            pass

    def _draw(self):
        lines = [f'{BOLD}ROBOT FIREWALL DASHBOARD{RESET}   '
                 f'{DIM}{datetime.datetime.now():%H:%M:%S}{RESET}', '']
        age = None if self.status_time is None else time.monotonic() - self.status_time
        if age is None or age > self.timeout:
            lines.append(f'{RED}{BOLD}FIREWALL UNREACHABLE{RESET} '
                         f'(no /firewall/status{"" if age is None else f" for {age:.0f}s"})')
            lines.append('Robot is protected by its own command timeout; '
                         'check WiFi / firewall service.')
        else:
            s = self.status
            if s['mode'] == 'LOCKDOWN':
                lines.append(f'Mode: {RED}{BOLD}LOCKDOWN{RESET}  {s["lockdown_reason"]}')
                lines.append(f'{DIM}Robot held at last safe pose. Re-arm: '
                             f'ros2 service call /firewall/rearm std_srvs/srv/Trigger{RESET}')
            else:
                lines.append(f'Mode: {GREEN}{BOLD}ARMED{RESET}  forwarding commands')
                lines.append('')
            lines.append(
                f'Traffic: {s["input_rate_hz"]:.0f} Hz in | forwarded {s["forwarded"]} | '
                f'clamped {s["clamped"]} | dropped {s["dropped"]} | robot state '
                f'{"ok" if s["robot_state_fresh"] else RED + "STALE" + RESET}')
            counters = s.get('counters', {})
            if counters:
                lines.append('Attacks: ' + ', '.join(
                    f'{k}={v}' for k, v in sorted(counters.items())))
        lines += ['', f'{BOLD}Incident feed{RESET}']
        if not self.events:
            lines.append(f'{DIM}(none yet){RESET}')
        for stamp, level, message in self.events:
            color = LEVEL_COLOR.get(level, '')
            lines.append(f'{DIM}{stamp}{RESET} {color}{message}{RESET}')
        print('\033[2J\033[H' + '\n'.join(lines), flush=True)


def main(args=None):
    rclpy.init(args=args)
    node = FirewallDashboard()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
