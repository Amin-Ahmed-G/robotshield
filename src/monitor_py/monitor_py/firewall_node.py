#!/usr/bin/env python3
"""
Robot command firewall bridging an untrusted and a trusted ROS 2 domain.

Runs on the gateway board (e.g. NanoPi) and joins two
ROS 2 domains in one process:

  untrusted domain (WiFi, laptop side)  --joint_commands-->  [inspect]
  trusted domain   (Ethernet, robot side) <--joint_commands--  forward/clamp
  trusted  joint_states  -->  monitored  -->  relayed to untrusted side

This process is the only bridge between the two domains. Every command is run
through CommandFirewall; incidents are published on /firewall/events, written
to a JSONL log, and summarised on /diagnostics and /firewall/status.

Usage:
  firewall_node [--untrusted-domain 10] [--trusted-domain 20]
                [--enclave /firewall] [--trusted-enclave ENCLAVE]
                [--ros-args --params-file params.yaml]

With --enclave and ROS_SECURITY_KEYSTORE set, the untrusted side runs with
SROS2 (DDS-Security) enforced, so only participants holding certificates from
the same keystore can talk to it. The trusted side is unsecured unless
--trusted-enclave is given.
Part of ros2_monitor_suite.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

from diagnostic_msgs.msg import DiagnosticArray, DiagnosticStatus
from monitor_py import firewall_rules as fw
from monitor_py.firewall_rules import CommandFirewall, FirewallConfig
from monitor_py.ros_conv import (command_to_joint_state, declare_limit_params,
                                 incident_to_status, joint_state_to_command,
                                 key_values, LEVELS)
import rclpy
from rclpy.context import Context
from rclpy.executors import ExternalShutdownException, SingleThreadedExecutor
from rclpy.node import Node
from rclpy.utilities import remove_ros_args
from sensor_msgs.msg import JointState
from std_msgs.msg import Float64MultiArray, String
from std_srvs.srv import Trigger

DEFAULT_JOINTS = ['joint_1', 'joint_2', 'joint_3', 'joint_4']


def sd_notify(state: str):
    """Minimal systemd notify (no python3-systemd dependency)."""
    addr = os.environ.get('NOTIFY_SOCKET')
    if not addr:
        return
    if addr.startswith('@'):
        addr = '\0' + addr[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.sendto(state.encode(), addr)


def init_context(domain_id: int, enclave: str, args) -> Context:
    """Create an rclpy context with per-context domain and security settings."""
    ctx = Context()
    ros_args = list(args)
    secure = bool(enclave)
    if secure:
        if not os.environ.get('ROS_SECURITY_KEYSTORE'):
            raise RuntimeError(f'enclave {enclave} requested but ROS_SECURITY_KEYSTORE is unset')
        os.environ['ROS_SECURITY_ENABLE'] = 'true'
        os.environ.setdefault('ROS_SECURITY_STRATEGY', 'Enforce')
        if '--ros-args' not in ros_args:
            ros_args.append('--ros-args')
        ros_args += ['--enclave', enclave]
    else:
        # rcl reads this at init time, so it can differ per context.
        os.environ['ROS_SECURITY_ENABLE'] = 'false'
    rclpy.init(context=ctx, domain_id=domain_id, args=ros_args)
    return ctx


class RobotFirewall:
    """Owns the two nodes and the rule engine; callbacks run on two threads."""

    def __init__(self, untrusted_ctx: Context, trusted_ctx: Context,
                 untrusted_domain: int, trusted_domain: int, secure: bool = False):
        # Parameter services are disabled on both sides: configuration comes
        # only from the params file on the gateway, never from the network.
        self.trusted = Node('firewall_gateway', context=trusted_ctx,
                            start_parameter_services=False)
        self.untrusted = Node('firewall', context=untrusted_ctx,
                              start_parameter_services=False)
        self.log = self.untrusted.get_logger()
        self.lock = threading.Lock()
        self.domains = (untrusted_domain, trusted_domain)
        self.secure = secure

        p = self.trusted.declare_parameter
        joint_names = list(p('joint_names', DEFAULT_JOINTS).value)
        cfg = FirewallConfig(
            joint_names=joint_names,
            limits=declare_limit_params(self.trusted, joint_names),
            max_step=p('max_step', 0.2).value,
            max_rate_hz=p('max_rate_hz', 50.0).value,
            burst=p('burst', 10.0).value,
            max_age_s=p('max_age_s', 0.5).value,
            max_future_s=p('max_future_s', 0.2).value,
            require_stamp=p('require_stamp', True).value,
            limit_action=p('limit_action', 'clamp').value,
            lockdown_threshold=p('lockdown_threshold', 20).value,
            lockdown_window_s=p('lockdown_window_s', 2.0).value,
            report_interval_s=p('report_interval_s', 1.0).value,
            state_margin=p('state_margin', 0.05).value,
            state_timeout_s=p('state_timeout_s', 0.5).value,
            start_locked=p('start_locked', True).value,
        )
        if cfg.limit_action not in ('clamp', 'drop'):
            raise ValueError("limit_action must be 'clamp' or 'drop'")
        self.core = CommandFirewall(cfg)

        self.command_topic = p('command_topic', 'joint_commands').value
        self.state_topic = p('state_topic', 'joint_states').value
        self.output_topic = p('output_topic', 'joint_commands').value
        self.output_type = p('output_type', 'joint_state').value
        self.allowed_publishers = list(p('allowed_publishers', ['']).value)
        self.allowed_publishers = [n for n in self.allowed_publishers if n]
        self.unauthorized_lockdown = p('unauthorized_lockdown', True).value
        self.expected_state_publishers = p('expected_state_publishers', 1).value
        self.nft_counters_file = p('nft_counters_file', '').value
        self.hardware_id = p('hardware_id', socket.gethostname()).value
        log_path = p('incident_log_path', '').value or str(
            Path.home() / '.ros' / 'robot_firewall' / 'incidents.jsonl')
        # Deep enough that bursts reach the rate limiter instead of being
        # silently discarded by the DDS history cache.
        queue_depth = p('input_queue_depth', 100).value
        hold_rate = p('hold_rate_hz', 10.0).value
        watch_period = p('watch_period_s', 1.0).value

        self.incident_log = Path(log_path)
        self.incident_log.parent.mkdir(parents=True, exist_ok=True)
        self._seen_unauthorized = set()
        self._nft_last = {}
        self._state_was_fresh = False
        self._alive = {'trusted': time.monotonic(), 'untrusted': time.monotonic()}

        # Trusted (robot) side
        if self.output_type == 'joint_state':
            self.robot_pub = self.trusted.create_publisher(JointState, self.output_topic, 10)
        elif self.output_type == 'float64_multi_array':
            self.robot_pub = self.trusted.create_publisher(
                Float64MultiArray, self.output_topic, 10)
        else:
            raise ValueError("output_type must be 'joint_state' or 'float64_multi_array'")
        self.trusted.create_subscription(JointState, self.state_topic, self._on_state, 10)
        self.trusted.create_timer(1.0 / hold_rate, self._hold_tick)

        # Untrusted (laptop) side
        self.state_relay = self.untrusted.create_publisher(JointState, self.state_topic, 10)
        self.events_pub = self.untrusted.create_publisher(
            DiagnosticStatus, '/firewall/events', 50)
        self.diag_pub = self.untrusted.create_publisher(DiagnosticArray, '/diagnostics', 10)
        self.status_pub = self.untrusted.create_publisher(String, '/firewall/status', 10)
        self.untrusted.create_subscription(
            JointState, self.command_topic, self._on_command, queue_depth)
        self.untrusted.create_service(Trigger, '/firewall/rearm', self._on_rearm)
        self.untrusted.create_service(Trigger, '/firewall/reset', self._on_reset)
        self.untrusted.create_timer(watch_period, self._watch_tick)

        self.log.info(
            f'Robot firewall up: untrusted domain {untrusted_domain} -> trusted domain '
            f'{trusted_domain}, joints={joint_names}, mode={self.core.mode}, '
            f'incident log {self.incident_log}')

    # ------------------------------------------------------------------
    def now(self) -> float:
        return self.untrusted.get_clock().now().nanoseconds * 1e-9

    def _report(self, incidents):
        for incident in incidents:
            self.events_pub.publish(incident_to_status(incident, self.hardware_id))
            line = incident.summary()
            if incident.severity == 'ERROR':
                self.log.error(line)
            else:
                self.log.warn(line)
            try:
                with self.incident_log.open('a') as f:
                    f.write(json.dumps(incident.to_dict()) + '\n')
            except OSError as exc:
                self.log.error(f'cannot write incident log: {exc}')

    def _publish_to_robot(self, cmd):
        if self.output_type == 'joint_state':
            self.robot_pub.publish(command_to_joint_state(cmd))
        else:
            self.robot_pub.publish(Float64MultiArray(data=[float(v) for v in cmd.position]))

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------
    def _on_command(self, msg: JointState):
        with self.lock:
            verdict = self.core.inspect(joint_state_to_command(msg), self.now())
            if verdict.command is not None:
                self._publish_to_robot(verdict.command)
        self._report(verdict.incidents)

    def _on_state(self, msg: JointState):
        with self.lock:
            incidents = self.core.observe_state(list(msg.name), list(msg.position), self.now())
        self.state_relay.publish(msg)
        self._report(incidents)

    def _hold_tick(self):
        self._alive['trusted'] = time.monotonic()
        with self.lock:
            if self.core.mode != fw.LOCKDOWN:
                return
            hold = self.core.hold_command(self.now())
            if hold is not None:
                self._publish_to_robot(hold)

    def _on_rearm(self, request, response):
        with self.lock:
            was_armed = self.core.mode == fw.ARMED
            ok, message = self.core.rearm(self.now())
        response.success, response.message = ok, message
        if was_armed:
            # No state change: answer the caller, but keep the incident feed quiet.
            return response
        self.log.warn(f'Re-arm requested: {message}')
        self.events_pub.publish(DiagnosticStatus(
            level=DiagnosticStatus.OK if ok else DiagnosticStatus.WARN,
            name='robot_firewall: REARM', message=message, hardware_id=self.hardware_id,
            values=key_values(attack='REARM', mode=self.core.mode, time=f'{self.now():.3f}')))
        return response

    def _on_reset(self, request, response):
        with self.lock:
            self.core.reset_counters()
        self._seen_unauthorized.clear()
        response.success, response.message = True, 'counters reset'
        return response

    # ------------------------------------------------------------------
    # Periodic watch: graph, robot state freshness, nftables, status
    # ------------------------------------------------------------------
    def _watch_tick(self):
        self._alive['untrusted'] = time.monotonic()
        now = self.now()
        incidents = []
        with self.lock:
            incidents += self._check_robot_lan(now)
            incidents += self._check_untrusted_publishers(now)
            incidents += self._check_state_freshness(now)
            incidents += self._check_nft_counters(now)
            incidents += self.core.flush(now)
            status = self.core.status(now)
        self._report(incidents)
        self._publish_status(status)
        if all(time.monotonic() - t < 5.0 for t in self._alive.values()):
            sd_notify('WATCHDOG=1')

    def _check_robot_lan(self, now):
        incidents = []
        out_pubs = self.trusted.count_publishers(self.output_topic)
        if out_pubs > 1:
            incidents += self.core.report_external(
                fw.ROGUE_DEVICE, f'{out_pubs - 1} extra publisher(s) on robot '
                f'{self.output_topic}', now, 'robot LAN', critical=True)
        state_pubs = self.trusted.count_publishers(self.state_topic)
        if state_pubs > self.expected_state_publishers:
            incidents += self.core.report_external(
                fw.STATE_SPOOFING, f'{state_pubs} publishers on robot {self.state_topic} '
                f'(expected {self.expected_state_publishers}); robot state may be faked',
                now, 'robot LAN', critical=True)
        return incidents

    def _check_untrusted_publishers(self, now):
        if not self.allowed_publishers:
            return []
        incidents = []
        for info in self.untrusted.get_publishers_info_by_topic(self.command_topic):
            name = info.node_name
            if name in self.allowed_publishers:
                continue
            key = tuple(info.endpoint_gid)
            if key in self._seen_unauthorized and self.core.mode == fw.LOCKDOWN:
                continue
            self._seen_unauthorized.add(key)
            incidents += self.core.report_external(
                fw.UNAUTHORIZED_PUBLISHER,
                f'node "{name}" publishing on {self.command_topic} is not allowlisted',
                now, name, critical=self.unauthorized_lockdown)
        return incidents

    def _check_state_freshness(self, now):
        fresh = self.core.state_fresh(now)
        incidents = []
        if self._state_was_fresh and not fresh:
            incidents = self.core.report_external(
                fw.STATE_STALE, f'no robot {self.state_topic} for more than '
                f'{self.core.cfg.state_timeout_s}s (robot link down?)', now, 'robot')
        self._state_was_fresh = fresh
        return incidents

    def _check_nft_counters(self, now):
        """Turn increases in nftables drop counters into NETWORK_PROBE events."""
        if not self.nft_counters_file:
            return []
        try:
            counters = json.loads(Path(self.nft_counters_file).read_text())
        except (OSError, ValueError):
            return []
        incidents = []
        for name, packets in counters.items():
            delta = packets - self._nft_last.get(name, packets)
            self._nft_last[name] = packets
            if delta > 0:
                incidents += self.core.report_external(
                    fw.NETWORK_PROBE, f'{delta} packet(s) blocked by nftables rule "{name}"',
                    now, name)
        return incidents

    def _publish_status(self, status):
        status['domains'] = {'untrusted': self.domains[0], 'trusted': self.domains[1]}
        status['time'] = self.now()
        status['implementation'] = 'python'
        status['secure'] = self.secure
        status['limits'] = {n: [lim.position_min, lim.position_max]
                            for n, lim in self.core.cfg.limits.items()
                            if n in self.core.cfg.joint_names}
        self.status_pub.publish(String(data=json.dumps(status)))
        level = 'ERROR' if status['mode'] == fw.LOCKDOWN else 'OK'
        message = status['lockdown_reason'] if level == 'ERROR' else 'armed, forwarding'
        top = DiagnosticStatus(
            level=LEVELS[level], name='robot_firewall: state', message=message,
            hardware_id=self.hardware_id,
            values=key_values(mode=status['mode'], forwarded=status['forwarded'],
                              clamped=status['clamped'], dropped=status['dropped'],
                              input_rate_hz=status['input_rate_hz'],
                              robot_state_fresh=status['robot_state_fresh'],
                              **{f'count.{k}': v for k, v in status['counters'].items()}))
        array = DiagnosticArray(status=[top])
        array.header.stamp = self.untrusted.get_clock().now().to_msg()
        self.diag_pub.publish(array)

    def destroy(self):
        self.trusted.destroy_node()
        self.untrusted.destroy_node()


def parse_args(argv):
    parser = argparse.ArgumentParser(prog='firewall_node', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--untrusted-domain', type=int,
                        default=int(os.environ.get('FIREWALL_UNTRUSTED_DOMAIN', 10)))
    parser.add_argument('--trusted-domain', type=int,
                        default=int(os.environ.get('FIREWALL_TRUSTED_DOMAIN', 20)))
    parser.add_argument('--enclave', default=os.environ.get('FIREWALL_ENCLAVE', ''),
                        help='SROS2 enclave for the untrusted side')
    parser.add_argument('--trusted-enclave', default='',
                        help='SROS2 enclave for the robot side (default: unsecured)')
    return parser.parse_args(remove_ros_args(argv)[1:])


def main(args=None):
    argv = sys.argv if args is None else args
    opts = parse_args(argv)
    if opts.untrusted_domain == opts.trusted_domain:
        sys.exit('untrusted and trusted domains must differ')

    # ROS args (params file, remaps) configure the gateway node on the trusted
    # side; the untrusted side only ever gets its enclave.
    trusted_ctx = init_context(opts.trusted_domain, opts.trusted_enclave, argv)
    untrusted_ctx = init_context(opts.untrusted_domain, opts.enclave, ['firewall_node'])

    firewall = RobotFirewall(untrusted_ctx, trusted_ctx,
                             opts.untrusted_domain, opts.trusted_domain, bool(opts.enclave))
    executors = []
    for node, ctx in ((firewall.trusted, trusted_ctx), (firewall.untrusted, untrusted_ctx)):
        executor = SingleThreadedExecutor(context=ctx)
        executor.add_node(node)
        executors.append(executor)
    worker = threading.Thread(target=executors[0].spin, daemon=True)
    worker.start()
    sd_notify('READY=1')
    try:
        executors[1].spin()
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        for executor in executors:
            executor.shutdown()
        firewall.destroy()
        for ctx in (untrusted_ctx, trusted_ctx):
            if ctx.ok():
                rclpy.shutdown(context=ctx)


if __name__ == '__main__':
    main()
