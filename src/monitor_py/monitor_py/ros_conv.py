"""
Conversions between ROS messages and firewall core types.

Also holds the shared limit-parameter helpers.
Part of ros2_monitor_suite.
"""

import math

from builtin_interfaces.msg import Time
from diagnostic_msgs.msg import DiagnosticStatus, KeyValue
from monitor_py.checks import JointLimits
from monitor_py.firewall_rules import Command, Incident
from sensor_msgs.msg import JointState

LEVELS = {'OK': DiagnosticStatus.OK, 'WARN': DiagnosticStatus.WARN,
          'ERROR': DiagnosticStatus.ERROR, 'STALE': DiagnosticStatus.STALE}


def stamp_to_sec(stamp: Time) -> float:
    return stamp.sec + stamp.nanosec * 1e-9


def sec_to_stamp(t: float) -> Time:
    sec = int(math.floor(t))
    return Time(sec=sec, nanosec=int((t - sec) * 1e9))


def joint_state_to_command(msg: JointState, source: str = '') -> Command:
    return Command(list(msg.name), list(msg.position), list(msg.velocity),
                   list(msg.effort), stamp_to_sec(msg.header.stamp), source)


def command_to_joint_state(cmd: Command) -> JointState:
    msg = JointState()
    msg.header.stamp = sec_to_stamp(cmd.stamp or 0.0)
    msg.name = list(cmd.names)
    msg.position = [float(v) for v in cmd.position]
    msg.velocity = [float(v) for v in cmd.velocity]
    msg.effort = [float(v) for v in cmd.effort]
    return msg


def key_values(**kwargs) -> list:
    return [KeyValue(key=k, value=str(v)) for k, v in kwargs.items()]


def incident_to_status(incident: Incident, hardware_id: str) -> DiagnosticStatus:
    tag = incident.mitre()
    mitre = {} if tag is None else dict(zip(
        ('mitre_technique_id', 'mitre_technique', 'mitre_tactic'), tag))
    return DiagnosticStatus(
        level=LEVELS.get(incident.severity, DiagnosticStatus.WARN),
        name=f'robot_firewall: {incident.attack}',
        message=incident.summary(),
        hardware_id=hardware_id,
        values=key_values(attack=incident.attack, action=incident.action,
                          count=incident.count, source=incident.source,
                          mode=incident.mode, time=f'{incident.time:.3f}',
                          detail=incident.detail, **mitre))


def declare_limit_defaults(node) -> dict:
    """
    Declare the global limit parameters shared by all joints.

    Global defaults: position_min, position_max, velocity_limit, effort_limit.
    Per-joint overrides (params file): limits.<joint>.position_min etc.
    Use a negative value for velocity/effort limits to disable them.
    """
    return {
        'position_min': node.declare_parameter('position_min', -1.0).value,
        'position_max': node.declare_parameter('position_max', 1.0).value,
        'velocity': node.declare_parameter('velocity_limit', 1.0).value,
        'effort': node.declare_parameter('effort_limit', -1.0).value,
    }


def declare_joint_limits(node, joint: str, defaults: dict) -> JointLimits:
    """Declare limits.<joint>.* (falling back to defaults) and build JointLimits."""
    values = {key: node.declare_parameter(f'limits.{joint}.{key}', default).value
              for key, default in defaults.items()}
    for key in ('velocity', 'effort'):
        if values[key] < 0:
            values[key] = math.inf
    return JointLimits(float(values['position_min']), float(values['position_max']),
                       float(values['velocity']), float(values['effort']))


def declare_limit_params(node, joint_names) -> dict:
    defaults = declare_limit_defaults(node)
    return {joint: declare_joint_limits(node, joint, defaults) for joint in joint_names}
