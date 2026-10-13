"""
Pure attack transforms and a legitimate commander trajectory.

Used by attack_sim_node: a legitimate commander that stays
close to the robot's current pose, and transforms that turn a legitimate
command into a specific attack. Kept free of rclpy for unit testing.
Part of ros2_monitor_suite.
"""

from dataclasses import dataclass, field, replace
import math
from typing import List

ATTACK_MODES = (
    'none',           # legitimate traffic only
    'overreach',      # commander aims past the position limits -> CLAMPED
    'overspeed',      # velocity far above limit -> CLAMPED
    'spike',          # sudden position jump -> STEP_JUMP
    'nan',            # NaN position -> INVALID_VALUE
    'flood',          # many copies per tick -> FLOOD, then LOCKDOWN
    'unknown_joint',  # extra joint name -> MALFORMED
    'replay',         # old timestamp -> REPLAY
    'spoof',          # second, non-allowlisted publisher -> UNAUTHORIZED_PUBLISHER
)


@dataclass
class CommandMsg:
    names: List[str]
    position: List[float]
    velocity: List[float] = field(default_factory=list)
    stamp: float = 0.0


def sine_targets(t: float, n_joints: int, amplitude: float, freq_hz: float) -> List[float]:
    """Smooth reference trajectory with a phase offset per joint."""
    return [amplitude * math.sin(2 * math.pi * freq_hz * t + i * math.pi / 4)
            for i in range(n_joints)]


def step_toward(current: List[float], target: List[float], max_delta: float) -> List[float]:
    """Move each joint from current toward target by at most max_delta."""
    return [c + max(-max_delta, min(max_delta, t - c)) for c, t in zip(current, target)]


def apply_attack(mode: str, msg: CommandMsg, joint_index: int = 0,
                 magnitude: float = 3.0, flood_copies: int = 40) -> List[CommandMsg]:
    """Return the message(s) to publish this tick for the given attack mode."""
    if mode not in ATTACK_MODES:
        raise ValueError(f'unknown attack mode {mode!r}')
    j = joint_index % len(msg.names)
    out = replace(msg, names=list(msg.names), position=list(msg.position),
                  velocity=list(msg.velocity))

    if mode == 'overspeed':
        if not out.velocity:
            out.velocity = [0.0] * len(out.names)
        out.velocity[j] = magnitude * 2
    elif mode == 'spike':
        out.position[j] += magnitude
    elif mode == 'nan':
        out.position[j] = math.nan
    elif mode == 'unknown_joint':
        out.names.append('joint_99')
        out.position.append(0.0)
        if out.velocity:
            out.velocity.append(0.0)
    elif mode == 'replay':
        out.stamp = msg.stamp - 5.0
    elif mode == 'flood':
        return [replace(out, stamp=msg.stamp + k * 1e-6) for k in range(flood_copies)]
    return [out]
