"""
Per-joint limit checking with debounce and hysteresis.

Pure Python (no rclpy) so the logic can be unit tested without a running ROS graph.
Part of ros2_monitor_suite.
"""

from dataclasses import dataclass
import math
from typing import Dict, List, Optional

OK = 'OK'
FAULT = 'FAULT'
INVALID = 'INVALID'

FIELDS = ('position', 'velocity', 'effort')

_SEVERITY = {OK: 0, FAULT: 1, INVALID: 2}


@dataclass
class JointLimits:
    """Allowed ranges for one joint. Infinite bounds disable a check."""

    position_min: float = -math.inf
    position_max: float = math.inf
    velocity: float = math.inf
    effort: float = math.inf

    def bounds(self, field: str):
        """Return (low, high) for a field; velocity/effort are symmetric."""
        if field == 'position':
            return self.position_min, self.position_max
        limit = abs(getattr(self, field))
        return -limit, limit

    def clamp(self, field: str, value: float) -> float:
        low, high = self.bounds(field)
        return min(max(value, low), high)

    def violates(self, field: str, value: float) -> bool:
        low, high = self.bounds(field)
        return value < low or value > high


@dataclass
class LimitEvent:
    """A state transition of one checked quantity."""

    joint: str
    field: str
    old_state: str
    new_state: str
    value: float
    low: float
    high: float

    def describe(self) -> str:
        if self.new_state == INVALID:
            return f'[{self.joint}] {self.field} is not finite ({self.value})'
        if self.new_state == FAULT:
            return (f'[{self.joint}] {self.field} {self.value:.3f} outside '
                    f'[{self.low:.3f}, {self.high:.3f}]')
        return f'[{self.joint}] {self.field} back within limits ({self.value:.3f})'


def _margin(bound: float, ratio: float) -> float:
    return abs(bound) * ratio if math.isfinite(bound) else 0.0


class LimitChecker:
    """
    Tracks one quantity against a [low, high] range.

    Enters FAULT after `debounce_count` consecutive out-of-range samples and
    only clears once the value is back inside the range shrunk by
    `hysteresis_ratio`, so a signal hovering at the limit does not flap.
    Non-finite values go straight to INVALID. `update()` returns an event only
    when the state changes.
    """

    def __init__(self, joint: str, field: str, low: float, high: float,
                 hysteresis_ratio: float = 0.05, debounce_count: int = 3):
        self.joint = joint
        self.field = field
        self.low = low
        self.high = high
        self.hysteresis_ratio = hysteresis_ratio
        self.debounce_count = max(1, int(debounce_count))
        self.reset()

    def reset(self):
        self.state = OK
        self.breach_count = 0
        self.peak = 0.0
        self.last_value: Optional[float] = None
        self._consecutive = 0

    def _inside_clear_band(self, value: float) -> bool:
        low = self.low + _margin(self.low, self.hysteresis_ratio)
        high = self.high - _margin(self.high, self.hysteresis_ratio)
        return low <= value <= high

    def update(self, value: float) -> Optional[LimitEvent]:
        self.last_value = value
        old = self.state

        if not math.isfinite(value):
            self._consecutive = 0
            if old != INVALID:
                self.breach_count += 1
            self.state = INVALID
        else:
            self.peak = max(self.peak, abs(value))
            outside = value < self.low or value > self.high
            if outside:
                self._consecutive += 1
                if old != FAULT and self._consecutive >= self.debounce_count:
                    self.state = FAULT
                    self.breach_count += 1
            else:
                self._consecutive = 0
                if old == INVALID or (old == FAULT and self._inside_clear_band(value)):
                    self.state = OK

        if self.state == old:
            return None
        return LimitEvent(self.joint, self.field, old, self.state, value,
                          self.low, self.high)


class JointHealth:
    """Position, velocity and effort checkers for one joint."""

    def __init__(self, name: str, limits: JointLimits,
                 hysteresis_ratio: float = 0.05, debounce_count: int = 3):
        self.name = name
        self.limits = limits
        self.checkers: Dict[str, LimitChecker] = {}
        for field in FIELDS:
            low, high = limits.bounds(field)
            self.checkers[field] = LimitChecker(
                name, field, low, high, hysteresis_ratio, debounce_count)

    def update(self, position=None, velocity=None, effort=None) -> List[LimitEvent]:
        events = []
        for field, value in zip(FIELDS, (position, velocity, effort)):
            if value is None:
                continue
            event = self.checkers[field].update(value)
            if event is not None:
                events.append(event)
        return events

    def worst_state(self) -> str:
        return max((c.state for c in self.checkers.values()),
                   key=lambda s: _SEVERITY[s])

    @property
    def breach_count(self) -> int:
        return sum(c.breach_count for c in self.checkers.values())

    def reset(self):
        for checker in self.checkers.values():
            checker.reset()
