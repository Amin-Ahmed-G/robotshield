"""
Application-layer rule engine for the robot command firewall.

Every joint command coming from the untrusted network is run through
`CommandFirewall.inspect()`, which returns whether to forward it (possibly
clamped) or drop it, plus any incidents to report. Repeated incidents
escalate to LOCKDOWN, where all input is dropped and the robot is held at its
last safe pose until an operator re-arms.

Pure Python (no rclpy) so every rule is unit testable.
Part of ros2_monitor_suite.
"""

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
import math
from typing import Dict, List, Optional, Tuple

from monitor_py.checks import FIELDS, JointLimits
from monitor_py.rate_tracker import RateTracker, TokenBucket

# Firewall modes
ARMED = 'ARMED'
LOCKDOWN = 'LOCKDOWN'

# Verdict actions
FORWARDED = 'FORWARDED'
CLAMPED = 'CLAMPED'
DROPPED = 'DROPPED'
ALERTED = 'ALERTED'

# Attack / incident types
MALFORMED = 'MALFORMED'
INVALID_VALUE = 'INVALID_VALUE'
LIMIT_VIOLATION = 'LIMIT_VIOLATION'
STEP_JUMP = 'STEP_JUMP'
FLOOD = 'FLOOD'
REPLAY = 'REPLAY'
UNAUTHORIZED_PUBLISHER = 'UNAUTHORIZED_PUBLISHER'
ROGUE_DEVICE = 'ROGUE_DEVICE_ON_ROBOT_LAN'
STATE_GUARD = 'STATE_GUARD'
STATE_STALE = 'STATE_STALE'
NETWORK_PROBE = 'NETWORK_PROBE'
BLOCKED_IN_LOCKDOWN = 'BLOCKED_IN_LOCKDOWN'
LOCKDOWN_ENTERED = 'LOCKDOWN'

CRITICAL = {ROGUE_DEVICE, STATE_GUARD, LOCKDOWN_ENTERED}


@dataclass
class Command:
    """Transport-independent joint command (maps to sensor_msgs/JointState)."""

    names: List[str]
    position: List[float]
    velocity: List[float] = field(default_factory=list)
    effort: List[float] = field(default_factory=list)
    stamp: Optional[float] = None
    source: str = ''

    def values(self, fld: str) -> List[float]:
        return getattr(self, fld)


@dataclass
class Incident:
    """One reportable security/safety event (possibly aggregating many msgs)."""

    time: float
    attack: str
    severity: str
    action: str
    count: int
    detail: str
    source: str = ''
    mode: str = ARMED

    def summary(self) -> str:
        text = f'{self.attack}: {self.detail}'
        if self.source:
            text += f' (source: {self.source})'
        if self.action in (DROPPED, CLAMPED):
            text += f'; {self.count} msg(s) {self.action.lower()}'
        if self.mode == LOCKDOWN:
            text += ' -> LOCKDOWN, robot holding last safe pose'
        return text

    def to_dict(self) -> dict:
        data = asdict(self)
        data['summary'] = self.summary()
        return data


@dataclass
class Verdict:
    action: str
    command: Optional[Command]
    incidents: List[Incident]


@dataclass
class FirewallConfig:
    joint_names: List[str]
    limits: Dict[str, JointLimits]
    max_step: float = 0.2
    max_rate_hz: float = 50.0
    burst: float = 10.0
    max_age_s: float = 0.5
    max_future_s: float = 0.2
    require_stamp: bool = True
    limit_action: str = 'clamp'
    lockdown_threshold: int = 20
    lockdown_window_s: float = 2.0
    report_interval_s: float = 1.0
    state_margin: float = 0.05
    state_timeout_s: float = 0.5
    start_locked: bool = True


class CommandFirewall:
    """Stateful rule engine; not thread safe (callers hold a lock)."""

    def __init__(self, config: FirewallConfig):
        self.cfg = config
        for name in config.joint_names:
            config.limits.setdefault(name, JointLimits())
        self.mode = LOCKDOWN if config.start_locked else ARMED
        self.lockdown_reason = 'startup: waiting for operator re-arm' \
            if config.start_locked else ''
        self.lockdown_since: Optional[float] = None
        self.bucket = TokenBucket(config.max_rate_hz, config.burst)
        self.input_rate = RateTracker(window_s=1.0)
        self.counters: Dict[str, int] = defaultdict(int)
        self.forwarded = 0
        self.clamped = 0
        self.dropped = 0
        self.last_accepted: Optional[List[float]] = None
        self.last_stamp: Optional[float] = None
        self.state: Optional[Dict[str, float]] = None
        self.state_time: Optional[float] = None
        self._recent = deque()
        self._pending: Dict[str, int] = defaultdict(int)
        self._pending_meta: Dict[str, Tuple[str, str, str]] = {}
        self._last_report: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Incident bookkeeping
    # ------------------------------------------------------------------
    def _severity(self, attack: str) -> str:
        return 'ERROR' if attack in CRITICAL else 'WARN'

    def _record(self, attack: str, detail: str, action: str, now: float,
                source: str = '', escalate: bool = True,
                critical: bool = False, report: bool = True) -> List[Incident]:
        """Count an event; return incidents that are due for reporting."""
        incidents = []
        self.counters[attack] += 1
        if not report:
            return incidents
        self._pending[attack] += 1
        self._pending_meta[attack] = (detail, action, source)

        last = self._last_report.get(attack)
        if last is None or now - last >= self.cfg.report_interval_s:
            incidents.append(self._emit(attack, now))

        if self.mode == ARMED:
            if critical:
                incidents.append(self._enter_lockdown(f'{attack}: {detail}', now))
            elif escalate:
                self._recent.append(now)
                while self._recent and now - self._recent[0] > self.cfg.lockdown_window_s:
                    self._recent.popleft()
                if len(self._recent) >= self.cfg.lockdown_threshold:
                    incidents.append(self._enter_lockdown(
                        f'{len(self._recent)} incidents in '
                        f'{self.cfg.lockdown_window_s:.1f}s (latest: {attack})', now))
        return incidents

    def _emit(self, attack: str, now: float) -> Incident:
        detail, action, source = self._pending_meta[attack]
        count = self._pending.pop(attack)
        self._last_report[attack] = now
        return Incident(now, attack, self._severity(attack), action, count,
                        detail, source, self.mode)

    def flush(self, now: float) -> List[Incident]:
        """Report aggregated counts that were held back by rate limiting."""
        due = [a for a, n in self._pending.items()
               if n and now - self._last_report.get(a, -math.inf)
               >= self.cfg.report_interval_s]
        return [self._emit(a, now) for a in due]

    def _enter_lockdown(self, reason: str, now: float) -> Incident:
        self.mode = LOCKDOWN
        self.lockdown_reason = reason
        self.lockdown_since = now
        self.counters[LOCKDOWN_ENTERED] += 1
        return Incident(now, LOCKDOWN_ENTERED, 'ERROR', ALERTED, 1, reason,
                        '', LOCKDOWN)

    def _drop(self, attack: str, detail: str, now: float, source: str,
              escalate: bool = True, report: bool = True) -> Verdict:
        self.dropped += 1
        return Verdict(DROPPED, None, self._record(
            attack, detail, DROPPED, now, source, escalate, report=report))

    # ------------------------------------------------------------------
    # Command inspection
    # ------------------------------------------------------------------
    def inspect(self, cmd: Command, now: float) -> Verdict:
        self.input_rate.tick(now)
        src = cmd.source

        if self.mode == LOCKDOWN:
            # Counted in status only; the LOCKDOWN incident already explains why.
            return self._drop(BLOCKED_IN_LOCKDOWN, 'input blocked during lockdown',
                              now, src, escalate=False, report=False)
        if not self.bucket.allow(now):
            return self._drop(FLOOD,
                              f'rate limit exceeded ({self.cfg.max_rate_hz:.0f} Hz sustained, '
                              f'burst {self.cfg.burst:.0f}); measured '
                              f'{self.input_rate.rate_hz(now):.0f} msgs in the last 1 s', now, src)

        problem = self._schema_problem(cmd)
        if problem:
            return self._drop(MALFORMED, problem, now, src)

        for fld in FIELDS:
            for name, value in zip(cmd.names, cmd.values(fld)):
                if not math.isfinite(value):
                    return self._drop(INVALID_VALUE,
                                      f'{name}.{fld} = {value}', now, src)

        problem = self._replay_problem(cmd, now)
        if problem:
            return self._drop(REPLAY, problem, now, src)

        ordered = self._reorder(cmd)

        reference = self._reference_positions()
        if reference is not None:
            for name, new, old in zip(ordered.names, ordered.position, reference):
                if abs(new - old) > self.cfg.max_step:
                    return self._drop(STEP_JUMP,
                                      f'{name} jumped {new - old:+.3f} rad '
                                      f'(max step {self.cfg.max_step} rad)',
                                      now, src)

        violations = []
        for fld in FIELDS:
            values = ordered.values(fld)
            for i, name in enumerate(ordered.names[:len(values)]):
                limits = self.cfg.limits[name]
                if limits.violates(fld, values[i]):
                    violations.append(f'{name}.{fld}={values[i]:.3f}')
                    values[i] = limits.clamp(fld, values[i])

        incidents = []
        action = FORWARDED
        if violations:
            detail = 'outside limits: ' + ', '.join(violations)
            if self.cfg.limit_action == 'drop':
                return self._drop(LIMIT_VIOLATION, detail, now, src)
            # A clamped command is safe to forward, so it does not escalate.
            action = CLAMPED
            self.clamped += 1
            incidents = self._record(LIMIT_VIOLATION, detail, CLAMPED, now, src,
                                     escalate=False)

        self.forwarded += 1
        self.last_accepted = list(ordered.position)
        if cmd.stamp is not None:
            self.last_stamp = cmd.stamp
        return Verdict(action, ordered, incidents)

    def _schema_problem(self, cmd: Command) -> str:
        expected = set(self.cfg.joint_names)
        if len(set(cmd.names)) != len(cmd.names):
            return 'duplicate joint names'
        unknown = [n for n in cmd.names if n not in expected]
        if unknown:
            return f'unknown joint(s): {", ".join(unknown)}'
        missing = [n for n in self.cfg.joint_names if n not in cmd.names]
        if missing:
            return f'missing joint(s): {", ".join(missing)}'
        if len(cmd.position) != len(cmd.names):
            return (f'{len(cmd.names)} names but {len(cmd.position)} positions')
        for fld in ('velocity', 'effort'):
            n = len(cmd.values(fld))
            if n not in (0, len(cmd.names)):
                return f'{len(cmd.names)} names but {n} {fld} values'
        if self.cfg.require_stamp and not cmd.stamp:
            return 'missing header stamp'
        return ''

    def _replay_problem(self, cmd: Command, now: float) -> str:
        if not cmd.stamp:
            return ''
        age = now - cmd.stamp
        if age > self.cfg.max_age_s:
            return f'stale command, stamped {age:.2f}s ago (max {self.cfg.max_age_s}s)'
        if -age > self.cfg.max_future_s:
            return f'command stamped {-age:.2f}s in the future'
        if self.last_stamp is not None and cmd.stamp <= self.last_stamp:
            return 'timestamp not newer than last accepted command'
        return ''

    def _reorder(self, cmd: Command) -> Command:
        index = {n: i for i, n in enumerate(cmd.names)}

        def pick(values):
            return [values[index[n]] for n in self.cfg.joint_names] if values else []

        return Command(list(self.cfg.joint_names), pick(cmd.position),
                       pick(cmd.velocity), pick(cmd.effort), cmd.stamp, cmd.source)

    def _reference_positions(self) -> Optional[List[float]]:
        if self.last_accepted is not None:
            return self.last_accepted
        if self.state is not None and all(n in self.state for n in self.cfg.joint_names):
            return [self.state[n] for n in self.cfg.joint_names]
        return None

    # ------------------------------------------------------------------
    # Robot state, external alerts, lockdown control
    # ------------------------------------------------------------------
    def observe_state(self, names: List[str], positions: List[float],
                      now: float) -> List[Incident]:
        """Feed robot joint_states; lock down if the robot is out of bounds."""
        self.state = dict(zip(names, positions))
        self.state_time = now
        bad = []
        for name, pos in self.state.items():
            limits = self.cfg.limits.get(name)
            if limits is None:
                continue
            if not math.isfinite(pos) or \
                    pos < limits.position_min - self.cfg.state_margin or \
                    pos > limits.position_max + self.cfg.state_margin:
                bad.append(f'{name}={pos:.3f}')
        if not bad:
            return []
        return self._record(STATE_GUARD, 'robot state outside limits: ' + ', '.join(bad),
                            ALERTED, now, 'robot', critical=True)

    def state_fresh(self, now: float) -> bool:
        return self.state_time is not None and \
            now - self.state_time <= self.cfg.state_timeout_s

    def report_external(self, attack: str, detail: str, now: float,
                        source: str = '', critical: bool = False) -> List[Incident]:
        """Record an alert detected outside inspect() (graph watch, nftables)."""
        return self._record(attack, detail, ALERTED, now, source,
                            escalate=not critical, critical=critical)

    def lockdown(self, reason: str, now: float) -> List[Incident]:
        if self.mode == LOCKDOWN:
            return []
        return [self._enter_lockdown(reason, now)]

    def rearm(self, now: float) -> Tuple[bool, str]:
        if self.mode == ARMED:
            return True, 'already armed'
        if not self.state_fresh(now):
            return False, 'refused: no fresh robot joint_states'
        missing = [n for n in self.cfg.joint_names if n not in self.state]
        if missing:
            return False, f'refused: robot state missing {", ".join(missing)}'
        for name in self.cfg.joint_names:
            if self.cfg.limits[name].violates('position', self.state[name]):
                return False, f'refused: {name} at {self.state[name]:.3f} is outside limits'
        self.mode = ARMED
        self.lockdown_reason = ''
        self.lockdown_since = None
        self.last_accepted = [self.state[n] for n in self.cfg.joint_names]
        self.last_stamp = None
        self._recent.clear()
        self.bucket.reset()
        return True, 'armed: forwarding commands from current robot pose'

    def hold_command(self, now: float) -> Optional[Command]:
        """Command that keeps the robot where it is (used during LOCKDOWN)."""
        pos = self._reference_positions()
        if pos is None:
            return None
        zeros = [0.0] * len(pos)
        return Command(list(self.cfg.joint_names), list(pos), zeros, [], now, 'firewall')

    def reset_counters(self):
        self.counters.clear()
        self.forwarded = self.clamped = self.dropped = 0
        self._pending.clear()
        self._last_report.clear()

    def status(self, now: float) -> dict:
        return {
            'mode': self.mode,
            'lockdown_reason': self.lockdown_reason,
            'lockdown_since': self.lockdown_since,
            'forwarded': self.forwarded,
            'clamped': self.clamped,
            'dropped': self.dropped,
            'input_rate_hz': round(self.input_rate.rate_hz(now), 1),
            'robot_state_fresh': self.state_fresh(now),
            'counters': dict(self.counters),
        }
