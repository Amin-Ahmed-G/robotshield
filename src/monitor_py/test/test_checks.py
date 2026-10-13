import math

from monitor_py.checks import FAULT, INVALID, JointHealth, JointLimits, LimitChecker, OK


def make(debounce=3, hyst=0.1):
    return LimitChecker('j', 'position', -1.0, 1.0, hyst, debounce)


def test_within_limits_no_event():
    c = make()
    assert all(c.update(v) is None for v in (0.0, 0.5, -0.99, 1.0))
    assert c.state == OK


def test_debounce_requires_consecutive_breaches():
    c = make(debounce=3)
    assert c.update(1.5) is None
    assert c.update(1.5) is None
    assert c.update(0.0) is None  # streak broken
    assert c.update(1.5) is None
    assert c.update(1.5) is None
    event = c.update(1.5)
    assert event is not None and event.new_state == FAULT
    assert c.breach_count == 1


def test_hysteresis_holds_fault_until_clear_band():
    c = make(debounce=1, hyst=0.1)
    assert c.update(1.2).new_state == FAULT
    assert c.update(0.95) is None  # inside limit but not inside 0.9 band
    assert c.state == FAULT
    event = c.update(0.85)
    assert event.new_state == OK and event.old_state == FAULT


def test_nan_is_invalid_immediately():
    c = make(debounce=5)
    assert c.update(math.nan).new_state == INVALID
    assert c.update(0.0).new_state == OK


def test_infinite_limits_disable_check():
    c = LimitChecker('j', 'effort', -math.inf, math.inf, 0.1, 1)
    assert c.update(1e9) is None
    assert c.update(math.inf).new_state == INVALID  # non-finite still flagged


def test_reset_and_peak():
    c = make(debounce=1)
    c.update(1.7)
    assert c.peak == 1.7 and c.state == FAULT
    c.reset()
    assert c.state == OK and c.breach_count == 0 and c.peak == 0.0


def test_joint_limits_clamp_and_bounds():
    lim = JointLimits(position_min=-0.5, position_max=2.0, velocity=1.0)
    assert lim.clamp('position', 3.0) == 2.0
    assert lim.clamp('position', -1.0) == -0.5
    assert lim.clamp('velocity', -4.0) == -1.0
    assert lim.violates('velocity', 1.1) and not lim.violates('effort', 1e6)


def test_joint_health_worst_state():
    h = JointHealth('j', JointLimits(-1, 1, 1, math.inf), 0.05, 1)
    events = h.update(position=0.0, velocity=2.0, effort=5.0)
    assert [e.field for e in events] == ['velocity']
    assert h.worst_state() == FAULT
    h.update(position=math.nan)
    assert h.worst_state() == INVALID
    assert h.breach_count == 2
