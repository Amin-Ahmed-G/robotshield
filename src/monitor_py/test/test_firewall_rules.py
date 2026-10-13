import math

from monitor_py import firewall_rules as fw
from monitor_py.checks import JointLimits
from monitor_py.firewall_rules import Command, CommandFirewall, FirewallConfig
import pytest

NAMES = ['j1', 'j2']


def make(**kw):
    cfg = {'joint_names': NAMES,
           'limits': {n: JointLimits(-1.0, 1.0, 1.0, 10.0) for n in NAMES},
           'max_step': 0.2, 'max_rate_hz': 50, 'burst': 10, 'max_age_s': 0.5,
           'lockdown_threshold': 5, 'lockdown_window_s': 2.0,
           'report_interval_s': 1.0, 'start_locked': False}
    cfg.update(kw)
    return CommandFirewall(FirewallConfig(**cfg))


def cmd(pos, t, names=None, vel=None, stamp=None):
    return Command(list(names or NAMES), list(pos), list(vel or []), [],
                   t if stamp is None else stamp, 'laptop')


def test_valid_command_forwarded():
    f = make()
    v = f.inspect(cmd([0.1, 0.1], 10.0), 10.0)
    assert v.action == fw.FORWARDED and v.command.position == [0.1, 0.1]
    assert v.incidents == [] and f.forwarded == 1


def test_reorders_to_configured_joint_order():
    f = make()
    v = f.inspect(cmd([0.2, 0.1], 10.0, names=['j2', 'j1']), 10.0)
    assert v.command.names == NAMES and v.command.position == [0.1, 0.2]


@pytest.mark.parametrize('names,pos,why', [
    (['j1', 'j2', 'j9'], [0, 0, 0], 'unknown'),
    (['j1'], [0], 'missing'),
    (['j1', 'j1'], [0, 0], 'duplicate'),
    (['j1', 'j2'], [0], 'positions'),
])
def test_malformed_dropped(names, pos, why):
    v = make().inspect(cmd(pos, 1.0, names=names), 1.0)
    assert v.action == fw.DROPPED
    assert v.incidents[0].attack == fw.MALFORMED and why in v.incidents[0].detail


def test_missing_stamp_is_malformed():
    v = make().inspect(cmd([0, 0], 1.0, stamp=0.0), 1.0)
    assert v.incidents[0].attack == fw.MALFORMED


def test_nan_and_inf_dropped():
    f = make()
    assert f.inspect(cmd([math.nan, 0], 1.0), 1.0).incidents[0].attack == fw.INVALID_VALUE
    assert f.inspect(cmd([0, 0], 1.1, vel=[math.inf, 0]), 1.1).action == fw.DROPPED


def test_position_clamped_by_default():
    f = make(max_step=10)
    v = f.inspect(cmd([1.5, -3.0], 1.0), 1.0)
    assert v.action == fw.CLAMPED and v.command.position == [1.0, -1.0]
    assert v.incidents[0].attack == fw.LIMIT_VIOLATION


def test_velocity_clamped():
    v = make().inspect(cmd([0, 0], 1.0, vel=[5.0, -0.5]), 1.0)
    assert v.action == fw.CLAMPED and v.command.velocity == [1.0, -0.5]


def test_clamps_do_not_escalate_to_lockdown():
    f = make(lockdown_threshold=3)
    for i in range(10):
        v = f.inspect(cmd([0, 0], 1.0 + i * 0.05, vel=[5.0, 0]), 1.0 + i * 0.05)
        assert v.action == fw.CLAMPED
    assert f.mode == fw.ARMED and f.clamped == 10


def test_limit_action_drop():
    v = make(limit_action='drop', max_step=10).inspect(cmd([1.5, 0], 1.0), 1.0)
    assert v.action == fw.DROPPED


def test_step_jump_dropped_against_last_accepted():
    f = make()
    f.inspect(cmd([0.0, 0.0], 1.0), 1.0)
    v = f.inspect(cmd([0.5, 0.0], 1.05), 1.05)
    assert v.action == fw.DROPPED and v.incidents[0].attack == fw.STEP_JUMP
    assert f.inspect(cmd([0.15, 0.0], 1.1), 1.1).action == fw.FORWARDED


def test_step_uses_robot_state_when_no_command_yet():
    f = make()
    f.observe_state(NAMES, [0.8, 0.0], 1.0)
    assert f.inspect(cmd([0.0, 0.0], 1.0), 1.0).incidents[0].attack == fw.STEP_JUMP


def test_replay_stale_future_and_nonmonotonic():
    f = make()
    assert f.inspect(cmd([0, 0], 10.0, stamp=5.0), 10.0).incidents[0].attack == fw.REPLAY
    assert f.inspect(cmd([0, 0], 10.0, stamp=11.0), 10.0).action == fw.DROPPED
    assert f.inspect(cmd([0, 0], 10.0, stamp=10.0), 10.0).action == fw.FORWARDED
    assert f.inspect(cmd([0, 0], 10.1, stamp=9.9), 10.1).action == fw.DROPPED


def test_flood_triggers_drops_then_lockdown():
    f = make(lockdown_threshold=5)
    verdicts = [f.inspect(cmd([0, 0], 1.0, stamp=1.0 + i * 1e-6), 1.0) for i in range(30)]
    actions = [v.action for v in verdicts]
    assert actions[:10] == [fw.FORWARDED] * 10
    assert all(a == fw.DROPPED for a in actions[10:])
    attacks = [i.attack for v in verdicts for i in v.incidents]
    assert fw.FLOOD in attacks and fw.LOCKDOWN_ENTERED in attacks
    assert f.mode == fw.LOCKDOWN


def test_incident_reports_are_rate_limited_and_flushed():
    f = make(lockdown_threshold=1000)
    reports = []
    for i in range(10):
        reports += f.inspect(cmd([math.nan, 0], 1.0 + i * 0.01), 1.0 + i * 0.01).incidents
    assert len(reports) == 1 and reports[0].count == 1
    flushed = f.flush(2.5)
    assert len(flushed) == 1 and flushed[0].count == 9
    assert f.counters[fw.INVALID_VALUE] == 10


def test_lockdown_blocks_everything_and_rearm_needs_fresh_safe_state():
    f = make(start_locked=True)
    assert f.mode == fw.LOCKDOWN
    blocked = f.inspect(cmd([0, 0], 1.0), 1.0)
    assert blocked.action == fw.DROPPED and blocked.incidents == []
    assert f.counters[fw.BLOCKED_IN_LOCKDOWN] == 1
    ok, msg = f.rearm(1.0)
    assert not ok and 'no fresh' in msg
    f.observe_state(NAMES, [0.3, 0.0], 1.0)
    ok, _ = f.rearm(1.1)
    assert ok and f.mode == fw.ARMED
    assert f.inspect(cmd([0.35, 0.0], 1.2), 1.2).action == fw.FORWARDED
    assert f.inspect(cmd([0.0, 0.0], 1.3), 1.3).action == fw.DROPPED  # step vs new pose


def test_rearm_refused_when_robot_outside_limits():
    f = make(start_locked=True, state_margin=1.0)
    f.observe_state(NAMES, [1.2, 0.0], 1.0)
    ok, msg = f.rearm(1.0)
    assert not ok and 'outside limits' in msg


def test_state_guard_is_critical():
    f = make()
    incidents = f.observe_state(NAMES, [1.5, 0.0], 1.0)
    assert {i.attack for i in incidents} == {fw.STATE_GUARD, fw.LOCKDOWN_ENTERED}
    assert f.mode == fw.LOCKDOWN


def test_external_critical_alert_locks_down():
    f = make()
    incidents = f.report_external(fw.ROGUE_DEVICE, '2 publishers', 1.0, critical=True)
    assert f.mode == fw.LOCKDOWN and incidents[-1].mode == fw.LOCKDOWN
    assert 'LOCKDOWN' in incidents[-1].summary()


def test_unauthorized_publisher_alert_escalates_only_when_critical():
    f = make()
    f.report_external(fw.UNAUTHORIZED_PUBLISHER, '/evil on joint_commands', 1.0)
    assert f.mode == fw.ARMED
    f.report_external(fw.UNAUTHORIZED_PUBLISHER, '/evil on joint_commands', 1.1, critical=True)
    assert f.mode == fw.LOCKDOWN


def test_hold_command_uses_last_accepted_with_zero_velocity():
    f = make()
    assert f.hold_command(1.0) is None
    f.inspect(cmd([0.1, 0.2], 1.0), 1.0)
    hold = f.hold_command(2.0)
    assert hold.position == [0.1, 0.2] and hold.velocity == [0.0, 0.0]


def test_summary_text():
    inc = fw.Incident(1.0, fw.FLOOD, 'WARN', fw.DROPPED, 812, '850 Hz exceeds 50 Hz limit',
                      'attacker', fw.LOCKDOWN)
    text = inc.summary()
    assert text.startswith('FLOOD: 850 Hz') and '812 msg(s) dropped' in text
    assert text.endswith('robot holding last safe pose')
    assert inc.to_dict()['summary'] == text
