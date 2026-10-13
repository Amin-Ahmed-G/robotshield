import math

from monitor_py.attacks import apply_attack, ATTACK_MODES, CommandMsg, sine_targets, step_toward
import pytest


def base():
    return CommandMsg(['a', 'b'], [0.1, 0.2], [0.0, 0.0], 100.0)


def test_sine_targets_bounded():
    vals = sine_targets(1.3, 4, 0.8, 0.2)
    assert len(vals) == 4 and all(abs(v) <= 0.8 for v in vals)


def test_step_toward_limits_delta():
    assert step_toward([0.0, 1.0], [5.0, 0.95], 0.1) == pytest.approx([0.1, 0.95])


def test_none_is_passthrough_and_does_not_mutate():
    msg = base()
    out = apply_attack('none', msg)
    assert out == [msg] and out[0] is not msg


@pytest.mark.parametrize('mode', ATTACK_MODES)
def test_every_mode_produces_messages(mode):
    assert apply_attack(mode, base())


def test_specific_transforms():
    assert apply_attack('spike', base(), 1, 3.0)[0].position[1] == pytest.approx(3.2)
    assert math.isnan(apply_attack('nan', base())[0].position[0])
    assert 'joint_99' in apply_attack('unknown_joint', base())[0].names
    assert apply_attack('replay', base())[0].stamp == 95.0
    assert apply_attack('overspeed', base(), 0, 3.0)[0].velocity[0] == 6.0
    flood = apply_attack('flood', base(), flood_copies=10)
    stamps = [m.stamp for m in flood]
    assert len(flood) == 10 and stamps == sorted(set(stamps))


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        apply_attack('bogus', base())
