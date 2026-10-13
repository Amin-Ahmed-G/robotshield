import math

from monitor_py.rate_tracker import RateTracker, TokenBucket
import pytest


def test_steady_rate():
    r = RateTracker(window_s=1.0)
    for i in range(50):
        r.tick(i * 0.1)
    assert r.rate_hz(4.9) == pytest.approx(10.0, abs=1.0)


def test_age_and_staleness():
    r = RateTracker()
    assert r.age_s(0.0) == math.inf
    r.tick(1.0)
    assert r.age_s(3.5) == pytest.approx(2.5)


def test_window_eviction():
    r = RateTracker(window_s=1.0)
    for i in range(10):
        r.tick(i * 0.1)
    assert r.rate_hz(5.0) == 0.0
    assert r.total == 10


def test_token_bucket_burst_then_rate():
    b = TokenBucket(rate=10.0, burst=5)
    assert sum(b.allow(0.0) for _ in range(20)) == 5
    assert b.allow(0.05) is False
    assert b.allow(0.2) is True  # refilled ~1.5 tokens


def test_token_bucket_sustained_legit_rate_passes():
    b = TokenBucket(rate=50.0, burst=10)
    assert all(b.allow(i * 0.05) for i in range(200))  # 20 Hz
