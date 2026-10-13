"""
Message rate tracking and token bucket rate limiting.

Time is always passed in by the caller so the logic is deterministic under test.
Part of ros2_monitor_suite.
"""

from collections import deque
import math


class RateTracker:
    """Rolling-window message rate and time since the last message."""

    def __init__(self, window_s: float = 1.0):
        self.window_s = window_s
        self._stamps = deque()
        self.total = 0
        self.last_time = None

    def tick(self, now: float):
        self._stamps.append(now)
        self.total += 1
        self.last_time = now
        self._evict(now)

    def _evict(self, now: float):
        while self._stamps and now - self._stamps[0] > self.window_s:
            self._stamps.popleft()

    def rate_hz(self, now: float) -> float:
        self._evict(now)
        return len(self._stamps) / self.window_s

    def age_s(self, now: float) -> float:
        if self.last_time is None:
            return math.inf
        return now - self.last_time

    def reset(self):
        self._stamps.clear()
        self.total = 0
        self.last_time = None


class TokenBucket:
    """Allows `rate` events per second on average with bursts up to `burst`."""

    def __init__(self, rate: float, burst: float):
        self.rate = rate
        self.burst = max(1.0, burst)
        self.reset()

    def reset(self):
        self._tokens = self.burst
        self._last = None

    def allow(self, now: float) -> bool:
        if self._last is not None:
            self._tokens = min(self.burst,
                               self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False
