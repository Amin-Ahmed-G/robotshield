"""Micro-benchmark of the Python rule engine (same scenario as the Rust
inspect_bench example). Prints JSON with percentiles in nanoseconds."""
import json
import math
import sys
import time

sys.path.insert(0, 'src/monitor_py')
from monitor_py.checks import JointLimits  # noqa: E402
from monitor_py.firewall_rules import Command, CommandFirewall, FirewallConfig  # noqa: E402

names = [f'joint_{i}' for i in range(1, 7)]
cfg = FirewallConfig(joint_names=names,
                     limits={n: JointLimits(-1.0, 1.0, 1.0, 10.0) for n in names},
                     max_rate_hz=1e12, burst=1e12, start_locked=False)
fw = CommandFirewall(cfg)
n = 200_000
samples = []
t = 1000.0
for i in range(n + 5000):
    t += 1e-4
    x = 0.5 * math.sin(i * 1e-3)
    cmd = Command(list(names), [x] * 6, [0.1] * 6, [], t, 'bench')
    start = time.perf_counter_ns()
    fw.inspect(cmd, t)
    dt = time.perf_counter_ns() - start
    if i >= 5000:
        samples.append(dt)
samples.sort()


def pct(p):
    return samples[int((len(samples) - 1) * p)]


print(json.dumps({'impl': 'python', 'n': len(samples), 'mean_ns': sum(samples) / len(samples),
                  'p50_ns': pct(0.5), 'p90_ns': pct(0.9), 'p99_ns': pct(0.99), 'p999_ns': pct(0.999)}))
