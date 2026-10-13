"""
Render the benchmark results in bench/results/ into docs/*.png.

  python3 bench/plot_results.py

Colors: blue = Rust / what reached the robot, orange = Python / what was
sent or requested, gray = baseline. Every series is directly labeled.
"""
import json
from pathlib import Path

import matplotlib
import matplotlib.ticker

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

R = Path('bench/results')
OUT = Path('docs')
OUT.mkdir(exist_ok=True)

SURFACE = '#fcfcfb'
INK = '#0b0b0b'
INK2 = '#52514e'
MUTED = '#8a8984'
GRID = '#e6e5e0'
BLUE = '#2a78d6'
ORANGE = '#eb6834'
SHADE_ATTACK = '#fbe3d9'
SHADE_LOCK = '#f4f3ef'

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 12,
    'axes.edgecolor': GRID, 'axes.labelcolor': INK2, 'axes.titleweight': 'bold',
    'axes.titlesize': 15, 'axes.titlecolor': INK, 'axes.titlelocation': 'left',
    'xtick.color': INK2, 'ytick.color': INK2, 'axes.grid': True, 'grid.color': GRID,
    'grid.linewidth': 0.8, 'figure.facecolor': SURFACE, 'axes.facecolor': SURFACE,
    'savefig.facecolor': SURFACE, 'axes.spines.top': False, 'axes.spines.right': False,
})


def footer(fig, text):
    fig.text(0.01, 0.01, text, fontsize=9, color=MUTED, ha='left', va='bottom')


def rule_engine():
    rust = json.loads((R / 'rules_rust.json').read_text())
    py = json.loads((R / 'rules_python.json').read_text())
    fig, ax = plt.subplots(figsize=(10, 4.2))
    rows = [('Python  (monitor_py)', py, ORANGE), ('Rust  (fw_core)', rust, BLUE)]
    for y, (label, d, color) in enumerate(rows):
        p50, p99 = d['p50_ns'] / 1000, d['p99_ns'] / 1000
        ax.barh(y, p50, height=0.5, color=color, zorder=3)
        ax.plot([p50, p99], [y, y], color=INK2, lw=1.5, zorder=4)
        ax.plot([p99], [y], marker='|', ms=14, color=INK2, zorder=4)
        ax.text(p99 + 0.3, y, f'{p50:.2f} µs median  ·  {p99:.1f} µs p99', va='center', color=INK, fontsize=12)
    ax.set_yticks(range(len(rows)), [r[0] for r in rows])
    ax.set_xlim(0, 23)
    ax.set_xlabel('time to inspect one 6-joint command (µs)')
    ax.grid(axis='y', visible=False)
    speedup = py['p50_ns'] / rust['p50_ns']
    ax.set_title(f'Rule engine: Rust checks a command {speedup:.0f}x faster than Python')
    footer(fig, 'All rules on the forward path (schema, NaN, replay, step, limits, rate). '
           f'{rust["n"]:,} / {py["n"]:,} samples, AMD Ryzen 7 7435HS. Bar = median, whisker = p99.')
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(OUT / 'perf_rule_engine.png', dpi=150)
    plt.close(fig)
    return speedup


def gateway_latency():
    fig, ax = plt.subplots(figsize=(10, 5))
    series = [('direct', 'No firewall (baseline)', MUTED), ('rust', 'Rust gateway', BLUE),
              ('python', 'Python gateway', ORANGE)]
    stats = {}
    for key, label, color in series:
        d = json.loads((R / f'latency_{key}.json').read_text())
        lat = [v / 1000.0 for v in d['latency_us']]
        n = len(lat)
        ys = [(i + 1) / n * 100 for i in range(n)]
        ax.plot(lat, ys, color=color, lw=2.2, zorder=3)
        p50 = lat[n // 2]
        stats[key] = (p50, lat[int((n - 1) * 0.99)], n, d['sent'])
        ax.text(lat[int(n * 0.55)] + 0.04, 52, f'{label}\n{p50:.2f} ms median',
                color=INK, fontsize=11, va='bottom')
    ax.axhline(50, color=GRID, lw=1, zorder=1)
    ax.set_xlabel('command latency, laptop publish → robot receive (ms)')
    ax.set_ylabel('% of commands delivered within')
    ax.set_ylim(0, 101)
    ax.set_xlim(0, max(s[1] for s in stats.values()) * 1.15)
    added_rust = stats['rust'][0] - stats['direct'][0]
    added_py = stats['python'][0] - stats['direct'][0]
    ax.set_title(f'End-to-end: the Rust firewall adds {added_rust:.1f} ms per command '
                 f'(Python: {added_py:.1f} ms)')
    footer(fig, f'{stats["rust"][3]} commands at 40 Hz per run, all {stats["rust"][2]} delivered in every mode. '
           'Same machine, two ROS 2 domains, Fast DDS. Receiver is an rclpy node in all modes.')
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(OUT / 'perf_gateway_latency.png', dpi=150)
    plt.close(fig)
    return added_rust, added_py


def timeline():
    d = json.loads((R / 'timeline.json').read_text())
    lockdown = next((t for t, a, _ in d['events'] if a == 'LOCKDOWN'), None)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7.5), sharex=True,
                                   gridspec_kw={'height_ratios': [1.25, 1]})
    end = 22.0
    for ax in (ax1, ax2):
        ax.axvspan(4, 12, color=SHADE_ATTACK, zorder=0, lw=0)
        ax.axvspan(15, 17, color=SHADE_ATTACK, zorder=0, lw=0)
        if lockdown:
            ax.axvspan(lockdown, end, color=SHADE_LOCK, zorder=0, lw=0, hatch='', alpha=1)
            ax.axvline(lockdown, color=INK2, lw=1.2, ls='-', zorder=2)
        ax.set_xlim(0, end)

    ct, cv = zip(*d['commanded'])
    rt, rv = zip(*d['robot'])
    ax1.plot(ct, cv, color=ORANGE, lw=1.8, ls='--', zorder=3)
    ax1.plot(rt, rv, color=BLUE, lw=2.4, zorder=4)
    for lim in (1.0, -1.0):
        ax1.axhline(lim, color=INK, lw=1, ls=':', zorder=2)
    ax1.text(0.15, 1.05, 'joint limit ±1.0 rad', color=INK2, fontsize=10)
    ax1.text(8.0, 1.55, 'OVERREACH attack: commander aims for ±1.5 rad', ha='center', color=INK, fontsize=11)
    ax1.text(16.0, 1.55, 'FLOOD', ha='center', color=INK, fontsize=11)
    ax1.text(17.9, 1.12, 'requested (dashed)', color=ORANGE, fontsize=11, fontweight='bold')
    ax1.text(0.3, -1.45, 'robot actual (clamped at ±1.0)', color=BLUE, fontsize=11, fontweight='bold')
    flood_start = min(t for t, _ in d['commanded'] if t >= 15.0)
    if lockdown:
        ax1.text(lockdown + 0.15, -1.45,
                 f'LOCKDOWN {1000 * (lockdown - flood_start):.0f} ms into the flood:\nrobot held in place',
                 color=INK, fontsize=10.5)
    ax1.set_ylim(-1.7, 1.75)
    ax1.set_ylabel('joint_1 position (rad)')
    ax1.set_title('Live attack run through the Rust gateway: clamp, then lock down')

    def binned(ts, width=0.25):
        n = int(end / width)
        counts = [0] * n
        for t in ts:
            i = int(t / width)
            if 0 <= i < n:
                counts[i] += 1
        return [(i + 0.5) * width for i in range(n)], [c / width for c in counts]

    sx, sy = binned(d['sent'])
    fx, fy = binned(d['forwarded'])
    ax2.step(sx, sy, where='mid', color=ORANGE, lw=1.8, zorder=3)
    ax2.step(fx, fy, where='mid', color=BLUE, lw=2.4, zorder=4)
    ax2.set_yscale('symlog', linthresh=10)
    ax2.set_ylim(0, 2000)
    ax2.set_yticks([0, 10, 20, 100, 600], ['0', '10', '20', '100', '600'])
    ax2.yaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax2.set_ylabel('commands per second')
    ax2.set_xlabel('time (s)')
    peak = max(sy)
    ax2.text(17.2, peak * 0.8, f'sent: up to {peak:.0f}/s', color=ORANGE, fontsize=11, fontweight='bold')
    ax2.text(0.3, 30, 'reached robot', color=BLUE, fontsize=11, fontweight='bold')
    if lockdown:
        ax2.text(17.3, 2.2, '0 forwarded after lockdown\n(attack and legit traffic blocked)', color=INK, fontsize=10)
    blocked = len(d['sent']) - len(d['forwarded'])
    footer(fig, f'{len(d["sent"])} commands sent, {len(d["forwarded"])} forwarded, {blocked} blocked. '
           'Robot: monitor_py robot_sim_node. Shaded = attack windows; gray = lockdown.')
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(OUT / 'perf_attack_timeline.png', dpi=150)
    plt.close(fig)
    peak_robot = max(abs(v) for v in rv)
    return peak_robot, lockdown


def v1_vs_v2():
    rows = [
        ('Where it runs', 'Passive tap (mirror port)', 'Inline gateway, only path to robot'),
        ('Response', 'JSON alerts', 'Forward / clamp / drop / LOCKDOWN'),
        ('Robot safety', '-', 'Holds last safe pose, boots locked'),
        ('Spoofed publishers', 'GUID prefix allowlist', 'Per-message drop + SROS2 certs'),
        ('Flood / DoS', 'Topic Hz threshold', 'Token bucket → lockdown'),
        ('Command content', '-', 'Limits, jumps, NaN, replay, schema'),
        ('Robot-side LAN', '-', 'Rogue device + state-spoof detection'),
        ('Network layer', '-', 'nftables default-drop, no routing'),
        ('Operator tooling', 'CLI + simulator', 'Rust GUI, one button per command'),
        ('Verification', '3 tests', '8/8 attack self-test, 39 Rust + 59 Py tests'),
    ]
    fig = plt.figure(figsize=(11, 6.6))
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.text(0.04, 0.94, 'RoboShield v1 → v2: from watching the network to protecting the robot',
            fontsize=16, fontweight='bold', color=INK, va='center')
    cols = [(0.04, 'Capability'), (0.30, 'v1  ·  RTPS watchdog'), (0.60, 'v2  ·  robot firewall')]
    top = 0.86
    for x, h in cols:
        ax.text(x, top, h, fontsize=12.5, fontweight='bold', color=INK2 if x < 0.6 else BLUE, va='center')
    row_h = 0.074
    for i, (cap, v1, v2) in enumerate(rows):
        y = top - (i + 1) * row_h
        if i % 2 == 0:
            ax.add_patch(FancyBboxPatch((0.025, y - row_h / 2 + 0.006), 0.95, row_h - 0.012,
                                        boxstyle='round,pad=0,rounding_size=0.008',
                                        facecolor='#f3f2ee', edgecolor='none'))
        ax.text(0.04, y, cap, fontsize=12, color=INK, va='center', fontweight='bold')
        ax.text(0.30, y, v1, fontsize=12, color=MUTED if v1 == '-' else INK2, va='center')
        ax.text(0.60, y, v2, fontsize=12, color=INK, va='center')
    ax.text(0.04, 0.025, 'github.com/Amin-Ahmed-G/robotshield   ·   v1 kept on branch roboshield-v1-nids',
            fontsize=10, color=MUTED)
    fig.savefig(OUT / 'v1_vs_v2.png', dpi=150)
    plt.close(fig)


if __name__ == '__main__':
    print('rule engine speedup:', round(rule_engine(), 1))
    print('added latency rust/python (ms):', [round(v, 2) for v in gateway_latency()])
    print('timeline peak robot |pos| / lockdown t:', timeline())
    v1_vs_v2()
    print('wrote', sorted(p.name for p in OUT.glob('*.png')))
