"""
Build the LinkedIn carousel: four 1080x1350 (4:5) slides with a shared frame.

  python3 bench/make_slides.py      # -> docs/linkedin/slide_{1..4}.png

Data comes from bench/results/ (see bench/README.md); slide 3 uses
docs/firewall_console.png (console at --zoom 1.5 after a self-test run).
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402
from PIL import Image  # noqa: E402

R = Path('bench/results')
OUT = Path('docs/linkedin')
OUT.mkdir(parents=True, exist_ok=True)
TOTAL = 4
REPO = 'github.com/Amin-Ahmed-G/robotshield'

SURFACE = '#fcfcfb'
CARD = '#f3f2ee'
INK = '#0b0b0b'
INK2 = '#52514e'
MUTED = '#8a8984'
GRID = '#e6e5e0'
BLUE = '#2a78d6'
ORANGE = '#eb6834'
SHADE_ATTACK = '#fbe3d9'
SHADE_LOCK = '#efeee9'

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 13,
    'axes.edgecolor': GRID, 'axes.labelcolor': INK2, 'xtick.color': INK2, 'ytick.color': INK2,
    'xtick.labelsize': 12, 'ytick.labelsize': 12, 'axes.grid': True, 'grid.color': GRID,
    'grid.linewidth': 0.8, 'figure.facecolor': SURFACE, 'axes.facecolor': SURFACE,
    'savefig.facecolor': SURFACE, 'axes.spines.top': False, 'axes.spines.right': False,
})


def frame(n, headline, sub, takeaway):
    """Portrait slide with the shared header/footer; returns the figure."""
    fig = plt.figure(figsize=(7.2, 9.0), dpi=150)
    fig.text(0.06, 0.955, f'ROBOSHIELD v2', fontsize=11, fontweight='bold', color=BLUE, va='center')
    fig.text(0.94, 0.955, f'{n} / {TOTAL}', fontsize=11, color=MUTED, ha='right', va='center')
    fig.text(0.06, 0.905, headline, fontsize=21, fontweight='bold', color=INK, va='top', linespacing=1.15)
    fig.text(0.06, 0.80, sub, fontsize=12.5, color=INK2, va='top', linespacing=1.35)
    fig.add_artist(plt.Line2D([0.06, 0.94], [0.085, 0.085], color=GRID, lw=1))
    fig.text(0.06, 0.06, takeaway, fontsize=12.5, color=INK, va='center', fontweight='bold')
    fig.text(0.06, 0.028, REPO, fontsize=10.5, color=MUTED, va='center')
    return fig


def save(fig, n):
    fig.savefig(OUT / f'slide_{n}.png', dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------- slide 1
def slide_timeline():
    d = json.loads((R / 'timeline.json').read_text())
    lockdown = next(t for t, a, _ in d['events'] if a == 'LOCKDOWN')
    flood_start = min(t for t, _ in d['commanded'] if t >= 15.0)
    react_ms = 1000 * (lockdown - flood_start)
    fig = frame(1, 'An attacker pushed the arm\npast its limits. It didn\'t move.',
                'Live run through the Rust gateway: an overreach attack gets clamped,\n'
                f'then a 600 msg/s flood triggers lockdown in ~{react_ms:.0f} ms.',
                'The robot never left its safe range.')
    ax1 = fig.add_axes((0.13, 0.43, 0.81, 0.31))
    ax2 = fig.add_axes((0.13, 0.15, 0.81, 0.22), sharex=ax1)
    end = 22.0
    for ax in (ax1, ax2):
        ax.axvspan(4, 12, color=SHADE_ATTACK, lw=0, zorder=0)
        ax.axvspan(lockdown, end, color=SHADE_LOCK, lw=0, zorder=0)
        ax.axvline(lockdown, color=INK2, lw=1.2, zorder=2)
        ax.set_xlim(0, end)
    ct, cv = zip(*d['commanded'])
    rt, rv = zip(*d['robot'])
    ax1.plot(ct, cv, color=ORANGE, lw=2, ls='--', zorder=3)
    ax1.plot(rt, rv, color=BLUE, lw=3, zorder=4)
    for lim in (1.0, -1.0):
        ax1.axhline(lim, color=INK, lw=1, ls=':', zorder=2)
    ax1.set_ylim(-1.75, 1.85)
    ax1.set_yticks([-1.5, -1, 0, 1, 1.5])
    ax1.set_ylabel('joint position (rad)', fontsize=12)
    ax1.text(8, 1.62, 'OVERREACH', ha='center', fontsize=12, fontweight='bold', color=INK)
    ax1.text(lockdown + 0.3, 1.62, 'FLOOD →\nLOCKDOWN', fontsize=11, fontweight='bold', color=INK, va='center')
    ax1.text(0.2, 1.1, 'limit ±1.0', fontsize=11, color=INK2)
    ax1.text(16.9, 1.15, 'attacker asks', fontsize=12, color=ORANGE, fontweight='bold')
    ax1.text(15.6, -1.45, 'robot holds', fontsize=12, color=BLUE, fontweight='bold')
    ax1.text(0.2, -1.5, 'robot clamped at ±1.0', fontsize=12, color=BLUE, fontweight='bold')
    plt.setp(ax1.get_xticklabels(), visible=False)

    def binned(ts, width=0.25):
        n = int(end / width)
        c = [0] * n
        for t in ts:
            if 0 <= int(t / width) < n:
                c[int(t / width)] += 1
        return [(i + 0.5) * width for i in range(n)], [v / width for v in c]

    sx, sy = binned(d['sent'])
    fx, fy = binned(d['forwarded'])
    ax2.step(sx, sy, where='mid', color=ORANGE, lw=2, zorder=3)
    ax2.step(fx, fy, where='mid', color=BLUE, lw=3, zorder=4)
    ax2.set_yscale('symlog', linthresh=10)
    ax2.set_ylim(0, 2500)
    ax2.set_yticks([0, 20, 600], ['0', '20', '600'])
    ax2.yaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax2.set_ylabel('msgs / s', fontsize=12)
    ax2.set_xlabel('time (s)', fontsize=12)
    ax2.text(0.3, 45, 'reached robot', color=BLUE, fontsize=12, fontweight='bold')
    ax2.text(lockdown + 2.3, 900, 'sent', color=ORANGE, fontsize=12, fontweight='bold')
    ax2.text(lockdown + 2.3, 1.2, '0 reach robot', color=INK, fontsize=11)
    save(fig, 1)
    return react_ms


# ---------------------------------------------------------------- slide 2
def slide_compare():
    rows = [
        ('Position', 'passive network tap', 'inline: the only path to the robot'),
        ('Response', 'writes an alert', 'clamp, drop, or lock down'),
        ('Robot safety', 'none', 'holds last safe pose, boots locked'),
        ('Spoofed publishers', 'flags DDS IDs', 'drops their messages + SROS2 certs'),
        ('Command content', 'not inspected', 'limits, jumps, NaN, replays'),
        ('Robot-side network', 'not covered', 'rogue devices, state spoofing'),
        ('Operator tooling', 'command line', 'GUI: every command is a button'),
    ]
    fig = frame(2, 'v1 watched the network.\nv2 protects the robot.',
                'RoboShield v1 parsed raw RTPS packets and raised alerts.\n'
                'v2 sits between the network and the robot and acts.',
                'Same project, one level up: from detecting to preventing.')
    ax = fig.add_axes((0.06, 0.10, 0.88, 0.645))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    n = len(rows)
    h = 1.0 / n
    for i, (cap, v1, v2) in enumerate(rows):
        top = 1 - i * h
        ax.add_patch(FancyBboxPatch((0, top - h + 0.012), 1, h - 0.024,
                                    boxstyle='round,pad=0,rounding_size=0.02',
                                    facecolor=CARD, edgecolor='none'))
        ax.text(0.04, top - 0.033, cap, fontsize=13, fontweight='bold', color=INK, va='center')
        ax.text(0.04, top - 0.075, 'v1', fontsize=11, color=MUTED, fontweight='bold', va='center')
        ax.text(0.11, top - 0.075, v1, fontsize=12, color=MUTED, va='center')
        ax.text(0.04, top - 0.113, 'v2', fontsize=11, color=BLUE, fontweight='bold', va='center')
        ax.text(0.11, top - 0.113, v2, fontsize=12.5, color=INK, va='center')
    save(fig, 2)


# ---------------------------------------------------------------- slide 3
def slide_console():
    shot = Image.open('docs/firewall_console.png').convert('RGB')
    status = shot.crop((0, 0, 620, 38))
    selftest = shot.crop((0, 468, 540, 790))
    fig = frame(3, '8 attack types.\n8 caught. One click.',
                'The Rust console runs every attack against the live firewall and\n'
                'checks each one is reported. Also 8/8 in a run with SROS2 enforced.',
                'Every debug command is a button. No terminal juggling.')
    aspect = 7.2 / 9.0
    top, bottom = 0.735, 0.335          # space between subtitle and the tiles
    gap, caption = 0.015, 0.03
    # Same width for strip and table, as large as the vertical space allows.
    per_w = (status.height / status.width + selftest.height / selftest.width) * aspect
    w = min(0.88, (top - bottom - gap - caption) / per_w)
    x = (1 - w) / 2
    h0 = w * status.height / status.width * aspect
    ax0 = fig.add_axes((x, top - h0, w, h0))
    ax0.imshow(status)
    ax0.set_axis_off()
    h1 = w * selftest.height / selftest.width * aspect
    ax1 = fig.add_axes((x, top - h0 - gap - h1, w, h1))
    ax1.imshow(selftest)
    ax1.set_axis_off()
    fig.text(x, top - h0 - gap - h1 - 0.012,
             'Status bar and self-test panel from the console, after one run.',
             fontsize=10.5, color=MUTED, va='top')
    tiles = [('8 / 8', 'attacks detected'), ('1.000', 'max robot position\n(limit 1.0 rad)'),
             ('0', 'msgs through from a\ncert-less attacker*')]
    for i, (big, small) in enumerate(tiles):
        x = 0.06 + i * 0.30
        fig.add_artist(FancyBboxPatch((x, 0.12), 0.28, 0.17, boxstyle='round,pad=0,rounding_size=0.015',
                                      transform=fig.transFigure, facecolor=CARD, edgecolor='none'))
        fig.text(x + 0.025, 0.245, big, fontsize=24, fontweight='bold', color=BLUE, va='center')
        fig.text(x + 0.025, 0.165, small, fontsize=11, color=INK2, va='center', linespacing=1.3)
    fig.text(0.06, 0.103, '* SROS2-enforced run, attacker publishing without certificates throughout.',
             fontsize=9.5, color=MUTED, va='center')
    save(fig, 3)


# ---------------------------------------------------------------- slide 4
def slide_speed():
    lat = {}
    for key in ('direct', 'rust', 'python'):
        d = json.loads((R / f'latency_{key}.json').read_text())['latency_us']
        lat[key] = (d[len(d) // 2] / 1000, d[int((len(d) - 1) * 0.99)] / 1000)
    rust = json.loads((R / 'rules_rust.json').read_text())
    py = json.loads((R / 'rules_python.json').read_text())
    added = lat['rust'][0] - lat['direct'][0]
    fig = frame(4, f'Security that costs\n{added:.1f} ms per command.',
                'Median time for a command to go from the laptop to the robot,\n'
                'with no firewall, through the Rust gateway, and through Python.',
                'Fast enough for real-time control loops.')
    ax = fig.add_axes((0.30, 0.47, 0.62, 0.27))
    rows = [('No firewall', 'direct', MUTED), ('Rust gateway', 'rust', BLUE), ('Python gateway', 'python', ORANGE)]
    for y, (label, key, color) in enumerate(reversed(rows)):
        p50, p99 = lat[key]
        ax.barh(y, p50, height=0.55, color=color, zorder=3)
        ax.text(p50 + 0.03, y, f'{p50:.2f} ms', va='center', fontsize=13, color=INK, fontweight='bold')
    ax.set_yticks(range(3), [r[0] for r in reversed(rows)], fontsize=13)
    ax.tick_params(axis='y', length=0)
    ax.set_xlim(0, 2.0)
    ax.set_xlabel('median latency (ms)', fontsize=12)
    ax.grid(axis='y', visible=False)

    def tile(x, big, small):
        fig.add_artist(FancyBboxPatch((x, 0.15), 0.42, 0.21, boxstyle='round,pad=0,rounding_size=0.015',
                                      transform=fig.transFigure, facecolor=CARD, edgecolor='none'))
        fig.text(x + 0.03, 0.30, big, fontsize=30, fontweight='bold', color=BLUE, va='center')
        fig.text(x + 0.03, 0.205, small, fontsize=11.5, color=INK2, va='center', linespacing=1.35)

    tile(0.06, f'{rust["p50_ns"] / 1000:.2f} µs', f'to check one command\n({py["p50_ns"] / rust["p50_ns"]:.0f}x faster than Python)')
    tile(0.52, '1000/1000', 'commands delivered\nin every latency run')
    fig.text(0.06, 0.125, 'Laptop benchmark (Ryzen 7 7435HS, ROS 2 Jazzy, Fast DDS). NanoPi numbers next.',
             fontsize=9.5, color=MUTED)
    save(fig, 4)
    return added


if __name__ == '__main__':
    print('lockdown reaction ms:', round(slide_timeline()))
    slide_compare()
    slide_console()
    print('added latency ms:', round(slide_speed(), 2))
    print(sorted(p.name for p in OUT.iterdir()))
