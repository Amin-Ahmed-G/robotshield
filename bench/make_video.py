"""
Build the LinkedIn video (1080x1350, H.264) from a screen recording of the
console running the self-test.

  # record: firewall_console --zoom 1.5, then
  #   ffmpeg -f x11grab -window_id <id> -framerate 30 -draw_mouse 0 -i :0 raw.mkv
  python3 bench/make_video.py raw.mkv docs/linkedin/roboshield_v2_selftest.mp4

The recording must be the 1920x985 console window (zoom 1.5).
"""
from pathlib import Path
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

W, H = 1080, 1350
BG = (22, 22, 22)
INK = (245, 245, 242)
INK2 = (190, 189, 182)
MUTED = (140, 139, 134)
BLUE = (57, 135, 229)
GREEN = (63, 185, 80)
BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
REG = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'

# Region of the 1920x985 console window shown in the frame: the attack
# buttons (active attack turns red) and the self-test results below them.
PANEL = (0, 225, 540, 565)          # x, y, w, h in the recording
SCALE = 1.72
PW, PH = round(PANEL[2] * SCALE), round(PANEL[3] * SCALE)
PX, PY = (W - PW) // 2, 222


def font(path, size):
    return ImageFont.truetype(path, size)


def card(path, lines):
    """Full-frame text card; lines = [(text, font, size, color, gap_after)]."""
    img = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(img)
    total = sum(size + gap for _, _, size, _, gap in lines)
    y = (H - total) // 2
    for text, face, size, color, gap in lines:
        f = font(face, size)
        d.text((80, y), text, font=f, fill=color)
        y += size + gap
    img.save(path)


def overlay(path):
    """Static frame around the live video: header, panel labels, footer."""
    img = Image.new('RGBA', (W, H), BG + (255,))
    d = ImageDraw.Draw(img)
    d.text((60, 52), 'ROBOSHIELD v2', font=font(BOLD, 26), fill=BLUE)
    d.text((W - 60, 52), 'real time, not sped up', font=font(REG, 24), fill=MUTED, anchor='ra')
    d.text((60, 100), '8 attacks vs. a live robot firewall', font=font(BOLD, 44), fill=INK)
    d.text((60, 172), 'Each row: one attack fired at the live firewall. PASS = caught.', font=font(REG, 26), fill=INK2)
    d.line((60, H - 125, W - 60, H - 125), fill=(60, 60, 58), width=2)
    d.text((60, H - 100), 'The robot never moved past its limit.', font=font(BOLD, 32), fill=INK)
    d.text((60, H - 52), 'Rust + ROS 2  ·  link in the comments', font=font(REG, 24), fill=MUTED)
    # Transparent window where the video shows through.
    d.rectangle((PX, PY, PX + PW - 1, PY + PH - 1), fill=(0, 0, 0, 0))
    img.save(path)


def run(cmd):
    subprocess.run(cmd, check=True)


def main(raw, out):
    tmp = Path(tempfile.mkdtemp(prefix='rs_video_'))
    card(tmp / 'intro.png', [
        ('ROBOSHIELD v2', BOLD, 30, BLUE, 40),
        ('I attacked my own', BOLD, 64, INK, 14),
        ('robot 8 different', BOLD, 64, INK, 14),
        ('ways.', BOLD, 64, INK, 50),
        ('Here is what the firewall did.', REG, 34, INK2, 0),
    ])
    card(tmp / 'end.png', [
        ('8 / 8', BOLD, 150, GREEN, 30),
        ('attacks caught', BOLD, 52, INK, 70),
        ('Robot max position: 1.000 rad (limit 1.0)', REG, 34, INK2, 22),
        ('Security cost: +0.5 ms per command', REG, 34, INK2, 22),
        ('Also 8/8 with SROS2 enforced', REG, 34, INK2, 70),
        ('RoboShield v2  ·  Rust + ROS 2', BOLD, 32, BLUE, 16),
        ('Code + benchmarks: link in the comments', REG, 28, MUTED, 0),
    ])
    overlay(tmp / 'frame.png')

    px, py, pw, ph = PANEL
    graph = (
        f'[0:v]fps=30,setsar=1,crop={pw}:{ph}:{px}:{py},scale={PW}:{PH}:flags=lanczos,'
        f'tpad=stop_mode=clone:stop_duration=2.5[st];'
        f'color=c=0x161616:s={W}x{H}:r=30[bg];'
        f'[bg][st]overlay={PX}:{PY}:shortest=1[b];'
        f'[b][1:v]overlay=0:0:shortest=1,format=yuv420p,fade=t=in:st=0:d=0.4[main];'
        f'[2:v]fps=30,format=yuv420p,fade=t=in:st=0:d=0.4,fade=t=out:st=2.1:d=0.4[intro];'
        f'[3:v]fps=30,format=yuv420p,fade=t=in:st=0:d=0.5[end];'
        f'[intro][main][end]concat=n=3:v=1:a=0[v]'
    )
    run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
         '-i', str(raw),
         '-loop', '1', '-i', str(tmp / 'frame.png'),
         '-loop', '1', '-t', '2.5', '-i', str(tmp / 'intro.png'),
         '-loop', '1', '-t', '4', '-i', str(tmp / 'end.png'),
         '-filter_complex', graph, '-map', '[v]',
         '-c:v', 'libx264', '-preset', 'slow', '-crf', '18', '-pix_fmt', 'yuv420p',
         '-r', '30', '-movflags', '+faststart', str(out)])


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))
