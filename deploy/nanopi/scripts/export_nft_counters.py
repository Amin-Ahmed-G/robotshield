#!/usr/bin/env python3
"""Export robot_fw nftables counters as {name: packets} JSON every 2 s."""
import json
import os
import subprocess
import time

OUT = '/run/robot_firewall/nft_counters.json'

while True:
    try:
        raw = subprocess.run(['nft', '-j', 'list', 'counters', 'table', 'inet', 'robot_fw'],
                             check=True, capture_output=True, text=True).stdout
        counters = {item['counter']['name']: item['counter']['packets']
                    for item in json.loads(raw)['nftables'] if 'counter' in item}
        tmp = OUT + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(counters, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, OUT)
    except (subprocess.CalledProcessError, ValueError, KeyError, OSError) as exc:
        print(f'counter export failed: {exc}', flush=True)
    time.sleep(2)
