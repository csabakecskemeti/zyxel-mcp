"""Probe the live GS1900-24E web GUI to verify login flow and dispatcher pages.

Usage:
    python probe.py            # login + dump dispatcher cmd page summaries
    python probe.py <cmd>      # dump forms found on one cmd page

Set ZYXEL_HOST / ZYXEL_USER / ZYXEL_PASSWORD env vars first.
"""
from __future__ import annotations

import re
import sys

from mcp_zyxel.zyxel_client import ZyxelClient

# Verified dispatcher cmd ids
CANDIDATE_CMDS = [
    13, 799, 1282, 1283, 1286, 1289, 1290, 1291, 1292, 1293, 1294,
    2049, 2065, 514, 512, 5899,
]


def probe() -> None:
    client = ZyxelClient()
    print(f"Target: {client.config.base_url}")
    client.login()
    print(f"Login OK — XSSID {client.xssid[:6]}…\n")

    arg = sys.argv[1] if len(sys.argv) > 1 else None
    cmds = [int(arg)] if arg else CANDIDATE_CMDS

    for cmd in cmds:
        try:
            html = client.get_cmd(cmd)
        except Exception as e:
            print(f"[cmd={cmd}] request failed: {e}")
            continue
        fields = sorted(set(re.findall(r'name="([^"]+)"', html)))[:10]
        print(f"[cmd={cmd}] {len(html)}B fields={fields}")


if __name__ == "__main__":
    probe()
