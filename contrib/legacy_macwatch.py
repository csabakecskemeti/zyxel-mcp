"""Clear the switch MAC table, then watch how it repopulates.

Useful when tracing which physical port a device actually lives on.
Reads credentials from the environment (see legacy_zyxel.py).

Usage:
    ZYXEL_HOST=192.168.1.1 ZYXEL_PASSWORD=... python contrib/legacy_macwatch.py
"""
import os
import re
import time

import legacy_zyxel

HOST = os.environ.get("ZYXEL_HOST", "").strip()
BASE = f"http://{HOST}/cgi-bin/dispatcher.cgi"

s = legacy_zyxel.login()

# Clear the dynamic MAC table (cmd 2051), then poll cmd 2065 as it refills.
r = s.post(
    BASE,
    data={
        "sysSubmit": "Delete All",
        "cmd": "2051",
        "portId": "0",
        "vlanId": "0",
        "macAddress": "",
        "forwarded": "3",
        "filter": "Apply",
    },
    timeout=10,
)
print("clear posted ->", r.status_code)


def read_table():
    html = s.get(f"{BASE}?cmd=2065", timeout=10).text
    rows = [x.strip() for x in re.findall(r"<div align=center>([^<]*)</div>", html)]
    return [tuple(rows[i:i + 4]) for i in range(0, len(rows), 4)]


print("immediately after clear:")
for entry in read_table():
    print(entry)

elapsed = 0
for target in (10, 30, 60):
    time.sleep(target - elapsed)
    elapsed = target
    print(f"--- after ~{target}s total:")
    for entry in read_table():
        print(entry)
