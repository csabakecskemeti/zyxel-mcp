"""Minimal standalone login helper for the GS1900 web GUI.

Kept for reference and quick one-off probing; the MCP server itself uses
`mcp_zyxel.zyxel_client` which implements the same handshake with session
handling, safety guardrails and auditing.

Credentials come from the environment, never from source:
    ZYXEL_HOST, ZYXEL_USER, ZYXEL_PASSWORD

Usage:
    ZYXEL_HOST=192.168.1.1 ZYXEL_PASSWORD=... python contrib/legacy_zyxel.py
"""
import os
import random
import re
import string
import time
from urllib.parse import quote

import requests

HOST = os.environ.get("ZYXEL_HOST", "").strip()
USER = os.environ.get("ZYXEL_USER", "admin").strip()
PASSWORD = os.environ.get("ZYXEL_PASSWORD", "").strip()


def encode(pw):
    """Replicate the login page's JS password obfuscation."""
    possible = string.ascii_letters + string.digits
    text = ""
    ln = len(pw)
    length = ln
    for i in range(1, 321 - ln):
        if i % 7 == 0 and length > 0:
            length -= 1
            text += pw[length]
        elif i == 123:
            text += "0" if ln < 10 else str(ln // 10)
        elif i == 289:
            text += str(ln % 10)
        else:
            text += possible[random.randrange(len(possible))]
    return text


def login():
    if not HOST or not PASSWORD:
        raise SystemExit("Set ZYXEL_HOST and ZYXEL_PASSWORD in the environment")
    base = f"http://{HOST}/cgi-bin/dispatcher.cgi"
    s = requests.Session()
    s.get(
        f"{base}?login=1&username={quote(USER)}"
        f"&password={quote(encode(PASSWORD))}&dummy={int(time.time() * 1000)}",
        timeout=10,
    )
    for _ in range(10):
        time.sleep(1)
        if "OK" in s.get(f"{base}?login_chk=1", timeout=10).text:
            break
    t = s.get(f"{base}?cmd=1", timeout=10).text
    s.cookies.set("XSSID", re.search(r'XSSID", "([^"]+)"', t).group(1))
    return s


if __name__ == "__main__":
    s = login()
    r = s.get(f"http://{HOST}/cgi-bin/dispatcher.cgi?cmd=1", timeout=10).text
    links = re.findall(r"cmd=(\d+)[^>]*>([^<]+)<", r)
    seen = {}
    for c, name in links:
        seen.setdefault(c, name.strip())
    for c, n in sorted(seen.items(), key=lambda x: int(x[0])):
        print(c, n)
