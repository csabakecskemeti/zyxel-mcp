"""HTTP client for the Zyxel GS1900-24E web GUI (Hydra/cgi-bin).

Protocol verified live against the switch (firmware V2.80):
  1. GET  dispatcher.cgi?cmd=0                      -> login page
  2. GET  dispatcher.cgi?login=1&username=U&password=P[encoded]&dummy=ts
     -> the GUI JS `encode()` obfuscates the password into a 320-char string:
        password chars are placed reversed at every 7th index, length digits
        at fixed positions 123 (tens) and 289 (units), rest random alnum.
  3. GET  dispatcher.cgi?login_chk=1                -> "OK" once authenticated
  4. GET  dispatcher.cgi?cmd=1                      -> frameset bootstrap; its
     HTML embeds an XSSID which MUST be sent as cookie AND form field.
  5. Pages are addressed by integer cmd: e.g. cmd=799 port status,
     cmd=1282 VLAN list, cmd=1290 Port PVID, cmd=1293 VLAN Port membership,
     cmd=2065 MAC table. Writes POST form data with hidden XSSID + cmd fields.
  6. Running config is copied to startup via cmd=5899
     (srcFile=1 running, dstFile=2 startup).
"""
from __future__ import annotations

import os
import random
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

DISPATCHER = "/cgi-bin/dispatcher.cgi"

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def encode_password(password: str) -> str:
    """Replicate the switch's login-page JS obfuscation of the password."""
    text: list[str] = []
    length = len(password)
    remaining = length
    for i in range(1, 321 - length):
        if i % 7 == 0 and remaining > 0:
            remaining -= 1
            text.append(password[remaining])
        elif i == 123:
            text.append("0" if length < 10 else str(length // 10))
        elif i == 289:
            text.append(str(length % 10))
        else:
            text.append(_ALNUM[random.randrange(len(_ALNUM))])
    return "".join(text)


class ZyxelAuthError(Exception):
    pass


class ZyxelRequestError(Exception):
    pass


@dataclass
class ZyxelConfig:
    host: str = ""
    scheme: str = "http"
    username: str = "admin"
    password: str = ""
    timeout: float = 10.0

    @classmethod
    def from_env(cls) -> "ZyxelConfig":
        password = os.environ.get("ZYXEL_PASSWORD", "").strip()
        pw_file = os.environ.get("ZYXEL_PASSWORD_FILE")
        if pw_file and not password:
            password = open(pw_file, encoding="utf-8").read().strip()
        host = os.environ.get("ZYXEL_HOST", "").strip()
        if not host:
            raise ValueError(
                "ZYXEL_HOST is not set. Set it to the switch management IP "
                "(e.g. in .env or the MCP client env config)."
            )
        return cls(
            host=host,
            scheme=os.environ.get("ZYXEL_SCHEME", "http").strip(),
            username=os.environ.get("ZYXEL_USER", "admin").strip(),
            password=password,
        )

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}"


class ZyxelClient:
    """Session wrapper around the GS1900 web GUI."""

    def __init__(self, config: ZyxelConfig | None = None):
        self.config = config or ZyxelConfig.from_env()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; mcp-zyxel/0.2)"
        )
        self.xssid: str | None = None
        self._logged_in_at: float = 0.0
        # GS1900 sessions idle-time out quickly; re-login if older than this.
        self._session_ttl = 240.0

    # -- low-level helpers -------------------------------------------------

    def _url(self) -> str:
        return urljoin(self.config.base_url + "/", DISPATCHER.lstrip("/"))

    def _is_login_page(self, text: str) -> bool:
        head = text[:4000].lower()
        return "login_chk" in head or (
            "password" in head and "username" in head and "xssid" not in head
        )

    def _check_response(self, resp: requests.Response) -> str:
        if resp.status_code == 401:
            raise ZyxelAuthError(
                "Switch returned 401 — session expired or bad credentials"
            )
        resp.raise_for_status()
        if self._is_login_page(resp.text):
            raise ZyxelAuthError("Switch returned the login page — session lost")
        return resp.text

    def get(self, params: dict[str, Any]) -> str:
        self._ensure_login()
        resp = self.session.get(
            self._url(), params=params, timeout=self.config.timeout, verify=False
        )
        return self._check_response(resp)

    def post(self, data: dict[str, Any]) -> str:
        cmd = str(data.get("cmd", ""))
        if cmd.isdigit():
            from .safety import check_write_cmd_allowed

            check_write_cmd_allowed(cmd)
        self._ensure_login()
        payload = {"XSSID": self.xssid}
        payload.update(data)
        resp = self.session.post(
            self._url(), data=payload, timeout=self.config.timeout, verify=False
        )
        return self._check_response(resp)

    def get_cmd(self, cmd: int) -> str:
        return self.get({"cmd": str(cmd)})

    def _ensure_login(self) -> None:
        if self._logged_in_at and (time.time() - self._logged_in_at) < self._session_ttl:
            return
        self.login()

    # -- auth ----------------------------------------------------------------

    def login(self) -> None:
        """Authenticate and capture the XSSID session token."""
        base = self._url()
        try:
            # The switch permits a single web session per user; clear any
            # stale session (e.g. from a previous run) before authenticating.
            self.session.get(base, params={"logout": "1"}, timeout=self.config.timeout,
                             verify=False)
            self.session.cookies.clear()
            time.sleep(0.5)
            self.session.get(base, params={"cmd": "0"}, timeout=self.config.timeout,
                             verify=False)
            resp = self.session.get(
                base,
                params={
                    "login": "1",
                    "username": self.config.username,
                    "password": encode_password(self.config.password),
                    "dummy": str(int(time.time() * 1000)),
                },
                timeout=self.config.timeout,
                verify=False,
            )
            resp.raise_for_status()
            time.sleep(1)
            chk = self.session.get(
                base, params={"login_chk": "1"}, timeout=self.config.timeout,
                verify=False,
            ).text.strip()
            if "OK" not in chk:
                raise ZyxelAuthError(f"Authentication failed (login_chk={chk!r})")
            bootstrap = self.session.get(
                base, params={"cmd": "1"}, timeout=self.config.timeout, verify=False
            ).text
            m = re.search(r'XSSID",\s*"([A-Za-z0-9]+)"', bootstrap)
            if not m:
                raise ZyxelAuthError("Login succeeded but no XSSID found")
            self.xssid = m.group(1)
        except requests.RequestException as e:
            raise ZyxelRequestError(f"HTTP error during login: {e}") from e
        self.session.cookies.set("XSSID", self.xssid)
        self._logged_in_at = time.time()

    def logout(self) -> None:
        try:
            self.session.get(
                self._url(), params={"logout": "1"}, timeout=self.config.timeout,
                verify=False,
            )
        except requests.RequestException:
            pass
        self.session.cookies.clear()
        self.xssid = None
        self._logged_in_at = 0.0

    # -- config helpers --------------------------------------------------------

    def save_config(self) -> None:
        """Copy running configuration to startup configuration."""
        self.post(
            {"cmd": "5899", "srcFile": "1", "dstFile": "2", "sysSubmit": "Apply"}
        )

    def submit_form(self, form_data: dict[str, Any]) -> str:
        """POST a feature form; XSSID is injected automatically.
        Writes to connectivity-critical dispatcher cmds are refused."""
        cmd = str(form_data.get("cmd", ""))
        if cmd.isdigit():
            from .safety import check_write_cmd_allowed

            check_write_cmd_allowed(cmd)
        payload = dict(form_data)
        payload.setdefault("XSSID", self.xssid)
        resp = self.session.post(
            self._url(), data=payload, timeout=self.config.timeout, verify=False
        )
        return self._check_response(resp)
