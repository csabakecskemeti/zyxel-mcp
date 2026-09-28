"""Typed read/write operations against the GS1900-24E web GUI.

Dispatcher cmd ids verified live against the switch firmware:
  512  System > Information
  799  Monitor > Port status
  1283 VLAN list table (ajax; needs pageindex)
  1290 Port PVID list; edit via POST cmd=1291 -> apply via POST cmd=1292
  1293 VLAN Port membership grid (per-VLAN radio buttons)
  2065 MAC address table
Membership radio values on cmd=1293: 1=Forbidden, 0=Excluded, 2=Tagged,
3=Untagged. A membership POST must echo every row's current selection plus
the hidden vlanMode_N fields, otherwise unsubmitted rows reset.
"""
from __future__ import annotations

import json
import re
from typing import Any

from bs4 import BeautifulSoup

from .safety import audit, check_ports_allowed, write_backup
from .zyxel_client import ZyxelClient

PAGE_SYSTEM = 13  # dashboard info (hidden inputs: name/uptime/cpu/mem)
PAGE_PORT_STATUS = 799
PAGE_PORT_COUNTERS = 797
PAGE_BANDWIDTH_UTIL = 789
PAGE_VLAN_LIST = 1282
PAGE_VLAN_LIST_AJAX = 1283
PAGE_VLAN_ADD = 1284
PAGE_VLAN_EDIT = 1286
PAGE_VLAN_DELETE = 1289
PAGE_PVID = 1290
PAGE_PVID_EDIT = 1291
PAGE_PVID_APPLY = 1292
PAGE_VLAN_PORT = 1293
PAGE_VLAN_PORT_APPLY = 1294  # hidden cmd in the membership form's POST
PAGE_MAC_TABLE = 2065
PAGE_MAC_TABLE_AJAX = 2049
PAGE_STP_MONITOR = 4113
PAGE_STP_CONFIG = 4096
PAGE_STP_APPLY = 4097
PAGE_LAG_MONITOR = 1043
PAGE_LAG_CONFIG = 1024
PAGE_LAG_APPLY = 1025
PAGE_LOOPGUARD_CONFIG = 5376
PAGE_LOOPGUARD_APPLY = 5377
PAGE_LLDP_MONITOR = 4362
PAGE_LLDP_CONFIG = 4352
PAGE_LLDP_APPLY = 4353
PAGE_PORTSEC_MONITOR = 782
PAGE_PORTSEC_CONFIG = 780
PAGE_PORTSEC_APPLY = 785
PAGE_SYSLOG_CONFIG = 3584
PAGE_SYSLOG_APPLY = 3585
PAGE_SYSLOG_MONITOR = 3596
PAGE_MIRROR_CONFIG = 1792
PAGE_MIRROR_APPLY = 1794
PAGE_PORT_CONFIG = 768
PAGE_PORT_EDIT = 769
PAGE_PORT_APPLY = 770
PAGE_SYSINFO_CONFIG = 512
PAGE_SYSINFO_APPLY = 513
PAGE_BACKUP = 5901
PAGE_BACKUP_APPLY = 5902
PAGE_SAVE_CONFIG = 5899
PAGE_REBOOT = 5888
PAGE_REBOOT_APPLY = 5889

# backup content types (cmd 5902 radio `type`)
BACKUP_TYPES = {
    "running": "1",
    "startup": "2",
    "backup": "3",
    "flash_log": "6",
    "buffer_log": "7",
    "tech_support": "8",
}

# membership radio values on the VLAN Port page
FORBIDDEN, EXCLUDED, TAGGED, UNTAGGED = "1", "0", "2", "3"
MODES = {
    "forbidden": FORBIDDEN,
    "excluded": EXCLUDED,
    "tagged": TAGGED,
    "untagged": UNTAGGED,
}
VALUE_LABELS = {FORBIDDEN: "Forbidden", EXCLUDED: "Excluded", TAGGED: "Tagged", UNTAGGED: "Untagged"}
NUM_PORTS = 24


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def _gs_rows(soup: BeautifulSoup) -> tuple[list[str], list[list[dict[str, str]]]]:
    """Parse a GS1900-style table.

    Returns (headers, rows) where each row cell is {"text": ..., "input": ...}.
    Header cells carry class font-3; data cells class font-4 with a centered
    div. Decorative border columns are skipped.
    """
    headers: list[str] = []
    for td in soup.find_all("td"):
        classes = td.get("class") or []
        div = td.find("div", align="center")
        if not div:
            continue
        if "font-3" in classes:
            headers.append(div.get_text(strip=True))
    # Group data cells by <tr>
    grouped: list[list[dict[str, str]]] = []
    for tr in soup.find_all("tr"):
        cells: list[dict[str, str]] = []
        for td in tr.find_all("td"):
            classes = td.get("class") or []
            div = td.find("div", align="center")
            if not div or "font-4" not in classes:
                continue
            inp = div.find("input")
            cell = {"text": div.get_text(strip=True)}
            if inp is not None and inp.get("name"):
                cell["input"] = f'{inp["name"]}={inp.get("value", "")}'
                cell["text"] = inp.get("value", "")
            cells.append(cell)
        if cells:
            grouped.append(cells)
    return headers, grouped


def _table_dicts(soup: BeautifulSoup) -> list[dict[str, str]]:
    headers, grouped = _gs_rows(soup)
    out = []
    for cells in grouped:
        if len(cells) == len(headers):
            out.append({h: c["text"] for h, c in zip(headers, cells)})
    return out


def _radio_map(html: str) -> dict[int, str]:
    """Return {row_index: selected_value} from checked membership radios."""
    sel: dict[int, str] = {}
    for m in re.finditer(
        r'<input[^>]*name="membership_(\d+)"[^>]*value="([^"]*)"[^>]*>', html
    ):
        idx, value = int(m.group(1)), m.group(2)
        if "checked" in m.group(0):
            sel[idx] = value
    return sel


def _hidden_xssid(html: str) -> str | None:
    m = re.search(r'name="XSSID"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else None


class ZyxelOps:
    def __init__(self, client: ZyxelClient | None = None):
        self.client = client or ZyxelClient()

    # ---- reads -------------------------------------------------------------

    def get_system_info(self) -> dict[str, str]:
        """System Information page (model, firmware, uptime, IPs)."""
        html = self.client.get_cmd(PAGE_SYSTEM)
        info: dict[str, str] = {}
        for inp in re.finditer(
            r'<input type=hidden name=(\w+) value="([^"]*)"', html
        ):
            info[inp.group(1)] = inp.group(2)
        audit("read", target="system_info")
        return info

    def get_port_status(self) -> list[dict[str, str]]:
        rows = _table_dicts(_soup(self.client.get_cmd(PAGE_PORT_STATUS)))
        audit("read", target="port_status")
        return rows

    def list_vlans(self) -> list[dict[str, str]]:
        html = self.client.post({"cmd": str(PAGE_VLAN_LIST_AJAX), "pageindex": "1"})
        rows: list[dict[str, str]] = []
        seen: set[str] = set()
        for cells in _gs_rows(_soup(html))[1]:
            r = [c["text"] for c in cells]
            if len(r) >= 3 and r[0].isdigit() and r[0] not in seen:
                seen.add(r[0])
                rows.append({"vlan_id": r[0], "name": r[1], "type": r[2]})
        audit("read", target="vlans")
        return rows

    def get_vlan_membership(self, vlan_id: int | None = None) -> dict[str, str]:
        """Per-port membership for one VLAN as {port_label: mode}."""
        if vlan_id is None:
            vlan_id = 1
        html = self.client.post({"cmd": str(PAGE_VLAN_PORT), "vid": str(vlan_id)})
        current = _radio_map(html)
        labels = [f"Port{i + 1:02d}" for i in range(NUM_PORTS)] + [
            f"LAG{i + 1}" for i in range(8)
        ]
        result = {
            labels[i]: VALUE_LABELS.get(v, v)
            for i, v in sorted(current.items())
            if i < len(labels)
        }
        audit("read", target="vlan_membership", vlan_id=vlan_id)
        return result

    def get_pvids(self) -> list[dict[str, str]]:
        html = self.client.get_cmd(PAGE_PVID)
        headers, grouped = _gs_rows(_soup(html))
        # Drop row-selector checkbox cells so data aligns with headers
        rows_out = []
        for cells in grouped:
            cells = [c for c in cells if not c.get("input", "").startswith("port=")]
            if len(cells) == len(headers):
                rows_out.append({h: c["text"] for h, c in zip(headers, cells)})
        audit("read", target="pvids")
        return rows_out

    def get_mac_table(self, vlan_id: int | None = None) -> list[dict[str, str]]:
        """Learned MAC addresses, optionally filtered by VLAN."""
        data: dict[str, Any] = {"cmd": str(PAGE_MAC_TABLE_AJAX), "pageindex": "1"}
        if vlan_id is not None:
            data["vlan"] = str(vlan_id)
        html = self.client.post(data)
        rows = _table_dicts(_soup(html))
        audit("read", target="mac_table", vlan_id=vlan_id)
        return rows

    # ---- writes (guarded) ----------------------------------------------------

    def _pre_write(self, ports: list[int], dry_run: bool, op: str) -> dict[str, Any]:
        check_ports_allowed(ports)
        result: dict[str, Any] = {"op": op, "dry_run": dry_run, "ports": ports}
        if not dry_run:
            backup = {
                "vlans": self.list_vlans(),
                "membership": {v: self.get_vlan_membership(v) for v in (1, 10, 20, 30, 40)},
                "pvids": self.get_pvids(),
            }
            path = write_backup(f"pre-{op}", json.dumps(backup, indent=2))
            result["backup"] = str(path)
        return result

    def set_port_vlan_membership(
        self, vlan_id: int, ports: list[int], mode: str, dry_run: bool = True
    ) -> dict[str, Any]:
        """Set port membership in a VLAN: tagged|untagged|forbidden|excluded.

        Replays every row's current selection so untouched ports keep their
        state, then applies the requested change.
        """
        if mode not in MODES:
            raise ValueError(f"mode must be one of {sorted(MODES)}")
        for p in ports:
            if not 1 <= p <= NUM_PORTS:
                raise ValueError(f"port {p} out of range 1-{NUM_PORTS}")
        result = self._pre_write(ports, dry_run, f"vlan{vlan_id}_membership_{mode}")
        if dry_run:
            return result

        html = self.client.post({"cmd": str(PAGE_VLAN_PORT), "vid": str(vlan_id)})
        current = _radio_map(html)
        form: dict[str, Any] = {
            # the membership form posts to hidden cmd 1294, not 1293
            "cmd": str(PAGE_VLAN_PORT_APPLY),
            "vid": str(vlan_id),
            "sysSubmit": "Apply",
        }
        changed = {p - 1 for p in ports}
        for i in range(NUM_PORTS):
            val = MODES[mode] if i in changed else current.get(i)
            if val is None:
                raise RuntimeError(f"switch did not report current membership row {i}")
            form[f"vlanMode_{i}"] = "0"
            form[f"membership_{i}"] = val
        self.client.submit_form(form)
        self.client.save_config()
        audit(
            "set_port_vlan_membership",
            vlan_id=vlan_id,
            ports=ports,
            mode=mode,
            before={f"port{p}": VALUE_LABELS.get(current.get(p - 1)) for p in ports},
        )
        return {"ok": True, **result}

    def set_pvid(self, port: int, pvid: int, dry_run: bool = True) -> dict[str, Any]:
        """Set a port's PVID (two-step: edit form, then apply)."""
        if not 1 <= port <= NUM_PORTS:
            raise ValueError(f"port {port} out of range 1-{NUM_PORTS}")
        if not 1 <= pvid <= 4094:
            raise ValueError(f"pvid {pvid} out of range 1-4094")
        result = self._pre_write([port], dry_run, f"port{port}_pvid_{pvid}")
        if dry_run:
            return result

        # Step 1: request the edit form for this port to learn its defaults
        edit_html = self.client.submit_form(
            {"cmd": str(PAGE_PVID_EDIT), "port": str(port)}
        )
        defaults = {}
        for name in ("frametype", "vlan_igrfilter", "vlan_trunk"):
            m = re.search(rf'name="{name}"[^>]*value="([^"]+)"[^>]*checked', edit_html)
            defaults[name] = m.group(1) if m else "0"
        # Step 2: apply
        self.client.submit_form(
            {
                "cmd": str(PAGE_PVID_APPLY),
                "portlist": str(port),
                "pvid": str(pvid),
                **defaults,
                "sysSubmit": "Apply",
            }
        )
        self.client.save_config()
        audit("set_pvid", port=port, pvid=pvid)
        return {"ok": True, **result}

    # ---- maintenance: backup / save / reboot --------------------------------

    def _stage_download(self, type_code: str, attempts: int = 3) -> "re.Match[str] | None":
        """Ask the switch to stage a config/log file for HTTP download.

        Firmware V2.70 stages only one export per web session, so a retry
        starts a fresh login.
        """
        for attempt in range(attempts):
            if attempt:
                self.client.login()
            self.client._ensure_login()
            self.client.get_cmd(PAGE_BACKUP)
            resp = self.client.session.post(
                self.client._url(),
                data={
                    "XSSID": self.client.xssid,
                    "cmd": str(PAGE_BACKUP_APPLY),
                    "upmethod": "1",  # HTTP download (not TFTP)
                    "type": type_code,
                    "sysSubmit": "Apply",
                },
                timeout=self.client.config.timeout * 3,
                verify=False,
            )
            self.client._token_stale = True
            m = re.search(r'window\.location\.href = "([^"]+)"', resp.text)
            if m:
                return m
        return None

    def backup_config(self, content: str = "running") -> dict[str, Any]:
        """Download a config/log backup over HTTP and store it in the backup
        dir. content: running|startup|backup|flash_log|buffer_log|tech_support.
        """
        if content not in BACKUP_TYPES:
            raise ValueError(f"content must be one of {sorted(BACKUP_TYPES)}")
        import requests as _requests

        m = self._stage_download(BACKUP_TYPES[content])
        if not m:
            raise RuntimeError("switch did not stage a backup download")
        dl = self.client.session.get(
            f"{self.client.config.base_url}{m.group(1)}",
            timeout=self.client.config.timeout * 3,
            verify=False,
        )
        if dl.status_code != 200:
            raise RuntimeError(f"backup download failed: HTTP {dl.status_code}")
        path = write_backup(f"{content.replace('_', '-')}", dl.content)
        audit("backup_config", content=content, file=str(path))
        return {"ok": True, "content": content, "file": str(path), "bytes": len(dl.content)}

    def get_running_config_text(self) -> str:
        """Fetch the running configuration as text (for diffing/auditing)."""
        m = self._stage_download(BACKUP_TYPES["running"])
        if not m:
            raise RuntimeError("switch did not stage a config download")
        dl = self.client.session.get(
            f"{self.client.config.base_url}{m.group(1)}",
            timeout=self.client.config.timeout * 3,
            verify=False,
        )
        dl.raise_for_status()
        return dl.content.decode("utf-8", "replace")

    def save_running_to_startup(self) -> dict[str, Any]:
        """Copy the running configuration to the startup configuration."""
        self.client.save_config()
        audit("save_running_to_startup")
        return {"ok": True, "action": "running -> startup"}

    def reboot(self, ack: str = "") -> dict[str, Any]:
        """Reboot the switch. Requires ack='REBOOT' — this drops connectivity
        for ~1 minute and discards unsaved running-config changes."""
        if ack != "REBOOT":
            return {
                "ok": False,
                "error": "pass ack='REBOOT' to confirm; unsaved running-config "
                "changes are lost and management is down ~1 minute",
            }
        write_backup("pre-reboot", self.get_running_config_text())
        self.client.submit_form(
            {"cmd": str(PAGE_REBOOT_APPLY), "sysSubmit": "Apply"}
        )
        audit("reboot")
        return {"ok": True, "action": "reboot initiated"}

    # ---- VLAN create/delete ---------------------------------------------------

    def create_vlan(self, vlan_id: int, name: str, dry_run: bool = True) -> dict[str, Any]:
        if not 1 <= vlan_id <= 4094:
            raise ValueError("vlan_id must be 1..4094")
        if vlan_id == 1:
            raise ValueError("VLAN 1 already exists (default)")
        existing = {v["vlan_id"] for v in self.list_vlans()}
        if str(vlan_id) in existing:
            raise ValueError(f"VLAN {vlan_id} already exists")
        result = self._pre_write([], dry_run, f"create_vlan_{vlan_id}")
        if dry_run:
            return result
        self.client.submit_form(
            {
                "cmd": str(PAGE_VLAN_ADD),
                "vidValue": str(vlan_id),
                "editName": name,
                "sysSubmit": "Add",
            }
        )
        self.client.save_config()
        audit("create_vlan", vlan_id=vlan_id, name=name)
        return {"ok": True, "vlan_id": vlan_id, **result}

    def delete_vlan(self, vlan_id: int, dry_run: bool = True) -> dict[str, Any]:
        if vlan_id == 1:
            raise ValueError("Refusing to delete VLAN 1 (default/management VLAN)")
        # refuse if any port is a member (would strand traffic)
        membership = self.get_vlan_membership(vlan_id)
        members = [p for p, m in membership.items() if m not in ("Excluded", "Forbidden")]
        if members:
            raise ValueError(
                f"Refusing to delete VLAN {vlan_id}: member ports {members}. "
                "Remove membership first."
            )
        result = self._pre_write([], dry_run, f"delete_vlan_{vlan_id}")
        if dry_run:
            return result
        # deletion is a GET link: cmd=1289&_del=<vid>
        self.client.get({"cmd": str(PAGE_VLAN_DELETE), "_del": str(vlan_id)})
        self.client.save_config()
        audit("delete_vlan", vlan_id=vlan_id)
        return {"ok": True, "vlan_id": vlan_id, **result}

    # ---- system / port configuration ------------------------------------------

    def set_system_info(
        self, name: str | None = None, location: str | None = None,
        contact: str | None = None, dry_run: bool = True,
    ) -> dict[str, Any]:
        """Set system name/location/contact (cosmetic; cannot break connectivity)."""
        html = self.client.get_cmd(PAGE_SYSINFO_CONFIG)
        current = {
            f: (re.search(rf'name="{f}"[^>]*value="([^"]*)"', html) or [None, ""])[1]
            for f in ("system_name", "system_location", "system_contact")
        }
        target = {
            "system_name": name if name is not None else current["system_name"],
            "system_location": location if location is not None else current["system_location"],
            "system_contact": contact if contact is not None else current["system_contact"],
        }
        result: dict[str, Any] = {
            "op": "set_system_info", "dry_run": dry_run,
            "current": current, "target": target,
        }
        if dry_run:
            return result
        self.client.submit_form(
            {"cmd": str(PAGE_SYSINFO_APPLY), **target, "sysSubmit": "Apply"}
        )
        self.client.save_config()
        audit("set_system_info", **target)
        return {"ok": True, **result}

    def _checked_radio(self, html: str, name: str) -> str:
        m = re.search(rf'name="{name}"[^>]*value="([^"]+)"[^>]*checked', html)
        return m.group(1) if m else "0"

    def set_port_config(
        self, port: int, enabled: bool | None = None,
        speed: str | None = None, duplex: str | None = None,
        flow_control: bool | None = None, description: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Configure a port. speed: auto|10M|100M|1000M, duplex: auto|half|full.
        Refuses protected ports AND disabling/modifying a port whose link is
        UP (could strand the link's traffic) unless force=true via dry_run=... no:
        call with dry_run=False only after reviewing the preview."""
        check_ports_allowed([port])
        SPEED = {"auto": "0", "10M": "1", "100M": "2", "1000M": "3"}
        DUPLEX = {"auto": "0", "half": "1", "full": "2"}
        if speed is not None and speed not in SPEED:
            raise ValueError(f"speed must be one of {sorted(SPEED)}")
        if duplex is not None and duplex not in DUPLEX:
            raise ValueError(f"duplex must be one of {sorted(DUPLEX)}")
        status = {r.get("Port"): r for r in self.get_port_status()}
        link = status.get(str(port), {}).get("Link Status", "?")
        # lock-out: refuse to touch a port with an active link that carries
        # our own management path (protected ports are already refused; here
        # we additionally refuse disabling any UP port)
        if enabled is False and link == "Up":
            raise ValueError(
                f"Refusing to disable port {port}: link is Up — disabling it "
                "may strand connected devices. Unplug or use the web GUI."
            )
        edit_html = self.client.submit_form(
            {"cmd": str(PAGE_PORT_EDIT), "port": str(port)}
        )
        current = {
            "state": self._checked_radio(edit_html, "state"),
            "speed": self._checked_radio(edit_html, "speed"),
            "duplex": self._checked_radio(edit_html, "duplex"),
            "fc": self._checked_radio(edit_html, "fc"),
            "descp": (re.search(r'name="descp"[^>]*value="([^"]*)"', edit_html) or [None, ""])[1],
        }
        target = dict(current)
        if enabled is not None:
            target["state"] = "1" if enabled else "0"
        if speed is not None:
            target["speed"] = SPEED[speed]
        if duplex is not None:
            target["duplex"] = DUPLEX[duplex]
        if flow_control is not None:
            target["fc"] = "1" if flow_control else "0"
        if description is not None:
            target["descp"] = description
        result: dict[str, Any] = {
            "op": f"port{port}_config", "dry_run": dry_run, "link": link,
            "current": current, "target": target,
        }
        if dry_run:
            return result
        self.client.submit_form(
            {
                "cmd": str(PAGE_PORT_APPLY),
                "portlist": str(port),
                **target,
                "sysSubmit": "Apply",
            }
        )
        self.client.save_config()
        audit("set_port_config", port=port, **target)
        return {"ok": True, **result}

    # ---- extra reads -----------------------------------------------------------

    def get_port_counters(self, port: int) -> dict[str, str]:
        """Per-port MIB counters (label/value rows on the Counters page)."""
        html = self.client.get(
            {"cmd": str(PAGE_PORT_COUNTERS), "port_mib_selected": str(port)}
        )
        out: dict[str, str] = {}
        for m in re.finditer(
            r'<td class="font-title"[^>]*>\s*([^<]+?)\s*</td>\s*'
            r'<td[^>]*font-4[^>]*>\s*([^<]*?)\s*</td>',
            html,
        ):
            out[m.group(1)] = m.group(2)
        audit("read", target="port_counters", port=port)
        return out

    def get_bandwidth_utilization(self) -> dict[str, str]:
        """Bandwidth utilization page is a JS-rendered graph; not machine
        readable. Use get_port_status / get_port_counters instead."""
        return {
            "note": "bandwidth graph is JS-rendered; use get_port_counters",
        }

    def _radio_config(self, cmd: int) -> dict[str, str]:
        """Return {field: checked_value_or_text} for a config page."""
        html = self.client.get_cmd(cmd)
        out: dict[str, str] = {}
        for name in sorted(set(re.findall(r'name="([^"]+)"', html))):
            if name in ("XSSID", "cmd", "sysSubmit", "Cancel", "selall"):
                continue
            m = re.search(rf'name="{name}"[^>]*value="([^"]*)"[^>]*checked', html)
            if m:
                out[name] = m.group(1)
            else:
                m = re.search(rf'name="{name}"[^>]*value="([^"]*)"', html)
                out[name] = m.group(1) if m else ""
        return out

    def get_stp_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_STP_CONFIG)
        audit("read", target="stp_config")
        return cfg

    def get_lag_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_LAG_CONFIG)
        audit("read", target="lag_config")
        return cfg

    def get_loopguard_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_LOOPGUARD_CONFIG)
        audit("read", target="loopguard_config")
        return cfg

    def get_lldp_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_LLDP_CONFIG)
        audit("read", target="lldp_config")
        return cfg

    def get_port_security_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_PORTSEC_CONFIG)
        audit("read", target="port_security_config")
        return cfg

    def get_syslog_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_SYSLOG_CONFIG)
        audit("read", target="syslog_config")
        return cfg

    def get_mirror_config(self) -> dict[str, str]:
        cfg = self._radio_config(PAGE_MIRROR_CONFIG)
        audit("read", target="mirror_config")
        return cfg
