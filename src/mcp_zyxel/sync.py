"""Snapshot the switch state into a git-friendly tree and optionally push it
to a git remote.

The destination is entirely operator-controlled and lives OUTSIDE this
package: set ZYXEL_SYNC_DIR to the directory that should hold the snapshot
and ZYXEL_SYNC_REMOTE to the repository that should receive it. The snapshot
is user data describing one particular switch, not part of this tool.

Files produced (all deterministic; sort keys, LF endings, stable order):
  $ZYXEL_SYNC_DIR/
    README.md                 topology + inventory (auto-generated)
    running-config.cfg        scrubbed CLI config (safe to publish)
    running-config.raw.cfg    unscrubbed copy (git-ignored)
    system.json               model / firmware / uptime / IPs
    vlans.json                VLAN id -> name / type
    ports.json                per-port PVID / VLAN / speed / link / desc
    membership.json           per-VLAN port membership matrix
    mac-table.json            learned MAC -> {port, vlan}
    lldp-neighbors.json       LLDP remote-info (may be empty)
    inventory.json            MAC -> {hostname, ip, notes} merged from DHCP
    .gitignore                excludes raw config + secrets
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .safety import audit
from .zyxel_client import ZyxelClient
from .zyxel_ops import ZyxelOps

SYNC_DIR_ENV = "ZYXEL_SYNC_DIR"
REMOTE_ENV = "ZYXEL_SYNC_REMOTE"
DHCP_LEASES_ENV = "ZYXEL_DHCP_LEASES"  # optional path to DHCP lease/host file

# MAC OUI prefixes -> vendor. Gives instant device identification without any
# external dependency. Extend freely; unknown prefixes simply render blank.
OUI_VENDORS = {
    "60:31:97": "ZyXEL (this switch)",
    "70:54:D2": "ASUS",
    "1C:B7:2C": "ASUS",
    "7C:05:07": "Dell/Intel NIC",
    "BC:24:11": "Proxmox VE (QEMU virtual NIC)",
    "5A:46:10": "locally-administered / virtual",
    "DA:9B:8C": "locally-administered / virtual",
    "C0:C7:DB": "Apple",
    "60:CF:84": "Intel",
    "78:86:2E": "Samsung",
}


# ---- scrubbing ------------------------------------------------------------

_SECRET_PATTERNS = [
    # username "admin" secret encrypted <b64>
    (re.compile(r'(secret encrypted\s+)\S+'), r'\1<REDACTED>'),
    # snmp community "public" rw
    (re.compile(r'(snmp community\s+")[^"]+(")'), r'\1<REDACTED>\2'),
    # any radius/tacacs shared key patterns (defensive)
    (re.compile(r'(key\s+encrypted\s+)\S+'), r'\1<REDACTED>'),
]


def scrub_config(text: str) -> str:
    """Redact password hashes and community strings from a CLI config."""
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


# Header comments that change on every read (uptime) and would otherwise
# produce a spurious git commit each time the sync runs.
_VOLATILE_LINE = re.compile(r'^! System Up Time:', re.I)


def strip_volatile_config(text: str) -> str:
    """Remove non-configuration, time-varying lines from a CLI config."""
    return "\n".join(
        line for line in text.splitlines() if not _VOLATILE_LINE.match(line)
    ) + "\n"


# ---- inventory helpers ----------------------------------------------------

_LEASE_LINE = re.compile(
    r'^\s*(?P<mac>[0-9a-f:]{17})\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<host>\S+)?', re.I,
)


def parse_dhcp_leases(path: Path) -> dict[str, dict[str, str]]:
    """Parse an OPNsense/dnsmasq/kea-style lease or hosts file if provided.

    Accepts either dnsmasq `dnsmasq.leases` format
    (`ts mac ip hostname client-id`) or Kea CSV (`address,hwaddr,...,hostname`).
    Returns {mac_upper: {"ip": ..., "hostname": ...}}.
    """
    out: dict[str, dict[str, str]] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # dnsmasq: "ts mac ip host client-id"
        parts = line.split()
        if len(parts) >= 4 and re.match(r'^\d+$', parts[0]) and \
                re.match(r'^[0-9a-f:]{17}$', parts[1], re.I):
            mac = parts[1].upper()
            out[mac] = {"ip": parts[2], "hostname": parts[3]}
            continue
        # Kea CSV: address,hwaddr,client_id,...,hostname,...
        if "," in line:
            fields = [c.strip() for c in line.split(",")]
            if len(fields) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', fields[0]) \
                    and re.match(r'^[0-9a-f:]{17}$', fields[1], re.I):
                mac = fields[1].upper()
                host = fields[9] if len(fields) > 9 else ""
                out[mac] = {"ip": fields[0], "hostname": host}
                continue
    return out


# ---- snapshot -------------------------------------------------------------


def vendor_for(mac: str) -> str:
    """Best-effort vendor name from the MAC OUI prefix."""
    prefix = mac.upper()[:8]
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    # locally-administered bit set in the first octet => virtual/randomised
    try:
        first = int(mac.split(":")[0], 16)
        if first & 0b10:
            return "locally-administered / virtual"
    except (ValueError, IndexError):
        pass
    return ""


def reverse_dns(ip: str) -> str:
    import socket

    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def load_annotations(d: Path) -> dict[str, dict[str, str]]:
    """Hand-maintained MAC -> {hostname, notes} overrides.

    This file is NEVER overwritten by a snapshot, so operator knowledge
    (what is actually plugged into port 8, etc.) survives regeneration and
    ends up in the committed README.
    """
    path = d / "annotations.json"
    if not path.exists():
        path.write_text(
            json.dumps(
                {
                    "_comment": "Hand-edited. MAC -> {hostname, role, notes}. "
                                "Never overwritten by sync; merged into "
                                "inventory.json and README.md.",
                    "00:00:00:00:00:00": {
                        "hostname": "example-host",
                        "role": "example — delete me",
                        "notes": "",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {
        k.upper(): v for k, v in raw.items()
        if not k.startswith("_") and isinstance(v, dict)
    }


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def sync_dir() -> Path:
    """Where snapshots are written. Must be set by the operator.

    Snapshots are *user data* describing a particular switch — they are
    deliberately never written inside this package's own source tree.
    """
    raw = os.environ.get(SYNC_DIR_ENV, "").strip()
    if not raw:
        raise RuntimeError(
            f"{SYNC_DIR_ENV} is not set. Point it at a directory outside this "
            "repository where the switch snapshot should be written, e.g. "
            f"{SYNC_DIR_ENV}=~/network-state/switch-config"
        )
    return Path(raw).expanduser().resolve()


def snapshot(ops: ZyxelOps | None = None) -> dict[str, Any]:
    """Pull the switch state and write it into the sync dir.

    Returns a summary describing files written.
    """
    ops = ops or ZyxelOps(ZyxelClient())
    d = sync_dir()
    d.mkdir(parents=True, exist_ok=True)

    system_raw = ops.get_system_info()
    # Drop volatile telemetry (uptime, wall clock, CPU/mem load) so a snapshot
    # is byte-identical when nothing about the *configuration* changed. This
    # keeps git history meaningful: one commit == one real config change.
    system = {k: v for k, v in system_raw.items()
              if k not in ("sysUptime", "sysCurrtime", "sysCpuUtilz",
                            "sysMemUtilz")}
    port_status = ops.get_port_status()
    pvids = ops.get_pvids()
    vlan_list = ops.list_vlans()
    membership: dict[str, dict[str, str]] = {}
    for v in vlan_list:
        vid = int(v["vlan_id"])
        membership[str(vid)] = ops.get_vlan_membership(vid)
    mac_rows = ops.get_mac_table()
    lldp = _safe(lambda: ops.get_lldp_config())
    running_raw = ops.get_running_config_text()
    running_scrubbed = strip_volatile_config(scrub_config(running_raw))

    leases_env = os.environ.get(DHCP_LEASES_ENV)
    leases = parse_dhcp_leases(Path(leases_env)) if leases_env else {}
    annotations = load_annotations(d)
    inventory = _build_inventory(mac_rows, port_status, pvids, leases,
                                  annotations)
    ports = _build_ports(port_status, pvids, membership, inventory)

    # Files
    _write_json(d / "system.json", system)
    _write_json(d / "vlans.json", vlan_list)
    _write_json(d / "ports.json", ports)
    _write_json(d / "membership.json", membership)
    _write_json(
        d / "mac-table.json",
        sorted(mac_rows, key=lambda r: (r.get("MAC Address", ""),
                                         r.get("VLAN", ""),
                                         r.get("Port", ""))),
    )
    _write_json(d / "lldp-neighbors.json", lldp or {})
    _write_json(d / "inventory.json", inventory)
    (d / "running-config.cfg").write_text(running_scrubbed, encoding="utf-8")
    (d / "running-config.raw.cfg").write_text(running_raw, encoding="utf-8")
    (d / ".gitignore").write_text(
        "# Never publish the unscrubbed config (contains hashes/community)\n"
        "running-config.raw.cfg\n",
        encoding="utf-8",
    )
    (d / "README.md").write_text(
        render_topology_readme(system, vlan_list, ports, membership,
                                mac_rows, inventory, lldp),
        encoding="utf-8",
    )

    audit("sync_snapshot", dir=str(d),
          vlans=len(vlan_list), ports=len(ports), macs=len(mac_rows))
    return {
        "ok": True,
        "dir": str(d),
        "files": sorted(p.name for p in d.iterdir() if p.is_file()),
        "counts": {"vlans": len(vlan_list), "ports": len(ports),
                    "macs": len(mac_rows), "known_hosts": len(inventory)},
    }


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


def _build_ports(port_status, pvids, membership, inventory):
    """Combine per-port link, PVID, membership, and known device into one row."""
    by_port_pvid = {r.get("Port"): r for r in pvids}
    by_port_status = {r.get("Port"): r for r in port_status}
    # port -> devices learned there (a MAC may appear on several ports)
    port_macs: dict[str, list[dict[str, str]]] = {}
    for mac, info in inventory.items():
        for prt in (info.get("ports") or [info.get("port", "")]):
            port_macs.setdefault(prt, []).append(
                {"mac": mac, "vlan": ", ".join(info.get("vlans", []))
                 or info.get("vlan", ""),
                 "hostname": info.get("hostname", ""),
                 "ip": info.get("ip", "")}
            )
    result: list[dict[str, Any]] = []
    all_ports = sorted(set(list(by_port_pvid) + list(by_port_status)),
                       key=_port_sort_key)
    for p in all_ports:
        pv = by_port_pvid.get(p, {})
        ps = by_port_status.get(p, {})
        vlans_here = sorted(
            [vid for vid, m in membership.items()
             if m.get(_port_membership_label(p), "Excluded")
                not in ("Excluded", "Forbidden")],
            key=int,
        )
        result.append({
            "port": p,
            "description": pv.get("Port Name") or ps.get("Port Name") or "",
            "link": ps.get("Link Status", ""),
            "speed": ps.get("Speed", ""),
            "duplex": ps.get("Duplex", ""),
            "state": ps.get("State", ""),
            "pvid": pv.get("PVID", ""),
            "accept_frame_type": pv.get("Accept Frame Type", ""),
            "vlan_trunk": pv.get("VLAN Trunk", ""),
            "vlans": vlans_here,
            "devices": sorted(port_macs.get(p, []),
                              key=lambda x: (x["vlan"], x["mac"])),
        })
    return result


def _port_sort_key(p: str) -> tuple[int, int]:
    """Order numeric ports before LAG*."""
    if p.isdigit():
        return (0, int(p))
    m = re.match(r'LAG(\d+)', p, re.I)
    return (1, int(m.group(1)) if m else 999)


def _port_membership_label(p: str) -> str:
    """Map a switch port label (e.g. '5', 'LAG1') to the membership dict key."""
    if p.isdigit():
        return f"Port{int(p):02d}"
    return p.upper()


def _build_inventory(mac_rows, port_status, pvids, leases, annotations=None):
    """Combine learned MACs with DHCP hostnames into an inventory keyed by MAC.

    A MAC can appear on several VLANs (e.g. a router trunk port), so `vlans`
    is a sorted list and `ports` collects every port it was learned on.
    `vlan`/`port` remain as the primary (first non-CPU) values for display.
    """
    inv: dict[str, dict[str, Any]] = {}
    for row in mac_rows:
        mac = row.get("MAC Address", "").upper()
        if not mac or mac.startswith("00:00:00:00"):
            continue
        port = row.get("Port", "")
        vlan = row.get("VLAN", "")
        entry = inv.setdefault(mac, {
            "port": port, "vlan": vlan, "ports": [], "vlans": [],
            "type": row.get("Type", ""), "hostname": "", "ip": "",
            "vendor": vendor_for(mac), "role": "", "notes": "",
        })
        if vlan and vlan not in entry["vlans"]:
            entry["vlans"].append(vlan)
        if port and port not in entry["ports"]:
            entry["ports"].append(port)
        # prefer the first-seen non-CPU port as the primary location
        if entry["port"] in ("", "CPU") and port not in ("", "CPU"):
            entry["port"] = port
            entry["vlan"] = vlan
        lease = leases.get(mac)
        if lease:
            entry["hostname"] = lease.get("hostname", "") or entry["hostname"]
            entry["ip"] = lease.get("ip", "") or entry["ip"]
    # Hand-maintained annotations win over everything else.
    for mac, ann in (annotations or {}).items():
        entry = inv.get(mac)
        if entry is None:
            continue
        for field in ("hostname", "ip", "role", "notes"):
            if ann.get(field):
                entry[field] = ann[field]
    # Fill any still-unknown hostname from reverse DNS when we know the IP.
    for entry in inv.values():
        if not entry["hostname"] and entry.get("ip"):
            entry["hostname"] = reverse_dns(entry["ip"])
        entry["vlans"] = sorted(entry["vlans"])
        entry["ports"] = sorted(entry["ports"], key=_port_sort_key)
    return inv


# ---- README (topology) ----------------------------------------------------


def render_topology_readme(system, vlan_list, ports, membership, mac_rows,
                            inventory, lldp) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    host = os.environ.get("ZYXEL_HOST", "?")
    sysname = system.get("sysName", "GS1900")
    model = "GS1900-24E"
    lines: list[str] = []
    lines += [
        f"# Homelab Switch Config — `{sysname}` ({model} at {host})",
        "",
        f"_Auto-generated by mcp-zyxel at {ts}. Do not edit by hand — it will_",
        "_be overwritten on the next `sync_to_github` call. Edit the sync_",
        "_module or the source-of-truth docs to change what appears here._",
        "",
        "## Rebuild-from-scratch summary",
        "",
        "If this switch dies, buy the same model, factory-reset it, and:",
        "",
        "1. Load `running-config.cfg` (secrets redacted; set new admin password"
        " + SNMP community).",
        "2. Verify VLANs and port assignments match the tables below.",
        "3. Cross-check learned MACs against `inventory.json` — every listed"
        " device should reappear on its documented port.",
        "",
    ]

    # System
    lines += ["## System", "", "```"]
    for k in ("sysName", "sysUptime", "sysCurrtime", "sysCpuUtilz", "sysMemUtilz"):
        if k in system:
            lines.append(f"{k:14s} {system[k]}")
    lines += ["```", ""]

    # VLANs
    lines += ["## VLANs", "", "| ID | Name | Type |", "|----|------|------|"]
    for v in sorted(vlan_list, key=lambda x: int(x["vlan_id"])):
        lines.append(f"| {v['vlan_id']} | {v['name']} | {v['type']} |")
    lines += [""]

    # Port map
    lines += [
        "## Port map",
        "",
        "| Port | Link | Speed | PVID | Trunk | VLAN members | Device(s) |",
        "|------|------|-------|------|-------|--------------|-----------|",
    ]
    for p in ports:
        devs = ", ".join(
            f"{d['hostname'] or d['mac']}"
            + (f" ({d['ip']})" if d.get('ip') else "")
            for d in p.get("devices", [])
        )
        lines.append(
            f"| {p['port']} | {p['link']} | {p['speed']} | {p['pvid']} | "
            f"{p['vlan_trunk']} | {','.join(p['vlans']) or '-'} | {devs or '-'} |"
        )
    lines += [""]

    # VLAN membership matrix
    lines += ["## VLAN membership matrix", "",
              "Rows = ports, columns = VLANs. `U`=untagged, `T`=tagged,"
              " `F`=forbidden, `-`=excluded.", ""]
    vids = sorted((int(v["vlan_id"]) for v in vlan_list))
    header = "| Port | " + " | ".join(f"V{v}" for v in vids) + " |"
    sep = "|------|" + "|".join(["----"] * len(vids)) + "|"
    lines += [header, sep]
    for p in ports:
        label = _port_membership_label(p["port"])
        cells = []
        for v in vids:
            m = membership.get(str(v), {}).get(label, "Excluded")
            cells.append({"Untagged": "U", "Tagged": "T",
                           "Forbidden": "F", "Excluded": "-"}.get(m, "?"))
        lines.append(f"| {p['port']} | " + " | ".join(cells) + " |")
    lines += [""]

    # Inventory / MAC map
    lines += [
        "## Device inventory (MAC address map)",
        "",
        f"Learned MACs at snapshot time: **{len(inventory)}** unique."
        " Hostnames/roles come from `annotations.json` (hand-maintained,"
        " never overwritten), the DHCP lease file when `ZYXEL_DHCP_LEASES`"
        " is set, and reverse DNS. Vendor is derived from the MAC OUI.",
        "",
        "> To name a device, add its MAC to `annotations.json` and re-run the"
        " sync — the entry will appear here permanently.",
        "",
        "| MAC | Hostname | Role | Vendor | IP | VLAN(s) | Port(s) |",
        "|-----|----------|------|--------|----|---------|---------|",
    ]
    for mac in sorted(inventory):
        e = inventory[mac]
        vlans = ", ".join(e.get("vlans", [])) or e.get("vlan", "")
        prts = ", ".join(e.get("ports", [])) or e.get("port", "")
        lines.append(
            f"| `{mac}` | {e.get('hostname','') or '—'} | {e.get('role','') or '—'} "
            f"| {e.get('vendor','') or '—'} | {e.get('ip','') or '—'} | "
            f"{vlans} | {prts} |"
        )
    lines += [""]

    # LLDP
    lines += ["## LLDP", "", "```json",
              json.dumps(lldp or {}, indent=2, sort_keys=True), "```", ""]
    lines += ["## Files in this directory", "",
              "- `running-config.cfg` — full CLI config (secrets redacted)",
              "- `annotations.json` — **hand-edited** MAC → hostname/role/notes;"
              " never overwritten by sync",
              "- `system.json`, `vlans.json`, `ports.json`, `membership.json`",
              "- `mac-table.json`, `inventory.json`, `lldp-neighbors.json`",
              "- `running-config.raw.cfg` — unscrubbed (`.gitignore`d)",
              ""]
    return "\n".join(lines)


# ---- git push -------------------------------------------------------------


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=check, capture_output=True, text=True,
    )


def push_to_github(remote: str | None = None,
                    branch: str = "main",
                    message: str | None = None) -> dict[str, Any]:
    """Init (if needed), commit and push the snapshot directory to GitHub."""
    d = sync_dir()
    if not d.exists():
        raise RuntimeError(f"sync dir {d} does not exist; run snapshot first")
    remote_url = remote or os.environ.get(REMOTE_ENV, "").strip()
    if not remote_url:
        raise RuntimeError(
            f"No git remote configured. Set {REMOTE_ENV} (or pass remote=...) "
            "to the repository that should receive the snapshot, e.g. "
            f"{REMOTE_ENV}=git@github.com:you/your-switch-config.git"
        )

    if not (d / ".git").exists():
        _git(d, "init", "-q", "-b", branch)
    # Ensure remote 'origin' matches desired URL
    existing = _git(d, "remote", check=False).stdout.split()
    if "origin" in existing:
        _git(d, "remote", "set-url", "origin", remote_url)
    else:
        _git(d, "remote", "add", "origin", remote_url)

    _git(d, "add", "-A")
    status = _git(d, "status", "--porcelain").stdout.strip()
    if not status:
        audit("sync_push", result="clean", remote=remote_url)
        return {"ok": True, "pushed": False, "reason": "no changes",
                "remote": remote_url}

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    msg = message or f"switch snapshot {ts}"
    _git(d, "commit", "-q", "-m", msg)
    try:
        push = _git(d, "push", "-u", "origin", branch)
        out = push.stdout + push.stderr
    except subprocess.CalledProcessError as e:
        audit("sync_push", result="failed", remote=remote_url,
              stderr=e.stderr[:500])
        raise RuntimeError(
            f"git push failed. Ensure the deploy key is added to "
            f"{remote_url} with write access. stderr: {e.stderr.strip()}"
        ) from e
    audit("sync_push", result="ok", remote=remote_url, branch=branch,
          message=msg)
    return {"ok": True, "pushed": True, "remote": remote_url,
            "branch": branch, "message": msg,
            "git_output": out.strip()[-400:]}
