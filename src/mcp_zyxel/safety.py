"""Safety guardrails: connectivity lock-outs, protected ports, auto-backup,
dry-run, audit log.

Connectivity lock-outs (never allowed, no override):
  - changing the switch management IP settings (System > IP)
  - deleting/editing users, admin accounts, or auth methods
  - disabling HTTP(S)/TELNET/SSH management services
  - firmware upload, configuration restore, factory reset, reboot
    (these have dedicated, explicitly-acknowledged tools instead)
Port protections:
  - ports in ZYXEL_PROTECTED_PORTS (uplink/AP trunk) refuse VLAN-membership,
    PVID, trunk-mode and port-disable writes
  - additionally, any port with an ACTIVE link refuses changes that could
    strand the link (PVID/trunk/membership flip) unless force=true
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

# Dispatcher cmd ids whose POSTs can sever management connectivity.
LOCKED_WRITE_CMDS = {
    "517",   # System > IP apply
    "526",   # Users apply
    "545",   # HTTP/HTTPS apply
    "549",   # TELNET/SSH apply
    "4865",  # Auth method apply
    "5897",  # Configuration restore
    "5891",  # Factory default
}

# Pages these lock-outs guard (for error messages)
LOCKED_FEATURES = {
    "517": "management IP settings",
    "526": "user accounts",
    "545": "HTTP/HTTPS service",
    "549": "TELNET/SSH service",
    "4865": "authentication methods",
    "5897": "configuration restore",
    "5891": "factory default",
}


class ProtectedPortError(Exception):
    pass


class ConnectivityLockError(Exception):
    pass


def protected_ports() -> set[int]:
    raw = os.environ.get("ZYXEL_PROTECTED_PORTS", "1,4")
    return {int(p.strip()) for p in raw.split(",") if p.strip().isdigit()}


def check_ports_allowed(ports: list[int]) -> None:
    blocked = protected_ports() & set(ports)
    if blocked:
        raise ProtectedPortError(
            f"Refusing to modify protected port(s) {sorted(blocked)} — "
            "these are uplink/trunk ports (OPNsense uplink=1, AP trunk=4). "
            "Override by changing ZYXEL_PROTECTED_PORTS."
        )


def check_write_cmd_allowed(cmd: int | str) -> None:
    """Refuse POSTs to dispatcher pages that can sever management access."""
    key = str(cmd)
    if key in LOCKED_WRITE_CMDS:
        raise ConnectivityLockError(
            f"Refusing to write {LOCKED_FEATURES.get(key, key)} via cmd={key}: "
            "this can sever management connectivity to the switch. There is "
            "no override; perform such changes from the console/web GUI."
        )


def audit_log_path() -> Path:
    return Path(os.environ.get("ZYXEL_AUDIT_LOG", "audit.jsonl"))


def audit(operation: str, **details: object) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "op": operation, **details}
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def backup_dir() -> Path:
    d = Path(os.environ.get("ZYXEL_BACKUP_DIR", "backups"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_backup(name: str, content: str | bytes) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    binary = isinstance(content, bytes)
    path = backup_dir() / f"{name}-{stamp}{'-config.bin' if binary else '.txt'}"
    if binary:
        path.write_bytes(content)  # type: ignore[arg-type]
    else:
        path.write_text(content, encoding="utf-8")  # type: ignore[arg-type]
    audit("backup_written", file=str(path), size=len(content))
    return path
