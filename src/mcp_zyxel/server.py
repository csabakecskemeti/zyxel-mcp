"""MCP server exposing Zyxel GS1900 switch tools.

Optionally also exposes the operator's own network documentation as MCP
resources, so an assistant can compare the switch's live state against the
intended design. Point ZYXEL_DOCS_DIR at a directory of markdown files to
enable this; it is disabled when unset.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .zyxel_client import ZyxelClient
from .zyxel_ops import ZyxelOps
from . import sync as _sync

mcp = FastMCP("zyxel-switch")

# Optional: operator-supplied network documentation (desired state / context).
DOCS_DIR_ENV = "ZYXEL_DOCS_DIR"


def _docs_dir() -> Path | None:
    raw = os.environ.get(DOCS_DIR_ENV, "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.is_dir() else None


@mcp.resource("zyxel://docs/{name}")
def network_doc(name: str) -> str:
    """Read a markdown file from ZYXEL_DOCS_DIR (e.g. the intended VLAN plan
    or topology) so live switch state can be compared against the design."""
    base = _docs_dir()
    if base is None:
        return (
            f"No documentation directory configured. Set {DOCS_DIR_ENV} to a "
            "folder of markdown files to expose them as MCP resources."
        )
    # Resolve safely: never escape the configured directory.
    candidate = (base / name).resolve()
    if not str(candidate).startswith(str(base.resolve())):
        return "Refusing to read outside the configured documentation directory."
    if not candidate.is_file():
        available = sorted(p.name for p in base.glob("*.md"))
        return f"{name} not found. Available: {', '.join(available) or '(none)'}"
    return candidate.read_text(encoding="utf-8")


def _ops() -> ZyxelOps:
    return ZyxelOps(ZyxelClient())


# ---- read tools ----


@mcp.tool()
def get_system_info() -> str:
    """Get switch system information (model, firmware, uptime, IP)."""
    return json.dumps(_ops().get_system_info(), indent=2)


@mcp.tool()
def get_port_status() -> str:
    """Get per-port link status (up/down, speed, duplex)."""
    return json.dumps(_ops().get_port_status(), indent=2)


@mcp.tool()
def list_vlans() -> str:
    """List all VLANs configured on the switch."""
    return json.dumps(_ops().list_vlans(), indent=2)


@mcp.tool()
def get_vlan_membership(vlan_id: int = 1) -> str:
    """Get 802.1Q VLAN port membership for a VLAN (tagged/untagged/
    forbidden/excluded per port)."""
    return json.dumps(_ops().get_vlan_membership(vlan_id), indent=2)


@mcp.tool()
def get_mac_table(vlan_id: int | None = None) -> str:
    """Learned MAC addresses, optionally filtered by VLAN."""
    return json.dumps(_ops().get_mac_table(vlan_id), indent=2)


@mcp.tool()
def get_pvids() -> str:
    """Get the PVID (port VLAN ID) for every port."""
    return json.dumps(_ops().get_pvids(), indent=2)


# ---- write tools (guarded: dry_run defaults to true) ----


@mcp.tool()
def set_port_vlan_membership(
    vlan_id: int, ports: list[int], mode: str, dry_run: bool = True
) -> str:
    """Set port membership in a VLAN
    (mode: tagged|untagged|forbidden|excluded).
    Protected ports (uplink 1, AP trunk 4) are refused. Auto-backs up current
    state before applying; running config is saved to startup on success.
    dry_run=true (default) previews without applying."""
    return json.dumps(
        _ops().set_port_vlan_membership(vlan_id, ports, mode, dry_run), indent=2
    )


@mcp.tool()
def set_pvid(port: int, pvid: int, dry_run: bool = True) -> str:
    """Set a port's PVID. Protected ports (1, 4) are refused.
    dry_run=true (default) previews without applying."""
    return json.dumps(_ops().set_pvid(port, pvid, dry_run), indent=2)


# ---- maintenance tools ----


@mcp.tool()
def backup_config(content: str = "running") -> str:
    """Download a backup over HTTP into the backup dir.
    content: running|startup|backup|flash_log|buffer_log|tech_support."""
    return json.dumps(_ops().backup_config(content), indent=2)


@mcp.tool()
def get_running_config_text() -> str:
    """Fetch the running configuration as text (diffing/auditing)."""
    return _ops().get_running_config_text()


@mcp.tool()
def save_running_to_startup() -> str:
    """Copy the running configuration to the startup configuration."""
    return json.dumps(_ops().save_running_to_startup(), indent=2)


@mcp.tool()
def reboot(ack: str = "") -> str:
    """Reboot the switch (drops management ~1 min, discards unsaved changes).
    Requires ack='REBOOT'. A config backup is taken first."""
    return json.dumps(_ops().reboot(ack), indent=2)


@mcp.tool()
def create_vlan(vlan_id: int, name: str, dry_run: bool = True) -> str:
    """Create a VLAN. dry_run=true (default) previews; auto-backup on apply."""
    return json.dumps(_ops().create_vlan(vlan_id, name, dry_run), indent=2)


@mcp.tool()
def delete_vlan(vlan_id: int, dry_run: bool = True) -> str:
    """Delete a VLAN. Refuses VLAN 1 and any VLAN with member ports.
    dry_run=true (default) previews."""
    return json.dumps(_ops().delete_vlan(vlan_id, dry_run), indent=2)


@mcp.tool()
def set_system_info(
    name: str | None = None, location: str | None = None,
    contact: str | None = None, dry_run: bool = True,
) -> str:
    """Set system name/location/contact. dry_run=true (default) previews."""
    return json.dumps(
        _ops().set_system_info(name, location, contact, dry_run), indent=2
    )


@mcp.tool()
def set_port_config(
    port: int, enabled: bool | None = None, speed: str | None = None,
    duplex: str | None = None, flow_control: bool | None = None,
    description: str | None = None, dry_run: bool = True,
) -> str:
    """Configure a port (speed: auto|10M|100M|1000M, duplex: auto|half|full).
    Refuses protected ports and disabling any port with link Up.
    dry_run=true (default) previews current vs target."""
    return json.dumps(
        _ops().set_port_config(
            port, enabled, speed, duplex, flow_control, description, dry_run
        ),
        indent=2,
    )


# ---- diagnostic reads ----


@mcp.tool()
def get_port_counters(port: int) -> str:
    """Per-port MIB counters (octets, packets, discards, errors)."""
    return json.dumps(_ops().get_port_counters(port), indent=2)


@mcp.tool()
def get_stp_config() -> str:
    """Spanning Tree global configuration."""
    return json.dumps(_ops().get_stp_config(), indent=2)


@mcp.tool()
def get_lag_config() -> str:
    """Link Aggregation (LACP) global configuration."""
    return json.dumps(_ops().get_lag_config(), indent=2)


@mcp.tool()
def get_loopguard_config() -> str:
    """Loop guard (RLDP) configuration."""
    return json.dumps(_ops().get_loopguard_config(), indent=2)


@mcp.tool()
def get_lldp_config() -> str:
    """LLDP configuration."""
    return json.dumps(_ops().get_lldp_config(), indent=2)


@mcp.tool()
def get_port_security_config() -> str:
    """Port Security configuration."""
    return json.dumps(_ops().get_port_security_config(), indent=2)


@mcp.tool()
def get_syslog_config() -> str:
    """Syslog configuration."""
    return json.dumps(_ops().get_syslog_config(), indent=2)


@mcp.tool()
def get_mirror_config() -> str:
    """Port mirroring configuration."""
    return json.dumps(_ops().get_mirror_config(), indent=2)


# ---- github sync tools ----


@mcp.tool()
def sync_snapshot() -> str:
    """Write a rebuild-ready snapshot of the switch into the directory given
    by ZYXEL_SYNC_DIR: scrubbed running config, JSON dumps of VLANs / ports /
    MACs / LLDP, a MAC-keyed inventory, and a generated topology README.
    Does NOT push to git."""
    return json.dumps(_sync.snapshot(_ops()), indent=2)


@mcp.tool()
def sync_to_github(message: str | None = None, branch: str = "main",
                    remote: str | None = None) -> str:
    """Snapshot, then commit and push it to the operator's own repository.
    The target comes from `remote` or ZYXEL_SYNC_REMOTE; the snapshot
    directory comes from ZYXEL_SYNC_DIR. Neither has a built-in default."""
    snap = _sync.snapshot(_ops())
    push = _sync.push_to_github(remote=remote, message=message, branch=branch)
    return json.dumps({"snapshot": snap, "push": push}, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
