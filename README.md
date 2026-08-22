# zyxel-mcp

An MCP server that lets AI clients safely read and configure **Zyxel GS1900**
series smart-managed switches.

The GS1900 has no REST API or SSH — only a JavaScript-heavy web GUI. This
server reverse-engineers that GUI into 26 typed MCP tools, wrapped in
guardrails that make it safe to point an LLM at production network hardware.

Verified against a **GS1900-24E**, firmware `V2.40(AAHK.1)`.

## Why it needs guardrails

An LLM reconfiguring a switch can trivially cut its own management path — one
wrong PVID on the uplink port and the device is only reachable by physically
plugging into it. This server therefore refuses, at the HTTP layer, any
operation that could sever connectivity.

**Hard lock-outs (no override):**

- management IP / DNS / gateway / management-VLAN changes
- user accounts and authentication methods
- disabling HTTP/HTTPS or TELNET/SSH management services
- configuration restore, factory reset, firmware upload
- deleting VLAN 1, or any VLAN that still has member ports
- disabling a port whose link is currently up
- **any** write to a port listed in `ZYXEL_PROTECTED_PORTS` (uplinks, AP trunks)

**Additional safety:**

- **Dry-run by default** — every write tool takes `dry_run` (default `true`)
  and returns a current-vs-target diff without touching the switch
- **Auto-backup** — running config is exported before any write
- **Audit log** — append-only JSONL of every read and write
- **Save-on-write** — successful writes are persisted running → startup

## Install

Requires Python 3.10+.

```bash
git clone git@github.com:hugil/zyxel-mcp.git
cd zyxel-mcp
cp .env.example .env      # then edit .env
uv run mcp-zyxel
```

Register with an MCP client over stdio, e.g. `.vscode/mcp.json`:

```json
{
  "servers": {
    "zyxel": {
      "command": "uv",
      "args": ["--directory", "/path/to/zyxel-mcp", "run", "mcp-zyxel"],
      "env": {
        "ZYXEL_HOST": "192.168.1.1",
        "ZYXEL_USER": "admin",
        "ZYXEL_PASSWORD": "...",
        "ZYXEL_PROTECTED_PORTS": "1,4"
      }
    }
  }
}
```

## Configuration

All configuration is environment-based; see [`.env.example`](.env.example).

| Variable | Required | Purpose |
|---|---|---|
| `ZYXEL_HOST` | yes | Switch management IP |
| `ZYXEL_USER` | | Username (default `admin`) |
| `ZYXEL_PASSWORD` | yes | Password, or use `ZYXEL_PASSWORD_FILE` |
| `ZYXEL_SCHEME` | | `http` (default) or `https` |
| `ZYXEL_PROTECTED_PORTS` | | Ports where writes are always refused |
| `ZYXEL_AUDIT_LOG` | | Audit log path |
| `ZYXEL_BACKUP_DIR` | | Pre-write backup directory |
| `ZYXEL_SYNC_DIR` | for sync | Where snapshots are written |
| `ZYXEL_SYNC_REMOTE` | for sync | Git remote receiving snapshots |
| `ZYXEL_DHCP_LEASES` | | DHCP lease file for MAC → hostname |

> Snapshots, backups and audit logs are **operator data**, not part of this
> tool. `ZYXEL_SYNC_DIR` has no default so they never land in this source
> tree — point it somewhere outside the repository.

## Tools (26)

**Reads** — `get_system_info`, `get_port_status`, `get_port_counters`,
`list_vlans`, `get_vlan_membership`, `get_mac_table`, `get_pvids`,
`get_stp_config`, `get_lag_config`, `get_loopguard_config`, `get_lldp_config`,
`get_port_security_config`, `get_syslog_config`, `get_mirror_config`,
`get_running_config_text`

**Writes** (dry-run default, auto-backup, auto-save) —
`set_port_vlan_membership`, `set_pvid`, `set_port_config`, `set_system_info`,
`create_vlan`, `delete_vlan`

**Maintenance** — `backup_config`, `save_running_to_startup`,
`reboot(ack='REBOOT')`

**Snapshot / sync** — `sync_snapshot`, `sync_to_github`

## Config snapshots

`sync_snapshot` writes a deterministic, rebuild-ready description of the
switch to `ZYXEL_SYNC_DIR`; `sync_to_github` also commits and pushes it to
`ZYXEL_SYNC_REMOTE`.

```
$ZYXEL_SYNC_DIR/
  README.md              generated topology: VLAN table, port map,
                         membership matrix, MAC/device inventory
  running-config.cfg     full CLI config, secrets redacted
  annotations.json       hand-edited MAC -> hostname/role/notes,
                         never overwritten by a snapshot
  system.json  vlans.json  ports.json  membership.json
  mac-table.json  inventory.json  lldp-neighbors.json
  running-config.raw.cfg unscrubbed, git-ignored — never committed
```

Snapshots are **idempotent**: volatile data (uptime, wall clock, CPU/memory
load, MAC-table ordering) is stripped or sorted, so a commit appears only
when the configuration genuinely changed.

Redacted before commit: admin password hashes, SNMP community strings,
RADIUS/TACACS keys. Serial number and MAC range are kept for RMA purposes.

The generated README is designed so that if the switch dies, someone can buy
the same model and rebuild the network from the committed files alone.

## How it works

The GS1900 web GUI is driven entirely through `/cgi-bin/dispatcher.cgi`:

1. **Login** — the password is obfuscated by the login page's JavaScript into
   a 320-character string (characters placed in reverse at every 7th index,
   length digits at fixed offsets 123 and 289, remainder random). This is
   reimplemented in `encode_password()`.
2. **Session** — poll `login_chk=1` until `OK`, then scrape the `XSSID` token
   from the `cmd=1` bootstrap page. It must be sent as both a cookie and a
   hidden form field on every write. Only one web session exists per user, so
   the client clears stale sessions before authenticating.
3. **Pages** — every feature is an integer `cmd` id, e.g. `799` port status,
   `1283` VLAN list (ajax), `1290`/`1291`/`1292` PVID list/edit/apply,
   `1293`/`1294` VLAN membership view/apply, `2049` MAC table, `5899` save
   running→startup.
4. **Membership writes** must echo *every* row's current selection plus the
   hidden `vlanMode_N` fields, or unsubmitted rows silently reset.

`contrib/` holds small standalone scripts used while reverse-engineering the
GUI; they are reference material, not part of the server.

## Layout

```
src/mcp_zyxel/
  server.py        MCP tool + resource definitions
  zyxel_client.py  auth, session, XSSID handling, locked-cmd enforcement
  zyxel_ops.py     typed reads/writes per feature page
  safety.py        connectivity lock-outs, protected ports, audit, backups
  sync.py          snapshot, scrubbing, topology README, git push
contrib/           standalone probing scripts (reference)
probe.py           dump dispatcher pages and their form fields
```

## Disclaimer

Not affiliated with Zyxel. Driving an undocumented web GUI is inherently
fragile — verify behaviour against your own firmware version, and keep the
dry-run defaults on until you trust it.

## License

MIT
