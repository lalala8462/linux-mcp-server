# CentOS read-only SSH overlay

The CentOS 7 compatibility server keeps its MCP tools read-only, but SSH account
permissions are an independent boundary. This repository includes a root-owned
fixed-command overlay for a dedicated `codex-ro` account.

## Repository assets

- `config/centos-policy.example.json`: Copy to the ignored
  `config/centos-policy.local.json` and set only approved read, scan, and log
  paths. Never use `/` as a read or scan root.
- `scripts/centos/linux-mcp-readonly.py`: Validates the fixed command allowlist,
  validates descriptor-backed paths, and rejects symlinks and path races.
- `scripts/centos/install-readonly-account.sh`: Installs the wrapper, policy,
  dedicated account marker, and forced public-key command.
- `scripts/centos/configure-log-access.sh`: Optional, separate log-permission
  setup. Review its file and group changes before running it.

## Account installation

Generate the client public key on the control system. Upload only the public key,
the local policy, `linux-mcp-readonly.py`, and `install-readonly-account.sh` to
the target server. Do not upload the private key.

For a new account, the target-server administrator runs:

```bash
sudo bash /tmp/linux-mcp-bootstrap/install-readonly-account.sh \
  /tmp/linux-mcp-bootstrap/id_ed25519.pub \
  /tmp/linux-mcp-bootstrap/centos-policy.local.json \
  codex-ro
```

If a legacy dedicated `codex-ro` already exists without
`/etc/linux-mcp-readonly/managed-account`, inspect its UID, groups, and sudo
rights first. Only then migrate it explicitly:

```bash
sudo bash /tmp/linux-mcp-bootstrap/install-readonly-account.sh \
  /tmp/linux-mcp-bootstrap/id_ed25519.pub \
  /tmp/linux-mcp-bootstrap/centos-policy.local.json \
  codex-ro \
  --adopt-existing
```

The installer rejects UID 0, a nonmatching primary group, wheel membership,
unapproved groups, usable noninteractive sudo, and account-name mismatches. It
locks the account password and installs an SSH forced command, so `codex-ro` is
not an interactive shell account.

## Host keys and verification

Verify the target ED25519 host-key fingerprint through a trusted channel before
placing it in `known_hosts`. Keep host-key verification enabled. Verify the
dedicated account only through an allowed fixed command or the MCP fixed tool
set; do not enable an arbitrary shell or `run_script` to troubleshoot it.
