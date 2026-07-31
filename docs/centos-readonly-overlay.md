# CentOS 6/7/8/Stream read-only SSH overlay

The CentOS 7 compatibility server keeps its MCP tools read-only, but SSH account
permissions are an independent boundary. This repository includes a root-owned
fixed-command overlay for a dedicated `codex-ro` account.

## Repository assets

- `config/centos-policy.example.json`: Copy to the ignored
  `config/centos-policy.local.json` and set one approved `allowed_root`. Never
  use `/` as the root. The policy does not change POSIX permissions or ACLs.
- `scripts/centos/linux-mcp-readonly.py`: Validates the fixed command allowlist,
  validates descriptor-backed paths, and rejects symlinks and path races. It
  remains syntax-compatible with the system Python 2.6 shipped by CentOS 6.
- `scripts/centos/install-readonly-account.sh`: Installs the wrapper, policy,
  dedicated account marker, and forced public-key command.
- `scripts/centos/uninstall-readonly-account.sh`: Performs an explicitly
  confirmed, backup-preserving reset of the managed account and overlay files.
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

Before changing the account or backing up the active files, the installer runs
the candidate wrapper with the same `/usr/bin/python` and `command -v tail`
lookup used by the SSH forced command. It also exercises the safe-open error
path to catch Python 2.6 implicit ASCII conversions. Syntax, encoding, runtime,
or unexpected lookup failures stop installation before the active wrapper is
overwritten.

CentOS 6/OpenSSH 5.3 cannot use Ed25519. Its host-specific deployment package
contains an RSA 4096 public key and the generated command includes
`--allow-rsa`. The installer rejects RSA unless that flag is present, requires
4096 bits, and always rejects DSA. CentOS 7/8/Stream continue to use Ed25519.

## Account reset

Codex only generates the uninstall archive; a target-server administrator must
run it through a trusted maintenance channel. The script requires an explicit
account confirmation, preserves timestamped backups, removes `codex-ro` and
its home, then removes the active marker, policy, and wrapper. It never removes
the shared `linux-mcp-logread` group.

## Host keys and verification

Host onboarding is two-stage. Generate an administrator-run discovery archive
with `linux-mcp-hosts discover`, import its bounded JSON with
`import-profile`, review the 19-tool capability matrix, and only then run
`prepare`. `prepare` requires a trusted host public-key file and writes
`known_hosts` directly from it; `ssh-keyscan` is never used as identity
evidence. Profiles are stored outside Git below
`~/.local/share/linux-mcp-server/hosts/<alias>/profile.json` with mode `0600`.

After the administrator installs the deployment archive, run `verify` with a
safe sample text file and a separate sample log under the host's `allowed_root`.
Confirm that `codex-ro` has POSIX or ACL read permission first; the policy does
not grant filesystem access. The command calls all 19 tools through an
in-process MCP client, stores only normalized outcome metadata, and reports
permission, timeout, authentication, and transport failures without retaining
file contents.

Use `rebuild-deployment` after wrapper or installer changes. It reuses the
managed key, includes only the public key, writes a file-hash manifest, and
refuses to overwrite an existing archive. Use `refresh` after OS, host-key, or
capability drift. Do not enable an arbitrary shell or `run_script`.
