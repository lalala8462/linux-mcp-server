# CentOS 6/7/8/Stream read-only SSH overlay

The CentOS 7 compatibility server keeps its MCP tools read-only, but SSH account
permissions are an independent boundary. This repository includes a root-owned
fixed-command overlay for a dedicated `codex-ro` account.

## Repository assets

- `config/centos-policy.example.json`: Copy to the ignored
  `config/centos-policy.local.json` and set 1–16 disjoint approved
  `allowed_roots`. Never use `/` as a root. The policy does not change POSIX
  permissions or ACLs.
- `scripts/centos/linux-mcp-readonly.py`: Validates the fixed command allowlist,
  validates descriptor-backed paths, and rejects symlinks and path races. It
  remains syntax-compatible with the system Python 2.6 shipped by CentOS 6.
- `scripts/centos/linux-mcp-privileged-read`: Optional, fixed-request root
  reader for approved regular files and directory metadata. It is installed
  only when the root-owned policy explicitly selects `read_mode=privileged`.
- `scripts/centos/install-readonly-account.sh`: Installs the wrapper, policy,
  dedicated account marker, and forced public-key command.
- `scripts/centos/uninstall-readonly-account.sh`: Performs an explicitly
  confirmed, backup-preserving reset of the managed account and overlay files.
- `scripts/centos/configure-log-access.sh`: Optional, separate log-permission
  setup. Review its file and group changes before running it.

## Account installation

Prefer the complete `linux-mcp-hosts` deployment archive described in the
[client guide](centos-client-guide.md). It includes the public key, policy, wrapper,
helper, SSH identity installer and bound deployment metadata with a file-hash
manifest. Never upload the private key. Use the complete CLI-generated archive;
an old wrapper-only archive or hand-copied sources lack the identity binding.

For a new account, the target-server administrator runs:

```bash
sudo bash /tmp/linux-mcp-bootstrap/install-readonly-account.sh \
  /tmp/linux-mcp-bootstrap/id_ed25519.pub \
  /tmp/linux-mcp-bootstrap/policy.json \
  codex-ro
```

If a legacy dedicated `codex-ro` already exists without
`/etc/linux-mcp-readonly/managed-account`, inspect its UID, groups, and sudo
rights first. Only then migrate it explicitly:

```bash
sudo bash /tmp/linux-mcp-bootstrap/install-readonly-account.sh \
  /tmp/linux-mcp-bootstrap/id_ed25519.pub \
  /tmp/linux-mcp-bootstrap/policy.json \
  codex-ro \
  --adopt-existing
```

The installer rejects UID 0, a nonmatching primary group, wheel membership,
unapproved groups, sudo rights beyond the single exact helper, and account-name mismatches. It
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
with repeated `--allowed-root` arguments, import its bounded JSON with
`import-profile`, review the 19-tool capability matrix, and only then run
`prepare`. `prepare` requires a trusted host public-key file and writes
`known_hosts` directly from it; `ssh-keyscan` is never used as identity
evidence. Profiles are stored outside Git below
`~/.local/share/linux-mcp-server/hosts/<alias>/profile.json` with mode `0600`.

Discovery validates that every approved root exists and is safe, but checks the
required `find`, `du`, and `stat` options only against the small extracted
discovery directory. It does not recursively scan approved roots. Real path
access is checked later as `codex-ro` by `verify`. Regenerate the discovery
archive to receive collector updates; an existing valid result remains
importable. Runtime `list_directories` calls ordered by size still analyze the
requested directory and can be slow for large trees.

For `user` mode, after the administrator installs the deployment archive, run `verify` with one
safe `--sample-file` under every configured root and a separate
`--sample-log-file` under any configured root. For example:

```bash
linux-mcp-hosts discover --alias server-1 \
  --allowed-root /usr \
  --allowed-root /data \
  --output-dir ~/.local/share/linux-mcp-server/bundles

linux-mcp-hosts verify --alias server-1 \
  --sample-file /usr/share/doc/example.txt \
  --sample-file /data/example.txt \
  --sample-log-file /data/example.log
```

Confirm that `codex-ro` has POSIX or ACL read permission first; the policy does
not grant filesystem access. The command calls all 19 tools through an
in-process MCP client, stores only normalized outcome metadata, and reports
permission, timeout, authentication, and transport failures without retaining
file contents. Privileged-mode samples and verification are described below.

Use `rebuild-deployment` after wrapper or installer changes. It reuses the
managed key, includes only the public key, writes a file-hash manifest, and
refuses to overwrite an existing archive. Wrapper version 6 bundles also include
`install-ssh-identity.py` and `deployment.json`. The installer checks the trusted
server host key, installed client public key and unchanged approved roots before
mutating the managed setup. Shared host keys on cloned machines do not bypass
the per-host client key check. A package is not a substitute for the operator's
trusted machine identification during first enrollment.

The account home, `.ssh` and `authorized_keys` become root-controlled with modes
`0755`, `0755`, `0644`, so sshd can read the public key while the account cannot
remove its forced command or replace the directory. Only a dedicated home named
after the account is accepted, under trusted ancestors. Descriptor-based opens,
exclusive temporary files and atomic replacement reject symlink/hardlink attacks;
the original key file is backed up with the active assets. Unexpected filesystem
objects stop installation and require administrator inspection.

Use `refresh` after OS, host-key, or capability drift. A subsequent `prepare`
validates and reuses the existing key pair instead of overwriting it; key algorithm
changes require separate reviewed migration. Each live `verify` clears the current
verified timestamp before checking, keeps historical successful state separately,
and records the latest attempt. Concurrent verification is rejected. Do not enable
an arbitrary shell or `run_script`.

Output is limited while receiving (default stdout 4 MiB, stderr 64 KiB), with two
commands per SSH connection by default. Overflow discards partial results. The
ordinary forced wrapper also has a 25-second execution alarm and nonblocking file
opens. Directory size means allocated bytes for version 6; old profile versions
remain explicitly marked as apparent bytes. Legacy `free` output reports an
explicitly estimated available value and preserves the raw used-with-cache value.

## Controlled privileged reading

`allowed_roots` is a path allowlist, not a POSIX permission grant. Policies and
legacy profiles without `read_mode` retain `user` behavior. For an explicitly
approved upgrade, use `rebuild-deployment --read-mode privileged`, keeping the
existing account, key, host identity and roots. The operator must review the
effective roots because root reading makes additional data inside them visible.

The privileged mode installs a root-owned `0700` helper and a `0440` sudoers
file granting only `codex-ro` the fixed helper with no command-line arguments.
The JSON request comes through stdin and cannot specify a policy, larger roots,
identity or arbitrary command. The helper checks kernel parent identity (including
sudo monitor and direct-exec modes), root
identity, root-controlled policy/ancestors, path components and the opened file
descriptor. Symlinks, special files, hard-linked files, writes, deletes and
unrecognized operations fail closed. It caps request/output size and runtime;
directory subprocesses are fixed `find`/`du` invocations with bounded output and
process-group cleanup. A failed scan never returns partial output as success.

Before changing the active setup, the installer checks the actual interpreter,
existing sudoers, exact authorization and protected paths. It requires
`/etc/sudoers.d` to be enabled, validates the candidate using `visudo`, and rejects
broad sudo rules rather than removing the original privilege check. It does not
enable root SSH login, store passwords, or add a service or port.

Every approved root receives a small `.linux-mcp-verify` sample tree owned by
root, including public text, `0600` root-only text/logs and `0700` directories.
Existing unexpected objects at those paths are rejected instead of overwritten.
`verify --alias <alias>` in privileged mode reads these through the actual MCP
tools and checks root file/log/directory access and out-of-root/symlink rejection
in addition to all 19 capability outcomes. It rejects imported results. File
permission failures are neither success nor unsupported capabilities. Verification
scans only the sample tree, avoiding a recursive scan of the full approved roots.

The uninstaller backs up and removes the managed helper and sudoers before the
final marker cleanup; historical backups and verification sample trees remain
for administrator-reviewed retention or removal. No business directory permission
or ACL is broadened by this mechanism.
