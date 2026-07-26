# CentOS 7 compatibility

Version `1.5.0+centos7.1` preserves the upstream fixed tool set and adds
read-only command variants for older util-linux and procps-ng releases.

When a new SSH connection is established, the server probes fixed command
shapes for:

- `findmnt --df --json`, falling back to `findmnt -D -P`;
- `lsblk --json`, falling back to `lsblk -P`, with an optional `PKNAME`
  hierarchy;
- `free -b -w`, falling back to `free -b`.

The probe rejects timeouts and permission failures instead of treating them as
platform incompatibilities. Selected fallback commands are recorded through a
structured `COMPAT_FALLBACK` audit event containing the host, OS version,
kernel, package version, capability, and variant. Command output is not included
in the event.

The remote SSH account must still enforce a root-owned fixed-command allowlist.
This fork does not enable arbitrary shell or `run_script` execution.
