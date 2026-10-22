#!/usr/bin/env python3
"""Manage the two-stage lifecycle for profiled CentOS MCP hosts."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

from datetime import datetime
from datetime import timezone
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from typing import cast
from typing import Literal

from linux_mcp_server import __version__
from linux_mcp_server.host_registry import CapabilityProfile
from linux_mcp_server.host_registry import HostProfile
from linux_mcp_server.host_registry import MANAGED_TOOL_NAMES
from linux_mcp_server.host_registry import normalize_allowed_roots
from linux_mcp_server.host_registry import normalize_ssh_public_key
from linux_mcp_server.host_registry import OSProfile
from linux_mcp_server.host_registry import PROFILE_SCHEMA_VERSION
from linux_mcp_server.host_registry import SSHProfile
from linux_mcp_server.host_registry import TOOL_BACKENDS


MAX_JSON_BYTES = 1024 * 1024
REGISTRY_DEFAULT = Path.home() / ".local" / "share" / "linux-mcp-server" / "hosts"
ASSET_ROOT = Path(__file__).resolve().parent / "centos"
COLLECTOR = ASSET_ROOT / "collect-host-profile.py"
INSTALLER = ASSET_ROOT / "install-readonly-account.sh"
WRAPPER = ASSET_ROOT / "linux-mcp-readonly.py"
PRIVILEGED_HELPER = ASSET_ROOT / "linux-mcp-privileged-read"
WRAPPER_VERSION = "5"
ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
ROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
VERIFICATION_REASONS = frozenset(
    {
        "matched profile",
        "permission_denied",
        "transport_closed",
        "command_timeout",
        "authentication_failed",
        "empty_output",
        "tool_error",
        "profile_mismatch",
    }
)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=path.name + ".",
        delete=False,
    ) as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"JSON file is missing or unsafe: {path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise RuntimeError(f"JSON file exceeds the 1 MiB limit: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Invalid JSON file: {path}") from error
    if not isinstance(payload, dict):
        raise RuntimeError("JSON root must be an object")
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_alias(alias: str) -> str:
    if not ALIAS_RE.fullmatch(alias):
        raise RuntimeError(f"Invalid managed host alias: {alias}")
    return alias


def validate_allowed_roots(values: list[str]) -> tuple[str, ...]:
    normalized = []
    for value in values:
        root = value.rstrip("/")
        if root == "" or root == "/" or not ROOT_RE.fullmatch(root) or ".." in root.split("/"):
            raise RuntimeError("allowed_roots entries must be safe non-root absolute paths")
        normalized.append(root)
    try:
        return normalize_allowed_roots(normalized)
    except ValueError as error:
        raise RuntimeError(str(error)) from error


def validate_discovery(  # noqa: C901
    payload: dict[str, Any],
    alias: str,
    allowed_roots: tuple[str, ...],
) -> dict[str, Any]:
    schema_version = payload.get("schema_version")
    root_field = "allowed_root" if schema_version == 1 else "allowed_roots"
    required = {"schema_version", "alias", root_field, "os", "ssh", "capabilities", "collected_at"}
    if set(payload) not in (required, required | {"runtime"}):
        raise RuntimeError(f"Discovery JSON fields do not match schema version {schema_version}")
    if schema_version not in (1, PROFILE_SCHEMA_VERSION):
        raise RuntimeError("Unsupported discovery schema version")
    if payload["alias"] != alias:
        raise RuntimeError("Discovery alias does not match the requested alias")
    discovered_roots = (
        validate_allowed_roots([payload["allowed_root"]])
        if schema_version == 1
        else validate_allowed_roots(payload["allowed_roots"])
    )
    if discovered_roots != allowed_roots:
        raise RuntimeError("Discovery allowed_roots do not match the requested roots")
    try:
        collected_at = datetime.fromisoformat(payload["collected_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise RuntimeError("Invalid discovery timestamp") from error
    if collected_at.tzinfo is None:
        raise RuntimeError("Discovery timestamp must include a timezone")
    os_profile = OSProfile.model_validate(payload["os"])
    capabilities = {name: CapabilityProfile.model_validate(value) for name, value in payload["capabilities"].items()}
    if set(capabilities) != MANAGED_TOOL_NAMES:
        raise RuntimeError("Discovery result does not contain exactly the 19 MCP capabilities")
    for tool_name, item in capabilities.items():
        if item.backend not in TOOL_BACKENDS[tool_name]:
            raise RuntimeError(f"Unsupported discovery backend for {tool_name}")
        if (item.backend == "none") != (item.status == "unsupported"):
            raise RuntimeError(f"Discovery backend/status mismatch for {tool_name}")
    ssh = payload["ssh"]
    if not isinstance(ssh, dict) or set(ssh) != {"server_version", "host_keys"}:
        raise RuntimeError("Invalid discovery SSH object")
    if not isinstance(ssh["server_version"], str) or len(ssh["server_version"]) > 512:
        raise RuntimeError("Invalid OpenSSH version")
    host_keys = ssh["host_keys"]
    if not isinstance(host_keys, list) or not 1 <= len(host_keys) <= 2:
        raise RuntimeError("Discovery must contain one or two supported host public keys")
    normalized_keys = []
    for item in host_keys:
        if not isinstance(item, dict) or set(item) != {"type", "public_key"}:
            raise RuntimeError("Invalid discovered host key")
        key_type = item["type"]
        public_key = normalize_public_key(item["public_key"])
        if key_type not in {"ssh-ed25519", "ssh-rsa"} or not public_key.startswith(key_type + " "):
            raise RuntimeError("Unsupported or mismatched host key")
        normalized_keys.append({"type": key_type, "public_key": public_key})
    normalized = dict(payload)
    normalized["schema_version"] = PROFILE_SCHEMA_VERSION
    normalized["allowed_roots"] = list(discovered_roots)
    normalized.pop("allowed_root", None)
    normalized["os"] = os_profile.model_dump(mode="json")
    normalized["capabilities"] = {name: capabilities[name].model_dump(mode="json") for name in sorted(capabilities)}
    normalized["ssh"] = {"server_version": ssh["server_version"], "host_keys": normalized_keys}
    runtime = payload.get("runtime")
    if runtime is not None:
        if not isinstance(runtime, dict) or set(runtime) != {"python_executable", "python_version"}:
            raise RuntimeError("Invalid discovery runtime object")
        executable = runtime["python_executable"]
        version = runtime["python_version"]
        if (
            not isinstance(executable, str)
            or not ROOT_RE.fullmatch(executable)
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        ):
            raise RuntimeError("Invalid discovery Python runtime")
        normalized["runtime"] = {
            "python_executable": executable,
            "python_version": version,
        }
    return normalized


def normalize_public_key(value: str) -> str:
    try:
        return normalize_ssh_public_key(value, {"ssh-ed25519", "ssh-rsa"})
    except ValueError as error:
        if isinstance(value, str) and value.startswith("ssh-dss "):
            raise RuntimeError("Only Ed25519 and RSA public keys are accepted") from error
        raise RuntimeError("Invalid SSH public key") from error


def fingerprint(public_key: str) -> str:
    blob = base64.b64decode(public_key.split()[1].encode("ascii"), validate=True)
    encoded = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + encoded


def registry_dir(args: argparse.Namespace, alias: str) -> Path:
    return args.registry / validate_alias(alias)


def profile_matrix(capabilities: dict[str, Any]) -> str:
    lines = ["tool                              status       backend"]
    for name in sorted(MANAGED_TOOL_NAMES):
        item = capabilities[name]
        lines.append(f"{name:<33} {item['status']:<12} {item['backend']}")
        if item.get("reason"):
            lines.append(f"  reason: {item['reason']}")
    return "\n".join(lines)


def windows_path_hint(path: Path) -> str | None:
    parts = path.resolve().parts
    if len(parts) >= 4 and parts[0] == "/" and parts[1] == "mnt" and len(parts[2]) == 1:
        return parts[2].upper() + ":\\" + "\\".join(parts[3:])
    distro = os.environ.get("WSL_DISTRO_NAME")
    if os.name == "posix" and distro and path.is_absolute():
        return "\\\\wsl$\\" + distro + "\\" + "\\".join(parts[1:])
    return None


def command_discover(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    allowed_roots = validate_allowed_roots(args.allowed_root)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle = output_dir / f"{alias}-discovery.tar.gz"
    root_arguments = " ".join(f"--allowed-root {root!r}" for root in allowed_roots)
    runner = (
        "#!/bin/sh\n"
        "set -eu\n"
        "umask 077\n"
        "if command -v python3 >/dev/null 2>&1; then PYTHON=python3; "
        "elif command -v python >/dev/null 2>&1; then PYTHON=python; "
        "else echo '未找到 Python 2.6/3.x' >&2; exit 1; fi\n"
        f'"$PYTHON" ./collect-host-profile.py --alias {alias!r} {root_arguments} '
        "> ./discovery-result.json\n"
        'echo "已生成 discovery-result.json；请通过可信渠道回传该文件。"\n'
    )
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp) / f"{alias}-discovery"
        stage.mkdir()
        shutil.copy2(COLLECTOR, stage / COLLECTOR.name)
        (stage / "run-discovery.sh").write_text(runner, encoding="utf-8", newline="\n")
        os.chmod(stage / "run-discovery.sh", 0o700)
        with tarfile.open(bundle, "w:gz") as archive:
            archive.add(stage, arcname=stage.name)
    digest = sha256_file(bundle)
    (bundle.with_suffix(bundle.suffix + ".sha256")).write_text(
        f"{digest}  {bundle.name}\n", encoding="ascii", newline="\n"
    )
    print(f"discovery_bundle={bundle}")
    print(f"sha256={digest}")
    hint = windows_path_hint(bundle)
    if hint:
        print(f"windows_path={hint}")


def command_import(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    allowed_roots = validate_allowed_roots(args.allowed_root)
    address = str(ipaddress.IPv4Address(args.address))
    if not 1 <= args.port <= 65535:
        raise RuntimeError("port must be in 1..65535")
    discovery = validate_discovery(read_json(args.discovery_json), alias, allowed_roots)
    actual_hash = sha256_file(args.bundle)
    hash_file = args.bundle.with_suffix(args.bundle.suffix + ".sha256")
    if hash_file.is_file():
        expected_hash = hash_file.read_text(encoding="ascii").split()[0]
        if expected_hash != actual_hash:
            raise RuntimeError("Discovery bundle SHA256 does not match its sidecar")
    host_dir = registry_dir(args, alias)
    if (host_dir / "profile.json").exists() and not args.replace:
        raise RuntimeError("A prepared profile already exists; use refresh instead")
    registration = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "alias": alias,
        "address": address,
        "port": args.port,
        "user": "codex-ro",
        "allowed_roots": list(allowed_roots),
        "discovery_bundle_sha256": actual_hash,
        "discovery": discovery,
    }
    atomic_json(host_dir / "discovery.json", registration)
    print(profile_matrix(discovery["capabilities"]))
    incomplete = [name for name, item in discovery["capabilities"].items() if item["status"] != "exact"]
    print(f"imported={alias}")
    print(f"state={'confirmation-required' if incomplete else 'ready'}")


def load_registration(args: argparse.Namespace, alias: str) -> dict[str, Any]:
    registration = read_json(registry_dir(args, alias) / "discovery.json")
    if registration.get("alias") != alias:
        raise RuntimeError("Stored discovery alias mismatch")
    root_values = registration["allowed_roots"] if "allowed_roots" in registration else [registration["allowed_root"]]
    allowed_roots = validate_allowed_roots(root_values)
    validate_discovery(
        registration["discovery"],
        alias,
        allowed_roots,
    )
    registration["schema_version"] = PROFILE_SCHEMA_VERSION
    registration["allowed_roots"] = list(allowed_roots)
    registration.pop("allowed_root", None)
    return registration


def select_host_key(
    discovery: dict[str, Any],
    trusted_key: str,
    major: int,
) -> tuple[Literal["ssh-ed25519", "ssh-rsa"], str]:
    key_type = trusted_key.split()[0]
    expected_type = "ssh-rsa" if major == 6 else "ssh-ed25519"
    if key_type != expected_type:
        raise RuntimeError(f"CentOS {major} requires a trusted {expected_type} host key")
    discovered = {item["public_key"] for item in discovery["ssh"]["host_keys"]}
    if trusted_key not in discovered:
        raise RuntimeError("Trusted host key was not present in the administrator discovery result")
    return cast(Literal["ssh-ed25519", "ssh-rsa"], key_type), fingerprint(trusted_key)


def generate_client_key(host_dir: Path, major: int) -> tuple[Literal["ed25519", "rsa"], Path]:
    key_type: Literal["ed25519", "rsa"] = "rsa" if major == 6 else "ed25519"
    private_key = host_dir / ("id_rsa" if key_type == "rsa" else "id_ed25519")
    if private_key.exists() or private_key.with_suffix(private_key.suffix + ".pub").exists():
        raise RuntimeError("Per-host key already exists; refusing to overwrite it")
    command = ["ssh-keygen", "-q", "-N", "", "-C", "linux-mcp-managed", "-f", str(private_key)]
    if key_type == "rsa":
        command.extend(["-t", "rsa", "-b", "4096"])
    else:
        command.extend(["-t", "ed25519"])
    subprocess.run(command, check=True)
    os.chmod(private_key, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(Path(str(private_key) + ".pub"), stat.S_IRUSR | stat.S_IWUSR)
    return key_type, private_key


def require_regular_asset(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is missing or unsafe: {path}")


def write_deployment_bundle(
    *,
    alias: str,
    allowed_roots: tuple[str, ...],
    major: int,
    private_key: Path,
    bundle: Path,
    read_mode: Literal["user", "privileged"] = "user",
) -> tuple[str, str]:
    """Create one deployment archive without reading or packaging the private key."""

    if not bundle.name.endswith(".tar.gz"):
        raise RuntimeError("Deployment output must end with .tar.gz")
    if read_mode not in ("user", "privileged"):
        raise RuntimeError("Invalid read mode")
    sidecar = bundle.with_suffix(bundle.suffix + ".sha256")
    if bundle.exists() or sidecar.exists():
        raise RuntimeError(f"Deployment output already exists: {bundle}")
    bundle.parent.mkdir(parents=True, exist_ok=True)
    public_key = Path(str(private_key) + ".pub")
    for source, label in (
        (COLLECTOR, "collector"),
        (INSTALLER, "installer"),
        (WRAPPER, "wrapper"),
        (PRIVILEGED_HELPER, "privileged helper"),
        (public_key, "client public key"),
    ):
        require_regular_asset(source, label)

    expected_public_type = "ssh-rsa" if major == 6 else "ssh-ed25519"
    normalized_public_key = normalize_public_key(public_key.read_text(encoding="ascii"))
    if not normalized_public_key.startswith(expected_public_type + " "):
        raise RuntimeError("Client public key type does not match the managed host")

    policy = {"allowed_roots": list(allowed_roots), "read_mode": read_mode}
    install_command = f"sudo bash ./install-readonly-account.sh ./{public_key.name} ./policy.json codex-ro"
    if major == 6:
        install_command += " --allow-rsa"

    temporary_bundle: Path | None = None
    try:
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp) / f"{alias}-deployment"
            stage.mkdir()
            shutil.copy2(INSTALLER, stage / INSTALLER.name)
            shutil.copy2(WRAPPER, stage / WRAPPER.name)
            shutil.copy2(PRIVILEGED_HELPER, stage / PRIVILEGED_HELPER.name)
            shutil.copy2(public_key, stage / public_key.name)
            (stage / "policy.json").write_text(
                json.dumps(policy, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="ascii",
                newline="\n",
            )
            (stage / "INSTALL.txt").write_text(install_command + "\n", encoding="utf-8", newline="\n")
            manifest_files = {
                item.name: sha256_file(item)
                for item in sorted(stage.iterdir(), key=lambda path: path.name)
                if item.is_file()
            }
            manifest = {
                "schema_version": 1,
                "alias": alias,
                "mcp_version": __version__,
                "wrapper_version": WRAPPER_VERSION,
                "files": manifest_files,
            }
            (stage / "MANIFEST.json").write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="ascii",
                newline="\n",
            )
            descriptor, temporary_name = tempfile.mkstemp(prefix=".linux-mcp-deployment-", dir=str(bundle.parent))
            os.close(descriptor)
            temporary_bundle = Path(temporary_name)
            with tarfile.open(temporary_bundle, "w:gz") as archive:
                archive.add(stage, arcname=stage.name)
        temporary_bundle.replace(bundle)
        temporary_bundle = None
    finally:
        if temporary_bundle is not None and temporary_bundle.exists():
            temporary_bundle.unlink()

    digest = sha256_file(bundle)
    sidecar.write_text(f"{digest}  {bundle.name}\n", encoding="ascii", newline="\n")
    return digest, install_command


def print_deployment_result(
    bundle: Path,
    digest: str,
    host_fingerprint: str,
    install_command: str,
) -> None:
    print(f"deployment_bundle={bundle}")
    print(f"sha256={digest}")
    print(f"host_fingerprint={host_fingerprint}")
    print(f"install_command={install_command}")
    hint = windows_path_hint(bundle)
    if hint:
        print(f"windows_path={hint}")


def command_prepare(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    registration = load_registration(args, alias)
    discovery = registration["discovery"]
    incomplete = [name for name, item in discovery["capabilities"].items() if item["status"] != "exact"]
    print(profile_matrix(discovery["capabilities"]))
    if incomplete and not args.accept_incomplete:
        raise RuntimeError("Partial or unsupported capabilities require --accept-incomplete")
    major = discovery["os"]["major"]
    if major == 6 and not args.allow_rsa:
        raise RuntimeError("CentOS 6 preparation requires explicit --allow-rsa")
    if major != 6 and args.allow_rsa:
        raise RuntimeError("--allow-rsa is restricted to CentOS 6")

    output_dir = args.output_dir.resolve()
    bundle = output_dir / f"{alias}-deployment.tar.gz"
    if bundle.exists() or bundle.with_suffix(bundle.suffix + ".sha256").exists():
        raise RuntimeError(f"Deployment output already exists: {bundle}")

    trusted_key = normalize_public_key(args.trusted_host_key_file.read_text(encoding="ascii"))
    host_key_type, host_fingerprint = select_host_key(discovery, trusted_key, major)
    host_dir = registry_dir(args, alias)
    client_key_type, private_key = generate_client_key(host_dir, major)
    known_hosts = host_dir / "known_hosts"
    known_host_name = (
        registration["address"] if registration["port"] == 22 else f"[{registration['address']}]:{registration['port']}"
    )
    known_hosts.write_text(f"{known_host_name} {trusted_key}\n", encoding="ascii", newline="\n")
    os.chmod(known_hosts, 0o600)

    profile = HostProfile(
        alias=alias,
        address=registration["address"],
        port=registration["port"],
        allowed_roots=registration["allowed_roots"],
        read_mode=getattr(args, "read_mode", "user"),
        os=discovery["os"],
        ssh=SSHProfile(
            server_version=discovery["ssh"]["server_version"],
            host_key_type=host_key_type,
            host_public_key=trusted_key,
            host_fingerprint=host_fingerprint,
            client_key_type=client_key_type,
            private_key_path=private_key.resolve(),
            known_hosts_path=known_hosts.resolve(),
            legacy_rsa=major == 6,
        ),
        capabilities=discovery["capabilities"],
        discovery_bundle_sha256=registration["discovery_bundle_sha256"],
        mcp_version=__version__,
        wrapper_version=WRAPPER_VERSION,
        discovered_at=discovery["collected_at"],
    )
    atomic_json(host_dir / "profile.json", profile.model_dump(mode="json"))

    digest, install_command = write_deployment_bundle(
        alias=alias,
        allowed_roots=tuple(registration["allowed_roots"]),
        major=major,
        private_key=private_key,
        bundle=bundle,
        read_mode=profile.read_mode,
    )
    print_deployment_result(bundle, digest, host_fingerprint, install_command)


def command_rebuild_deployment(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    host_dir = registry_dir(args, alias)
    profile = HostProfile.model_validate(read_json(host_dir / "profile.json"))
    read_mode = getattr(args, "read_mode", None) or profile.read_mode
    private_key = profile.ssh.private_key_path
    expected_name = "id_rsa" if profile.ssh.client_key_type == "rsa" else "id_ed25519"
    if private_key.parent.resolve() != host_dir.resolve() or private_key.name != expected_name:
        raise RuntimeError("Managed private key path does not belong to the selected host")
    require_regular_asset(private_key, "managed private key")
    if os.name == "posix" and private_key.stat().st_mode & 0o077:
        raise RuntimeError("Managed private key permissions are too broad")

    bundle = args.output.resolve()
    digest, install_command = write_deployment_bundle(
        alias=alias,
        allowed_roots=profile.allowed_roots,
        major=profile.os.major,
        private_key=private_key,
        bundle=bundle,
        read_mode=read_mode,
    )
    updated_payload = profile.model_dump(mode="json")
    updated_payload["mcp_version"] = __version__
    updated_payload["wrapper_version"] = WRAPPER_VERSION
    updated_payload["read_mode"] = read_mode
    updated_payload["verified_at"] = None
    updated = HostProfile.model_validate(updated_payload)
    atomic_json(host_dir / "profile.json", updated.model_dump(mode="json"))
    print_deployment_result(bundle, digest, profile.ssh.host_fingerprint, install_command)
    print("state=prepared")


def command_list(args: argparse.Namespace) -> None:
    if not args.registry.is_dir():
        return
    print(
        "alias                           address          port  user      version       ssh          read_mode   state"
    )
    for host_dir in sorted(path for path in args.registry.iterdir() if path.is_dir() and not path.is_symlink()):
        try:
            registration = read_json(host_dir / "discovery.json")
            profile_path = host_dir / "profile.json"
            discovery = registration["discovery"]
            key_type = "pending"
            read_mode = "user"
            state = "discovered"
            if profile_path.is_file():
                profile = HostProfile.model_validate(read_json(profile_path))
                key_type = profile.ssh.host_key_type
                read_mode = profile.read_mode
                state = "verified" if profile.verified_at else "prepared"
            print(
                f"{registration['alias']:<31} {registration['address']:<16} {registration['port']:<5} "
                f"codex-ro  {discovery['os']['version']:<13} {key_type:<12} {read_mode:<11} {state}"
            )
        except (KeyError, RuntimeError, ValueError):
            print(f"{host_dir.name:<31} {'invalid':<13} {'-':<12} invalid")


def command_show(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    registration = load_registration(args, alias)
    discovery = registration["discovery"]
    print(
        f"alias={alias}\naddress={registration['address']}:{registration['port']}\n"
        f"centos={discovery['os']['version']}\nopenssh={discovery['ssh']['server_version']}\n"
        f"allowed_roots={','.join(registration['allowed_roots'])}"
    )
    runtime = discovery.get("runtime")
    if runtime is not None:
        print(f"python={runtime['python_executable']} {runtime['python_version']}")
    profile_path = registry_dir(args, alias) / "profile.json"
    if profile_path.is_file():
        profile = HostProfile.model_validate(read_json(profile_path))
        print(f"host_key={profile.ssh.host_key_type} {profile.ssh.host_fingerprint}")
        print(f"client_key={profile.ssh.client_key_type}")
        print(f"state={'verified' if profile.verified_at else 'prepared'}")
        print(f"read_mode={profile.read_mode}")
    else:
        print("state=discovered")
    print(profile_matrix(discovery["capabilities"]))


def command_verify(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    host_dir = registry_dir(args, alias)
    profile = HostProfile.model_validate(read_json(host_dir / "profile.json"))
    if profile.read_mode == "privileged":
        if args.results_json is not None:
            raise RuntimeError("Privileged verification requires live MCP calls; imported results are not accepted")
        if not args.sample_file:
            args.sample_file = [Path(root) / ".linux-mcp-verify/public.txt" for root in profile.allowed_roots]
        if args.sample_log_file is None:
            args.sample_log_file = Path(profile.allowed_roots[0]) / ".linux-mcp-verify/private/app.log"
    if args.results_json is not None:
        results = read_json(args.results_json)
    else:
        if not args.sample_file or args.sample_log_file is None:
            raise RuntimeError("live verification requires --sample-file for every root and --sample-log-file")
        validate_verification_paths(profile, args.sample_file, args.sample_log_file)
        results = asyncio.run(run_mcp_verification(args, profile))
        atomic_json(host_dir / "verification.json", results)
        print(f"verification_results={host_dir / 'verification.json'}")
    accept_verification_results(profile, results)
    updated_payload = profile.model_dump(mode="json")
    updated_payload["verified_at"] = results["completed_at"]
    updated = HostProfile.model_validate(updated_payload)
    atomic_json(host_dir / "profile.json", updated.model_dump(mode="json"))
    print(f"verified={alias}")
    print(f"verified_at={updated.verified_at}")


def accept_verification_results(profile: HostProfile, results: dict[str, Any]) -> None:
    alias = profile.alias
    required = {"schema_version", "alias", "completed_at", "tools"}
    if profile.read_mode == "privileged":
        required.add("read_checks")
    if set(results) != required:
        raise RuntimeError("Invalid verification result schema")
    if results["schema_version"] != 1 or results["alias"] != alias:
        raise RuntimeError("Verification result identity mismatch")
    if not isinstance(results["tools"], dict) or set(results["tools"]) != MANAGED_TOOL_NAMES:
        raise RuntimeError("Verification must contain exactly all 19 tools")
    expected_outcome = {"exact": "success", "partial": "partial", "unsupported": "unsupported"}
    failures = []
    for tool_name, capability_item in profile.capabilities.items():
        item = results["tools"][tool_name]
        if not isinstance(item, dict) or set(item) != {"outcome", "reason"}:
            raise RuntimeError(f"Invalid verification item: {tool_name}")
        if item["reason"] not in VERIFICATION_REASONS:
            raise RuntimeError(f"Invalid verification reason: {tool_name}")
        if item["outcome"] != expected_outcome[capability_item.status]:
            failures.append(f"{tool_name}({item['reason']})")
    if failures:
        raise RuntimeError("Verification outcomes do not match the profile: " + ", ".join(sorted(failures)))
    if profile.read_mode == "privileged":
        checks = results["read_checks"]
        expected = {name for name, _, _, _ in privileged_verification_cases(profile)}
        if (
            not isinstance(checks, dict)
            or set(checks) != expected
            or any(value != "success" for value in checks.values())
        ):
            raise RuntimeError("Privileged read boundary checks did not all pass")


def classify_verification_failure(rendered: str, *, is_error: bool) -> str:
    normalized = rendered.casefold()
    if "authentication failed" in normalized or "permission denied (publickey" in normalized:
        return "authentication_failed"
    if "permission denied" in normalized or "errno 13" in normalized:
        return "permission_denied"
    if "transport closed" in normalized or "connection lost" in normalized:
        return "transport_closed"
    if "timed out" in normalized or "timeout" in normalized:
        return "command_timeout"
    if not rendered.strip():
        return "empty_output"
    if is_error or normalized.lstrip().startswith("error "):
        return "tool_error"
    return "profile_mismatch"


def is_read_boundary_denial(rendered: str, path: str) -> bool:
    # 排除错误中回显的路径，避免 outside-link 文件名把缺失/权限错误误判为越界拒绝。
    message = rendered.casefold().replace(path.casefold(), "")
    return any(
        reason in message
        for reason in (
            "path is outside approved roots",
            "outside the managed allowed_roots",
            "路径不在批准范围",
            "symlinks and special files are not allowed",
            "opened path changed or contains a symlink",
        )
    )


def _is_within_posix_root(path: Path, root: str) -> bool:
    raw_path = path.as_posix()
    parsed = PurePosixPath(raw_path)
    return (
        raw_path.startswith("/")
        and ".." not in parsed.parts
        and (raw_path == root or raw_path.startswith(root.rstrip("/") + "/"))
    )


def validate_verification_paths(profile: HostProfile, sample_files: list[Path], sample_log_file: Path) -> None:
    uncovered = set(profile.allowed_roots)
    for sample_file in sample_files:
        matching = [root for root in profile.allowed_roots if _is_within_posix_root(sample_file, root)]
        if len(matching) != 1:
            raise RuntimeError(f"Sample file is outside managed allowed_roots: {sample_file}")
        uncovered.discard(matching[0])
    if uncovered:
        raise RuntimeError("Missing --sample-file coverage for roots: " + ", ".join(sorted(uncovered)))
    if not any(_is_within_posix_root(sample_log_file, root) for root in profile.allowed_roots):
        raise RuntimeError(f"Sample log file is outside managed allowed_roots: {sample_log_file}")


async def run_mcp_verification(args: argparse.Namespace, profile: HostProfile) -> dict[str, Any]:
    """Call all public fixed tools through an in-process MCP client and retain no payloads."""

    from fastmcp.client import Client

    from linux_mcp_server.config import CONFIG
    from linux_mcp_server.server import mcp

    CONFIG.host_registry_path = args.registry
    CONFIG.require_managed_host = True
    CONFIG.allowed_roots = ",".join(profile.allowed_roots)
    tool_arguments: dict[str, list[dict[str, Any]]] = {
        "get_system_information": [{}],
        "get_cpu_information": [{}],
        "get_memory_information": [{}],
        "get_disk_usage": [{}],
        "get_hardware_information": [{}],
        "list_services": [{}],
        "get_service_status": [{"service_name": args.service}],
        "get_service_logs": [{"service_name": args.service, "lines": 1}],
        "list_processes": [{}],
        "get_process_info": [{"pid": args.pid}],
        "get_journal_logs": [{"lines": 1}],
        "read_log_file": [{"log_path": args.sample_log_file.as_posix(), "lines": 1}],
        "get_network_interfaces": [{}],
        "get_network_connections": [{}],
        "get_listening_ports": [{}],
        "list_block_devices": [{}],
        "list_directories": [
            {
                "path": root + "/.linux-mcp-verify" if profile.read_mode == "privileged" else root,
                "order_by": "name",
                "top_n": 1,
            }
            for root in profile.allowed_roots
        ],
        "list_files": [
            {
                "path": root + "/.linux-mcp-verify" if profile.read_mode == "privileged" else root,
                "order_by": "name",
                "top_n": 1,
            }
            for root in profile.allowed_roots
        ],
        "read_file": [{"path": path.as_posix()} for path in args.sample_file],
    }
    results: dict[str, dict[str, str]] = {}
    access_preflight = ("read_file", "read_log_file")
    ordered_tools = access_preflight + tuple(sorted(MANAGED_TOOL_NAMES - set(access_preflight)))
    async with Client(mcp) as client:
        exposed = await client.list_tools()
        if {tool.name for tool in exposed} != MANAGED_TOOL_NAMES or any(
            tool.annotations is None or tool.annotations.readOnlyHint is not True for tool in exposed
        ):
            raise RuntimeError("Verification requires exactly the 19 fixed read-only MCP tools")
        for tool_name in ordered_tools:
            capability = profile.capabilities[tool_name]
            argument_sets = tool_arguments[tool_name]
            if capability.status == "unsupported":
                argument_sets = argument_sets[:1]
            reason = "matched profile"
            outcome = {"exact": "success", "partial": "partial", "unsupported": "unsupported"}[capability.status]
            for arguments_template in argument_sets:
                arguments = dict(arguments_template)
                arguments["host"] = profile.alias
                call_result = await client.call_tool(
                    tool_name,
                    arguments=arguments,
                    raise_on_error=False,
                )
                rendered = " ".join(getattr(item, "text", "") for item in call_result.content)
                reported_error = rendered.lstrip().casefold().startswith("error ")
                if capability.status == "unsupported":
                    call_matched = call_result.is_error and profile.alias in rendered and tool_name in rendered
                elif capability.status == "partial":
                    call_matched = not call_result.is_error and not reported_error and "PARTIAL:" in rendered
                else:
                    call_matched = not call_result.is_error and not reported_error and bool(rendered.strip())
                if not call_matched:
                    outcome = "failed"
                    reason = classify_verification_failure(rendered, is_error=call_result.is_error)
                    break
            results[tool_name] = {
                "outcome": outcome,
                "reason": reason,
            }
            print(f"verification_tool={tool_name} outcome={outcome} reason={reason}", flush=True)
        read_checks = {}
        if profile.read_mode == "privileged":
            for name, tool, arguments, expected_text in privileged_verification_cases(profile):
                call = await client.call_tool(
                    tool, arguments={**arguments, "host": profile.alias}, raise_on_error=False
                )
                rendered = " ".join(getattr(item, "text", "") for item in call.content)
                failed = call.is_error or rendered.lstrip().casefold().startswith("error ")
                boundary_error = is_read_boundary_denial(rendered, str(arguments.get("path", "")))
                matched = (
                    failed and boundary_error if expected_text is None else not failed and expected_text in rendered
                )
                read_checks[name] = "success" if matched else "failed"
                print(f"verification_read_check={name} outcome={read_checks[name]}", flush=True)
    result = {
        "schema_version": 1,
        "alias": profile.alias,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "tools": results,
    }
    if profile.read_mode == "privileged":
        result["read_checks"] = read_checks
    return result


def privileged_verification_cases(profile: HostProfile) -> list[tuple[str, str, dict[str, Any], str | None]]:
    cases = []
    for index, root in enumerate(profile.allowed_roots):
        base = root + "/.linux-mcp-verify"
        prefix = f"root_{index + 1}_"
        cases.extend(
            [
                (
                    prefix + "root_file",
                    "read_file",
                    {"path": base + "/private/root-only.txt"},
                    "linux-mcp-verification-v1",
                ),
                (
                    prefix + "root_log",
                    "read_log_file",
                    {"log_path": base + "/private/app.log", "lines": 1},
                    "linux-mcp-verification-v1",
                ),
                (prefix + "root_files", "list_files", {"path": base + "/private", "order_by": "name"}, "root-only.txt"),
                (prefix + "root_dirs", "list_directories", {"path": base + "/private", "order_by": "name"}, "nested"),
                (
                    prefix + "root_dir_sizes",
                    "list_directories",
                    {"path": base + "/private", "order_by": "size"},
                    "nested",
                ),
                (prefix + "symlink_escape", "read_file", {"path": base + "/outside-link"}, None),
            ]
        )
    cases.append(("outside_roots", "read_file", {"path": "/__linux_mcp_outside_approved_roots__/sample.txt"}, None))
    return cases


def command_refresh(args: argparse.Namespace) -> None:
    alias = validate_alias(args.alias)
    registration = load_registration(args, alias)
    refreshed = validate_discovery(
        read_json(args.discovery_json),
        alias,
        tuple(registration["allowed_roots"]),
    )
    old = registration["discovery"]
    changes = []
    for label, before, after in (
        ("os", old["os"], refreshed["os"]),
        ("ssh", old["ssh"], refreshed["ssh"]),
        ("runtime", old.get("runtime"), refreshed.get("runtime")),
        ("capabilities", old["capabilities"], refreshed["capabilities"]),
    ):
        if before != after:
            changes.append(label)
    print("changed=" + (",".join(changes) if changes else "none"))
    if not changes:
        return
    print(profile_matrix(refreshed["capabilities"]))
    if not args.accept_changes:
        raise RuntimeError("Profile drift requires --accept-changes after review")
    registration["discovery"] = refreshed
    registration["discovery_bundle_sha256"] = sha256_file(args.bundle)
    atomic_json(registry_dir(args, alias) / "discovery.json", registration)
    profile_path = registry_dir(args, alias) / "profile.json"
    if profile_path.exists():
        profile_path.rename(registry_dir(args, alias) / "profile.stale.json")
    print("state=discovered")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--registry", type=Path, default=REGISTRY_DEFAULT)
    subcommands = result.add_subparsers(dest="command", required=True)

    discover = subcommands.add_parser("discover")
    discover.add_argument("--alias", required=True)
    discover.add_argument("--allowed-root", action="append", required=True)
    discover.add_argument("--output-dir", type=Path, required=True)
    discover.set_defaults(handler=command_discover)

    import_profile = subcommands.add_parser("import-profile")
    import_profile.add_argument("--alias", required=True)
    import_profile.add_argument("--address", required=True)
    import_profile.add_argument("--port", type=int, default=22)
    import_profile.add_argument("--allowed-root", action="append", required=True)
    import_profile.add_argument("--discovery-json", type=Path, required=True)
    import_profile.add_argument("--bundle", type=Path, required=True)
    import_profile.add_argument("--replace", action="store_true")
    import_profile.set_defaults(handler=command_import)

    list_command = subcommands.add_parser("list")
    list_command.set_defaults(handler=command_list)

    show = subcommands.add_parser("show")
    show.add_argument("--alias", required=True)
    show.set_defaults(handler=command_show)

    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--alias", required=True)
    prepare.add_argument("--trusted-host-key-file", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--accept-incomplete", action="store_true")
    prepare.add_argument("--allow-rsa", action="store_true")
    prepare.add_argument("--read-mode", choices=("user", "privileged"), default="user")
    prepare.set_defaults(handler=command_prepare)

    rebuild = subcommands.add_parser("rebuild-deployment")
    rebuild.add_argument("--alias", required=True)
    rebuild.add_argument("--output", type=Path, required=True)
    rebuild.add_argument("--read-mode", choices=("user", "privileged"))
    rebuild.set_defaults(handler=command_rebuild_deployment)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--alias", required=True)
    verify.add_argument("--results-json", type=Path)
    verify.add_argument("--sample-file", type=Path, action="append")
    verify.add_argument("--sample-log-file", type=Path)
    verify.add_argument("--service", default="sshd")
    verify.add_argument("--pid", type=int, default=1)
    verify.set_defaults(handler=command_verify)

    refresh = subcommands.add_parser("refresh")
    refresh.add_argument("--alias", required=True)
    refresh.add_argument("--discovery-json", type=Path, required=True)
    refresh.add_argument("--bundle", type=Path, required=True)
    refresh.add_argument("--accept-changes", action="store_true")
    refresh.set_defaults(handler=command_refresh)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
