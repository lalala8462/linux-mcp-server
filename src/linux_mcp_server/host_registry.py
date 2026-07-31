"""Validated per-host profiles for managed SSH diagnostics."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import struct

from pathlib import Path
from pathlib import PurePosixPath
from typing import Literal

from pydantic import AwareDatetime
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator


PROFILE_SCHEMA_VERSION = 1
MANAGED_TOOL_NAMES = frozenset(
    {
        "get_system_information",
        "get_cpu_information",
        "get_memory_information",
        "get_disk_usage",
        "get_hardware_information",
        "list_services",
        "get_service_status",
        "get_service_logs",
        "list_processes",
        "get_process_info",
        "get_journal_logs",
        "read_log_file",
        "get_network_interfaces",
        "get_network_connections",
        "get_listening_ports",
        "list_block_devices",
        "list_directories",
        "list_files",
        "read_file",
    }
)
TOOL_BACKENDS: dict[str, frozenset[str]] = {
    "get_system_information": frozenset({"modern_os_release", "centos6_procfs"}),
    "get_cpu_information": frozenset({"procfs_procps"}),
    "get_memory_information": frozenset({"native_wide", "centos7_basic"}),
    "get_disk_usage": frozenset({"native_json", "centos7_pairs", "centos6_df"}),
    "get_hardware_information": frozenset({"hardware_commands"}),
    "list_services": frozenset({"systemd", "centos6_chkconfig"}),
    "get_service_status": frozenset({"systemd", "none"}),
    "get_service_logs": frozenset({"journalctl", "none"}),
    "list_processes": frozenset({"procps"}),
    "get_process_info": frozenset({"procps_procfs"}),
    "get_journal_logs": frozenset({"journalctl", "none"}),
    "read_log_file": frozenset({"bounded_tail"}),
    "get_network_interfaces": frozenset({"ip_brief", "ip_address"}),
    "get_network_connections": frozenset({"ss", "netstat"}),
    "get_listening_ports": frozenset({"ss", "netstat"}),
    "list_block_devices": frozenset({"native_json", "centos7_pairs_parent", "centos7_pairs_flat", "none"}),
    "list_directories": frozenset({"gnu_coreutils", "none"}),
    "list_files": frozenset({"gnu_coreutils", "none"}),
    "read_file": frozenset({"gnu_coreutils", "none"}),
}
TOOL_BACKENDS = {tool_name: backends | frozenset({"none"}) for tool_name, backends in TOOL_BACKENDS.items()}
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/=]+$")


def normalize_ssh_public_key(value: str, allowed_types: set[str]) -> str:
    """Validate an SSH public-key wire type and discard optional comments."""

    if not isinstance(value, str):
        raise ValueError("invalid SSH public key")
    stripped = value.strip()
    if any(character in stripped for character in ("\x00", "\r", "\n")):
        raise ValueError("invalid SSH public key")
    fields = stripped.split()
    if len(fields) < 2 or fields[0] not in allowed_types:
        raise ValueError("unsupported SSH public key type")
    try:
        decoded = base64.b64decode(fields[1].encode("ascii"), validate=True)
        if len(decoded) < 8:
            raise ValueError("SSH public key is too short")
        key_type_size = struct.unpack(">I", decoded[:4])[0]
        wire_type = decoded[4 : 4 + key_type_size].decode("ascii")
    except (ValueError, UnicodeDecodeError, UnicodeEncodeError, struct.error) as error:
        raise ValueError("invalid SSH public key encoding") from error
    if wire_type != fields[0] or 4 + key_type_size >= len(decoded):
        raise ValueError("SSH public key wire type mismatch")
    return fields[0] + " " + fields[1]


class CapabilityProfile(BaseModel):
    """One MCP tool's compatibility result for a managed host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["exact", "partial", "unsupported"]
    backend: str
    reason: str = ""

    @field_validator("backend", "reason")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(character in value for character in ("\x00", "\r", "\n")):
            raise ValueError("capability text contains control characters")
        return value


class OSProfile(BaseModel):
    """Normalized CentOS identity captured by the discovery package."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Literal["centos"]
    version: str
    major: Literal[6, 7, 8, 9]
    release_source: str
    kernel: str
    architecture: str


class SSHProfile(BaseModel):
    """Per-host SSH identity and explicitly selected cryptographic profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_version: str
    host_key_type: Literal["ssh-ed25519", "ssh-rsa"]
    host_public_key: str
    host_fingerprint: str
    host_key_confirmed: Literal[True] = True
    client_key_type: Literal["ed25519", "rsa"]
    private_key_path: Path
    known_hosts_path: Path
    legacy_rsa: bool = False

    @field_validator("private_key_path", "known_hosts_path")
    @classmethod
    def require_absolute_ssh_paths(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("managed SSH paths must be absolute")
        return value

    @field_validator("host_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if not _FINGERPRINT_RE.fullmatch(value):
            raise ValueError("host fingerprint must use the SSH SHA256 format")
        return value

    @model_validator(mode="after")
    def validate_algorithm_pair(self) -> SSHProfile:
        is_rsa = self.host_key_type == "ssh-rsa" or self.client_key_type == "rsa"
        if is_rsa != self.legacy_rsa:
            raise ValueError("RSA key types require legacy_rsa=true and legacy_rsa requires RSA")
        if self.legacy_rsa and not (self.host_key_type == "ssh-rsa" and self.client_key_type == "rsa"):
            raise ValueError("legacy RSA requires RSA host and client keys")
        try:
            normalized = normalize_ssh_public_key(
                self.host_public_key,
                {"ssh-ed25519", "ssh-rsa"},
            )
        except ValueError as error:
            raise ValueError("invalid managed host public key") from error
        if normalized != self.host_public_key or not normalized.startswith(self.host_key_type + " "):
            raise ValueError("host public key type does not match host_key_type")
        key_blob = base64.b64decode(normalized.split()[1].encode("ascii"), validate=True)
        expected_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip(
            "="
        )
        if self.host_fingerprint != expected_fingerprint:
            raise ValueError("host public key fingerprint mismatch")
        return self


class HostProfile(BaseModel):
    """Complete local contract for one managed host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = PROFILE_SCHEMA_VERSION
    alias: str
    address: str
    port: int = Field(ge=1, le=65535)
    user: Literal["codex-ro"] = "codex-ro"
    allowed_root: str
    os: OSProfile
    ssh: SSHProfile
    capabilities: dict[str, CapabilityProfile]
    discovery_bundle_sha256: str
    mcp_version: str
    wrapper_version: str
    discovered_at: AwareDatetime
    verified_at: AwareDatetime | None = None

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if not _ALIAS_RE.fullmatch(value):
            raise ValueError("invalid managed host alias")
        return value

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    @field_validator("allowed_root")
    @classmethod
    def validate_allowed_root(cls, value: str) -> str:
        normalized = str(PurePosixPath(value))
        if (
            not value.startswith("/")
            or normalized == "/"
            or value.rstrip("/") != normalized
            or ".." in PurePosixPath(value).parts
            or any(character in value for character in ("\x00", "\r", "\n"))
        ):
            raise ValueError("allowed_root must be one safe non-root absolute path")
        return normalized

    @field_validator("discovery_bundle_sha256")
    @classmethod
    def validate_bundle_hash(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("discovery bundle hash must be lowercase SHA256")
        return value

    @model_validator(mode="after")
    def require_all_tools(self) -> HostProfile:
        actual = set(self.capabilities)
        if actual != MANAGED_TOOL_NAMES:
            missing = ", ".join(sorted(MANAGED_TOOL_NAMES - actual))
            extra = ", ".join(sorted(actual - MANAGED_TOOL_NAMES))
            raise ValueError(f"capability set mismatch; missing=[{missing}] extra=[{extra}]")
        for tool_name, capability in self.capabilities.items():
            if capability.backend not in TOOL_BACKENDS[tool_name]:
                raise ValueError(f"unsupported backend for {tool_name}: {capability.backend}")
            if (capability.backend == "none") != (capability.status == "unsupported"):
                raise ValueError(f"backend/status mismatch for {tool_name}")
        if self.os.major == 6 and not self.ssh.legacy_rsa:
            raise ValueError("CentOS 6 profiles must explicitly use legacy RSA")
        if self.os.major != 6 and self.ssh.legacy_rsa:
            raise ValueError("legacy RSA is restricted to CentOS 6 profiles")
        return self

    def require_tool(self, tool_name: str) -> CapabilityProfile:
        capability = self.capabilities[tool_name]
        if capability.status == "unsupported":
            raise RuntimeError(
                f"Host '{self.alias}' (CentOS {self.os.version}) does not support "
                f"'{tool_name}': {capability.reason or capability.backend}"
            )
        return capability


class HostRegistry:
    """Load profiles from an alias-addressed, non-symlinked local directory."""

    def __init__(self, root: Path):
        self.root = root

    def load(self, alias: str) -> HostProfile:
        if not _ALIAS_RE.fullmatch(alias):
            raise RuntimeError(f"Invalid managed host alias: {alias}")
        host_dir = self.root / alias
        profile_path = host_dir / "profile.json"
        if self.root.is_symlink() or host_dir.is_symlink() or profile_path.is_symlink() or not profile_path.is_file():
            raise RuntimeError(f"Managed host profile not found: {alias}")
        if os.name == "posix":
            if stat.S_IMODE(host_dir.stat().st_mode) & 0o077:
                raise RuntimeError(f"Managed host directory permissions are too broad: {alias}")
            if stat.S_IMODE(profile_path.stat().st_mode) & 0o077:
                raise RuntimeError(f"Managed host profile permissions are too broad: {alias}")
        try:
            payload = json.loads(profile_path.read_text(encoding="utf-8"))
            profile = HostProfile.model_validate(payload)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"Invalid managed host profile: {alias}") from error
        if profile.alias != alias:
            raise RuntimeError(f"Managed host profile alias mismatch: {alias}")
        expected_parent = host_dir.resolve()
        if (
            profile.ssh.private_key_path.parent.resolve() != expected_parent
            or profile.ssh.known_hosts_path.parent.resolve() != expected_parent
        ):
            raise RuntimeError(f"Managed SSH files must remain inside the alias directory: {alias}")
        return profile


def get_managed_profile(host: str) -> HostProfile | None:
    """Return a validated managed profile, respecting the configured fail-closed mode."""

    from linux_mcp_server.config import CONFIG

    if CONFIG.host_registry_path is None:
        if CONFIG.require_managed_host:
            raise RuntimeError("Managed host registry is required but not configured")
        return None
    try:
        return HostRegistry(CONFIG.host_registry_path).load(host)
    except RuntimeError:
        if CONFIG.require_managed_host:
            raise
        return None


def get_host_capability(host: str | None, tool_name: str) -> CapabilityProfile | None:
    """Return one persisted capability when the call targets a managed alias."""

    if host is None:
        return None
    profile = get_managed_profile(host)
    if profile is None:
        return None
    return profile.capabilities[tool_name]


def get_host_allowed_root(host: str | None) -> Path | None:
    """Return the only approved path root for a managed alias."""

    if host is None:
        return None
    profile = get_managed_profile(host)
    return Path(profile.allowed_root) if profile is not None else None
