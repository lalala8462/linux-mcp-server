"""Managed host profile and per-alias SSH security tests."""

import os

from datetime import datetime
from datetime import timezone
from pathlib import Path

import asyncssh
import pytest

from fastmcp.exceptions import ToolError

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.connection.ssh import SSHConnectionManager
from linux_mcp_server.host_registry import HostProfile
from linux_mcp_server.host_registry import HostRegistry
from linux_mcp_server.host_registry import MANAGED_TOOL_NAMES


RSA_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAEEJCQkJCQkJCQkJCQkJCQkI="
ED25519_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"


def capability_matrix(major: int) -> dict[str, dict[str, str]]:
    modern_backends = {
        "get_system_information": "modern_os_release",
        "get_cpu_information": "procfs_procps",
        "get_memory_information": "native_wide",
        "get_disk_usage": "native_json",
        "get_hardware_information": "hardware_commands",
        "list_services": "systemd",
        "get_service_status": "systemd",
        "get_service_logs": "journalctl",
        "list_processes": "procps",
        "get_process_info": "procps_procfs",
        "get_journal_logs": "journalctl",
        "read_log_file": "bounded_tail",
        "get_network_interfaces": "ip_brief",
        "get_network_connections": "ss",
        "get_listening_ports": "ss",
        "list_block_devices": "native_json",
        "list_directories": "gnu_coreutils",
        "list_files": "gnu_coreutils",
        "read_file": "gnu_coreutils",
    }
    result = {name: {"status": "exact", "backend": modern_backends[name], "reason": ""} for name in MANAGED_TOOL_NAMES}
    result["get_disk_usage"]["backend"] = "centos6_df" if major == 6 else "native_json"
    result["get_memory_information"]["backend"] = "centos7_basic" if major == 6 else "native_wide"
    result["list_block_devices"]["backend"] = "centos7_pairs_flat" if major == 6 else "native_json"
    result["get_network_interfaces"]["backend"] = "ip_address" if major == 6 else "ip_brief"
    result["get_network_connections"]["backend"] = "netstat" if major == 6 else "ss"
    result["get_listening_ports"]["backend"] = "netstat" if major == 6 else "ss"
    result["get_system_information"]["backend"] = "centos6_procfs" if major == 6 else "modern_os_release"
    if major == 6:
        result["get_hardware_information"] = {
            "status": "partial",
            "backend": "hardware_commands",
            "reason": "missing: lsusb",
        }
        result["list_services"] = {
            "status": "partial",
            "backend": "centos6_chkconfig",
            "reason": "running count unavailable",
        }
        for tool_name in ("get_service_status", "get_service_logs", "get_journal_logs"):
            result[tool_name] = {
                "status": "unsupported",
                "backend": "none",
                "reason": "journald or safe service status is unavailable",
            }
    return result


def make_profile(tmp_path: Path, *, major: int = 7, alias: str = "server-1") -> HostProfile:
    private_key = tmp_path / ("id_rsa" if major == 6 else "id_ed25519")
    known_hosts = tmp_path / "known_hosts"
    private_key.write_text("private test fixture\n", encoding="utf-8")
    legacy_rsa = major == 6
    public_key = RSA_PUBLIC_KEY if legacy_rsa else ED25519_PUBLIC_KEY
    known_hosts.write_text(f"192.0.2.10 {public_key}\n", encoding="utf-8")
    private_key.chmod(0o600)
    known_hosts.chmod(0o600)
    return HostProfile.model_validate(
        {
            "schema_version": 1,
            "alias": alias,
            "address": "192.0.2.10",
            "port": 22,
            "user": "codex-ro",
            "allowed_root": "/data",
            "os": {
                "id": "centos",
                "version": "6.5" if major == 6 else str(major),
                "major": major,
                "release_source": "/etc/redhat-release" if major == 6 else "/etc/os-release",
                "kernel": "2.6.32" if major == 6 else "3.10.0",
                "architecture": "x86_64",
            },
            "ssh": {
                "server_version": "OpenSSH_5.3p1" if major == 6 else "OpenSSH_7.4p1",
                "host_key_type": "ssh-rsa" if legacy_rsa else "ssh-ed25519",
                "host_public_key": public_key,
                "host_fingerprint": (
                    "SHA256:a5cn+JoXE37v8A7EGkS3HJEts8tzUozmRRpY2VTPxqs"
                    if legacy_rsa
                    else "SHA256:ycecTFElO4tMaWgqfHQDEUjUete0Tsl0wmvU/kkDXFc"
                ),
                "client_key_type": "rsa" if legacy_rsa else "ed25519",
                "private_key_path": str(private_key.resolve()),
                "known_hosts_path": str(known_hosts.resolve()),
                "legacy_rsa": legacy_rsa,
            },
            "capabilities": capability_matrix(major),
            "discovery_bundle_sha256": "a" * 64,
            "mcp_version": "1.5.1",
            "wrapper_version": "2",
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "verified_at": None,
        }
    )


@pytest.mark.parametrize("major", (6, 7, 8, 9))
def test_supported_centos_profiles_contain_exactly_all_tools(tmp_path, major):
    profile = make_profile(tmp_path, major=major)

    assert set(profile.capabilities) == MANAGED_TOOL_NAMES
    if major == 6:
        assert profile.ssh.legacy_rsa
        assert profile.capabilities["get_journal_logs"].status == "unsupported"
    else:
        assert not profile.ssh.legacy_rsa
        assert all(item.status == "exact" for item in profile.capabilities.values())


@pytest.mark.parametrize("tool_name", sorted(MANAGED_TOOL_NAMES))
def test_all_nineteen_tool_capabilities_are_addressable(tmp_path, tool_name):
    profile = make_profile(tmp_path, major=7)

    assert profile.require_tool(tool_name).status == "exact"


def test_centos6_unsupported_tool_error_identifies_host_version_and_tool(tmp_path):
    profile = make_profile(tmp_path, major=6)

    with pytest.raises(RuntimeError, match=r"server-1.*CentOS 6\.5.*get_journal_logs"):
        profile.require_tool("get_journal_logs")


def test_profile_rejects_rsa_on_non_centos6(tmp_path):
    profile = make_profile(tmp_path, major=6).model_dump(mode="json")
    profile["os"]["major"] = 7
    profile["os"]["version"] = "7"

    with pytest.raises(ValueError, match="restricted to CentOS 6"):
        HostProfile.model_validate(profile)


def test_profile_rejects_tampered_host_fingerprint(tmp_path):
    profile = make_profile(tmp_path).model_dump(mode="json")
    profile["ssh"]["host_fingerprint"] = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        HostProfile.model_validate(profile)


def test_profile_rejects_allowed_root_traversal(tmp_path):
    profile = make_profile(tmp_path).model_dump(mode="json")
    profile["allowed_root"] = "/data/../etc"

    with pytest.raises(ValueError, match="allowed_root"):
        HostProfile.model_validate(profile)


def test_registry_rejects_alias_mismatch(tmp_path):
    profile = make_profile(tmp_path, alias="stored")
    profile_dir = tmp_path / "requested"
    profile_dir.mkdir()
    profile_dir.chmod(0o700)
    profile_path = profile_dir / "profile.json"
    profile_path.write_text(profile.model_dump_json(), encoding="utf-8")
    profile_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="alias mismatch"):
        HostRegistry(tmp_path).load("requested")


def test_registry_rejects_broad_host_directory_permissions(tmp_path):
    profile = make_profile(tmp_path)
    profile_dir = tmp_path / profile.alias
    profile_dir.mkdir()
    (profile_dir / "profile.json").write_text(profile.model_dump_json(), encoding="utf-8")
    (profile_dir / "profile.json").chmod(0o600)
    profile_dir.chmod(0o755)

    if os.name == "posix":
        with pytest.raises(RuntimeError, match="directory permissions"):
            HostRegistry(tmp_path).load(profile.alias)


async def test_managed_centos6_injects_rsa_only_for_target_alias(tmp_path, mocker):
    profile = make_profile(tmp_path, major=6)
    connection = mocker.AsyncMock(asyncssh.SSHClientConnection)
    connection.get_extra_info.return_value = "codex-ro"
    connection.is_closed.return_value = False
    connect = mocker.patch("asyncssh.connect", new=mocker.AsyncMock(return_value=connection))
    probe = mocker.patch.object(SSHConnectionManager, "_probe_compatibility", autospec=True)
    mocker.patch(
        "linux_mcp_server.connection.ssh.get_managed_profile",
        autospec=True,
        side_effect=lambda host: profile if host == profile.alias else None,
    )
    manager = SSHConnectionManager()
    manager._connections.clear()
    manager._compatibility.clear()

    await manager.get_connection(profile.alias)

    kwargs = connect.call_args.kwargs
    assert kwargs["host"] == profile.address
    assert kwargs["client_keys"] == [str(profile.ssh.private_key_path)]
    assert kwargs["known_hosts"] == str(profile.ssh.known_hosts_path)
    assert kwargs["server_host_key_algs"] == ["ssh-rsa"]
    assert kwargs["signature_algs"] == ["ssh-rsa"]
    probe.assert_not_called()


async def test_unsupported_tool_is_rejected_before_function_body(tmp_path, mocker):
    profile = make_profile(tmp_path, major=6)
    mocker.patch(
        "linux_mcp_server.audit.get_managed_profile",
        autospec=True,
        return_value=profile,
    )
    executed = False

    @log_tool_call
    async def get_journal_logs(host=None):
        nonlocal executed
        executed = True

    with pytest.raises(ToolError, match="get_journal_logs"):
        await get_journal_logs(host=profile.alias)
    assert not executed


async def test_managed_host_rejects_run_script_before_function_body(tmp_path, mocker):
    profile = make_profile(tmp_path)
    mocker.patch(
        "linux_mcp_server.audit.get_managed_profile",
        autospec=True,
        return_value=profile,
    )
    executed = False

    @log_tool_call
    async def run_script(host=None):
        nonlocal executed
        executed = True

    with pytest.raises(ToolError, match=r"does not permit tool 'run_script'"):
        await run_script(host=profile.alias)
    assert not executed
