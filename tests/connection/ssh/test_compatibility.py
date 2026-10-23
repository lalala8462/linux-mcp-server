"""Tests for SSH compatibility probing and command selection."""

import logging

import asyncssh
import pytest

from linux_mcp_server.compatibility import COMPATIBILITY_COMMANDS
from linux_mcp_server.compatibility import HostCompatibility
from linux_mcp_server.connection.ssh import execute_compatible_command
from linux_mcp_server.connection.ssh import SSHConnectionManager
from linux_mcp_server.execution_context import ExecutionContext
from linux_mcp_server.execution_context import use_execution_context


NATIVE_RESULTS = (
    (0, "centos-host", ""),
    (0, 'ID="centos"\nVERSION_ID="7"\n', ""),
    (0, "3.10.0-1127.el7.x86_64", ""),
    (0, '{"filesystems": []}', ""),
    (0, '{"blockdevices": []}', ""),
    (0, "Mem: 10 2 8 0 0 0 8\n", ""),
)


async def test_probe_compatibility_selects_native_variants(mocker):
    manager = SSHConnectionManager()
    run_probe = mocker.patch.object(manager, "_run_probe_command", autospec=True)
    run_probe.side_effect = NATIVE_RESULTS

    profile = await manager._probe_compatibility("server.example.com", mocker.Mock())

    assert profile.os_id == "centos"
    assert profile.os_version == "7"
    assert profile.variants == {
        "disk_usage": "native_json",
        "block_devices": "native_json",
        "memory_info": "native_wide",
    }


async def test_probe_compatibility_selects_centos7_variants(mocker):
    manager = SSHConnectionManager()
    run_probe = mocker.patch.object(manager, "_run_probe_command", autospec=True)
    run_probe.side_effect = (
        (0, "centos-host", ""),
        (0, 'ID="centos"\nVERSION_ID="7"\n', ""),
        (0, "3.10.0-1127.el7.x86_64", ""),
        (1, "", "unrecognized option '--json'"),
        (
            0,
            'SOURCE="/dev/sda1" FSTYPE="xfs" SIZE="10G" USED="2G" AVAIL="8G" USE%="20%" TARGET="/"',
            "",
        ),
        (1, "", "unrecognized option '--json'"),
        (1, "", "unknown column: PKNAME"),
        (0, 'NAME="sda" SIZE="10G" TYPE="disk" MOUNTPOINT="/" FSTYPE="xfs" MODEL=""', ""),
        (1, "", "invalid option -- 'w'"),
        (0, "Mem: 10 2 8\n", ""),
    )

    profile = await manager._probe_compatibility("server.example.com", mocker.Mock())

    assert profile.variants == {
        "disk_usage": "centos7_pairs",
        "block_devices": "centos7_pairs_flat",
        "memory_info": "centos7_basic",
    }


async def test_probe_compatibility_does_not_mask_permission_errors(mocker):
    manager = SSHConnectionManager()
    run_probe = mocker.patch.object(manager, "_run_probe_command", autospec=True)
    run_probe.side_effect = (
        (0, "centos-host", ""),
        (0, 'ID="centos"\nVERSION_ID="7"\n', ""),
        (0, "3.10.0", ""),
        (1, "", "Permission denied"),
    )

    with pytest.raises(ConnectionError, match="exit code 1"):
        await manager._probe_compatibility("server.example.com", mocker.Mock())


async def test_probe_compatibility_fails_closed_on_malformed_output(mocker):
    manager = SSHConnectionManager()
    run_probe = mocker.patch.object(manager, "_run_probe_command", autospec=True)
    run_probe.side_effect = (
        (0, "centos-host", ""),
        (0, 'ID="centos"\nVERSION_ID="7"\n', ""),
        (0, "3.10.0", ""),
        (0, '{"filesystems": "invalid"}', ""),
    )

    with pytest.raises(ConnectionError, match="malformed output"):
        await manager._probe_compatibility("server.example.com", mocker.Mock())


async def test_probe_timeout_is_not_treated_as_incompatibility(mocker):
    manager = SSHConnectionManager()
    connection = mocker.Mock()
    mocker.patch(
        "linux_mcp_server.connection.ssh.run_bounded_remote",
        autospec=True,
        side_effect=asyncssh.TimeoutError(
            env=None,
            command="hostname",
            subsystem=None,
            exit_status=None,
            exit_signal=None,
            returncode=None,
            stdout="",
            stderr="",
        ),
    )
    mocker.patch(
        "linux_mcp_server.connection.ssh.get_remote_bin_path",
        autospec=True,
        return_value="/usr/bin/hostname",
    )

    with pytest.raises(ConnectionError, match="timed out"):
        await manager._run_probe_command("server.example.com", connection, ("hostname",))


async def test_probe_connection_error_is_not_treated_as_incompatibility(mocker):
    manager = SSHConnectionManager()
    connection = mocker.Mock()
    mocker.patch(
        "linux_mcp_server.connection.ssh.run_bounded_remote",
        autospec=True,
        side_effect=asyncssh.Error(1, "connection lost"),
    )
    mocker.patch(
        "linux_mcp_server.connection.ssh.get_remote_bin_path",
        autospec=True,
        return_value="/usr/bin/hostname",
    )

    with pytest.raises(ConnectionError, match="probe failed"):
        await manager._run_probe_command("server.example.com", connection, ("hostname",))


async def test_execute_compatible_command_uses_selected_variant(mocker):
    manager = SSHConnectionManager()
    profile = HostCompatibility(
        host="server.example.com",
        hostname="centos-host",
        os_id="centos",
        os_version="7",
        kernel="3.10.0",
        variants={
            "disk_usage": "centos7_pairs",
            "block_devices": "centos7_pairs_flat",
            "memory_info": "centos7_basic",
        },
    )
    mocker.patch.object(manager, "get_compatibility", autospec=True, return_value=profile)
    log_fallback = mocker.patch.object(manager, "log_fallback", autospec=True)
    execute = mocker.patch(
        "linux_mcp_server.connection.ssh.execute_command",
        autospec=True,
        return_value=(0, "pairs", ""),
    )

    with use_execution_context(ExecutionContext(allow_ssh_default=True)):
        result = await execute_compatible_command("disk_usage", host="server.example.com")

    assert result == (0, "pairs", "", "centos7_pairs")
    assert execute.call_args.args[0] == COMPATIBILITY_COMMANDS["disk_usage"][1].args
    log_fallback.assert_called_once()


def test_log_fallback_records_system_version_once(mocker, caplog):
    manager = SSHConnectionManager()
    manager._logged_fallbacks.clear()
    profile = HostCompatibility(
        host="server.example.com",
        hostname="centos-host",
        os_id="centos",
        os_version="7",
        kernel="3.10.0",
        variants={"disk_usage": "centos7_pairs"},
    )
    mocker.patch.object(
        manager,
        "_connection_settings",
        autospec=True,
        return_value=("pool-key", None, "codex-ro"),
    )

    with caplog.at_level(logging.INFO):
        manager.log_fallback("server.example.com", "disk_usage", profile)
        manager.log_fallback("server.example.com", "disk_usage", profile)

    records = [record for record in caplog.records if record.getMessage().startswith("COMPAT_FALLBACK")]
    assert len(records) == 1
    assert records[0].os_version == "7"
    assert not hasattr(records[0], "stdout")
