"""只读边界、资源限制与生命周期的回归测试。"""

import argparse
import asyncio
import importlib.util
import json
import os
import subprocess
import sys

from datetime import datetime
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace

import asyncssh
import pytest

from linux_mcp_server.connection import limits
from linux_mcp_server.parsers import parse_free_output
from tests.test_host_registry import ED25519_PUBLIC_KEY
from tests.test_host_registry import make_profile
from tests.test_manage_linux_hosts import discovery
from tests.test_manage_linux_hosts import MANAGER


def load_asset(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), MANAGER.ASSET_ROOT / name)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IDENTITY = load_asset("install-ssh-identity.py")
WRAPPER = load_asset("linux-mcp-readonly.py")


def test_identity_public_key_rejects_additional_unforced_key():
    with pytest.raises(ValueError, match="one line"):
        IDENTITY.public_key(ED25519_PUBLIC_KEY + "\n" + ED25519_PUBLIC_KEY)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_authorized_keys_rejects_nonexclusive_regular_file(tmp_path, kind):
    other = tmp_path / "other"
    other.write_text("must remain unchanged", encoding="utf-8")
    key = tmp_path / "authorized_keys"
    if kind == "symlink":
        key.symlink_to(other)
    elif kind == "hardlink":
        os.link(other, key)
    else:
        os.mkfifo(key)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((OSError, ValueError)):
            IDENTITY.read_authorized(descriptor, os.getuid())
    finally:
        os.close(descriptor)
    assert other.read_text(encoding="utf-8") == "must remain unchanged"


@pytest.mark.parametrize("home", ["/", "/root", "/home/../root", "/tmp/unsafe-home"])
def test_home_rejects_unsafe_root_or_writable_ancestor(mocker, home):
    mocker.patch.object(
        IDENTITY.pwd, "getpwnam", autospec=True, return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir=home)
    )
    with pytest.raises((OSError, ValueError)):
        IDENTITY.open_home("codex-ro")


@pytest.mark.parametrize("mismatch", ["key", "roots", "missing", "extra"])
def test_managed_upgrade_rejects_identity_and_scope_drift(tmp_path, mismatch):
    policy = {"allowed_roots": ["/data"], "read_mode": "privileged"}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"allowed_roots": ["/data"]}), encoding="utf-8")
    old = ('command="fixed" ' + ED25519_PUBLIC_KEY + "\n").encode()
    key = ED25519_PUBLIC_KEY
    if mismatch == "key":
        key = "ssh-ed25519 AAAAother"
    elif mismatch == "roots":
        policy["allowed_roots"] = ["/data", "/usr"]
    elif mismatch == "missing":
        old = None
    else:
        old += (ED25519_PUBLIC_KEY + "\n").encode()
    with pytest.raises(ValueError):
        IDENTITY.check_existing(old, key, policy, True, str(policy_path))


def test_managed_upgrade_accepts_same_key_and_scope(tmp_path):
    policy = {"allowed_roots": ["/data"]}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    IDENTITY.check_existing(
        ('command="fixed" ' + ED25519_PUBLIC_KEY).encode(), ED25519_PUBLIC_KEY, policy, True, str(policy_path)
    )


def test_deployment_rejects_wrong_host_identity():
    metadata = {
        "schema_version": 1,
        "alias": "server-1",
        "host_public_key": ED25519_PUBLIC_KEY,
        "client_public_key": ED25519_PUBLIC_KEY,
        "allowed_roots": ["/data"],
    }
    with pytest.raises(ValueError, match="different SSH host"):
        IDENTITY.check_target(metadata, ED25519_PUBLIC_KEY, {"allowed_roots": ["/data"]}, [])


@pytest.mark.parametrize(
    "other_key", [b"ecdsa-sha2-nistp256 AAAA example\n", b"ssh-dss AAAA example\n", b"ssh-rsa AAAA example\n"]
)
def test_deployment_ignores_other_host_key_types_before_trusted_key(tmp_path, mocker, other_key):
    other = tmp_path / "ssh_host_other_key.pub"
    trusted = tmp_path / "ssh_host_ed25519_key.pub"
    other.write_bytes(other_key)
    trusted.write_text(ED25519_PUBLIC_KEY + "\n", encoding="ascii")
    metadata = {
        "schema_version": 1,
        "alias": "server-1",
        "host_public_key": ED25519_PUBLIC_KEY,
        "client_public_key": ED25519_PUBLIC_KEY,
        "allowed_roots": ["/data"],
    }
    original = IDENTITY.os.lstat

    def root_owned(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if Path(path) in (other, trusted):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
        return info

    mocker.patch.object(IDENTITY.os, "lstat", autospec=True, side_effect=root_owned)
    IDENTITY.check_target(metadata, ED25519_PUBLIC_KEY, {"allowed_roots": ["/data"]}, [str(other), str(trusted)])
    with pytest.raises(ValueError, match="different SSH host"):
        IDENTITY.check_target(metadata, ED25519_PUBLIC_KEY, {"allowed_roots": ["/data"]}, [str(other)])


def test_deployment_still_rejects_wrong_key_of_selected_type(tmp_path, mocker):
    candidate = tmp_path / "ssh_host_ed25519_key.pub"
    candidate.write_text("ssh-ed25519 AAAAother\n", encoding="ascii")
    metadata = {
        "schema_version": 1,
        "alias": "server-1",
        "host_public_key": ED25519_PUBLIC_KEY,
        "client_public_key": ED25519_PUBLIC_KEY,
        "allowed_roots": ["/data"],
    }
    mocker.patch.object(IDENTITY.os, "lstat", autospec=True, return_value=SimpleNamespace(st_mode=0o100644, st_uid=0))
    with pytest.raises(ValueError, match="different SSH host"):
        IDENTITY.check_target(metadata, ED25519_PUBLIC_KEY, {"allowed_roots": ["/data"]}, [str(candidate)])


def test_user_wrapper_fifo_race_cannot_block(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(WRAPPER.PolicyError, match="普通文件"):
        WRAPPER._open_verified_path(str(fifo), (str(tmp_path),), "file")


@pytest.mark.parametrize(
    "data,used,available,estimated",
    [
        (
            "total used free shared buffers cached\nMem: 1000 900 100 0 100 600\n-/+ buffers/cache: 200 800",
            200,
            800,
            True,
        ),
        ("total used free shared buff/cache available\nMem: 1000 200 100 0 700 750", 200, 750, False),
        ("total used free shared buffers cache available\nMem: 1000 200 100 0 100 600 750", 200, 750, False),
    ],
)
def test_memory_metrics_distinguish_reported_and_estimated(data, used, available, estimated):
    ram = parse_free_output(data).ram
    assert (ram.used, ram.available, ram.available_is_estimate) == (used, available, estimated)
    assert ram.used_including_cache == (900 if estimated else None)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
async def test_local_output_limit_discards_partial_output(mocker, stream):
    mocker.patch.object(limits.CONFIG, "max_command_output_bytes", 1024)
    mocker.patch.object(limits.CONFIG, "max_command_stderr_bytes", 1024)
    descriptor = 1 if stream == "stdout" else 2
    with pytest.raises(ConnectionError, match="partial output discarded"):
        await limits.run_bounded_local([sys.executable, "-c", f"import os; os.write({descriptor}, b'x'*100000)"], 5)


async def test_remote_streaming_limit_closes_channel(mocker):
    connection = mocker.Mock(spec=asyncssh.SSHClientConnection)
    process = mocker.Mock(spec=asyncssh.SSHClientProcess)
    process.stdin = mocker.Mock()
    process.stdout = asyncio.StreamReader()
    process.stderr = asyncio.StreamReader()
    process.stdout.feed_data(b"x" * 2048)
    process.stderr.feed_eof()
    connection.create_process = mocker.AsyncMock(return_value=process)
    mocker.patch.object(limits.CONFIG, "max_command_output_bytes", 1024)
    with pytest.raises(ConnectionError, match="exceeds"):
        await limits.run_bounded_remote(connection, "fixed", timeout=5)
    process.close.assert_called_once_with()


async def test_remote_missing_exit_status_is_failure(mocker):
    connection = mocker.Mock(spec=asyncssh.SSHClientConnection)
    process = mocker.Mock(spec=asyncssh.SSHClientProcess)
    process.stdin = mocker.Mock()
    process.exit_status = None
    process.stdout = asyncio.StreamReader()
    process.stderr = asyncio.StreamReader()
    process.stdout.feed_eof()
    process.stderr.feed_eof()
    process.wait_closed = mocker.AsyncMock()
    connection.create_process = mocker.AsyncMock(return_value=process)
    result = await limits.run_bounded_remote(connection, "fixed", timeout=5)
    assert result.exit_status == 255


@pytest.mark.parametrize("oversized", [False, True])
async def test_real_ssh_transport_has_bounded_binary_output(mocker, oversized):
    class TestServer(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async def handle(process):
        process.stdout.write(b"x" * (2048 if oversized else 20))
        process.stderr.write(b"diagnostic")
        process.exit(0)

    server = await asyncssh.create_server(
        TestServer,
        "127.0.0.1",
        0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=handle,
        encoding=None,
    )
    mocker.patch.object(limits.CONFIG, "max_command_output_bytes", 1024)
    try:
        async with asyncssh.connect("127.0.0.1", port=server.get_port(), username="test", known_hosts=None) as conn:
            if oversized:
                with pytest.raises(ConnectionError, match="exceeds"):
                    await limits.run_bounded_remote(conn, "fixture", timeout=5, encoding=None)
            else:
                result = await limits.run_bounded_remote(conn, "fixture", timeout=5, encoding=None)
                assert result.exit_status == 0
                assert result.stdout == b"x" * 20 and result.stderr == b"diagnostic"
    finally:
        server.close()
        await server.wait_closed()


async def test_cancelled_remote_read_closes_channel(mocker):
    connection = mocker.Mock(spec=asyncssh.SSHClientConnection)
    process = mocker.Mock(spec=asyncssh.SSHClientProcess)
    process.stdin = mocker.Mock()
    process.stdout = asyncio.StreamReader()
    process.stderr = asyncio.StreamReader()
    ready = asyncio.Event()

    async def create(*args, **kwargs):
        ready.set()
        return process

    connection.create_process = mocker.AsyncMock(side_effect=create)
    task = asyncio.create_task(limits.run_bounded_remote(connection, "fixed", timeout=5))
    await ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    process.close.assert_called_once_with()


async def test_command_slots_limit_concurrency(mocker):
    mocker.patch.object(limits.CONFIG, "max_concurrent_commands_per_host", 2)
    active = 0
    peak = 0

    async def task():
        nonlocal active, peak
        async with limits.command_slot("test-host"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1

    await asyncio.gather(*(task() for _ in range(6)))
    assert peak == 2


def test_failed_reverification_clears_verified_status(tmp_path, mocker):
    registry = tmp_path / "registry"
    directory = registry / "server-1"
    profile = make_profile(tmp_path)
    profile = profile.model_copy(update={"verified_at": datetime.now(timezone.utc)})
    MANAGER.atomic_json(directory / "profile.json", profile.model_dump(mode="json"))
    args = argparse.Namespace(
        registry=registry,
        alias="server-1",
        results_json=None,
        sample_file=[Path("/data/sample")],
        sample_log_file=Path("/data/log"),
    )
    mocker.patch.object(MANAGER, "run_mcp_verification", autospec=True, side_effect=RuntimeError("transport closed"))
    with pytest.raises(RuntimeError, match="transport closed"):
        MANAGER.command_verify(args)
    assert MANAGER.read_json(directory / "profile.json")["verified_at"] is None
    assert MANAGER.read_json(directory / "last-successful-verification.json")["verified_at"] is not None
    assert MANAGER.read_json(directory / "verification-attempt.json")["status"] == "failed"


def test_parallel_verification_is_rejected(tmp_path):
    with MANAGER.verification_lock(tmp_path):
        with pytest.raises(BlockingIOError):
            with MANAGER.verification_lock(tmp_path):
                pytest.fail("concurrent verification must be rejected")


def test_refresh_prepare_reuses_existing_private_key(tmp_path, mocker):
    registry = tmp_path / "registry"
    directory = registry / "server-1"
    profile = make_profile(tmp_path)
    directory.mkdir(parents=True)
    private = directory / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)], check=True)
    payload = profile.model_dump(mode="json")
    payload["ssh"]["private_key_path"] = str(private)
    payload["ssh"]["known_hosts_path"] = str(directory / "known_hosts")
    payload["read_mode"] = "privileged"
    MANAGER.atomic_json(directory / "profile.stale.json", payload)
    registration = {
        "schema_version": 2,
        "alias": "server-1",
        "address": profile.address,
        "port": 22,
        "user": "codex-ro",
        "allowed_roots": ["/data"],
        "discovery_bundle_sha256": "a" * 64,
        "discovery": discovery(),
    }
    MANAGER.atomic_json(directory / "discovery.json", registration)
    trusted = tmp_path / "trusted.pub"
    trusted.write_text(ED25519_PUBLIC_KEY, encoding="ascii")
    before = private.read_bytes()
    generate = mocker.patch.object(MANAGER, "generate_client_key", autospec=True)
    MANAGER.command_prepare(
        argparse.Namespace(
            registry=registry,
            alias="server-1",
            allow_rsa=False,
            accept_incomplete=False,
            output_dir=tmp_path / "out",
            trusted_host_key_file=trusted,
        )
    )
    generate.assert_not_called()
    assert private.read_bytes() == before
    assert MANAGER.read_json(directory / "profile.json")["read_mode"] == "privileged"


def test_directory_size_uses_allocated_blocks_for_sparse_file(tmp_path):
    sparse = tmp_path / "sparse"
    with sparse.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024)
    prepared, descriptor = WRAPPER._prepare_path_command(
        ["du", "-b", "--one-file-system", "--max-depth=1", str(tmp_path)],
        {"allowed_roots": (str(tmp_path),)},
    )
    try:
        result = subprocess.run(prepared, check=True, capture_output=True, text=True, pass_fds=(descriptor,))
    finally:
        os.close(descriptor)
    allocated = int(result.stdout.split()[0])
    assert allocated < 1024 * 1024
    assert sparse.stat().st_size == 64 * 1024 * 1024
