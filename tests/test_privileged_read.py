"""受控 root 读取的协议、描述符、路径替换与资源上限测试。"""

import ast
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tokenize

from pathlib import Path
from types import SimpleNamespace

import pytest

from fastmcp.exceptions import ToolError

from linux_mcp_server.commands import CommandSpec
from linux_mcp_server.tools import storage


SOURCE = Path(__file__).parents[1] / "scripts/centos/linux-mcp-privileged-read"
LOADER = importlib.machinery.SourceFileLoader("privileged_read_test", str(SOURCE))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("无法加载受控读取 helper")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


@pytest.fixture
def read_policy(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    return {"roots": [str(root)], "bytes": 1024, "lines": 10}


def request(policy, *, op="read", path=None, limit=100, output_format=""):
    payload = {
        "version": 1,
        "op": op,
        "path": path or policy["roots"][0] + "/text.txt",
        "limit": limit,
        "format": output_format,
    }
    return HELPER.parse_request(json.dumps(payload).encode(), policy)


def test_helper_keeps_python26_syntax_and_no_shell_execution():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    forbidden = (ast.Set, ast.SetComp, ast.DictComp, ast.JoinedStr, ast.AnnAssign, ast.AsyncFunctionDef)
    assert not [node for node in ast.walk(tree) if isinstance(node, forbidden)]
    assert "shell=True" not in SOURCE.read_text(encoding="utf-8")
    tokens = tokenize.generate_tokens(io.StringIO(SOURCE.read_text(encoding="utf-8")).readline)
    assert not [
        token for token in tokens if token.type == tokenize.STRING and token.string.lower().startswith(('rb"', "rb'"))
    ]


@pytest.mark.parametrize("op", ["write", "delete", "shell", "install", "cat", "read;id", ""])
def test_rejects_non_read_operations(read_policy, op):
    with pytest.raises(HELPER.ReadDenied):
        request(read_policy, op=op)


@pytest.mark.parametrize("path", ["relative", "/etc/passwd", "/", "/data/../etc/passwd", "/data//file", "/data/x\n"])
def test_rejects_outside_or_ambiguous_paths(read_policy, path):
    with pytest.raises(HELPER.ReadDenied):
        request(read_policy, path=path)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1026, "100", 1.5, None])
def test_read_limit_is_strictly_bounded(read_policy, limit):
    with pytest.raises(HELPER.ReadDenied):
        request(read_policy, limit=limit)


@pytest.mark.parametrize("raw", [b"{}", b"[]", b"null", b"not-json", b" " * 8193])
def test_request_shape_and_input_size_are_bounded(read_policy, raw):
    with pytest.raises((HELPER.ReadDenied, ValueError)):
        HELPER.parse_request(raw, read_policy)


def test_file_read_stat_tail_and_sentinel(read_policy):
    target = Path(read_policy["roots"][0]) / "text.txt"
    target.write_bytes(b"first\nsecond\nthird\n")
    assert HELPER.execute_request(request(read_policy, limit=5), read_policy) == b"first"
    assert HELPER.execute_request(request(read_policy, op="stat", limit=0), read_policy) == b"19\n"
    assert HELPER.execute_request(request(read_policy, op="tail", limit=2), read_policy) == b"second\nthird\n"
    target.write_bytes(b"x" * 1025)
    assert len(HELPER.execute_request(request(read_policy, limit=1025), read_policy)) == 1025
    with pytest.raises(HELPER.ReadDenied, match="byte limit"):
        HELPER.execute_request(request(read_policy, op="tail", limit=1), read_policy)


def test_large_log_reads_only_bounded_suffix(read_policy):
    target = Path(read_policy["roots"][0]) / "text.txt"
    target.write_bytes(b"old\n" * 5000 + b"last\n")
    assert HELPER.execute_request(request(read_policy, op="tail", limit=2), read_policy) == b"old\nlast\n"


def test_rejects_final_and_parent_symlinks_and_hardlinks(read_policy, tmp_path):
    root = Path(read_policy["roots"][0])
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret"
    secret.write_text("outside", encoding="utf-8")
    (root / "text.txt").symlink_to(secret)
    with pytest.raises(HELPER.ReadDenied):
        HELPER.execute_request(request(read_policy), read_policy)
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    with pytest.raises(HELPER.ReadDenied):
        HELPER.execute_request(request(read_policy, path=str(root / "linked-dir/secret")), read_policy)
    os.link(secret, root / "hardlink")
    with pytest.raises(HELPER.ReadDenied, match="hard-linked"):
        HELPER.execute_request(request(read_policy, path=str(root / "hardlink")), read_policy)


def test_rejects_fifo_without_opening_or_blocking(read_policy, mocker):
    root = Path(read_policy["roots"][0])
    fifo = root / "text.txt"
    os.mkfifo(fifo)
    original = HELPER.os.open
    opened = []

    def observe(path, flags):
        opened.append(str(path))
        return original(path, flags)

    mocker.patch.object(HELPER.os, "open", side_effect=observe)
    with pytest.raises(HELPER.ReadDenied, match="special"):
        HELPER.execute_request(request(read_policy), read_policy)
    assert not any(path.endswith("/text.txt") for path in opened)


def test_detects_replacement_after_open(read_policy, mocker):
    root = Path(read_policy["roots"][0])
    target = root / "text.txt"
    target.write_text("sample", encoding="utf-8")
    mocker.patch.object(HELPER.os, "readlink", autospec=True, return_value="/etc/passwd")
    with pytest.raises(HELPER.ReadDenied, match="changed"):
        HELPER.execute_request(request(read_policy), read_policy)


def test_fixed_directory_operations_and_errors(read_policy):
    root = Path(read_policy["roots"][0])
    (root / "text.txt").write_text("sample", encoding="utf-8")
    (root / "nested").mkdir()
    for op, output_format, expected in (
        ("list_files", "name", b"text.txt"),
        ("list_files", "size", b"6\ttext.txt"),
        ("list_dirs", "name", b"nested"),
        ("directory_sizes", "", b"nested"),
    ):
        data = HELPER.execute_request(
            request(read_policy, op=op, path=str(root), limit=0, output_format=output_format), read_policy
        )
        assert expected in data
    with pytest.raises(HELPER.ReadDenied, match="partial output"):
        HELPER.fixed_listing(["/bin/sh", "-c", "printf partial; exit 1"])


def test_directory_output_is_bounded(read_policy, mocker):
    mocker.patch.object(HELPER, "MAX_OUTPUT", 4)
    with pytest.raises(HELPER.ReadDenied, match="output exceeds"):
        HELPER.fixed_listing(["/bin/sh", "-c", "printf 123456"])


def test_local_user_cannot_spoof_sudo_identity():
    result = subprocess.run(
        [sys.executable, str(SOURCE)],
        input=b"{}",
        capture_output=True,
        env={**os.environ, "SUDO_UID": "0", "SUDO_USER": "codex-ro"},
        timeout=5,
    )
    assert result.returncode == 126
    assert result.stdout == b""


def test_policy_root_control_and_mode(read_policy, tmp_path, mocker):
    policy_file = tmp_path / "policy.json"
    payload = {"allowed_roots": read_policy["roots"], "read_mode": "privileged"}
    policy_file.write_text(json.dumps(payload), encoding="utf-8")
    mocker.patch.object(HELPER, "POLICY_PATH", str(policy_file))
    trust = mocker.patch.object(HELPER, "trusted_path", autospec=True)
    assert HELPER.load_policy()["roots"] == read_policy["roots"]
    trust.assert_called_once_with(str(policy_file), "file")
    for patch in (
        {"read_mode": "user"},
        {"allowed_roots": ["/"]},
        {"allowed_roots": ["/data", "/data/nested"]},
        {"max_file_read_bytes": 99999999},
        {"max_log_lines": True},
        {"allowed_root": "/etc"},
    ):
        policy_file.write_text(json.dumps({**payload, **patch}), encoding="utf-8")
        with pytest.raises(HELPER.ReadDenied):
            HELPER.load_policy()


def test_root_controlled_paths_reject_writable_or_symlinked_files(tmp_path, mocker):
    target = tmp_path / "helper"
    target.write_text("public", encoding="utf-8")
    info = os.stat_result((stat.S_IFREG | 0o666, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    mocker.patch.object(HELPER.os, "lstat", autospec=True, return_value=info)
    with pytest.raises(HELPER.ReadDenied, match="untrusted"):
        HELPER.trusted_path(str(target), "file")


async def test_privileged_directory_tool_rejects_partial_failure(mocker):
    command = mocker.Mock(spec=CommandSpec)
    command.run = mocker.AsyncMock(spec=CommandSpec.run, return_value=(126, "partial", "privileged read timed out"))
    parser = mocker.create_autospec(storage.parse_directory_listing, return_value=[])
    mocker.patch.object(
        storage, "get_managed_profile", autospec=True, return_value=SimpleNamespace(read_mode="privileged")
    )
    with pytest.raises(ToolError, match="timed out"):
        await storage._list_resources(
            Path("/data"), command, storage.OrderBy.SIZE, storage.SortBy.ASCENDING, 1, "server-a", parser
        )
    parser.assert_not_called()


@pytest.mark.parametrize(
    "executable,parent_uid,allowed",
    [
        ("/usr/bin/sudo", 0, True),
        ("/usr/bin/python", 1001, True),
        ("/usr/bin/python", 1002, False),
        ("/usr/bin/python", 0, False),
    ],
)
def test_sudo_identity_uses_kernel_parent_not_just_environment(mocker, executable, parent_uid, allowed):
    mocker.patch.object(HELPER.sys, "argv", [HELPER.HELPER_PATH])
    mocker.patch.object(HELPER.os, "getuid", autospec=True, return_value=0)
    mocker.patch.object(HELPER.os, "geteuid", autospec=True, return_value=0)
    mocker.patch.object(HELPER.pwd, "getpwnam", autospec=True, return_value=SimpleNamespace(pw_uid=1001))
    mocker.patch.dict(HELPER.os.environ, {"SUDO_UID": "1001"})
    mocker.patch.object(HELPER, "trusted_path", autospec=True)
    mocker.patch.object(HELPER.os.path, "realpath", autospec=True, return_value=executable)
    status = f"Uid:\t{parent_uid}\t{parent_uid}\t{parent_uid}\t{parent_uid}\n".encode()
    mocker.patch("builtins.open", mocker.mock_open(read_data=status))
    if allowed:
        HELPER.require_identity()
    else:
        with pytest.raises(HELPER.ReadDenied, match="identity"):
            HELPER.require_identity()
