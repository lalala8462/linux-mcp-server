# -*- coding: utf-8 -*-
from __future__ import print_function

import ast
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER_PATH = os.path.join(ROOT, "scripts", "centos", "linux-mcp-readonly.py")
SPEC = importlib.util.spec_from_file_location("linux_mcp_readonly", WRAPPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("无法加载只读包装器模块")
WRAPPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRAPPER)


def test_wrapper_avoids_python27_collection_syntax():
    with open(WRAPPER_PATH, encoding="utf-8") as source_file:
        source = source_file.read()

    tree = ast.parse(source, filename=WRAPPER_PATH)
    incompatible_nodes = [
        (type(node).__name__, node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Set, ast.SetComp, ast.DictComp))
    ]
    assert incompatible_nodes == []


def test_wrapper_avoids_python26_implicit_ascii_error_formatting():
    with open(WRAPPER_PATH, encoding="utf-8") as source_file:
        tree = ast.parse(source_file.read(), filename=WRAPPER_PATH)

    unsafe_lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mod):
            continue
        template = getattr(node.left, "value", None)
        if isinstance(template, str) and any(ord(char) > 127 for char in template):
            unsafe_lines.append(node.lineno)

    assert unsafe_lines == []


def test_error_formatting_decodes_utf8_bytes_before_interpolation():
    message = WRAPPER._format_text(
        "拒绝：%s".encode(),
        "服务器未安装命令：tail".encode(),
    )

    assert message == "拒绝：服务器未安装命令：tail"


def test_exception_text_preserves_unicode():
    assert WRAPPER._exception_text(Exception("无法安全打开目标")) == "无法安全打开目标"


def test_command_split_accepts_native_text_and_utf8_bytes():
    expected = ["command", "-v", "tail"]

    assert WRAPPER._split_command("command -v tail") == expected
    assert WRAPPER._split_command(b"command -v tail") == expected


class ReadonlyWrapperTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.allowed_root = os.path.join(self.temp_dir.name, "project")
        self.second_root = os.path.join(self.temp_dir.name, "data")
        self.read_root = self.allowed_root
        self.scan_root = os.path.join(self.allowed_root, "scan")
        os.makedirs(self.allowed_root)
        os.makedirs(self.second_root)
        os.makedirs(self.scan_root)
        self.read_file = os.path.join(self.read_root, "application.yml")
        self.log_file = os.path.join(self.allowed_root, "messages")
        self.second_file = os.path.join(self.second_root, "second.txt")
        with open(self.read_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("server.port=8080\n")
        with open(self.log_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("test\n")
        with open(self.second_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("second\n")
        self.policy = {
            "allowed_roots": (
                os.path.realpath(self.allowed_root),
                os.path.realpath(self.second_root),
            ),
            "max_file_read_bytes": 1048576,
            "max_log_lines": 10000,
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def assert_denied(self, command):
        with self.assertRaises(WRAPPER.PolicyError):
            WRAPPER.validate_command(command, self.policy)

    def test_allows_fixed_system_commands(self):
        commands = (
            "hostname",
            "uname -r",
            "uptime -p",
            "cat /etc/os-release",
            "grep -c '^processor' /proc/cpuinfo",
            "systemctl list-units --type=service --all --no-pager",
            "ps aux --sort=-%cpu",
            "ss -tulnp",
        )
        for command in commands:
            self.assertTrue(WRAPPER.validate_command(command, self.policy))

    def test_all_upstream_1_5_0_command_shapes(self):
        commands = (
            "systemctl list-units --type=service --all --no-pager",
            "systemctl list-units --type=service --state=running --no-pager",
            "systemctl status mysqld.service --no-pager --full",
            "journalctl -u mysqld.service -n 50 --no-pager",
            "journalctl -n 100 --no-pager --unit mysqld.service --priority err --since '1 hour ago' _TRANSPORT=journal",
            "ss -tunap",
            "ss -tulnp",
            "netstat -tunap",
            "netstat -tulnp",
            "ip -brief address",
            "ip address",
            "cat /proc/net/dev",
            "tail -n 100 %s" % shlex_quote(self.log_file),
            "ps aux --sort=-%cpu",
            "ps -p 123 -o pid,user,stat,pcpu,pmem,vsz,rss,etime,comm,args",
            "cat /proc/123/status",
            "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL --json",
            "lsblk -P -o NAME,KNAME,PKNAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL",
            "lsblk -P -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL",
            "findmnt --df --json",
            "findmnt -D -P -o SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%,TARGET",
            "df -P -B1",
            "chkconfig --list",
            "du -b --one-file-system --max-depth=1 %s" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%f\\n'" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%T@\\t%%f\\n'" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%s\\t%%f\\n'" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%f\\n'" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%T@\\t%%f\\n'" % shlex_quote(self.scan_root),
            "head --bytes 1048576 -- %s" % shlex_quote(self.read_file),
            "head --bytes 1048577 -- %s" % shlex_quote(self.read_file),
            "stat --dereference --format %%s -- %s" % shlex_quote(self.read_file),
            "hostname",
            "cat /etc/os-release",
            "cat /etc/redhat-release",
            "cat /proc/uptime",
            "cat /proc/stat",
            "uname -r",
            "uname -m",
            "uptime -p",
            "uptime -s",
            "grep -m 1 'model name' /proc/cpuinfo",
            "grep -c '^processor' /proc/cpuinfo",
            "grep '^core id' /proc/cpuinfo",
            "grep -m 1 'cpu MHz' /proc/cpuinfo",
            "cat /proc/loadavg",
            "top -bn1",
            "free -b -w",
            "free -b",
            "lscpu",
            "lspci",
            "lsusb",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(WRAPPER.validate_command(command, self.policy))

    def test_allows_read_file_in_root(self):
        command = "head --bytes 1024 -- %s" % shlex_quote(self.read_file)
        validated = WRAPPER.validate_command(command, self.policy)
        self.assertEqual(os.path.realpath(self.read_file), validated[-1])

    def test_allows_read_file_in_each_root(self):
        command = "head --bytes 1024 -- %s" % shlex_quote(self.second_file)
        validated = WRAPPER.validate_command(command, self.policy)
        self.assertEqual(os.path.realpath(self.second_file), validated[-1])

    def test_load_policy_accepts_legacy_single_root(self):
        policy_path = os.path.join(self.temp_dir.name, "single-root-policy.json")
        with open(policy_path, "w", encoding="utf-8") as file_handle:
            json.dump({"allowed_root": self.allowed_root}, file_handle)
        policy = WRAPPER.load_policy(policy_path)
        self.assertEqual((os.path.realpath(self.allowed_root),), policy["allowed_roots"])

    def test_rejects_legacy_three_scope_policy(self):
        policy_path = os.path.join(self.temp_dir.name, "legacy-policy.json")
        with open(policy_path, "w", encoding="utf-8") as file_handle:
            json.dump({"read_roots": [self.allowed_root]}, file_handle)
        with self.assertRaises(WRAPPER.PolicyError):
            WRAPPER.load_policy(policy_path)

    def test_rejects_root_as_allowed_root(self):
        policy_path = os.path.join(self.temp_dir.name, "root-policy.json")
        with open(policy_path, "w", encoding="utf-8") as file_handle:
            json.dump({"allowed_root": "/"}, file_handle)
        with self.assertRaises(WRAPPER.PolicyError):
            WRAPPER.load_policy(policy_path)

    def test_rejects_invalid_allowed_roots_lists(self):
        invalid_roots = (
            [],
            ["/"],
            [self.allowed_root, self.allowed_root],
            [self.allowed_root, os.path.join(self.allowed_root, "child")],
            [self.allowed_root] * 17,
        )
        for index, roots in enumerate(invalid_roots):
            with self.subTest(roots=roots):
                policy_path = os.path.join(self.temp_dir.name, "invalid-policy-%s.json" % index)
                with open(policy_path, "w", encoding="utf-8") as file_handle:
                    json.dump({"allowed_roots": roots}, file_handle)
                with self.assertRaises(WRAPPER.PolicyError):
                    WRAPPER.load_policy(policy_path)

    def test_denies_sibling_directory_with_shared_prefix(self):
        sibling = self.allowed_root + "-other"
        os.makedirs(sibling)
        outside_file = os.path.join(sibling, "outside.log")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("outside\n")
        self.assert_denied("tail -n 1 %s" % shlex_quote(outside_file))

    def test_allows_directory_and_file_scans(self):
        commands = (
            "du -b --one-file-system --max-depth=1 %s" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%f\\n'" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%s\\t%%f\\n'" % shlex_quote(self.scan_root),
        )
        for command in commands:
            self.assertTrue(WRAPPER.validate_command(command, self.policy))

    def test_denies_read_outside_root(self):
        outside_file = os.path.join(self.temp_dir.name, "secret")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")
        self.assert_denied("head --bytes 1024 -- %s" % shlex_quote(outside_file))

    def test_denies_symlink_escape(self):
        outside_file = os.path.join(self.temp_dir.name, "secret")
        link_path = os.path.join(self.read_root, "linked-secret")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")
        os.symlink(outside_file, link_path)
        self.assert_denied("head --bytes 1024 -- %s" % shlex_quote(link_path))

    def test_rejects_final_component_symlink_when_opening(self):
        outside_file = os.path.join(self.temp_dir.name, "secret")
        link_path = os.path.join(self.read_root, "linked-secret")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")
        os.symlink(outside_file, link_path)
        with self.assertRaises(WRAPPER.PolicyError):
            WRAPPER._open_verified_path(link_path, self.policy["allowed_roots"], "file")

    def test_opened_descriptor_survives_later_path_replacement(self):
        replaceable = os.path.join(self.read_root, "replaceable.txt")
        outside_file = os.path.join(self.temp_dir.name, "secret")
        with open(replaceable, "w", encoding="utf-8") as file_handle:
            file_handle.write("approved\n")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")

        descriptor = WRAPPER._open_verified_path(
            replaceable,
            self.policy["allowed_roots"],
            "file",
        )
        try:
            os.rename(replaceable, replaceable + ".old")
            os.symlink(outside_file, replaceable)
            self.assertEqual(os.read(descriptor, 64), b"approved\n")
        finally:
            os.close(descriptor)

    def test_opened_directory_descriptor_survives_later_path_replacement(self):
        replaceable = os.path.join(self.scan_root, "replaceable")
        outside_dir = os.path.join(self.temp_dir.name, "outside")
        os.makedirs(replaceable)
        os.makedirs(outside_dir)
        with open(os.path.join(replaceable, "approved.txt"), "w", encoding="utf-8") as file_handle:
            file_handle.write("approved\n")
        with open(os.path.join(outside_dir, "secret.txt"), "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")

        descriptor = WRAPPER._open_verified_path(
            replaceable,
            self.policy["allowed_roots"],
            "directory",
        )
        try:
            os.rename(replaceable, replaceable + ".old")
            os.symlink(outside_dir, replaceable)
            output = subprocess.check_output(
                [
                    WRAPPER.resolve_binary("find"),
                    "-H",
                    WRAPPER._fd_path(descriptor),
                    "-mindepth",
                    "1",
                    "-maxdepth",
                    "1",
                    "-type",
                    "f",
                    "-printf",
                    "%f\\n",
                ],
                pass_fds=(descriptor,),
            )
            self.assertEqual(b"approved.txt\n", output)
        finally:
            os.close(descriptor)

    def test_prepared_path_commands_use_verified_descriptors(self):
        scan_file = os.path.join(self.scan_root, "child.txt")
        with open(scan_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("child\n")

        commands = (
            ("head --bytes 1024 -- %s" % shlex_quote(self.read_file), b"server.port=8080\n"),
            ("stat --dereference --format %%s -- %s" % shlex_quote(self.read_file), b"17\n"),
            ("tail -n 1 %s" % shlex_quote(self.log_file), b"test\n"),
            (
                "du -b --one-file-system --max-depth=1 %s" % shlex_quote(self.scan_root),
                None,
            ),
            (
                "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%f\\n'" % shlex_quote(self.scan_root),
                b"child.txt\n",
            ),
        )
        for command, expected in commands:
            with self.subTest(command=command):
                validated = WRAPPER.validate_command(command, self.policy)
                prepared, descriptor = WRAPPER._prepare_path_command(validated, self.policy)
                try:
                    self.assertIn("/proc/self/fd/", " ".join(prepared))
                    output = subprocess.check_output(
                        [WRAPPER.resolve_binary(prepared[0])] + prepared[1:],
                        pass_fds=(descriptor,),
                    )
                    if expected is not None:
                        self.assertEqual(expected, output)
                    else:
                        self.assertTrue(output)
                finally:
                    os.close(descriptor)

    def test_denies_generic_or_mutating_commands(self):
        commands = (
            "rm -f /tmp/file",
            "touch /tmp/file",
            "sudo id",
            "bash -c id",
            "curl https://example.com",
            "hostname; id",
            "cat /etc/shadow",
            "findmnt -D -P -o SOURCE,TARGET",
            "lsblk -P -o NAME,UUID",
        )
        for command in commands:
            self.assert_denied(command)

    def test_denies_pipeline_and_redirection(self):
        self.assert_denied("hostname | sh")
        self.assert_denied("hostname > /tmp/output")

    def test_allows_registered_log_only(self):
        command = "tail -n 100 %s" % shlex_quote(self.log_file)
        validated = WRAPPER.validate_command(command, self.policy)
        self.assertEqual(os.path.realpath(self.log_file), validated[-1])

    def test_denies_excessive_limits(self):
        self.assert_denied("head --bytes 1048578 -- %s" % shlex_quote(self.read_file))
        self.assert_denied("tail -n 10001 %s" % shlex_quote(self.log_file))


def shlex_quote(value):
    try:
        import shlex

        return shlex.quote(value)
    except AttributeError:
        return "'" + value.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":
    unittest.main()
