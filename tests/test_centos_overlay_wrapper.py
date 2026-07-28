# -*- coding: utf-8 -*-
from __future__ import print_function

import importlib.util
import os
import subprocess
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAPPER_PATH = os.path.join(ROOT, "scripts", "centos", "linux-mcp-readonly.py")
SPEC = importlib.util.spec_from_file_location("linux_mcp_readonly", WRAPPER_PATH)
WRAPPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRAPPER)


class ReadonlyWrapperTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.read_root = os.path.join(self.temp_dir.name, "project")
        self.scan_root = os.path.join(self.temp_dir.name, "scan")
        os.makedirs(self.read_root)
        os.makedirs(self.scan_root)
        self.read_file = os.path.join(self.read_root, "application.yml")
        self.log_file = os.path.join(self.temp_dir.name, "messages")
        with open(self.read_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("server.port=8080\n")
        with open(self.log_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("test\n")
        self.policy = {
            "read_roots": [os.path.realpath(self.read_root)],
            "scan_roots": [os.path.realpath(self.scan_root)],
            "log_paths": [os.path.realpath(self.log_file)],
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
            "du -b --one-file-system --max-depth=1 %s" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%f\\n'"
            % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%T@\\t%%f\\n'"
            % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%s\\t%%f\\n'"
            % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%f\\n'"
            % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%T@\\t%%f\\n'"
            % shlex_quote(self.scan_root),
            "head --bytes 1048576 -- %s" % shlex_quote(self.read_file),
            "head --bytes 1048577 -- %s" % shlex_quote(self.read_file),
            "stat --dereference --format %%s -- %s" % shlex_quote(self.read_file),
            "hostname",
            "cat /etc/os-release",
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

    def test_allows_directory_and_file_scans(self):
        commands = (
            "du -b --one-file-system --max-depth=1 %s" % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type d -printf '%%f\\n'"
            % shlex_quote(self.scan_root),
            "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%s\\t%%f\\n'"
            % shlex_quote(self.scan_root),
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
            WRAPPER._open_verified_path(link_path, self.policy["read_roots"], "file")

    def test_opened_descriptor_survives_later_path_replacement(self):
        replaceable = os.path.join(self.read_root, "replaceable.txt")
        outside_file = os.path.join(self.temp_dir.name, "secret")
        with open(replaceable, "w", encoding="utf-8") as file_handle:
            file_handle.write("approved\n")
        with open(outside_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("secret\n")

        descriptor = WRAPPER._open_verified_path(
            replaceable,
            self.policy["read_roots"],
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
            self.policy["scan_roots"],
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
                "find %s -mindepth 1 -maxdepth 1 -type f -printf '%%f\\n'"
                % shlex_quote(self.scan_root),
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
