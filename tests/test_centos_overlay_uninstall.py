# -*- coding: utf-8 -*-
"""Safety checks for the managed-account uninstall script."""

import os
import subprocess
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "centos", "uninstall-readonly-account.sh")


class UninstallReadonlyAccountTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.bin_dir = os.path.join(self.temp_dir.name, "bin")
        os.makedirs(self.bin_dir)
        self._write_command(
            "stat",
            """#!/bin/sh
case "$2" in
  %U) printf '%s\\n' "${FAKE_MARKER_OWNER:-root}" ;;
  %a) printf '%s\\n' "${FAKE_MARKER_MODE:-644}" ;;
  *) exit 2 ;;
esac
""",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_command(self, name, content):
        path = os.path.join(self.bin_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, 0o755)

    def _run_function(self, function, *arguments, **environment):
        process_environment = os.environ.copy()
        process_environment["PATH"] = self.bin_dir + os.pathsep + process_environment["PATH"]
        process_environment.update(environment)
        return subprocess.run(
            ["bash", "-c", 'source "$1"; "$2" "${@:3}"', "bash", SCRIPT, function] + list(arguments),
            env=process_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_script_has_valid_bash_syntax(self):
        subprocess.check_call(["bash", "-n", SCRIPT])

    def test_rejects_root_account_and_mismatched_confirmation(self):
        root_result = self._run_function("validate_account_name", "root")
        self.assertNotEqual(0, root_result.returncode)
        mismatch = self._run_function("require_confirmed_account", "other-ro", "codex-ro")
        self.assertNotEqual(0, mismatch.returncode)
        self.assertIn("不一致", mismatch.stderr.decode("utf-8"))

    def test_reads_only_safe_managed_marker(self):
        marker = os.path.join(self.temp_dir.name, "managed-account")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("codex-ro\n")
        result = self._run_function("read_managed_account", marker)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        self.assertEqual(b"codex-ro\n", result.stdout)
        unsafe = self._run_function("read_managed_account", marker, FAKE_MARKER_OWNER="codex-ro")
        self.assertNotEqual(0, unsafe.returncode)

    def test_refuses_private_group_shared_by_another_account(self):
        self._write_command(
            "getent",
            """#!/bin/sh
case "$1" in
  group) printf 'codex-ro:x:1001:\\n' ;;
  passwd) printf '%s\\n' "${FAKE_PASSWD_ENTRY:-}" ;;
  *) exit 2 ;;
esac
""",
        )
        shared = self._run_function(
            "assert_private_group_unused",
            "codex-ro",
            FAKE_PASSWD_ENTRY="other:x:1002:1001::/home/other:/sbin/nologin",
        )
        self.assertNotEqual(0, shared.returncode)
        self.assertIn("其他账号", shared.stderr.decode("utf-8"))
        private = self._run_function(
            "assert_private_group_unused",
            "codex-ro",
            FAKE_PASSWD_ENTRY="codex-ro:x:1001:1001::/home/codex-ro:/sbin/nologin",
        )
        self.assertEqual(0, private.returncode, private.stderr.decode("utf-8"))

    def test_refuses_private_group_with_supplementary_member(self):
        self._write_command(
            "getent",
            """#!/bin/sh
case "$1" in
  group) printf 'codex-ro:x:1001:other\\n' ;;
  passwd) printf 'codex-ro:x:1001:1001::/home/codex-ro:/sbin/nologin\\n' ;;
  *) exit 2 ;;
esac
""",
        )
        result = self._run_function("assert_private_group_unused", "codex-ro")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("其他成员", result.stderr.decode("utf-8"))

    def test_selects_recovery_when_managed_account_is_already_absent(self):
        self._write_command(
            "id",
            """#!/bin/sh
exit "${FAKE_ID_STATUS:-0}"
""",
        )
        result = self._run_function("determine_uninstall_mode", "codex-ro", FAKE_ID_STATUS="1")
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        self.assertEqual(b"recover\n", result.stdout)

    def test_removes_marker_last_to_allow_recovery_after_interruption(self):
        self._write_command(
            "rm",
            """#!/bin/sh
printf '%s\\n' "$@"
""",
        )
        result = self._run_function(
            "remove_managed_files",
            "/usr/local/libexec/linux-mcp-readonly.py",
            "/etc/linux-mcp-readonly/policy.json",
            "/etc/linux-mcp-readonly/managed-account",
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        self.assertEqual(
            b"-f\n--\n/usr/local/libexec/linux-mcp-readonly.py\n"
            b"/etc/linux-mcp-readonly/policy.json\n/etc/linux-mcp-readonly/managed-account\n",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
