# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import subprocess
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "centos", "install-readonly-account.sh")


class InstallReadonlyAccountTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.bin_dir = os.path.join(self.temp_dir.name, "bin")
        os.makedirs(self.bin_dir)
        self._write_command(
            "id",
            """#!/bin/sh
case "$1" in
  -u) printf '%s\\n' "$FAKE_UID" ;;
  -gn) printf '%s\\n' "$FAKE_PRIMARY_GROUP" ;;
  -nG) printf '%s\\n' "$FAKE_GROUPS" ;;
  *) exit 0 ;;
esac
""",
        )
        self._write_command(
            "sudo",
            """#!/bin/sh
exit "${FAKE_SUDO_STATUS:-1}"
""",
        )
        self._write_command(
            "runuser",
            """#!/bin/sh
[ "$1" = "-u" ] && [ "$3" = "--" ] || exit 2
shift 3
exec "$@"
""",
        )
        self._write_command(
            "stat",
            """#!/bin/sh
case "$2" in
  %U) printf '%s\\n' "$FAKE_MARKER_OWNER" ;;
  %a) printf '%s\\n' "$FAKE_MARKER_MODE" ;;
  *) exit 2 ;;
esac
""",
        )
        self._write_command(
            "date",
            """#!/bin/sh
printf '%s\\n' '20260101T000000Z'
""",
        )
        self._write_command(
            "install",
            """#!/bin/sh
if [ "$1" = "-d" ]; then
  for argument in "$@"; do target="$argument"; done
  mkdir -p "$target"
  exit 0
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|-g|-m) shift 2 ;;
    *) source="$1"; target="$2"; break ;;
  esac
done
cp "$source" "$target"
""",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_command(self, name, content):
        path = os.path.join(self.bin_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, 0o755)

    def _environment(self, **overrides):
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": self.bin_dir + os.pathsep + environment["PATH"],
                "FAKE_UID": "1001",
                "FAKE_PRIMARY_GROUP": "codex-ro",
                "FAKE_GROUPS": "codex-ro systemd-journal linux-mcp-logread",
                "FAKE_SUDO_STATUS": "1",
                "FAKE_MARKER_OWNER": "root",
                "FAKE_MARKER_MODE": "644",
            }
        )
        environment.update(overrides)
        return environment

    def _run_function(self, function, *arguments, **environment):
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; "$2" "${@:3}"',
                "bash",
                SCRIPT,
                function,
            ]
            + list(arguments),
            env=self._environment(**environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_script_has_valid_bash_syntax(self):
        subprocess.check_call(["bash", "-n", SCRIPT])

    def test_accepts_dedicated_account_with_only_allowed_groups(self):
        result = self._run_function("validate_existing_account", "codex-ro")
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))

    def test_rejects_uid_zero_account(self):
        result = self._run_function(
            "validate_existing_account",
            "root",
            FAKE_UID="0",
            FAKE_PRIMARY_GROUP="root",
            FAKE_GROUPS="root",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("UID 0", result.stderr.decode("utf-8"))

    def test_rejects_wheel_as_first_or_only_group(self):
        result = self._run_function(
            "validate_existing_account",
            "codex-ro",
            FAKE_GROUPS="wheel",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("wheel", result.stderr.decode("utf-8"))

    def test_rejects_sudo_enabled_account(self):
        result = self._run_function(
            "validate_existing_account",
            "codex-ro",
            FAKE_SUDO_STATUS="0",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("sudo", result.stderr.decode("utf-8"))

    def test_reads_only_root_owned_safe_marker(self):
        marker = os.path.join(self.temp_dir.name, "managed-account")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("codex-ro\n")
        result = self._run_function("read_managed_account", marker)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        self.assertEqual(b"codex-ro\n", result.stdout)

        unsafe = self._run_function(
            "read_managed_account",
            marker,
            FAKE_MARKER_OWNER="codex-ro",
        )
        self.assertNotEqual(0, unsafe.returncode)

    def test_rejects_managed_account_name_mismatch(self):
        marker = os.path.join(self.temp_dir.name, "managed-account")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("codex-ro\n")
        result = self._run_function(
            "validate_managed_account",
            marker,
            "different-ro",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("不能改用", result.stderr.decode("utf-8"))

    def test_backup_copies_existing_files_once_without_overwrite(self):
        wrapper = os.path.join(self.temp_dir.name, "wrapper.py")
        policy = os.path.join(self.temp_dir.name, "policy.json")
        backup_root = os.path.join(self.temp_dir.name, "backups")
        for path, content in ((wrapper, "old wrapper\n"), (policy, "old policy\n")):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)

        command = (
            'source "$1"; WRAPPER_TARGET="$2"; POLICY_TARGET="$3"; '
            'BACKUP_ROOT="$4"; BACKUP_DIR=""; backup_existing_files; printf "%s" "$BACKUP_DIR"'
        )
        result = subprocess.run(
            ["bash", "-c", command, "bash", SCRIPT, wrapper, policy, backup_root],
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        backup_dir = result.stdout.decode("utf-8")
        self.assertEqual(
            os.path.join(backup_root, "20260101T000000Z"),
            backup_dir,
        )
        with open(os.path.join(backup_dir, "wrapper.py"), encoding="utf-8") as handle:
            self.assertEqual("old wrapper\n", handle.read())
        with open(os.path.join(backup_dir, "policy.json"), encoding="utf-8") as handle:
            self.assertEqual("old policy\n", handle.read())

        duplicate = subprocess.run(
            ["bash", "-c", command, "bash", SCRIPT, wrapper, policy, backup_root],
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(0, duplicate.returncode)
        self.assertIn("拒绝覆盖", duplicate.stderr.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
