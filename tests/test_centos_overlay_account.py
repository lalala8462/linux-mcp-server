# -*- coding: utf-8 -*-
from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "centos", "install-readonly-account.sh")
WRAPPER = os.path.join(ROOT, "scripts", "centos", "linux-mcp-readonly.py")


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
if [ "${FAKE_SUDO_STATUS:-1}" = 1 ]; then
  printf '%s\\n' 'User codex-ro is not allowed to run sudo on test-host.'
else
  printf '%s\\n' "${FAKE_SUDO_LISTING:-User codex-ro may run the following commands on test-host:}"
fi
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
        self._write_command(
            "ssh-keygen",
            """#!/bin/sh
printf '%s SHA256:fake key\\n' "${FAKE_KEY_BITS:-4096}"
""",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_accepts_only_exact_helper_sudo_authorization(self):
        listing = ('User codex-ro may run the following commands on test-host:\n'
                   '    (root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read ""')
        result = self._run_function(
            "validate_existing_account", "codex-ro", FAKE_SUDO_STATUS="0", FAKE_SUDO_LISTING=listing
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        escaped = self._run_function(
            "validate_existing_account", "codex-ro", FAKE_SUDO_STATUS="0",
            FAKE_SUDO_LISTING=listing.replace('""', '\\"\\"'),
        )
        self.assertEqual(0, escaped.returncode, escaped.stderr.decode("utf-8"))
        for rule in (
            "(ALL) NOPASSWD: ALL",
            "(root) NOPASSWD: /usr/bin/python",
            "(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read",
            '(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read "", /bin/sh',
        ):
            denied = self._run_function(
                "validate_existing_account", "codex-ro", FAKE_SUDO_STATUS="0",
                FAKE_SUDO_LISTING="User codex-ro may run the following commands on test-host:\n    " + rule,
            )
            self.assertNotEqual(0, denied.returncode)

    def test_helper_runtime_preflight_uses_actual_interpreter(self):
        helper = os.path.join(ROOT, "scripts", "centos", "linux-mcp-privileged-read")
        result = self._run_function("validate_helper_runtime", helper, sys.executable)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))

    def test_sudoers_restricts_arguments_and_passes_visudo(self):
        output = os.path.join(self.temp_dir.name, "sudoers")
        result = self._run_function("write_sudoers", output)
        self.assertEqual(0, result.returncode)
        with open(output, encoding="utf-8") as stream:
            self.assertIn('linux-mcp-privileged-read ""', stream.read())
        result = subprocess.run(["/usr/sbin/visudo", "-cf", output], capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))

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

    def test_policy_validator_declares_utf8_for_python2(self):
        with open(SCRIPT, encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn(
            "<<'PY'\n# -*- coding: utf-8 -*-\nfrom __future__ import print_function",
            script,
        )

    def test_wrapper_runtime_preflight_accepts_forced_command_lookup(self):
        result = self._run_function("validate_wrapper_runtime", WRAPPER, sys.executable)

        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))

    def test_wrapper_runtime_preflight_checks_safe_open_error_formatting(self):
        with open(SCRIPT, encoding="utf-8") as handle:
            script = handle.read()

        self.assertIn('wrapper._open_verified_path(', script)
        self.assertIn('rendered.startswith(u"无法安全打开目标：")', script)

    def test_wrapper_runtime_preflight_rejects_syntax_errors(self):
        wrapper = os.path.join(self.temp_dir.name, "invalid-wrapper.py")
        with open(wrapper, "w", encoding="utf-8") as handle:
            handle.write("def invalid(:\n")

        result = self._run_function("validate_wrapper_runtime", wrapper, sys.executable)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("运行时自检失败", result.stderr.decode("utf-8"))

    def test_wrapper_runtime_preflight_rejects_unexpected_output(self):
        wrapper = os.path.join(self.temp_dir.name, "invalid-output.py")
        with open(wrapper, "w", encoding="utf-8") as handle:
            handle.write("print('tail')\n")

        result = self._run_function("validate_wrapper_runtime", wrapper, sys.executable)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("命令定位结果无效", result.stderr.decode("utf-8"))

    def test_wrapper_runtime_preflight_runs_before_active_file_changes(self):
        with open(SCRIPT, encoding="utf-8") as handle:
            script = handle.read()

        preflight = script.index('validate_wrapper_runtime "${WRAPPER_SOURCE}"')
        backup = script.index("backup_existing_files", preflight)
        wrapper_install = script.index(
            'install -o root -g root -m 0755 "${WRAPPER_SOURCE}" "${WRAPPER_TARGET}"',
            preflight,
        )
        self.assertLess(preflight, backup)
        self.assertLess(preflight, wrapper_install)

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

    def test_policy_requires_safe_allowed_roots(self):
        policy = os.path.join(self.temp_dir.name, "policy.json")
        with open(policy, "w", encoding="utf-8") as handle:
            json.dump({"allowed_roots": [self.temp_dir.name, "/usr"]}, handle)
        valid = self._run_function("validate_policy_file", policy)
        self.assertEqual(0, valid.returncode, valid.stderr.decode("utf-8"))

        with open(policy, "w", encoding="utf-8") as handle:
            json.dump({"allowed_root": self.temp_dir.name}, handle)
        legacy_single = self._run_function("validate_policy_file", policy)
        self.assertEqual(0, legacy_single.returncode, legacy_single.stderr.decode("utf-8"))

        with open(policy, "w", encoding="utf-8") as handle:
            json.dump({"read_roots": [self.temp_dir.name]}, handle)
        legacy = self._run_function("validate_policy_file", policy)
        self.assertNotEqual(0, legacy.returncode)

        with open(policy, "w", encoding="utf-8") as handle:
            json.dump({"allowed_root": "/"}, handle)
        root = self._run_function("validate_policy_file", policy)
        self.assertNotEqual(0, root.returncode)

        for roots in ([], [self.temp_dir.name, self.temp_dir.name], ["/data", "/data/log"], ["/data"] * 17):
            with open(policy, "w", encoding="utf-8") as handle:
                json.dump({"allowed_roots": roots}, handle)
            invalid = self._run_function("validate_policy_file", policy)
            self.assertNotEqual(0, invalid.returncode)

    def test_rsa_requires_explicit_flag_and_4096_bits(self):
        public_key = os.path.join(self.temp_dir.name, "id_rsa.pub")
        with open(public_key, "w", encoding="ascii") as handle:
            handle.write("ssh-rsa QUFBQUFBQUFBQUFBQUFBQUFB linux-mcp\n")

        denied = self._run_function("validate_public_key", public_key, "false")
        self.assertNotEqual(0, denied.returncode)
        self.assertIn("--allow-rsa", denied.stderr.decode("utf-8"))

        accepted = self._run_function("validate_public_key", public_key, "true")
        self.assertEqual(0, accepted.returncode, accepted.stderr.decode("utf-8"))

        wrong_size = self._run_function(
            "validate_public_key",
            public_key,
            "true",
            FAKE_KEY_BITS="2048",
        )
        self.assertNotEqual(0, wrong_size.returncode)
        self.assertIn("4096", wrong_size.stderr.decode("utf-8"))

    def test_ed25519_key_must_parse_as_256_bits(self):
        public_key = os.path.join(self.temp_dir.name, "id_ed25519.pub")
        with open(public_key, "w", encoding="ascii") as handle:
            handle.write("ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFB linux-mcp\n")

        accepted = self._run_function(
            "validate_public_key",
            public_key,
            "false",
            FAKE_KEY_BITS="256",
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr.decode("utf-8"))

        malformed = self._run_function(
            "validate_public_key",
            public_key,
            "false",
            FAKE_KEY_BITS="0",
        )
        self.assertNotEqual(0, malformed.returncode)

    def test_dsa_is_always_rejected(self):
        public_key = os.path.join(self.temp_dir.name, "id_dsa.pub")
        with open(public_key, "w", encoding="ascii") as handle:
            handle.write("ssh-dss QUFBQUFBQUFBQUFBQUFBQUFB linux-mcp\n")
        result = self._run_function("validate_public_key", public_key, "true")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("DSA", result.stderr.decode("utf-8"))

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
