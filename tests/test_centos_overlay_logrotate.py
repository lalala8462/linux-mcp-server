# -*- coding: utf-8 -*-
from __future__ import print_function

import importlib.util
import io
import os
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(ROOT, "scripts", "centos", "configure-logrotate.py")
SPEC = importlib.util.spec_from_file_location("configure_logrotate", SCRIPT_PATH)
CONFIGURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIGURE)


class ConfigureLogrotateTest(unittest.TestCase):
    def test_updates_existing_create_and_postrotate(self):
        original = """/var/log/messages /var/log/secure {
    missingok
    create 0600 root root
    postrotate
        /bin/kill -HUP 1
    endscript
}
"""
        updated = CONFIGURE.update_config_text(
            original,
            ["/var/log/messages", "/var/log/secure"],
            "root",
            "linux-mcp-logread",
            "/usr/local/sbin/linux-mcp-fix-log-permissions",
        )

        self.assertIn("create 0640 root linux-mcp-logread", updated)
        self.assertIn("/bin/kill -HUP 1", updated)
        self.assertIn("/usr/local/sbin/linux-mcp-fix-log-permissions", updated)

    def test_adds_create_and_postrotate(self):
        original = """/var/log/mysqld.log {
    weekly
}
"""
        updated = CONFIGURE.update_config_text(
            original,
            ["/var/log/mysqld.log"],
            "mysql",
            "linux-mcp-logread",
            "/usr/local/sbin/linux-mcp-fix-log-permissions",
        )

        self.assertIn("create 0640 mysql linux-mcp-logread", updated)
        self.assertIn("postrotate", updated)
        self.assertIn("endscript", updated)

    def test_is_idempotent(self):
        original = """/var/log/messages {
    create 0640 root linux-mcp-logread
    postrotate
        /usr/local/sbin/linux-mcp-fix-log-permissions
    endscript
}
"""
        updated = CONFIGURE.update_config_text(
            original,
            ["/var/log/messages"],
            "root",
            "linux-mcp-logread",
            "/usr/local/sbin/linux-mcp-fix-log-permissions",
        )

        self.assertEqual(original, updated)

    def test_rejects_missing_block(self):
        with self.assertRaises(CONFIGURE.ConfigError):
            CONFIGURE.update_config_text(
                "/var/log/other {\n}\n",
                ["/var/log/messages"],
                "root",
                "linux-mcp-logread",
                "/usr/local/sbin/linux-mcp-fix-log-permissions",
            )

    def test_counts_only_active_matching_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            with io.open(os.path.join(directory, "mysql"), "w", encoding="utf-8") as handle:
                handle.write(
                    "# /var/log/mysqld.log {\n"
                    "#    create 0640 mysql mysql\n"
                    "#}\n"
                )
            self.assertEqual(
                CONFIGURE.matching_config_paths(
                    directory,
                    "/var/log/mysqld.log",
                ),
                [],
            )

            active_path = os.path.join(directory, "active")
            with io.open(active_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "/var/log/mysqld.log {\n"
                    "    create 0640 mysql mysql\n"
                    "}\n"
                )
            with io.open(
                active_path + ".linux-mcp-backup",
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    "/var/log/mysqld.log {\n"
                    "    create 0640 mysql mysql\n"
                    "}\n"
                )
            self.assertEqual(
                CONFIGURE.matching_config_paths(
                    directory,
                    "/var/log/mysqld.log",
                ),
                [active_path],
            )

            self.assertEqual(
                CONFIGURE.matching_config_paths(
                    active_path,
                    "/var/log/mysqld.log",
                ),
                [active_path],
            )

    def test_migrates_legacy_backup_outside_logrotate_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            logrotate_dir = os.path.join(directory, "logrotate.d")
            backup_dir = os.path.join(directory, "linux-mcp-readonly", "logrotate-backups")
            os.makedirs(logrotate_dir)
            legacy_path = os.path.join(logrotate_dir, "syslog.linux-mcp-backup")
            with io.open(legacy_path, "w", encoding="utf-8") as handle:
                handle.write("/var/log/messages {\n}\n")

            CONFIGURE.migrate_legacy_backups(logrotate_dir, backup_dir)

            self.assertFalse(os.path.exists(legacy_path))
            self.assertTrue(
                os.path.isfile(
                    os.path.join(
                        backup_dir,
                        "syslog.linux-mcp-backup",
                    )
                )
            )


if __name__ == "__main__":
    unittest.main()
