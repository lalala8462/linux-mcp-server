#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""为批准日志的现有 logrotate 块增加最小只读组权限。"""
from __future__ import print_function

import glob
import io
import os
import re
import shutil
import sys
import tempfile


CREATE_RE = re.compile(r"^(\s*)create(?:\s+\S+){0,3}\s*$")
POSTROTATE_RE = re.compile(r"^\s*postrotate\s*$")
ENDSCRIPT_RE = re.compile(r"^\s*endscript\s*$")


class ConfigError(Exception):
    pass


def _ensure_backup_dir(backup_dir):
    if os.path.exists(backup_dir):
        if os.path.islink(backup_dir) or not os.path.isdir(backup_dir):
            raise ConfigError("备份路径不是普通目录：%s" % backup_dir)
        return
    os.makedirs(backup_dir, 0o755)


def migrate_legacy_backups(logrotate_dir, backup_dir):
    legacy_paths = sorted(glob.glob(os.path.join(logrotate_dir, "*.linux-mcp-backup")))
    if not legacy_paths:
        return
    _ensure_backup_dir(backup_dir)
    for legacy_path in legacy_paths:
        if os.path.islink(legacy_path) or not os.path.isfile(legacy_path):
            raise ConfigError("旧备份不是普通文件：%s" % legacy_path)
        destination = os.path.join(backup_dir, os.path.basename(legacy_path))
        if os.path.exists(destination):
            raise ConfigError("安全备份已存在，拒绝覆盖：%s" % destination)
        os.rename(legacy_path, destination)
        print("已迁移备份：%s -> %s" % (legacy_path, destination))


def _blocks(lines):
    start = None
    depth = 0
    for index, line in enumerate(lines):
        structural_line = "" if line.lstrip().startswith("#") else line
        if start is None and "{" in structural_line:
            start = index
            depth = structural_line.count("{") - structural_line.count("}")
            if depth == 0:
                yield start, index
                start = None
            continue
        if start is not None:
            depth += structural_line.count("{") - structural_line.count("}")
            if depth == 0:
                yield start, index
                start = None
    if start is not None:
        raise ConfigError("logrotate 配置的大括号不完整")


def _header(lines, start):
    header_lines = []
    index = start
    while index >= 0:
        header_lines.insert(0, lines[index].split("{", 1)[0])
        if index == 0 or lines[index - 1].strip().endswith("}"):
            break
        index -= 1
    return " ".join(header_lines)


def matching_blocks(text, log_path):
    lines = text.splitlines(True)
    matches = []
    for start, end in _blocks(lines):
        header_tokens = _header(lines, start).split()
        if log_path in header_tokens:
            matches.append((start, end))
    return matches


def _config_paths(logrotate_root):
    if os.path.isfile(logrotate_root):
        return [logrotate_root]
    return [
        path
        for path in sorted(glob.glob(os.path.join(logrotate_root, "*")))
        if os.path.isfile(path) and not path.endswith(".linux-mcp-backup")
    ]


def matching_config_paths(logrotate_root, log_path):
    matches = []
    for config_path in _config_paths(logrotate_root):
        with io.open(config_path, "r", encoding="utf-8") as handle:
            if matching_blocks(handle.read(), log_path):
                matches.append(config_path)
    return matches


def update_config_text(text, log_paths, owner, group_name, hook_path):
    lines = text.splitlines(True)
    target = None
    for start, end in _blocks(lines):
        header_tokens = _header(lines, start).split()
        if any(path in header_tokens for path in log_paths):
            if target is not None:
                raise ConfigError("一个配置文件包含多个匹配块")
            target = (start, end)
    if target is None:
        raise ConfigError("配置文件中没有匹配的日志块")

    start, end = target
    create_indexes = [index for index in range(start + 1, end) if CREATE_RE.match(lines[index].rstrip("\r\n"))]
    create_line = "    create 0640 %s %s\n" % (owner, group_name)
    if len(create_indexes) > 1:
        raise ConfigError("匹配块包含多个 create 指令")
    if create_indexes:
        lines[create_indexes[0]] = create_line
    else:
        lines.insert(start + 1, create_line)
        end += 1

    block_text = "".join(lines[start : end + 1])
    if hook_path in block_text:
        return "".join(lines)

    postrotate = None
    endscript = None
    for index in range(start + 1, end):
        if POSTROTATE_RE.match(lines[index]):
            postrotate = index
        elif postrotate is not None and ENDSCRIPT_RE.match(lines[index]):
            endscript = index
            break

    hook_line = "        %s\n" % hook_path
    if postrotate is not None:
        if endscript is None:
            raise ConfigError("postrotate 缺少 endscript")
        lines.insert(endscript, hook_line)
    else:
        lines[end:end] = [
            "    postrotate\n",
            hook_line,
            "    endscript\n",
        ]
    return "".join(lines)


def _write_atomic(path, content):
    directory = os.path.dirname(path)
    descriptor, temp_path = tempfile.mkstemp(prefix=".linux-mcp-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content.encode("utf-8"))
        shutil.copymode(path, temp_path)
        os.rename(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def configure(logrotate_dir, group_name, hook_path, path_owners):
    backup_dir = os.path.join(
        os.path.dirname(logrotate_dir.rstrip(os.sep)),
        "linux-mcp-readonly",
        "logrotate-backups",
    )
    migrate_legacy_backups(logrotate_dir, backup_dir)

    configs = {}
    for config_path in _config_paths(logrotate_dir):
        with io.open(config_path, "r", encoding="utf-8") as handle:
            configs[config_path] = handle.read()

    assignments = {}
    for log_path, owner in path_owners:
        found = []
        for config_path, text in configs.items():
            if matching_blocks(text, log_path):
                found.append(config_path)
        if len(found) != 1:
            raise ConfigError("%s 必须且只能匹配一个 logrotate 配置，实际 %d" % (log_path, len(found)))
        assignments.setdefault(found[0], []).append((log_path, owner))

    updates = {}
    for config_path, items in assignments.items():
        owners = set(owner for _, owner in items)
        if len(owners) != 1:
            raise ConfigError("%s 的同一日志块包含不同 owner" % config_path)
        paths = [path for path, _ in items]
        updates[config_path] = update_config_text(
            configs[config_path],
            paths,
            next(iter(owners)),
            group_name,
            hook_path,
        )

    for config_path, updated in updates.items():
        if updated == configs[config_path]:
            continue
        _ensure_backup_dir(backup_dir)
        backup = os.path.join(
            backup_dir,
            os.path.basename(config_path) + ".linux-mcp-backup",
        )
        if not os.path.exists(backup):
            shutil.copy2(config_path, backup)
        _write_atomic(config_path, updated)
        print("已更新：%s" % config_path)


def main(argv):
    if len(argv) == 4 and argv[1] == "--match-count":
        print(len(matching_config_paths(argv[2], argv[3])))
        return 0
    if len(argv) < 5 or (len(argv) - 4) % 2:
        print(
            "用法：configure-logrotate.py --match-count <logrotate目录> <日志路径>\n"
            "  或：configure-logrotate.py <logrotate目录> <组名> <hook路径> <日志路径> <owner> [...]",
            file=sys.stderr,
        )
        return 2
    pairs = list(zip(argv[4::2], argv[5::2]))
    try:
        configure(argv[1], argv[2], argv[3], pairs)
        return 0
    except ConfigError as error:
        print("错误：%s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
