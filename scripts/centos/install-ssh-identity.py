#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""管理员安装阶段的身份校验和安全公钥写入；兼容 Python 2.6。"""

from __future__ import print_function

import errno
import glob
import json
import os
import pwd
import re
import stat
import sys
import uuid


def public_key(value):
    value = value.strip()
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ValueError("public key must be one line")
    parts = value.split()
    if len(parts) < 2 or parts[0] not in ("ssh-rsa", "ssh-ed25519"):
        raise ValueError("invalid public key")
    return " ".join(parts[:2])


def read_json(path):
    with open(path, "rb") as stream:
        return json.loads(stream.read().decode("utf-8"))


def roots(policy):
    values = policy.get("allowed_roots", [policy.get("allowed_root")])
    return sorted(values)


def check_target(metadata, key, policy, host_key_files=None):
    if set(metadata) != set(("schema_version", "alias", "host_public_key", "client_public_key", "allowed_roots")):
        raise ValueError("invalid deployment identity schema")
    if metadata["schema_version"] != 1 or public_key(metadata["client_public_key"]) != public_key(key):
        raise ValueError("deployment client identity mismatch")
    if sorted(metadata["allowed_roots"]) != roots(policy):
        raise ValueError("deployment roots mismatch")
    expected = public_key(metadata["host_public_key"])
    for path in host_key_files if host_key_files is not None else glob.glob("/etc/ssh/ssh_host_*_key.pub"):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe server host key file")
        with open(path, "rb") as stream:
            if public_key(stream.read().decode("ascii")) == expected:
                return
    raise ValueError("deployment belongs to a different SSH host identity")


def open_home(account):
    entry = pwd.getpwnam(account)
    home = entry.pw_dir
    if (
        entry.pw_uid == 0
        or os.path.basename(home) != account
        or home.startswith(("/root/", "/etc/", "/usr/", "/proc/", "/sys/", "/dev/"))
        or os.path.normpath(home) != home
        or not home.startswith("/")
    ):
        raise ValueError("unsafe account home")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = home.strip("/").split("/")
        for part in parts:
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("home ancestors must be controlled by root")
            child = os.open("/proc/self/fd/%d/%s" % (descriptor, part), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid not in (0, entry.pw_uid) or info.st_mode & 0o022:
            raise ValueError("unsafe home ownership or permissions")
        return entry, descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_authorized(directory, uid):
    try:
        descriptor = os.open(
            "/proc/self/fd/%d/authorized_keys" % directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, uid):
            raise ValueError("unsafe authorized_keys type or owner")
        if info.st_mode & 0o022 or info.st_size > 65536:
            raise ValueError("unsafe authorized_keys permissions or size")
        data = os.read(descriptor, 65537)
        if len(data) > 65536:
            raise ValueError("authorized_keys too large")
        return data
    finally:
        os.close(descriptor)


def check_existing(old, key, policy, managed, policy_path):
    if managed:
        if old is None:
            raise ValueError("managed account is missing authorized_keys")
        lines = [line for line in old.decode("ascii").splitlines() if line.strip()]
        matches = [re.search(r" (ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+)(?: |$)", line) for line in lines]
        if len(matches) != 1 or matches[0] is None or matches[0].group(1) != public_key(key):
            raise ValueError("upgrade client key differs from the installed identity; refusing replacement")
        if roots(read_json(policy_path)) != roots(policy):
            raise ValueError("upgrade roots differ from the installed policy; refusing scope change")


def install_identity(account, key, policy, managed, policy_path, content=None, backup=None):
    entry, home = open_home(account)
    directory = None
    try:
        path = "/proc/self/fd/%d/.ssh" % home
        try:
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.ENOENT or managed:
                raise
            if content is None:
                return
            os.mkdir(path, 0o700)
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            os.fchown(directory, entry.pw_uid, entry.pw_gid)
        info = os.fstat(directory)
        if info.st_uid not in (0, entry.pw_uid) or info.st_mode & 0o022:
            raise ValueError("unsafe .ssh ownership or permissions")
        for name in ("rc", "environment"):
            if os.path.lexists("/proc/self/fd/%d/%s" % (directory, name)):
                raise ValueError("SSH startup hooks/environment require administrator inspection")
        old = read_authorized(directory, entry.pw_uid)
        check_existing(old, key, policy, managed, policy_path)
        if content is None:
            return
        # 专用账号不能替换 .ssh 或去掉 ForceCommand；目录仍可供 sshd 以该 UID 遍历。
        os.fchown(home, 0, 0)
        os.fchmod(home, 0o755)
        os.fchown(directory, 0, 0)
        os.fchmod(directory, 0o755)
        old = read_authorized(directory, entry.pw_uid)
        check_existing(old, key, policy, managed, policy_path)
        if old is not None and backup:
            descriptor = os.open(
                os.path.join(backup, "authorized_keys"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            try:
                os.write(descriptor, old)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        temporary = "/proc/self/fd/%d/.authorized_keys.%s" % (directory, uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, content)
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        # 基于固定目录描述符替换目录项，不跟随旧文件、符号链接或硬链接。
        os.rename(temporary, "/proc/self/fd/%d/authorized_keys" % directory)
        os.fsync(directory)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(home)


def main():
    action, account, key_path, policy_path, metadata_path, managed, backup = sys.argv[1:]
    with open(key_path, "rb") as stream:
        key = public_key(stream.read().decode("ascii"))
    policy = read_json(policy_path)
    check_target(read_json(metadata_path), key, policy)
    if action == "target":
        return
    forced = 'command="/usr/bin/python -BEs /usr/local/libexec/linux-mcp-readonly.py",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty'
    content = (forced + " " + key + "\n").encode("ascii") if action == "install" else None
    install_identity(account, key, policy, managed == "true", "/etc/linux-mcp-readonly/policy.json", content, backup)


if __name__ == "__main__":
    main()
