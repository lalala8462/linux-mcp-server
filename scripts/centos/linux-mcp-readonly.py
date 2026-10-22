#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CentOS 7 SSH ForceCommand 只读命令包装器。

兼容 Python 2.6/3.x。所有命令均经 shlex 解析、参数白名单校验后，
使用绝对路径和参数数组执行，不调用 Shell。
"""

from __future__ import print_function

import json
import os
import re
import shlex
import stat
import subprocess
import sys
import syslog


try:
    TEXT_TYPE = unicode  # pyright: ignore[reportUndefinedVariable]
    STRING_TYPES = (basestring,)  # pyright: ignore[reportUndefinedVariable]
except NameError:
    TEXT_TYPE = str
    STRING_TYPES = (str,)


POLICY_PATH = "/etc/linux-mcp-readonly/policy.json"
PRIVILEGED_HELPER = "/usr/local/libexec/linux-mcp-privileged-read"
MAX_ALLOWED_ROOTS = 16
BINARY_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
PROC_SELF_FD = "/proc/self/fd"
ALLOWED_BINARIES = set((
    "cat",
    "command",
    "du",
    "df",
    "find",
    "findmnt",
    "free",
    "grep",
    "head",
    "hostname",
    "chkconfig",
    "ip",
    "journalctl",
    "lscpu",
    "lspci",
    "lsblk",
    "lsusb",
    "netstat",
    "ps",
    "ss",
    "stat",
    "systemctl",
    "tail",
    "top",
    "uname",
    "uptime",
))
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,200}$")
PID_RE = re.compile(r"^[1-9][0-9]{0,9}$")
INTEGER_RE = re.compile(r"^[0-9]{1,10}$")
PRIORITY_RE = re.compile(r"^[A-Za-z0-9.!-]{1,64}$")
TRANSPORT_RE = re.compile(r"^_TRANSPORT=(audit|driver|journal|kernel|stdout|syslog)$")
SINCE_RE = re.compile(r"^[A-Za-z0-9 :+._-]{1,128}$")


class PolicyError(Exception):
    """命令或策略不符合只读白名单。"""


def _write_syslog(priority, message):
    if sys.version_info[0] < 3 and isinstance(message, TEXT_TYPE):
        message = message.encode("utf-8")
    syslog.syslog(priority, message)


def _write_stderr(message):
    if sys.version_info[0] < 3 and isinstance(message, TEXT_TYPE):
        message = message.encode("utf-8")
    print(message, file=sys.stderr)


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _format_text(template, *values):
    return _text(template) % tuple(_text(value) for value in values)


def _exception_text(error):
    return TEXT_TYPE(error)


def _split_command(original_command):
    # Python 2.6 shlex 必须接收原生字节串；Python 3 才将 bytes 解码为 str。
    if sys.version_info[0] >= 3:
        if isinstance(original_command, bytes):
            original_command = original_command.decode("utf-8", "strict")
    return shlex.split(original_command, posix=True)


def load_policy(path=POLICY_PATH):  # noqa: C901
    with open(path, "rb") as policy_file:
        data = json.loads(_text(policy_file.read()))

    legacy_keys = ("read_roots", "scan_roots", "log_paths")
    if any(key in data for key in legacy_keys):
        raise PolicyError("策略格式已过期，请使用统一的 allowed_roots 重新生成部署包")

    has_single_root = "allowed_root" in data
    has_multiple_roots = "allowed_roots" in data
    if has_single_root == has_multiple_roots:
        raise PolicyError("策略必须且只能包含 allowed_root 或 allowed_roots")
    roots = [data["allowed_root"]] if has_single_root else data["allowed_roots"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ALLOWED_ROOTS:
        raise PolicyError("allowed_roots 必须包含 1..16 个目录")

    normalized_roots = []
    for root in roots:
        if not isinstance(root, STRING_TYPES):
            raise PolicyError("allowed_roots 中的目录必须是字符串")
        root = _text(root)
        if not root.startswith("/") or "\x00" in root or "\r" in root or "\n" in root or ".." in root.split("/"):
            raise PolicyError("allowed_roots 中的目录必须是安全的绝对路径")
        normalized = os.path.realpath(root)
        if normalized == "/":
            raise PolicyError("allowed_roots 不能包含 /")
        normalized_roots.append(normalized)

    if len(set(normalized_roots)) != len(normalized_roots):
        raise PolicyError("allowed_roots 不能包含重复目录")
    normalized_roots.sort()
    for index, root in enumerate(normalized_roots):
        for other in normalized_roots[index + 1 :]:
            if other.startswith(root.rstrip(os.sep) + os.sep):
                raise PolicyError("allowed_roots 不能包含父子重叠目录")
    data["allowed_roots"] = tuple(normalized_roots)
    data.pop("allowed_root", None)
    data["read_mode"] = data.get("read_mode", "user")
    if data["read_mode"] not in ("user", "privileged"):
        raise PolicyError("read_mode 必须是 user 或 privileged")

    data["max_file_read_bytes"] = int(data.get("max_file_read_bytes", 1048576))
    data["max_log_lines"] = int(data.get("max_log_lines", 10000))
    if data["max_file_read_bytes"] < 1 or data["max_file_read_bytes"] > 1048576:
        raise PolicyError("max_file_read_bytes 必须在 1..1048576 之间")
    if data["max_log_lines"] < 1 or data["max_log_lines"] > 10000:
        raise PolicyError("max_log_lines 必须在 1..10000 之间")
    return data


def resolve_binary(name):
    if name not in ALLOWED_BINARIES or name == "command":
        raise PolicyError(_format_text("命令不在白名单：%s", name))

    for directory in BINARY_DIRS:
        candidate = os.path.join(directory, name)
        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            continue
        real_candidate = os.path.realpath(candidate)
        file_stat = os.stat(real_candidate)
        if file_stat.st_uid != 0:
            raise PolicyError(_format_text("程序不是 root 所有：%s", real_candidate))
        if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError(_format_text("程序可被非 root 修改：%s", real_candidate))
        return real_candidate
    raise PolicyError(_format_text("服务器未安装命令：%s", name))


def _within(path, roots):
    canonical = os.path.realpath(path)
    for root in roots:
        normalized_root = root.rstrip(os.sep) or os.sep
        if canonical == normalized_root:
            return canonical
        if canonical.startswith(normalized_root + os.sep):
            return canonical
    raise PolicyError(_format_text("路径不在批准范围：%s", path))


def _read_path(path, policy):
    canonical = _within(path, policy["allowed_roots"])
    if policy.get("read_mode", "user") != "privileged" and not os.path.isfile(canonical):
        raise PolicyError(_format_text("读取目标不是普通文件：%s", path))
    return canonical


def _scan_path(path, policy):
    canonical = _within(path, policy["allowed_roots"])
    if policy.get("read_mode", "user") != "privileged" and not os.path.isdir(canonical):
        raise PolicyError(_format_text("扫描目标不是目录：%s", path))
    return canonical


def _log_path(path, policy):
    canonical = _within(path, policy["allowed_roots"])
    if policy.get("read_mode", "user") != "privileged" and not os.path.isfile(canonical):
        raise PolicyError(_format_text("日志目标不是普通文件：%s", path))
    return canonical


def _fd_path(descriptor):
    return os.path.join(PROC_SELF_FD, str(descriptor))


def _make_inheritable(descriptor):
    """Python 3 默认给新文件描述符设置 close-on-exec；Python 2 默认继承。"""
    if hasattr(os, "set_inheritable"):
        os.set_inheritable(descriptor, True)


def _open_verified_path(path, roots, expected_kind, exact_path=None):
    """打开并再次验证路径，返回可安全传递给固定命令的文件描述符。"""
    if not hasattr(os, "O_NOFOLLOW"):
        raise PolicyError("系统不支持 O_NOFOLLOW，拒绝路径命令")
    if not os.path.isdir(PROC_SELF_FD):
        raise PolicyError("系统不支持 /proc/self/fd，拒绝路径命令")

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if expected_kind == "directory":
        if not hasattr(os, "O_DIRECTORY"):
            raise PolicyError("系统不支持 O_DIRECTORY，拒绝目录命令")
        flags |= os.O_DIRECTORY

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PolicyError(_format_text("无法安全打开目标：%s", _exception_text(error)))

    try:
        target_stat = os.fstat(descriptor)
        if expected_kind == "file" and not stat.S_ISREG(target_stat.st_mode):
            raise PolicyError(_format_text("读取目标不是普通文件：%s", path))
        if expected_kind == "directory" and not stat.S_ISDIR(target_stat.st_mode):
            raise PolicyError(_format_text("扫描目标不是目录：%s", path))

        opened_path = os.path.realpath(_fd_path(descriptor))
        if exact_path is not None:
            if opened_path != exact_path:
                raise PolicyError(_format_text("打开后的日志目标已变化：%s", path))
        else:
            _within(opened_path, roots)
        _make_inheritable(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _prepare_path_command(validated, policy):
    """用已验证的文件描述符替换路径，避免验证后再次按名称打开。"""
    command = list(validated)
    name = command[0]
    descriptor = None

    if name in ("head", "stat"):
        descriptor = _open_verified_path(command[-1], policy["allowed_roots"], "file")
        command[-1] = _fd_path(descriptor)
    elif name == "tail":
        descriptor = _open_verified_path(
            command[-1],
            policy["allowed_roots"],
            "file",
        )
        command[-1] = _fd_path(descriptor)
    elif name == "du":
        descriptor = _open_verified_path(command[-1], policy["allowed_roots"], "directory")
        command.insert(1, "-H")
        command[-1] = _fd_path(descriptor)
    elif name == "find":
        descriptor = _open_verified_path(command[1], policy["allowed_roots"], "directory")
        command.insert(1, "-H")
        command[2] = _fd_path(descriptor)

    return command, descriptor


def _bounded_integer(value, minimum, maximum, label):
    if not INTEGER_RE.match(value):
        raise PolicyError(_format_text("%s 不是整数", label))
    parsed = int(value)
    if parsed < minimum or parsed > maximum:
        raise PolicyError(_format_text("%s 超出范围 %d..%d", label, minimum, maximum))
    return value


def _reject_ambiguous_tokens(argv):
    for token in argv:
        if "\x00" in token:
            raise PolicyError("参数包含 NUL")
        if token not in ("%f\\n", "%T@\\t%f\\n", "%s\\t%f\\n"):
            if any(char in token for char in (";", "|", "&", ">", "<", "`")):
                raise PolicyError("参数包含 Shell 元字符")
            if "$(" in token:
                raise PolicyError("参数包含命令替换")


def _validate_journalctl(args, policy):
    if len(args) == 5 and args[0] == "-u" and args[2] == "-n" and args[4] == "--no-pager":
        if not SERVICE_RE.match(args[1]):
            raise PolicyError("服务名无效")
        _bounded_integer(args[3], 1, policy["max_log_lines"], "日志行数")
        return args

    if len(args) < 3 or args[0] != "-n" or args[2] != "--no-pager":
        raise PolicyError("journalctl 参数不在白名单")
    _bounded_integer(args[1], 1, policy["max_log_lines"], "日志行数")

    index = 3
    seen = set()
    while index < len(args):
        token = args[index]
        if token in ("--unit", "--priority", "--since"):
            if token in seen or index + 1 >= len(args):
                raise PolicyError("journalctl 可选参数无效")
            value = args[index + 1]
            if token == "--unit" and not SERVICE_RE.match(value):
                raise PolicyError("journalctl unit 无效")
            if token == "--priority" and not PRIORITY_RE.match(value):
                raise PolicyError("journalctl priority 无效")
            if token == "--since" and not SINCE_RE.match(value):
                raise PolicyError("journalctl since 无效")
            seen.add(token)
            index += 2
            continue
        if TRANSPORT_RE.match(token) and "_TRANSPORT" not in seen:
            seen.add("_TRANSPORT")
            index += 1
            continue
        raise PolicyError("journalctl 可选参数不在白名单")
    return args


def validate_command(original_command, policy):  # noqa: C901
    if not original_command or len(original_command) > 4096:
        raise PolicyError("SSH_ORIGINAL_COMMAND 为空或过长")
    try:
        argv = _split_command(original_command)
    except ValueError as error:
        raise PolicyError(_format_text("命令解析失败：%s", error))
    if not argv:
        raise PolicyError("命令为空")
    _reject_ambiguous_tokens(argv)

    name = os.path.basename(argv[0])
    args = argv[1:]
    if name not in ALLOWED_BINARIES or name == "command":
        raise PolicyError(_format_text("命令不在白名单：%s", name))

    exact = {
        "hostname": [()],
        "uname": [("-r",), ("-m",)],
        "uptime": [("-p",), ("-s",)],
        "top": [("-bn1",)],
        "free": [("-b", "-w"), ("-b",)],
        "ss": [("-tunap",), ("-tulnp",)],
        "netstat": [("-tunap",), ("-tulnp",)],
        "ip": [("-brief", "address"), ("address",)],
        "lscpu": [()],
        "lspci": [()],
        "lsusb": [()],
        "lsblk": [
            ("-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL", "--json"),
            ("-P", "-o", "NAME,KNAME,PKNAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
            ("-P", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
        ],
        "findmnt": [
            ("--df", "--json"),
            ("-D", "-P", "-o", "SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%,TARGET"),
        ],
        "df": [("-P", "-B1")],
        "chkconfig": [("--list",)],
    }
    if name in exact:
        if tuple(args) not in exact[name]:
            raise PolicyError(_format_text("%s 参数不在白名单", name))
        return [name] + args

    if name == "cat":
        allowed = (
            ("/etc/os-release",),
            ("/etc/redhat-release",),
            ("/proc/loadavg",),
            ("/proc/net/dev",),
            ("/proc/stat",),
            ("/proc/uptime",),
        )
        if tuple(args) in allowed:
            return [name] + args
        if len(args) == 1 and re.match(r"^/proc/[1-9][0-9]{0,9}/status$", args[0]):
            return [name] + args
        raise PolicyError("cat 目标不在白名单")

    if name == "grep":
        allowed = (
            ("-m", "1", "model name", "/proc/cpuinfo"),
            ("-c", "^processor", "/proc/cpuinfo"),
            ("^core id", "/proc/cpuinfo"),
            ("-m", "1", "cpu MHz", "/proc/cpuinfo"),
        )
        if tuple(args) not in allowed:
            raise PolicyError("grep 参数不在白名单")
        return [name] + args

    if name == "systemctl":
        if tuple(args) in (
            ("list-units", "--type=service", "--all", "--no-pager"),
            ("list-units", "--type=service", "--state=running", "--no-pager"),
        ):
            return [name] + args
        if len(args) == 4 and args[0] == "status" and args[2:] == ["--no-pager", "--full"]:
            if not SERVICE_RE.match(args[1]):
                raise PolicyError("服务名无效")
            return [name] + args
        raise PolicyError("systemctl 参数不在白名单")

    if name == "journalctl":
        return [name] + _validate_journalctl(args, policy)

    if name == "ps":
        if tuple(args) == ("aux", "--sort=-%cpu"):
            return [name] + args
        expected_format = "pid,user,stat,pcpu,pmem,vsz,rss,etime,comm,args"
        if len(args) == 4 and args[0] == "-p" and PID_RE.match(args[1]) and args[2:] == ["-o", expected_format]:
            return [name] + args
        raise PolicyError("ps 参数不在白名单")

    if name == "du":
        if len(args) != 4 or tuple(args[:3]) != ("-b", "--one-file-system", "--max-depth=1"):
            raise PolicyError("du 参数不在白名单")
        args[3] = _scan_path(args[3], policy)
        return [name] + args

    if name == "find":
        if len(args) != 9:
            raise PolicyError("find 参数数量无效")
        if tuple(args[1:6]) != ("-mindepth", "1", "-maxdepth", "1", "-type"):
            raise PolicyError("find 深度参数无效")
        if args[6] not in ("d", "f") or args[7] != "-printf":
            raise PolicyError("find 类型或输出参数无效")
        allowed_formats = set((
            ("d", "%f\\n"),
            ("d", "%T@\\t%f\\n"),
            ("f", "%f\\n"),
            ("f", "%T@\\t%f\\n"),
            ("f", "%s\\t%f\\n"),
        ))
        if (args[6], args[8]) not in allowed_formats:
            raise PolicyError("find 输出格式无效")
        args[0] = _scan_path(args[0], policy)
        return [name] + args

    if name == "head":
        if len(args) != 4 or args[0] != "--bytes" or args[2] != "--":
            raise PolicyError("head 参数不在白名单")
        # MCP 固定多读取一个哨兵字节，用于判断文件是否超过返回上限。
        # 这里只额外允许 max + 1 这一种边界，不开放任意更大读取。
        _bounded_integer(
            args[1],
            1,
            policy["max_file_read_bytes"] + 1,
            "读取字节数",
        )
        args[3] = _read_path(args[3], policy)
        return [name] + args

    if name == "stat":
        if len(args) != 5 or tuple(args[:4]) != ("--dereference", "--format", "%s", "--"):
            raise PolicyError("stat 参数不在白名单")
        args[4] = _read_path(args[4], policy)
        return [name] + args

    if name == "tail":
        if len(args) != 3 or args[0] != "-n":
            raise PolicyError("tail 参数不在白名单")
        _bounded_integer(args[1], 1, policy["max_log_lines"], "日志行数")
        args[2] = _log_path(args[2], policy)
        return [name] + args

    raise PolicyError(_format_text("命令尚未实现白名单校验：%s", name))


def _handle_command_lookup(original_command):
    try:
        argv = _split_command(original_command)
    except ValueError:
        return False
    if len(argv) != 3 or argv[0] != "command" or argv[1] != "-v":
        return False
    name = argv[2]
    if name not in ALLOWED_BINARIES or name == "command":
        raise PolicyError(_format_text("禁止查询程序：%s", name))
    print(resolve_binary(name))
    return True


def _privileged_request(command):
    """已校验的固定文件命令映射为 helper 操作，不把命令文本交给 root。"""
    name = command[0]
    request = {"version": 1, "op": "", "path": command[-1], "limit": 0, "format": ""}
    if name in ("head", "tail", "stat"):
        request["op"] = {"head": "read", "tail": "tail", "stat": "stat"}[name]
        if name != "stat":
            request["limit"] = int(command[2])
    elif name == "du":
        request["op"] = "directory_sizes"
    elif name == "find":
        request["path"] = command[1]
        request["op"] = "list_files" if command[7] == "f" else "list_dirs"
        request["format"] = {"%f\\n": "name", "%T@\\t%f\\n": "modified", "%s\\t%f\\n": "size"}[command[9]]
    else:
        return None
    return request


def _run_privileged_read(request):
    sudo = None
    for directory in BINARY_DIRS:
        candidate = os.path.realpath(os.path.join(directory, "sudo"))
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            info = os.stat(candidate)
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise PolicyError("sudo 程序权限不安全")
            sudo = candidate
            break
    if sudo is None:
        raise PolicyError("未安装 sudo，受控提权读取不可用")
    process = subprocess.Popen(
        [sudo, "-n", "--", PRIVILEGED_HELPER], stdin=subprocess.PIPE,
        env={"PATH": ":".join(BINARY_DIRS), "LANG": "C", "LC_ALL": "C"},
    )
    process.communicate(json.dumps(request, ensure_ascii=True).encode("ascii"))
    return process.returncode


def main():
    original_command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        if _handle_command_lookup(original_command):
            return 0
        policy = load_policy()
        validated = validate_command(original_command, policy)
        if policy["read_mode"] == "privileged":
            request = _privileged_request(validated)
            if request is not None:
                _write_syslog(syslog.LOG_INFO, _format_text("PRIVILEGED %s", request["op"]))
                return _run_privileged_read(request)
        prepared, _descriptor = _prepare_path_command(validated, policy)
        binary = resolve_binary(prepared[0])
        argv = [binary] + prepared[1:]
        _write_syslog(syslog.LOG_INFO, _format_text("ALLOW %s", original_command.replace("\n", "\\n")))
        safe_env = {
            "HOME": os.path.expanduser("~"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": ":".join(BINARY_DIRS),
            "USER": os.environ.get("USER", "codex-ro"),
        }
        os.execve(binary, argv, safe_env)
    except PolicyError as error:
        _write_syslog(
            syslog.LOG_WARNING,
            _format_text("DENY %s reason=%s", original_command.replace("\n", "\\n"), _exception_text(error)),
        )
        _write_stderr(_format_text("拒绝：%s", _exception_text(error)))
        return 126
    except Exception as error:
        _write_syslog(syslog.LOG_ERR, _format_text("ERROR %s", _exception_text(error)))
        _write_stderr(_format_text("包装器错误：%s", _exception_text(error)))
        return 125


if __name__ == "__main__":
    sys.exit(main())
