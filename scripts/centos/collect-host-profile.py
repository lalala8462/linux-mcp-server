#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Collect a bounded, read-only CentOS compatibility profile (Python 2.6/3.x)."""

from __future__ import print_function

import argparse
import datetime
import json
import os
import platform
import re
import subprocess
import sys


SCHEMA_VERSION = 2
MAX_ALLOWED_ROOTS = 16
MAX_PROBE_BYTES = 1024 * 1024
CAPABILITY_PROBE_ROOT = os.path.dirname(os.path.realpath(__file__))
TOOLS = (
    "get_system_information",
    "get_cpu_information",
    "get_memory_information",
    "get_disk_usage",
    "get_hardware_information",
    "list_services",
    "get_service_status",
    "get_service_logs",
    "list_processes",
    "get_process_info",
    "get_journal_logs",
    "read_log_file",
    "get_network_interfaces",
    "get_network_connections",
    "get_listening_ports",
    "list_block_devices",
    "list_directories",
    "list_files",
    "read_file",
)
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def read_bounded(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_PROBE_BYTES + 1)
    if len(data) > MAX_PROBE_BYTES:
        raise RuntimeError("probe input is too large: {0}".format(path))
    return data.decode("utf-8", "replace")


def executable(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep) + ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run_probe(argv):
    binary = executable(argv[0])
    if binary is None:
        return 127, "", "command unavailable"
    devnull = open(os.devnull, "rb")
    try:
        process = subprocess.Popen(
            [binary] + list(argv[1:]),
            stdin=devnull,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
    finally:
        devnull.close()
    if len(stdout) > MAX_PROBE_BYTES or len(stderr) > MAX_PROBE_BYTES:
        return 1, "", "probe output exceeded limit"
    return process.returncode, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")


def capability(status, backend, reason=""):
    return {"status": status, "backend": backend, "reason": reason}


def detect_os():
    if os.path.isfile("/etc/os-release"):
        source = "/etc/os-release"
        raw = read_bounded(source)
        values = {}
        for line in raw.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip("\"'")
        os_id = values.get("ID", "").lower()
        version = values.get("VERSION", "") or values.get("PRETTY_NAME", "") or values.get("VERSION_ID", "")
    elif os.path.isfile("/etc/redhat-release"):
        source = "/etc/redhat-release"
        raw = read_bounded(source).strip()
        os_id = "centos" if "centos" in raw.lower() else ""
        match = re.search(r"release\s+([0-9]+(?:\.[0-9]+)*)", raw, re.I)
        version = match.group(1) if match else ""
    else:
        raise RuntimeError("no supported CentOS release file found")
    if os_id not in ("centos", "centos_stream", "centos-stream"):
        raise RuntimeError("discovery is restricted to CentOS")
    try:
        version_match = re.search(r"([0-9]+)(?:\.[0-9]+)*", version)
        major = int(version_match.group(1)) if version_match else 0
    except (TypeError, ValueError):
        raise RuntimeError("unable to determine CentOS major version")
    if major not in (6, 7, 8, 9):
        raise RuntimeError("unsupported CentOS major version: {0}".format(major))
    return {
        "id": "centos",
        "version": version,
        "major": major,
        "release_source": source,
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }


def detect_ssh():
    code, _, stderr = run_probe(("ssh", "-V"))
    version = stderr.strip() if code == 0 else ""
    keys = []
    for key_type, path in (
        ("ssh-ed25519", "/etc/ssh/ssh_host_ed25519_key.pub"),
        ("ssh-rsa", "/etc/ssh/ssh_host_rsa_key.pub"),
    ):
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        fields = read_bounded(path).strip().split()
        if len(fields) >= 2 and fields[0] == key_type:
            keys.append({"type": key_type, "public_key": fields[0] + " " + fields[1]})
    if not keys:
        raise RuntimeError("no supported SSH host public key found")
    return {"server_version": version, "host_keys": keys}


def detect_runtime():
    return {
        "python_executable": os.path.realpath(sys.executable),
        "python_version": "{0}.{1}.{2}".format(
            sys.version_info[0],
            sys.version_info[1],
            sys.version_info[2],
        ),
    }


def valid_free(args, minimum):
    code, stdout, _ = run_probe(args)
    rows = [line.split() for line in stdout.splitlines() if line.startswith("Mem:")]
    if code or len(rows) != 1 or len(rows[0]) < minimum:
        return False
    try:
        for value in rows[0][1:minimum]:
            int(value)
    except ValueError:
        return False
    return True


def command_ok(args, require_output=True):
    code, stdout, _ = run_probe(args)
    return code == 0 and (bool(stdout.strip()) if require_output else True)


def json_command_ok(args, list_key):
    code, stdout, _ = run_probe(args)
    if code:
        return False
    try:
        value = json.loads(stdout)
    except ValueError:
        return False
    return isinstance(value, dict) and isinstance(value.get(list_key), list)


def pairs_command_ok(args, required):
    code, stdout, _ = run_probe(args)
    if code or not stdout.strip():
        return False
    for line in stdout.splitlines():
        fields = set(re.findall(r'([A-Z0-9%]+)="(?:\\.|[^"])*"(?:\s+|$)', line))
        if fields != set(required):
            return False
    return True


def df_command_ok():
    code, stdout, _ = run_probe(("df", "-P", "-B1"))
    lines = [line for line in stdout.splitlines() if line.strip()]
    if code or len(lines) < 2 or "Filesystem" not in lines[0]:
        return False
    for line in lines[1:]:
        fields = line.split(None, 5)
        if (
            len(fields) != 6
            or not all(value.isdigit() for value in fields[1:4])
            or not re.match(r"^\d{1,3}%$", fields[4])
        ):
            return False
    return True


def system_information_ok(modern):
    if modern and not os.path.isfile("/etc/os-release"):
        return False
    if not modern and not os.path.isfile("/etc/redhat-release"):
        return False
    try:
        uptime = read_bounded("/proc/uptime").split()[0]
        float(uptime)
        stat_lines = read_bounded("/proc/stat").splitlines()
    except (IOError, IndexError, ValueError):
        return False
    return any(re.match(r"^btime\s+\d+$", line) for line in stat_lines)


def socket_table_ok(args, backend):
    code, stdout, _ = run_probe(args)
    if code:
        return False
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return False
    if backend == "ss":
        return lines[0].startswith("Netid ") or lines[0].startswith("State ")
    return any(line.startswith("Proto ") for line in lines)


def storage_capabilities_ok():
    find_ok = command_ok(
        ("find", CAPABILITY_PROBE_ROOT, "-mindepth", "1", "-maxdepth", "1"),
        require_output=False,
    )
    du_ok = command_ok(("du", "-b", "--one-file-system", "--max-depth=0", CAPABILITY_PROBE_ROOT))
    stat_ok = command_ok(("stat", "--dereference", "--format", "%s", "--", CAPABILITY_PROBE_ROOT))
    return find_ok, du_ok, stat_ok


def detect_capabilities(os_profile):  # noqa: C901
    major = os_profile["major"]
    modern = major >= 7
    result = {}

    system_ok = system_information_ok(modern)
    result["get_system_information"] = capability(
        "exact" if system_ok else "unsupported",
        ("modern_os_release" if modern else "centos6_procfs") if system_ok else "none",
        "" if system_ok else "release or procfs system information was not parseable",
    )
    cpu_ok = all(
        command_ok(args)
        for args in (
            ("grep", "-m", "1", "model name", "/proc/cpuinfo"),
            ("grep", "-c", "^processor", "/proc/cpuinfo"),
            ("cat", "/proc/loadavg"),
            ("top", "-bn1"),
        )
    )
    result["get_cpu_information"] = capability(
        "exact" if cpu_ok else "unsupported",
        "procfs_procps" if cpu_ok else "none",
        "" if cpu_ok else "CPU procfs/procps output was not parseable",
    )

    if valid_free(("free", "-b", "-w"), 8):
        result["get_memory_information"] = capability("exact", "native_wide")
    elif valid_free(("free", "-b"), 4):
        result["get_memory_information"] = capability("exact", "centos7_basic")
    else:
        result["get_memory_information"] = capability("unsupported", "none", "free output was not parseable")

    if json_command_ok(("findmnt", "--df", "--json"), "filesystems"):
        disk_backend = "native_json"
    elif pairs_command_ok(
        ("findmnt", "-D", "-P", "-o", "SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%,TARGET"),
        ("SOURCE", "FSTYPE", "SIZE", "USED", "AVAIL", "USE%", "TARGET"),
    ):
        disk_backend = "centos7_pairs"
    elif df_command_ok():
        disk_backend = "centos6_df"
    else:
        disk_backend = ""
    result["get_disk_usage"] = capability(
        "exact" if disk_backend else "unsupported",
        disk_backend or "none",
        "" if disk_backend else "no parseable fixed disk-usage backend",
    )

    hardware = [name for name in ("lscpu", "lspci", "lsusb") if executable(name) and command_ok((name,))]
    result["get_hardware_information"] = capability(
        "exact" if len(hardware) == 3 else "partial",
        "hardware_commands",
        "" if len(hardware) == 3 else "missing: " + ",".join(sorted(set(("lscpu", "lspci", "lsusb")) - set(hardware))),
    )

    systemd = modern and command_ok(("systemctl", "list-units", "--type=service", "--all", "--no-pager"))
    if systemd:
        result["list_services"] = capability("exact", "systemd")
        result["get_service_status"] = capability("exact", "systemd")
    elif executable("chkconfig"):
        result["list_services"] = capability(
            "partial", "centos6_chkconfig", "SysV enablement is available; running count is unavailable"
        )
        result["get_service_status"] = capability(
            "unsupported", "none", "SysV init scripts are not executed by the read-only wrapper"
        )
    else:
        result["list_services"] = capability("unsupported", "none", "no supported service manager")
        result["get_service_status"] = capability("unsupported", "none", "no supported service manager")

    journal = systemd and command_ok(("journalctl", "--no-pager", "-n", "1"), require_output=False)
    for tool in ("get_service_logs", "get_journal_logs"):
        result[tool] = capability(
            "exact" if journal else "unsupported",
            "journalctl" if journal else "none",
            "" if journal else "journald is unavailable",
        )

    ps_list = command_ok(("ps", "aux", "--sort=-%cpu"))
    ps_detail = command_ok(("ps", "-p", "1", "-o", "pid,user,stat,pcpu,pmem,vsz,rss,etime,comm,args"))
    result["list_processes"] = capability(
        "exact" if ps_list else "unsupported",
        "procps" if ps_list else "none",
        "" if ps_list else "procps output failed",
    )
    result["get_process_info"] = capability(
        "exact" if ps_detail else "unsupported",
        "procps_procfs" if ps_detail else "none",
        "" if ps_detail else "procps detail output failed",
    )
    ip_brief_code, ip_brief_output, _ = run_probe(("ip", "-brief", "address"))
    ip_address_code, ip_address_output, _ = run_probe(("ip", "address"))
    if ip_brief_code == 0 and any(len(line.split()) >= 2 for line in ip_brief_output.splitlines()):
        interface_backend = "ip_brief"
    elif ip_address_code == 0 and any(re.match(r"^\d+:\s+\S+:", line) for line in ip_address_output.splitlines()):
        interface_backend = "ip_address"
    else:
        interface_backend = ""
    result["get_network_interfaces"] = capability(
        "exact" if interface_backend else "unsupported",
        interface_backend or "none",
        "" if interface_backend else "ip address output unavailable",
    )
    for tool, ss_args, netstat_args in (
        ("get_network_connections", ("ss", "-tunap"), ("netstat", "-tunap")),
        ("get_listening_ports", ("ss", "-tulnp"), ("netstat", "-tulnp")),
    ):
        if socket_table_ok(ss_args, "ss"):
            connection_backend = "ss"
        elif socket_table_ok(netstat_args, "netstat"):
            connection_backend = "netstat"
        else:
            connection_backend = ""
        result[tool] = capability(
            "exact" if connection_backend else "unsupported",
            connection_backend or "none",
            "" if connection_backend else "no parseable ss or netstat output",
        )

    if json_command_ok(
        ("lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL", "--json"),
        "blockdevices",
    ):
        block_backend = "native_json"
    elif pairs_command_ok(
        ("lsblk", "-P", "-o", "NAME,KNAME,PKNAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
        ("NAME", "KNAME", "PKNAME", "SIZE", "TYPE", "MOUNTPOINT", "FSTYPE", "MODEL"),
    ):
        block_backend = "centos7_pairs_parent"
    elif pairs_command_ok(
        ("lsblk", "-P", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
        ("NAME", "SIZE", "TYPE", "MOUNTPOINT", "FSTYPE", "MODEL"),
    ):
        block_backend = "centos7_pairs_flat"
    else:
        block_backend = ""
    result["list_block_devices"] = capability(
        "exact" if block_backend else "unsupported",
        block_backend or "none",
        "" if block_backend else "no parseable lsblk pairs or JSON output",
    )

    find_ok, du_ok, stat_ok = storage_capabilities_ok()
    storage_ok = find_ok and du_ok and stat_ok
    for tool in ("list_directories", "list_files"):
        result[tool] = capability(
            "exact" if storage_ok else "unsupported",
            "gnu_coreutils" if storage_ok else "none",
            "" if storage_ok else "required GNU find/du/stat options failed",
        )
    head_ok = command_ok(("head", "--bytes", "1", "--", "/proc/version"))
    tail_ok = command_ok(("tail", "--lines", "1", "--", "/proc/version"))
    result["read_log_file"] = capability(
        "exact" if tail_ok else "unsupported",
        "bounded_tail" if tail_ok else "none",
        "" if tail_ok else "required GNU tail options failed",
    )
    result["read_file"] = capability(
        "exact" if head_ok and stat_ok else "unsupported",
        "gnu_coreutils" if head_ok and stat_ok else "none",
        "" if head_ok and stat_ok else "required GNU head/stat options failed",
    )
    if set(result) != set(TOOLS):
        raise RuntimeError("internal capability set mismatch")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alias", required=True)
    parser.add_argument("--allowed-root", action="append", required=True)
    args = parser.parse_args()
    if not ALIAS.match(args.alias):
        raise RuntimeError("invalid alias")
    if not 1 <= len(args.allowed_root) <= MAX_ALLOWED_ROOTS:
        raise RuntimeError("allowed roots must contain 1..16 directories")
    allowed_roots = []
    for root in args.allowed_root:
        normalized = root.rstrip("/")
        if (
            not SAFE_PATH.match(root)
            or normalized == ""
            or normalized == "/"
            or ".." in root.split("/")
            or not os.path.isdir(root)
        ):
            raise RuntimeError("allowed roots must contain existing safe absolute directories")
        allowed_roots.append(normalized)
    if len(set(allowed_roots)) != len(allowed_roots):
        raise RuntimeError("allowed roots must not contain duplicate directories")
    allowed_roots.sort()
    resolved_roots = sorted(os.path.realpath(root) for root in allowed_roots)
    if len(set(resolved_roots)) != len(resolved_roots):
        raise RuntimeError("allowed roots must not resolve to duplicate directories")
    for index, root in enumerate(resolved_roots):
        for other in resolved_roots[index + 1 :]:
            if other.startswith(root.rstrip("/") + "/"):
                raise RuntimeError("allowed roots must not contain overlapping directories")
    os_profile = detect_os()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "alias": args.alias,
        "allowed_roots": allowed_roots,
        "os": os_profile,
        "ssh": detect_ssh(),
        "runtime": detect_runtime(),
        "capabilities": detect_capabilities(os_profile),
        "collected_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(encoded) > MAX_PROBE_BYTES:
        raise RuntimeError("discovery result exceeded limit")
    print(encoded)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("discovery failed: {0}".format(error), file=sys.stderr)
        sys.exit(1)
