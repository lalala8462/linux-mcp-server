"""Compatibility profiles and parsers for older Linux command variants."""

import json
import re

from collections.abc import Mapping

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from linux_mcp_server.models import BlockDevice
from linux_mcp_server.models import BlockDevices
from linux_mcp_server.models import DiskUsage


MAX_COMPAT_OUTPUT_BYTES = 1024 * 1024


class CommandVariant(BaseModel):
    """One fixed read-only command shape for a compatibility capability."""

    model_config = ConfigDict(frozen=True)

    name: str
    args: tuple[str, ...]


class HostCompatibility(BaseModel):
    """Capabilities detected for one SSH connection."""

    host: str
    hostname: str
    os_id: str
    os_version: str
    kernel: str
    variants: dict[str, str] = Field(default_factory=dict)


COMPATIBILITY_COMMANDS: Mapping[str, tuple[CommandVariant, ...]] = {
    "disk_usage": (
        CommandVariant(name="native_json", args=("findmnt", "--df", "--json")),
        CommandVariant(
            name="centos7_pairs",
            args=("findmnt", "-D", "-P", "-o", "SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%,TARGET"),
        ),
        CommandVariant(name="centos6_df", args=("df", "-P", "-B1")),
    ),
    "block_devices": (
        CommandVariant(
            name="native_json",
            args=("lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL", "--json"),
        ),
        CommandVariant(
            name="centos7_pairs_parent",
            args=("lsblk", "-P", "-o", "NAME,KNAME,PKNAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
        ),
        CommandVariant(
            name="centos7_pairs_flat",
            args=("lsblk", "-P", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"),
        ),
    ),
    "memory_info": (
        CommandVariant(name="native_wide", args=("free", "-b", "-w")),
        CommandVariant(name="centos7_basic", args=("free", "-b")),
    ),
}


_PAIR_RE = re.compile(r'([A-Z0-9%]+)="((?:\\.|[^"])*)"(?:\s+|$)')
_SIZE_RE = re.compile(r"^\d+(?:\.\d+)?(?:[KMGTPEZY](?:i?B)?)?$", re.IGNORECASE)
_PERCENT_RE = re.compile(r"^\d{1,3}(?:\.\d+)?%$")


def parse_os_release(stdout: str) -> tuple[str, str]:
    """Return the OS ID and VERSION_ID without retaining the full file."""

    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ID", "VERSION_ID"}:
            values[key] = value.strip().strip("\"'")
    return values.get("ID", ""), values.get("VERSION_ID", "")


def _bounded_output(stdout: str) -> None:
    if len(stdout.encode("utf-8", errors="replace")) > MAX_COMPAT_OUTPUT_BYTES:
        raise ValueError("Compatibility command output exceeds the 1 MiB limit")


def _decode_util_linux_value(value: str) -> str:
    decoded = bytearray()
    position = 0
    while position < len(value):
        if value[position] != "\\":
            decoded.extend(value[position].encode("utf-8"))
            position += 1
            continue
        if position + 3 >= len(value) or value[position + 1] != "x":
            raise ValueError("Unsupported escape in util-linux pairs output")
        escaped = value[position + 2 : position + 4]
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", escaped):
            raise ValueError("Unsupported escape in util-linux pairs output")
        decoded.append(int(escaped, 16))
        position += 4
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Invalid UTF-8 escape in util-linux pairs output") from error


def _require_exact_fields(fields: Mapping[str, str], required: set[str], command: str) -> None:
    missing = required - fields.keys()
    extra = fields.keys() - required
    if missing:
        raise ValueError(f"Missing {command} fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"Unexpected {command} fields: {', '.join(sorted(extra))}")


def _validate_size(value: str, field: str) -> None:
    if not _SIZE_RE.fullmatch(value):
        raise ValueError(f"Invalid numeric size in {field}")


def parse_pairs_line(line: str) -> dict[str, str]:
    """Parse one util-linux ``--pairs`` line and reject ambiguous input."""

    fields: dict[str, str] = {}
    position = 0
    for match in _PAIR_RE.finditer(line):
        if line[position : match.start()].strip():
            raise ValueError("Malformed util-linux pairs output")
        key = match.group(1)
        if key in fields:
            raise ValueError(f"Duplicate field in util-linux pairs output: {key}")
        fields[key] = _decode_util_linux_value(match.group(2))
        position = match.end()

    if line[position:].strip() or not fields:
        raise ValueError("Malformed util-linux pairs output")
    return fields


def parse_findmnt_pairs(stdout: str) -> DiskUsage:
    """Convert CentOS 7 ``findmnt -D -P`` output to the upstream model."""

    _bounded_output(stdout)
    required = {"SOURCE", "FSTYPE", "SIZE", "USED", "AVAIL", "USE%", "TARGET"}
    filesystems = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = parse_pairs_line(line)
        _require_exact_fields(fields, required, "findmnt")
        for field in ("SIZE", "USED", "AVAIL"):
            _validate_size(fields[field], field)
        if not _PERCENT_RE.fullmatch(fields["USE%"]):
            raise ValueError("Invalid percentage in USE%")
        filesystems.append(
            {
                "source": fields["SOURCE"],
                "fstype": fields["FSTYPE"],
                "size": fields["SIZE"],
                "used": fields["USED"],
                "avail": fields["AVAIL"],
                "use%": fields["USE%"],
                "target": fields["TARGET"],
            }
        )
    if not filesystems:
        raise ValueError("findmnt pairs output is empty")
    return DiskUsage.model_validate({"filesystems": filesystems})


def parse_df_posix(stdout: str) -> DiskUsage:
    """Convert fixed ``df -P -B1`` output to the common disk model."""

    _bounded_output(stdout)
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) < 2 or "Filesystem" not in lines[0]:
        raise ValueError("df output does not contain a valid header")
    filesystems = []
    for line in lines[1:]:
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise ValueError("df output contains an invalid row")
        source, size, used, avail, use_percent, target = fields
        for field, value in (("size", size), ("used", used), ("avail", avail)):
            if not value.isdigit():
                raise ValueError(f"df output contains an invalid {field}")
        if not _PERCENT_RE.fullmatch(use_percent):
            raise ValueError("df output contains an invalid percentage")
        filesystems.append(
            {
                "source": source,
                "fstype": "",
                "size": size,
                "used": used,
                "avail": avail,
                "use%": use_percent,
                "target": target,
            }
        )
    return DiskUsage.model_validate({"filesystems": filesystems})


def parse_lsblk_pairs(stdout: str, *, require_parent_fields: bool = False) -> BlockDevices:
    """Convert CentOS 7 ``lsblk -P`` output to the upstream model."""

    _bounded_output(stdout)
    required = {"NAME", "SIZE", "TYPE", "MOUNTPOINT", "FSTYPE", "MODEL"}
    if require_parent_fields:
        required.update({"KNAME", "PKNAME"})
    rows: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = parse_pairs_line(line)
        _require_exact_fields(fields, required, "lsblk")
        _validate_size(fields["SIZE"], "SIZE")
        rows.append(fields)
    if not rows:
        raise ValueError("lsblk pairs output is empty")

    nodes: dict[str, BlockDevice] = {}
    for fields in rows:
        name = fields["NAME"]
        if name in nodes:
            raise ValueError(f"Duplicate block device: {name}")
        nodes[name] = BlockDevice(
            name=name,
            size=fields["SIZE"],
            type=fields["TYPE"],
            mountpoint=fields.get("MOUNTPOINT") or None,
            fstype=fields.get("FSTYPE") or None,
            model=fields.get("MODEL") or None,
            children=[],
        )

    child_names: set[str] = set()
    if require_parent_fields:
        kernel_names = {fields["KNAME"]: fields["NAME"] for fields in rows}
        if len(kernel_names) != len(rows):
            raise ValueError("Duplicate kernel name in lsblk output")
        for fields in rows:
            parent_name = kernel_names.get(fields["PKNAME"], fields["PKNAME"])
            name = fields["NAME"]
            if not parent_name:
                continue
            if parent_name == name or parent_name not in nodes:
                raise ValueError(f"Invalid parent device for {name}")
            nodes[parent_name].children.append(nodes[name])
            child_names.add(name)

    return BlockDevices.model_validate(
        {"blockdevices": [node.model_dump() for name, node in nodes.items() if name not in child_names]}
    )


def _validate_disk_output(variant: str, stdout: str) -> None:
    if variant == "native_json":
        data = json.loads(stdout)
        if not isinstance(data, dict) or not isinstance(data.get("filesystems"), list):
            raise ValueError("findmnt JSON does not contain filesystems")
        DiskUsage.model_validate(data)
    elif variant == "centos6_df":
        parse_df_posix(stdout)
    else:
        parse_findmnt_pairs(stdout)


def _validate_block_output(variant: str, stdout: str) -> None:
    if variant == "native_json":
        data = json.loads(stdout)
        if not isinstance(data, dict) or not isinstance(data.get("blockdevices"), list):
            raise ValueError("lsblk JSON does not contain blockdevices")
        BlockDevices.model_validate(data)
    else:
        parse_lsblk_pairs(stdout, require_parent_fields=variant == "centos7_pairs_parent")


def _validate_memory_output(variant: str, stdout: str) -> None:
    mem_lines = [line.split() for line in stdout.splitlines() if line.startswith("Mem:")]
    minimum_fields = 8 if variant == "native_wide" else 4
    if len(mem_lines) != 1 or len(mem_lines[0]) < minimum_fields:
        raise ValueError("free output does not contain a valid Mem line")
    for value in mem_lines[0][1:minimum_fields]:
        int(value)


def validate_variant_output(capability: str, variant: str, stdout: str) -> None:
    """Fail if a probe output cannot be consumed by the matching tool."""

    _bounded_output(stdout)
    validators = {
        "disk_usage": _validate_disk_output,
        "block_devices": _validate_block_output,
        "memory_info": _validate_memory_output,
    }
    try:
        validator = validators[capability]
    except KeyError as error:
        raise ValueError(f"Unknown compatibility capability: {capability}") from error
    validator(variant, stdout)
