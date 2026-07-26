"""Tests for CentOS 7 compatibility parsers."""

import pytest

from linux_mcp_server.compatibility import parse_findmnt_pairs
from linux_mcp_server.compatibility import parse_lsblk_pairs
from linux_mcp_server.compatibility import parse_os_release
from linux_mcp_server.compatibility import parse_pairs_line
from linux_mcp_server.compatibility import validate_variant_output


def test_parse_os_release():
    assert parse_os_release('NAME="CentOS Linux"\nID="centos"\nVERSION_ID="7"\n') == ("centos", "7")


def test_parse_pairs_line_decodes_hex_escapes():
    assert parse_pairs_line(r'NAME="hello\x20\xe4\xb8\xad" TYPE="disk"') == {
        "NAME": "hello 中",
        "TYPE": "disk",
    }


@pytest.mark.parametrize(
    "line",
    (
        "",
        'NAME="sda" trailing',
        'NAME="sda" NAME="sdb"',
        r'NAME="bad\qescape"',
        r'NAME="\xff"',
        'NAME="unterminated',
    ),
)
def test_parse_pairs_line_rejects_malformed_input(line):
    with pytest.raises(ValueError):
        parse_pairs_line(line)


def test_parse_findmnt_pairs():
    output = (
        r'SOURCE="/dev/mapper/root" FSTYPE="xfs" SIZE="50G" USED="20G" '
        r'AVAIL="30G" USE%="40%" TARGET="/data\x20disk"'
    )

    result = parse_findmnt_pairs(output)

    assert result.filesystems[0].source == "/dev/mapper/root"
    assert result.filesystems[0].target == "/data disk"
    assert result.filesystems[0].use_percent == "40%"


def test_parse_findmnt_pairs_requires_all_fields():
    with pytest.raises(ValueError, match="Missing findmnt fields"):
        parse_findmnt_pairs(r'SOURCE="/dev/sda1" TARGET="/"')


def test_parse_lsblk_pairs_builds_parent_tree():
    output = "\n".join(
        (
            r'NAME="sda" KNAME="sda" PKNAME="" SIZE="100G" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL="Disk\x20Model"',
            r'NAME="sda1" KNAME="sda1" PKNAME="sda" SIZE="100G" TYPE="part" MOUNTPOINT="/" FSTYPE="xfs" MODEL=""',
        )
    )

    result = parse_lsblk_pairs(output, require_parent_fields=True)

    assert result.total == 1
    assert result.block_devices[0].model == "Disk Model"
    assert result.block_devices[0].children[0].name == "sda1"


def test_parse_lsblk_pairs_uses_kernel_name_for_parent():
    output = "\n".join(
        (
            r'NAME="mapper-root" KNAME="dm-0" PKNAME="" SIZE="100G" TYPE="disk" MOUNTPOINT="/" FSTYPE="xfs" MODEL=""',
            r'NAME="child" KNAME="dm-1" PKNAME="dm-0" SIZE="10G" TYPE="lvm" MOUNTPOINT="/data" FSTYPE="xfs" MODEL=""',
        )
    )

    result = parse_lsblk_pairs(output, require_parent_fields=True)

    assert result.block_devices[0].children[0].name == "child"


def test_parse_lsblk_pairs_without_pkname_returns_flat_devices():
    output = "\n".join(
        (
            r'NAME="sda" SIZE="100G" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL=""',
            r'NAME="sda1" SIZE="100G" TYPE="part" MOUNTPOINT="/" FSTYPE="xfs" MODEL=""',
        )
    )

    result = parse_lsblk_pairs(output)

    assert result.total == 2
    assert [device.name for device in result.block_devices] == ["sda", "sda1"]


def test_parse_lsblk_pairs_rejects_duplicate_devices():
    output = "\n".join(
        (
            r'NAME="sda" SIZE="100G" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL=""',
            r'NAME="sda" SIZE="100G" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL=""',
        )
    )
    with pytest.raises(ValueError, match="Duplicate block device"):
        parse_lsblk_pairs(output)


@pytest.mark.parametrize(
    "output",
    (
        r'SOURCE="/dev/sda1" FSTYPE="xfs" SIZE="bad" USED="2G" AVAIL="8G" USE%="20%" TARGET="/"',
        r'SOURCE="/dev/sda1" FSTYPE="xfs" SIZE="10G" USED="2G" AVAIL="8G" USE%="bad" TARGET="/"',
    ),
)
def test_parse_findmnt_pairs_rejects_invalid_numbers(output):
    with pytest.raises(ValueError):
        parse_findmnt_pairs(output)


def test_parse_lsblk_pairs_requires_parent_columns():
    output = r'NAME="sda" SIZE="100G" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL=""'

    with pytest.raises(ValueError, match="Missing lsblk fields"):
        parse_lsblk_pairs(output, require_parent_fields=True)


def test_parse_lsblk_pairs_rejects_invalid_size():
    output = r'NAME="sda" SIZE="invalid" TYPE="disk" MOUNTPOINT="" FSTYPE="" MODEL=""'

    with pytest.raises(ValueError, match="Invalid numeric size"):
        parse_lsblk_pairs(output)


@pytest.mark.parametrize(
    ("capability", "variant", "stdout"),
    (
        ("disk_usage", "native_json", '{"filesystems": []}'),
        ("block_devices", "native_json", '{"blockdevices": []}'),
        ("memory_info", "native_wide", "Mem: 10 2 8 0 0 0 8\n"),
        ("memory_info", "centos7_basic", "Mem: 10 2 8\n"),
    ),
)
def test_validate_variant_output(capability, variant, stdout):
    validate_variant_output(capability, variant, stdout)


def test_validate_variant_output_rejects_oversized_data():
    with pytest.raises(ValueError, match="1 MiB"):
        parse_findmnt_pairs("x" * (1024 * 1024 + 1))


def test_validate_variant_output_rejects_unknown_capability():
    with pytest.raises(ValueError, match="Unknown"):
        validate_variant_output("unknown", "native", "data")
