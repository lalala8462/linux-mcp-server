#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法（必须以 root 执行）：
  install-readonly-account.sh <公钥文件> <策略 JSON> [账号名] [--adopt-existing] [--allow-rsa]

示例（首次创建）：
  sudo bash install-readonly-account.sh \
    /tmp/id_ed25519.pub \
    /tmp/centos-policy.local.json \
    codex-ro

示例（迁移旧版已存在账号，必须显式确认）：
  sudo bash install-readonly-account.sh \
    /tmp/id_ed25519.pub \
    /tmp/centos-policy.local.json \
    codex-ro \
    --adopt-existing

CentOS 6/OpenSSH 5.3 的 RSA 4096 公钥必须显式增加 --allow-rsa。
DSA 公钥始终拒绝。
EOF
}

fail() {
  echo "错误：$*" >&2
  exit 1
}

validate_account_name() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "账号名无效：$1"
}

validate_existing_account() {
  local account="$1"
  local uid primary_group group

  uid="$(id -u "${account}")"
  [[ "${uid}" -ne 0 ]] || fail "拒绝使用 UID 0 账号：${account}"
  primary_group="$(id -gn "${account}")"
  [[ "${primary_group}" == "${account}" ]] || fail "账号主组必须同名：${account}"

  for group in $(id -nG "${account}"); do
    case "${group}" in
      "${account}"|systemd-journal|linux-mcp-logread)
        ;;
      wheel)
        fail "账号属于 wheel 组，拒绝接管：${account}"
        ;;
      *)
        fail "账号存在未批准的补充组 ${group}，拒绝接管：${account}"
        ;;
    esac
  done

  if command -v sudo >/dev/null 2>&1; then
    validate_sudo_access "${account}"
  elif [[ "${READ_MODE:-user}" == privileged ]]; then
    fail "未安装 sudo，受控 helper 不可用"
  fi
}

validate_sudo_access() {
  local account="$1" listing rules
  command -v sudo >/dev/null 2>&1 || fail "未安装 sudo，无法配置受控 helper"
  # 由管理员查询完整授权，不能把 requiretty/认证失败误判为没有 sudo 权限。
  if ! listing="$(LC_ALL=C sudo -n -l -U "${account}" 2>&1)"; then
    [[ "${listing}" == *"is not allowed to run sudo"* ]] && return 0
    fail "无法可靠查询账号 sudo 权限：${account}"
  fi
  rules="$(printf '%s\n' "${listing}" | awk '
    /may run the following commands/ { found=1; next }
    found { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); if (length) print }
  ')"
  # sudo 版本不同，列表可能把空参数标记显示为转义引号；两者都只接受固定 helper。
  [[ "${rules}" == '(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read ""' || \
     "${rules}" == '(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read \"\"' ]] || \
    fail "账号具有非本工具精确 helper 的 sudo 权限，拒绝接管：${account}"
}

validate_install_layout() {
  /usr/bin/python - "$@" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import stat
import sys
root = os.lstat("/")
if root.st_uid != 0 or root.st_mode & 0o022 or not stat.S_ISDIR(root.st_mode):
    raise ValueError("根目录必须由 root 控制")
for path in sys.argv[1:]:
    current = "/"
    for component in path.strip("/").split("/"):
        current = os.path.join(current, component)
        if not os.path.lexists(current):
            break
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("安装路径必须由 root 控制且不可被普通用户替换")
PY
}

write_sudoers() {
  local output="$1"
  printf '%s\n' 'Defaults:codex-ro !requiretty' \
    'codex-ro ALL=(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read ""' > "${output}"
}

validate_helper_runtime() {
  local helper_source="$1" python_bin="${2:-/usr/bin/python}"
  "${python_bin}" - "${helper_source}" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import print_function
import imp
import sys
sys.dont_write_bytecode = True
helper = imp.load_source("linux_mcp_privileged_preflight", sys.argv[1])
try:
    helper.parse_request(b'{}', {"roots": ["/data"], "bytes": 1024, "lines": 10})
except helper.ReadDenied:
    pass
else:
    raise RuntimeError("helper accepted invalid request")
PY
}

prepare_verification_samples() {
  /usr/bin/python - <<'PY'
# -*- coding: utf-8 -*-
from __future__ import print_function
import errno
import imp
import json
import os
import stat
import sys
sys.dont_write_bytecode = True

with open("/etc/linux-mcp-readonly/policy.json", "rb") as stream:
    mode = json.loads(stream.read().decode("utf-8")).get("read_mode", "user")
if mode == "privileged":
    helper = imp.load_source("linux_mcp_sample_helper", "/usr/local/libexec/linux-mcp-privileged-read")
    policy = helper.load_policy()

    def sample_directory(parent, name, permissions):
        path = helper.fs_path(helper.fd_path(parent) + "/" + name)
        created = False
        try:
            os.mkdir(path, permissions)
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                raise ValueError("验收目录类型或属主不匹配")
            helper.within(helper.text(os.readlink(helper.fd_path(descriptor))), policy["roots"])
            if created:
                os.fchmod(descriptor, permissions)
            elif stat.S_IMODE(info.st_mode) != permissions:
                raise ValueError("验收目录已有权限不匹配")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    marker = b"linux-mcp-verification-v1\n"

    def sample_file(parent, name, permissions):
        helper.within(helper.text(os.readlink(helper.fd_path(parent))), policy["roots"])
        path = helper.fs_path(helper.fd_path(parent) + "/" + name)
        created = False
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, permissions)
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise ValueError("验收文件类型或属主不匹配")
            helper.within(helper.text(os.readlink(helper.fd_path(descriptor))), policy["roots"])
            if created:
                os.fchmod(descriptor, permissions)
                os.write(descriptor, marker)
            elif stat.S_IMODE(info.st_mode) != permissions or os.read(descriptor, len(marker) + 1) != marker:
                raise ValueError("验收文件已有权限或内容不匹配，不覆盖")
        finally:
            os.close(descriptor)

    for root in policy["roots"]:
        descriptor = helper.open_path(root, policy["roots"], "directory")
        opened = [descriptor]
        try:
            base = sample_directory(descriptor, ".linux-mcp-verify", 0o755)
            opened.append(base)
            private = sample_directory(base, "private", 0o700)
            opened.append(private)
            opened.append(sample_directory(private, "nested", 0o700))
            sample_file(base, "public.txt", 0o644)
            sample_file(private, "root-only.txt", 0o600)
            sample_file(private, "app.log", 0o600)
            helper.within(helper.text(os.readlink(helper.fd_path(base))), policy["roots"])
            link = helper.fs_path(helper.fd_path(base) + "/outside-link")
            destination = "/__linux_mcp_outside_approved_roots__/sample.txt"
            if os.path.lexists(link):
                if os.lstat(link).st_uid != 0 or not os.path.islink(link) or helper.text(os.readlink(link)) != destination:
                    raise ValueError("验收符号链接已存在但目标不匹配")
            else:
                os.symlink(destination, link)
            print("verification_samples=" + root + "/.linux-mcp-verify")
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)
PY
}

read_managed_account() {
  local marker="$1"
  local account mode owner

  [[ -f "${marker}" && ! -L "${marker}" ]] || fail "受管账号标记不是普通文件：${marker}"
  owner="$(stat -c '%U' "${marker}")"
  mode="$(stat -c '%a' "${marker}")"
  [[ "${owner}" == "root" && "${mode}" =~ ^[0-6][0-4][0-4]$ ]] || \
    fail "受管账号标记权限不安全：${marker}"
  account="$(tr -d '\r\n' < "${marker}")"
  validate_account_name "${account}"
  printf '%s\n' "${account}"
}

validate_managed_account() {
  local marker="$1"
  local expected_account="$2"
  local managed_account

  managed_account="$(read_managed_account "${marker}")"
  [[ "${managed_account}" == "${expected_account}" ]] || \
    fail "受管账号为 ${managed_account}，不能改用 ${expected_account}"
  id "${expected_account}" >/dev/null 2>&1 || fail "受管账号不存在：${expected_account}"
  validate_existing_account "${expected_account}"
}

backup_existing_files() {
  local timestamp target

  if [[ ! -e "${WRAPPER_TARGET}" && ! -e "${POLICY_TARGET}" ]]; then
    return
  fi
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP_DIR="${BACKUP_ROOT}/${timestamp}"
  [[ ! -e "${BACKUP_DIR}" ]] || fail "备份目录已存在，拒绝覆盖：${BACKUP_DIR}"
  install -d -o root -g root -m 0700 "${BACKUP_DIR}"

  for target in "${WRAPPER_TARGET}" "${POLICY_TARGET}" "${HELPER_TARGET:-/usr/local/libexec/linux-mcp-privileged-read}" "${SUDOERS_TARGET:-/etc/sudoers.d/linux-mcp-codex-ro}"; do
    [[ -e "${target}" ]] || continue
    [[ -f "${target}" && ! -L "${target}" ]] || fail "待备份目标不是普通文件：${target}"
    install -o root -g root -m 0600 "${target}" "${BACKUP_DIR}/$(basename "${target}")"
  done
}

write_managed_account() {
  local temporary

  [[ ! -e "${ACCOUNT_MARKER}" ]] || fail "受管账号标记已存在，拒绝覆盖：${ACCOUNT_MARKER}"
  temporary="$(mktemp "${CONFIG_DIR}/.managed-account.XXXXXX")"
  printf '%s\n' "${TARGET_USER}" > "${temporary}"
  chown root:root "${temporary}"
  chmod 0644 "${temporary}"
  mv "${temporary}" "${ACCOUNT_MARKER}"
}

validate_policy_file() {
  local python_bin="/usr/bin/python"
  if [[ ! -x "${python_bin}" ]]; then
    python_bin="$(command -v python3)" || fail "未找到可用 Python，无法校验策略"
  fi
  "${python_bin}" - "$1" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import print_function

import json
import os
import sys

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)

with open(sys.argv[1], "rb") as handle:
    policy = json.loads(handle.read().decode("utf-8"))

if any(key in policy for key in ("read_roots", "scan_roots", "log_paths")):
    raise ValueError("策略格式已过期，请使用 allowed_roots")
if policy.get("read_mode", "user") not in ("user", "privileged"):
    raise ValueError("read_mode 必须是 user 或 privileged")
for field, maximum in (("max_file_read_bytes", 1048576), ("max_log_lines", 10000)):
    value = policy.get(field, maximum)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("读取上限必须是允许范围内的整数")
has_single_root = "allowed_root" in policy
has_multiple_roots = "allowed_roots" in policy
if has_single_root == has_multiple_roots:
    raise ValueError("策略必须且只能包含 allowed_root 或 allowed_roots")
roots = [policy["allowed_root"]] if has_single_root else policy["allowed_roots"]
if not isinstance(roots, list) or not 1 <= len(roots) <= 16:
    raise ValueError("allowed_roots 必须包含 1..16 个目录")

normalized_roots = []
for root in roots:
    if (
        not isinstance(root, string_types)
        or not root.startswith("/")
        or "\x00" in root
        or "\r" in root
        or "\n" in root
        or ".." in root.split("/")
    ):
        raise ValueError("allowed_roots 中的目录必须是安全的绝对路径")
    normalized = os.path.realpath(root)
    if policy.get("read_mode", "user") == "privileged" and normalized != root.rstrip("/"):
        raise ValueError("受控 root 读取的批准根目录不能包含符号链接")
    if normalized == "/":
        raise ValueError("allowed_roots 不能包含 /")
    normalized_roots.append(normalized)

if len(set(normalized_roots)) != len(normalized_roots):
    raise ValueError("allowed_roots 不能包含重复目录")
normalized_roots.sort()
for index, root in enumerate(normalized_roots):
    for other in normalized_roots[index + 1:]:
        if other.startswith(root.rstrip(os.sep) + os.sep):
            raise ValueError("allowed_roots 不能包含父子重叠目录")
PY
}

validate_wrapper_runtime() {
  local wrapper_source="$1"
  local python_bin="${2:-/usr/bin/python}"
  local resolved

  [[ -x "${python_bin}" ]] || fail "固定命令解释器不存在：${python_bin}"
  if ! resolved="$(
    SSH_ORIGINAL_COMMAND='command -v tail' \
      "${python_bin}" "${wrapper_source}" 2>&1
  )"; then
    fail "只读包装器运行时自检失败：${resolved}"
  fi
  [[ "${resolved}" == /*/tail ]] || fail "只读包装器命令定位结果无效：${resolved}"

  if ! "${python_bin}" - "${wrapper_source}" <<'PY'
# -*- coding: utf-8 -*-
from __future__ import print_function

import imp
import sys

wrapper = imp.load_source("linux_mcp_readonly_preflight", sys.argv[1])
try:
    wrapper._open_verified_path(
        "/__linux_mcp_readonly_preflight_missing__",
        ("/",),
        "file",
    )
except wrapper.PolicyError as error:
    rendered = wrapper._exception_text(error)
    if not rendered.startswith(u"无法安全打开目标："):
        raise RuntimeError("unexpected safe-open error")
else:
    raise RuntimeError("missing preflight path was opened")
PY
  then
    fail "只读包装器安全打开异常自检失败"
  fi
}

validate_public_key() {
  local public_key_file="$1"
  local allow_rsa="$2"
  local public_key key_bits rsa_bits

  public_key="$(tr -d '\r\n' < "${public_key_file}")"
  case "${public_key}" in
    ssh-ed25519\ *)
      key_bits="$(ssh-keygen -lf "${public_key_file}" 2>/dev/null | awk '{print $1}')"
      [[ "${key_bits}" == "256" ]] || fail "Ed25519 公钥格式无效"
      ;;
    ssh-rsa\ *)
      [[ "${allow_rsa}" == true ]] || fail "RSA 公钥必须显式传入 --allow-rsa"
      rsa_bits="$(ssh-keygen -lf "${public_key_file}" 2>/dev/null | awk '{print $1}')"
      [[ "${rsa_bits}" == "4096" ]] || fail "仅接受 RSA 4096 公钥"
      ;;
    ssh-dss\ *|*)
      fail "仅接受 Ed25519，或显式 --allow-rsa 的 RSA 4096 公钥；DSA 始终拒绝"
      ;;
  esac
  printf '%s\n' "${public_key}"
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  fail "必须以 root 执行。"
fi

if [[ "$#" -lt 2 || "$#" -gt 5 ]]; then
  usage >&2
  exit 1
fi

readonly PUBLIC_KEY_FILE="$1"
readonly POLICY_FILE="$2"
shift 2
TARGET_USER="codex-ro"
ADOPT_EXISTING=false
ALLOW_RSA=false
TARGET_USER_SET=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --adopt-existing)
      [[ "${ADOPT_EXISTING}" == false ]] || fail "--adopt-existing 不能重复指定"
      ADOPT_EXISTING=true
      ;;
    --allow-rsa)
      [[ "${ALLOW_RSA}" == false ]] || fail "--allow-rsa 不能重复指定"
      ALLOW_RSA=true
      ;;
    --*)
      fail "未知参数：$1"
      ;;
    *)
      [[ "${TARGET_USER_SET}" == false ]] || fail "只能指定一个账号名"
      TARGET_USER="$1"
      TARGET_USER_SET=true
      ;;
  esac
  shift
done
readonly TARGET_USER
readonly ADOPT_EXISTING
readonly ALLOW_RSA
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WRAPPER_SOURCE="${SCRIPT_DIR}/linux-mcp-readonly.py"
readonly WRAPPER_TARGET="/usr/local/libexec/linux-mcp-readonly.py"
readonly HELPER_SOURCE="${SCRIPT_DIR}/linux-mcp-privileged-read"
readonly HELPER_TARGET="/usr/local/libexec/linux-mcp-privileged-read"
readonly SUDOERS_TARGET="/etc/sudoers.d/linux-mcp-codex-ro"
readonly CONFIG_DIR="/etc/linux-mcp-readonly"
readonly POLICY_TARGET="${CONFIG_DIR}/policy.json"
readonly ACCOUNT_MARKER="${CONFIG_DIR}/managed-account"
readonly BACKUP_ROOT="${CONFIG_DIR}/backups"
BACKUP_DIR=""
WRITE_ACCOUNT_MARKER=false

validate_account_name "${TARGET_USER}"
[[ "${TARGET_USER}" == codex-ro ]] || fail "固定 helper 只允许 codex-ro 账号"
for required_file in "${PUBLIC_KEY_FILE}" "${POLICY_FILE}" "${WRAPPER_SOURCE}" "${HELPER_SOURCE}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || fail "文件不存在或是符号链接：${required_file}"
done
validate_wrapper_runtime "${WRAPPER_SOURCE}"
if ! validate_policy_file "${POLICY_FILE}"; then
  fail "策略必须是包含 1..16 个安全 allowed_roots 的有效 JSON。"
fi
READ_MODE="$(/usr/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("read_mode", "user"))' "${POLICY_FILE}")"
readonly READ_MODE
validate_install_layout "${CONFIG_DIR}" /usr/local/libexec "${POLICY_TARGET}"
if [[ "${READ_MODE}" == privileged ]]; then
  validate_helper_runtime "${HELPER_SOURCE}" || fail "helper 运行时自检失败"
  validate_install_layout /etc/sudoers.d "${HELPER_TARGET}" "${SUDOERS_TARGET}"
  command -v visudo >/dev/null 2>&1 || fail "未安装 visudo，无法校验专用 sudoers"
  visudo -c || fail "现有 sudoers 校验失败，拒绝修改安装状态"
  grep -Eq '^[[:space:]]*(#|@)includedir[[:space:]]+/etc/sudoers.d([[:space:]]|$)' /etc/sudoers || \
    fail "sudoers 尚未启用 /etc/sudoers.d，请管理员先通过 visudo 配置"
  sudoers_candidate="$(mktemp /var/tmp/linux-mcp-sudoers.XXXXXX)"
  trap 'rm -f -- "${sudoers_candidate}"' EXIT
  write_sudoers "${sudoers_candidate}"
  visudo -cf "${sudoers_candidate}" || fail "专用 sudoers 语法校验失败"
fi

public_key="$(validate_public_key "${PUBLIC_KEY_FILE}" "${ALLOW_RSA}")"

if [[ -e "${ACCOUNT_MARKER}" ]]; then
  validate_managed_account "${ACCOUNT_MARKER}" "${TARGET_USER}"
elif id "${TARGET_USER}" >/dev/null 2>&1; then
  [[ "${ADOPT_EXISTING}" == true ]] || \
    fail "账号已存在但未受管；如确认是旧版专用账号，请显式传入 --adopt-existing"
  validate_existing_account "${TARGET_USER}"
  install -d -o root -g root -m 0755 "${CONFIG_DIR}"
  WRITE_ACCOUNT_MARKER=true
else
  [[ "${ADOPT_EXISTING}" == false ]] || fail "账号不存在，不能使用 --adopt-existing"
  useradd --create-home --user-group --shell /bin/sh "${TARGET_USER}"
  validate_existing_account "${TARGET_USER}"
  install -d -o root -g root -m 0755 "${CONFIG_DIR}"
  WRITE_ACCOUNT_MARKER=true
fi

passwd -l "${TARGET_USER}" >/dev/null
usermod --shell /bin/sh "${TARGET_USER}"
install -d -o root -g root -m 0755 /usr/local/libexec
install -d -o root -g root -m 0755 "${CONFIG_DIR}"
backup_existing_files
install -o root -g root -m 0755 "${WRAPPER_SOURCE}" "${WRAPPER_TARGET}"
install -o root -g root -m 0644 "${POLICY_FILE}" "${POLICY_TARGET}"
if [[ "${READ_MODE}" == privileged ]]; then
  install -o root -g root -m 0700 "${HELPER_SOURCE}" "${HELPER_TARGET}"
  [[ -d /etc/sudoers.d ]] || install -d -o root -g root -m 0750 /etc/sudoers.d
  install -o root -g root -m 0440 "${sudoers_candidate}" "${SUDOERS_TARGET}"
  visudo -c || fail "全局 sudoers 校验失败，请管理员恢复备份"
  validate_sudo_access "${TARGET_USER}"
  prepare_verification_samples
fi

readonly USER_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
readonly SSH_DIR="${USER_HOME}/.ssh"
readonly AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"
install -d -o "${TARGET_USER}" -g "${TARGET_USER}" -m 0700 "${SSH_DIR}"

forced_command='command="/usr/bin/python /usr/local/libexec/linux-mcp-readonly.py",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty'
printf '%s %s\n' "${forced_command}" "${public_key}" > "${AUTHORIZED_KEYS}"
chown "${TARGET_USER}:${TARGET_USER}" "${AUTHORIZED_KEYS}"
chmod 0600 "${AUTHORIZED_KEYS}"

if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF "${SSH_DIR}" >/dev/null || true
fi
if [[ "${WRITE_ACCOUNT_MARKER}" == true ]]; then
  write_managed_account
fi

echo "安装完成："
echo "  account=${TARGET_USER}"
echo "  wrapper=${WRAPPER_TARGET}"
echo "  policy=${POLICY_TARGET}"
echo "  authorized_keys=${AUTHORIZED_KEYS}"
if [[ -n "${BACKUP_DIR}" ]]; then
  echo "  backup=${BACKUP_DIR}"
else
  echo "  backup=none（首次安装）"
fi
echo "请继续执行文档中的拒绝测试和允许命令测试。"
