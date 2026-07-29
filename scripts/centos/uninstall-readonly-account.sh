#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法（必须以 root 执行）：
  uninstall-readonly-account.sh --confirm-account codex-ro

仅删除带 /etc/linux-mcp-readonly/managed-account 标记的受管账号。
删除前会备份当前包装器、策略和标记；历史备份会保留。
EOF
}

fail() {
  echo "错误：$*" >&2
  exit 1
}

validate_account_name() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "账号名无效：$1"
  [[ "$1" != "root" ]] || fail "拒绝删除 root"
}

read_managed_account() {
  local account mode owner marker="$1"

  [[ -f "${marker}" && ! -L "${marker}" ]] || fail "受管账号标记不是普通文件：${marker}"
  owner="$(stat -c '%U' "${marker}")"
  mode="$(stat -c '%a' "${marker}")"
  [[ "${owner}" == "root" && "${mode}" =~ ^[0-6][0-4][0-4]$ ]] || \
    fail "受管账号标记权限不安全：${marker}"
  account="$(tr -d '\r\n' < "${marker}")"
  validate_account_name "${account}"
  printf '%s\n' "${account}"
}

require_confirmed_account() {
  [[ "$1" == "$2" ]] || fail "确认账号与受管账号不一致：$1"
}

require_regular_root_file() {
  local path="$1"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "受管目标不是安全的普通文件：${path}"
  [[ "$(stat -c '%U' "${path}")" == "root" ]] || fail "受管目标不是 root 所有：${path}"
}

backup_current_files() {
  local timestamp target require_all="$1"

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP_DIR="${BACKUP_ROOT}/${timestamp}-uninstall"
  [[ ! -e "${BACKUP_DIR}" ]] || fail "备份目录已存在，拒绝覆盖：${BACKUP_DIR}"
  install -d -o root -g root -m 0700 "${BACKUP_DIR}"
  for target in "${WRAPPER_TARGET}" "${POLICY_TARGET}" "${ACCOUNT_MARKER}"; do
    if [[ ! -e "${target}" && ! -L "${target}" ]]; then
      [[ "${require_all}" == true ]] && fail "受管目标不存在：${target}"
      continue
    fi
    require_regular_root_file "${target}"
    install -o root -g root -m 0600 "${target}" "${BACKUP_DIR}/$(basename "${target}")"
  done
}

determine_uninstall_mode() {
  if id "$1" >/dev/null 2>&1; then
    printf '%s\n' "delete"
  else
    printf '%s\n' "recover"
  fi
}

remove_managed_files() {
  # 最后删除标记，以便中断后仍可安全恢复清理。
  rm -f -- "$1" "$2" "$3"
}

assert_private_group_unused() {
  local account="$1" group_entry group_gid group_members member

  group_entry="$(getent group "${account}")"
  [[ -n "${group_entry}" ]] || return
  group_gid="$(printf '%s\n' "${group_entry}" | cut -d: -f3)"
  [[ -n "${group_gid}" ]] || fail "账号私有组 GID 无效：${account}"
  group_members="$(printf '%s\n' "${group_entry}" | cut -d: -f4)"
  for member in ${group_members//,/ }; do
    [[ "${member}" == "${account}" ]] || fail "账号私有组仍包含其他成员：${account}"
  done
  if getent passwd | awk -F: -v gid="${group_gid}" -v account="${account}" \
      '$4 == gid && $1 != account { found = 1 } END { exit(found ? 0 : 1) }'; then
    fail "账号私有组仍被其他账号使用：${account}"
  fi
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

[[ "${EUID}" -eq 0 ]] || fail "必须以 root 执行。"
[[ "$#" -eq 2 && "$1" == "--confirm-account" ]] || { usage >&2; exit 1; }
readonly CONFIRMED_ACCOUNT="$2"
validate_account_name "${CONFIRMED_ACCOUNT}"

readonly CONFIG_DIR="/etc/linux-mcp-readonly"
readonly WRAPPER_TARGET="/usr/local/libexec/linux-mcp-readonly.py"
readonly POLICY_TARGET="${CONFIG_DIR}/policy.json"
readonly ACCOUNT_MARKER="${CONFIG_DIR}/managed-account"
readonly BACKUP_ROOT="${CONFIG_DIR}/backups"
readonly TARGET_USER="$(read_managed_account "${ACCOUNT_MARKER}")"
require_confirmed_account "${CONFIRMED_ACCOUNT}" "${TARGET_USER}"
readonly UNINSTALL_MODE="$(determine_uninstall_mode "${TARGET_USER}")"

if [[ "${UNINSTALL_MODE}" == "delete" ]]; then
  [[ "$(id -u "${TARGET_USER}")" -ne 0 ]] || fail "拒绝删除 UID 0 账号：${TARGET_USER}"
  [[ "$(id -gn "${TARGET_USER}")" == "${TARGET_USER}" ]] || fail "账号主组必须同名：${TARGET_USER}"

  if command -v pgrep >/dev/null 2>&1 && pgrep -u "${TARGET_USER}" >/dev/null 2>&1; then
    fail "账号仍有运行中的进程，拒绝删除：${TARGET_USER}"
  fi
fi

if [[ "${UNINSTALL_MODE}" == "delete" ]]; then
  backup_current_files true
else
  backup_current_files false
fi
assert_private_group_unused "${TARGET_USER}"
if [[ "${UNINSTALL_MODE}" == "delete" ]]; then
  userdel --remove "${TARGET_USER}"
fi
if getent group "${TARGET_USER}" >/dev/null 2>&1; then
  groupdel "${TARGET_USER}"
fi
remove_managed_files "${WRAPPER_TARGET}" "${POLICY_TARGET}" "${ACCOUNT_MARKER}"

if [[ "${UNINSTALL_MODE}" == "delete" ]]; then
  echo "删除完成："
else
  echo "恢复清理完成："
fi
echo "  account=${TARGET_USER}"
echo "  backup=${BACKUP_DIR}"
echo "  保留目录=${BACKUP_ROOT}"
