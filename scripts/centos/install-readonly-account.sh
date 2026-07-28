#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法（必须以 root 执行）：
  install-readonly-account.sh <公钥文件> <策略 JSON> [账号名] [--adopt-existing]

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

  command -v runuser >/dev/null 2>&1 || \
    fail "未找到 runuser，无法安全确认账号 sudo 权限：${account}"
  if command -v sudo >/dev/null 2>&1 && \
      runuser -u "${account}" -- sudo -n -l >/dev/null 2>&1; then
    fail "账号具有 sudo 权限，拒绝接管：${account}"
  fi
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

  for target in "${WRAPPER_TARGET}" "${POLICY_TARGET}"; do
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

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  fail "必须以 root 执行。"
fi

if [[ "$#" -lt 2 || "$#" -gt 4 ]]; then
  usage >&2
  exit 1
fi

readonly PUBLIC_KEY_FILE="$1"
readonly POLICY_FILE="$2"
shift 2
TARGET_USER="codex-ro"
ADOPT_EXISTING=false
TARGET_USER_SET=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --adopt-existing)
      [[ "${ADOPT_EXISTING}" == false ]] || fail "--adopt-existing 不能重复指定"
      ADOPT_EXISTING=true
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
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WRAPPER_SOURCE="${SCRIPT_DIR}/linux-mcp-readonly.py"
readonly WRAPPER_TARGET="/usr/local/libexec/linux-mcp-readonly.py"
readonly CONFIG_DIR="/etc/linux-mcp-readonly"
readonly POLICY_TARGET="${CONFIG_DIR}/policy.json"
readonly ACCOUNT_MARKER="${CONFIG_DIR}/managed-account"
readonly BACKUP_ROOT="${CONFIG_DIR}/backups"
BACKUP_DIR=""
WRITE_ACCOUNT_MARKER=false

validate_account_name "${TARGET_USER}"
for required_file in "${PUBLIC_KEY_FILE}" "${POLICY_FILE}" "${WRAPPER_SOURCE}"; do
  [[ -f "${required_file}" ]] || fail "文件不存在：${required_file}"
done
if ! /usr/bin/python -m json.tool "${POLICY_FILE}" >/dev/null; then
  fail "策略文件不是有效 JSON。"
fi

public_key="$(tr -d '\r\n' < "${PUBLIC_KEY_FILE}")"
[[ "${public_key}" =~ ^ssh-ed25519[[:space:]] ]] || fail "仅接受 Ed25519 公钥。"

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
