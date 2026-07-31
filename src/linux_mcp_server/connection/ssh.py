"""SSH executor for remote command execution.

This module provides functionality to execute commands on remote systems via SSH,
with connection pooling and SSH key discovery. It seamlessly routes commands to
either local or remote execution based on the provided parameters.
"""

import asyncio
import logging
import os
import shlex
import shutil
import subprocess
import time

from collections.abc import Sequence
from pathlib import Path
from typing import Optional

import asyncssh

from linux_mcp_server import __version__
from linux_mcp_server.audit import Event
from linux_mcp_server.audit import log_compat_fallback
from linux_mcp_server.audit import log_ssh_command
from linux_mcp_server.audit import log_ssh_connect
from linux_mcp_server.audit import Status
from linux_mcp_server.compatibility import COMPATIBILITY_COMMANDS
from linux_mcp_server.compatibility import HostCompatibility
from linux_mcp_server.compatibility import parse_os_release
from linux_mcp_server.compatibility import validate_variant_output
from linux_mcp_server.config import CONFIG
from linux_mcp_server.execution_context import get_execution_context
from linux_mcp_server.host_registry import get_managed_profile
from linux_mcp_server.host_registry import HostProfile
from linux_mcp_server.utils.types import Host


logger = logging.getLogger("linux-mcp-server")
_UNSUPPORTED_OPTION_MARKERS = (
    "invalid option",
    "illegal option",
    "unknown column",
    "unknown option",
    "unrecognized option",
)


def discover_ssh_key() -> str | None:
    """
    Discover SSH private key for authentication.

    Checks in order:
    1. LINUX_MCP_SSH_KEY_PATH environment variable
    2. Default locations: ~/.ssh/id_ed25519, ~/.ssh/id_rsa, ~/.ssh/id_ecdsa

    Returns:
        Path to SSH private key if found, None otherwise.
    """
    logger.debug("Discovering SSH key for authentication")

    env_key = CONFIG.ssh_key_path
    if env_key:
        logger.debug(f"Checking SSH key from environment: {env_key}")
        key_path = Path(env_key)
        if key_path.exists() and key_path.is_file():
            logger.info(f"Using SSH key from environment: {env_key}")
            return str(key_path)
        else:
            logger.warning(f"SSH key specified in LINUX_MCP_SSH_KEY_PATH not found: {env_key}")
            return None

    # Check default locations (prefer modern algorithms)
    if CONFIG.search_for_ssh_key:
        home = Path.home()
        default_keys = [
            home / ".ssh" / "id_ed25519",
            home / ".ssh" / "id_ecdsa",
            home / ".ssh" / "id_rsa",
        ]

        logger.debug(f"Checking default SSH key locations: {[str(k) for k in default_keys]}")

        for key_path in default_keys:
            if key_path.exists() and key_path.is_file():
                logger.info(f"Using SSH key: {key_path}")
                return str(key_path)

        logger.warning("No SSH private key found in default locations")

    logger.debug("Not providing an SSH key")


class SSHConnectionManager:
    """
    Manages SSH connections with connection pooling.

    This class implements a singleton pattern to maintain a pool of SSH connections
    across the lifetime of the application, improving performance by reusing
    connections to the same hosts.
    """

    _instance: Optional["SSHConnectionManager"] = None
    _compatibility: dict[str, HostCompatibility]
    _connections: dict[str, asyncssh.SSHClientConnection]
    _logged_fallbacks: set[tuple[str, str]]
    _ssh_key: str | None

    def __new__(cls):
        """Implement singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._compatibility = {}
            cls._instance._connections = {}
            cls._instance._logged_fallbacks = set()
            cls._instance._ssh_key = discover_ssh_key()
        return cls._instance

    def _connection_settings(self, host: str) -> tuple[str, str | None, str]:
        profile = get_managed_profile(host)
        if profile is not None:
            ssh_key = str(profile.ssh.private_key_path)
            key = (
                f"{profile.alias}:{profile.address}:{profile.port}:{ssh_key}:"
                f"{profile.user}:{profile.ssh.host_fingerprint}"
            )
            return key, ssh_key, profile.user

        context = get_execution_context()
        if context is not None:
            ssh_key = str(context.ssh_key_path) if context.ssh_key_path else self._ssh_key
            username = context.ssh_key_user or CONFIG.user
        else:
            ssh_key = self._ssh_key
            username = CONFIG.user
        key = f"{host}:{ssh_key or 'default'}:{username or 'default'}"
        return key, ssh_key, username

    async def get_connection(self, host: str) -> asyncssh.SSHClientConnection:
        """
        Get or create an SSH connection to a host.

        Args:
            host: Remote host address
            username: SSH username

        Returns:
            SSH connection object

        Raises:
            ConnectionError: If connection fails
        """
        profile = get_managed_profile(host)
        key, ssh_key, username = self._connection_settings(host)

        # Return existing connection if available
        if key in self._connections:
            conn = self._connections[key]
            if not conn.is_closed():
                # DEBUG level: Log connection reuse and pool state
                logger.debug(f"SSH_REUSE: {key} | pool_size={len(self._connections)}")
                # Use audit log with connection reuse info
                log_ssh_connect(
                    host,
                    username=conn.get_extra_info("username"),
                    status=Status.success,
                    reused=True,
                    key_path=ssh_key,
                )
                return conn
            else:
                # Connection was closed, remove it
                logger.debug(f"SSH_POOL: remove_closed_connection | connection={key}")
                del self._connections[key]
                self._compatibility.pop(key, None)
                self._logged_fallbacks = {item for item in self._logged_fallbacks if item[0] != key}

        # Create new connection
        # DEBUG level: Log connection attempt before it completes
        logger.debug(f"{Event.SSH_CONNECTING}: {key} | key={ssh_key or 'none'}")

        try:
            # Determine host key verification settings
            if CONFIG.verify_host_keys:
                known_hosts = (
                    str(profile.ssh.known_hosts_path) if profile is not None else str(CONFIG.effective_known_hosts_path)
                )
            else:
                logger.warning("SSH host key verification disabled - vulnerable to MITM attacks")
                known_hosts = None

            connect_kwargs = {
                "host": profile.address if profile is not None else host,
                "known_hosts": known_hosts,
                "passphrase": CONFIG.key_passphrase.get_secret_value() or None,
            }
            if profile is not None:
                connect_kwargs["port"] = profile.port
                self._validate_managed_ssh_files(profile)
                if profile.ssh.legacy_rsa:
                    connect_kwargs["server_host_key_algs"] = ["ssh-rsa"]
                    connect_kwargs["signature_algs"] = ["ssh-rsa"]

            # Use custom SSH key if provided, otherwise use default
            if ssh_key:
                connect_kwargs["client_keys"] = [ssh_key]

            # Use custom username if provided, otherwise use CONFIG.user
            if username:
                connect_kwargs["username"] = username

            conn = await asyncssh.connect(**connect_kwargs)
            self._connections[key] = conn

            # Log successful connection using audit function
            log_ssh_connect(
                host,
                username=conn.get_extra_info("username"),
                status=Status.success,
                reused=False,
                key_path=ssh_key,
            )

            # DEBUG level: Log pool state
            logger.debug(f"SSH_POOL: add_connection | connections={len(self._connections)}")

            try:
                self._compatibility[key] = (
                    self._profile_compatibility(profile)
                    if profile is not None
                    else await self._probe_compatibility(host, conn)
                )
            except Exception:
                self._connections.pop(key, None)
                conn.close()
                raise

            return conn

        except asyncssh.PermissionDenied as e:
            # Use audit log for authentication failure
            error_msg = str(e)
            log_ssh_connect(host, status=Status.failed, error=f"Permission denied: {error_msg}")
            raise ConnectionError(f"Authentication failed for {host}") from e
        except asyncssh.Error as e:
            # Use audit log for connection failure
            error_msg = str(e)
            log_ssh_connect(host, status=Status.failed, error=error_msg)
            raise ConnectionError(f"Failed to connect to {host}: {e}") from e

    @staticmethod
    def _validate_managed_ssh_files(profile: HostProfile) -> None:
        for label, path in (
            ("private key", profile.ssh.private_key_path),
            ("known_hosts", profile.ssh.known_hosts_path),
        ):
            if path.is_symlink() or not path.is_file():
                raise ConnectionError(f"Managed {label} is missing or unsafe for {profile.alias}")
            if os.name == "posix" and path.stat().st_mode & 0o077:
                raise ConnectionError(f"Managed {label} permissions are too broad for {profile.alias}")
        expected_host = profile.address if profile.port == 22 else f"[{profile.address}]:{profile.port}"
        try:
            known_hosts = profile.ssh.known_hosts_path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise ConnectionError(f"Managed known_hosts is unreadable for {profile.alias}") from error
        expected_line = f"{expected_host} {profile.ssh.host_public_key}"
        if known_hosts.strip() != expected_line:
            raise ConnectionError(f"Managed known_hosts does not match the profile for {profile.alias}")

    @staticmethod
    def _profile_compatibility(profile: HostProfile) -> HostCompatibility:
        capability_tools = {
            "disk_usage": "get_disk_usage",
            "block_devices": "list_block_devices",
            "memory_info": "get_memory_information",
        }
        variants = {
            capability: profile.capabilities[tool_name].backend
            for capability, tool_name in capability_tools.items()
            if profile.capabilities[tool_name].status != "unsupported"
        }
        return HostCompatibility(
            host=profile.alias,
            hostname=profile.alias,
            os_id=profile.os.id,
            os_version=profile.os.version,
            kernel=profile.os.kernel,
            variants=variants,
        )

    async def _run_probe_command(
        self,
        host: str,
        conn: asyncssh.SSHClientConnection,
        command: Sequence[str],
    ) -> tuple[int, str, str]:
        binary = command[0]
        if not Path(binary).is_absolute():
            binary = await get_remote_bin_path(binary, host, conn)
        cmd_str = shlex.join([binary, *command[1:]])
        start_time = time.time()
        try:
            result = await conn.run(
                cmd_str,
                check=False,
                timeout=CONFIG.command_timeout,
                encoding="utf-8",
            )
        except asyncssh.TimeoutError:
            raise ConnectionError(f"Compatibility probe timed out on {host}") from None
        except asyncssh.Error as error:
            raise ConnectionError(f"Compatibility probe failed on {host}: {error}") from error

        return_code = result.exit_status if result.exit_status is not None else 0
        stdout = (
            result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else result.stdout or ""
        )
        stderr = (
            result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else result.stderr or ""
        )
        log_ssh_command(cmd_str, host, exit_code=return_code, duration=time.time() - start_time)
        return return_code, stdout, stderr

    async def _probe_required_text(
        self,
        host: str,
        conn: asyncssh.SSHClientConnection,
        command: Sequence[str],
        label: str,
    ) -> str:
        return_code, stdout, _ = await self._run_probe_command(host, conn, command)
        if return_code != 0 or not stdout.strip():
            raise ConnectionError(f"Compatibility probe could not read {label} on {host}")
        return stdout.strip()

    async def _probe_compatibility(
        self,
        host: str,
        conn: asyncssh.SSHClientConnection,
    ) -> HostCompatibility:
        hostname = await self._probe_required_text(host, conn, ("hostname",), "hostname")
        os_release = await self._probe_required_text(host, conn, ("cat", "/etc/os-release"), "os-release")
        kernel = await self._probe_required_text(host, conn, ("uname", "-r"), "kernel")
        os_id, os_version = parse_os_release(os_release)

        selected: dict[str, str] = {}
        for capability, variants in COMPATIBILITY_COMMANDS.items():
            for variant in variants:
                return_code, stdout, stderr = await self._run_probe_command(host, conn, variant.args)
                if return_code == 0:
                    try:
                        validate_variant_output(capability, variant.name, stdout)
                    except (TypeError, ValueError) as error:
                        raise ConnectionError(
                            f"Compatibility probe for {capability} returned malformed output on {host}"
                        ) from error
                    selected[capability] = variant.name
                    break

                normalized_error = stderr.casefold()
                if any(marker in normalized_error for marker in _UNSUPPORTED_OPTION_MARKERS):
                    continue
                raise ConnectionError(
                    f"Compatibility probe for {capability} failed with exit code {return_code} on {host}"
                )
            else:
                raise ConnectionError(f"No compatible {capability} command was found on {host}")

        return HostCompatibility(
            host=host,
            hostname=hostname,
            os_id=os_id,
            os_version=os_version,
            kernel=kernel,
            variants=selected,
        )

    async def get_compatibility(self, host: str) -> HostCompatibility:
        """Return the profile collected for the current SSH identity."""

        key, _, _ = self._connection_settings(host)
        await self.get_connection(host)
        try:
            return self._compatibility[key]
        except KeyError as error:
            raise ConnectionError(f"Compatibility profile is unavailable for {host}") from error

    def log_fallback(self, host: str, capability: str, profile: HostCompatibility) -> None:
        """Write one fallback event per capability and SSH connection."""

        key, _, _ = self._connection_settings(host)
        log_key = (key, capability)
        if log_key in self._logged_fallbacks:
            return
        variants = COMPATIBILITY_COMMANDS[capability]
        selected_variant = profile.variants[capability]
        if selected_variant == variants[0].name:
            return
        log_compat_fallback(
            host=host,
            hostname=profile.hostname,
            os_id=profile.os_id,
            os_version=profile.os_version,
            kernel=profile.kernel,
            package_version=__version__,
            capability=capability,
            primary_variant=variants[0].name,
            selected_variant=selected_variant,
        )
        self._logged_fallbacks.add(log_key)

    async def execute_remote(
        self,
        command: Sequence[str],
        host: str,
        timeout: int = CONFIG.command_timeout,
        encoding: str | None = "utf-8",
    ) -> tuple[int, str | bytes, str | bytes]:
        """
        Execute a command on a remote host via SSH.

        Commands are subject to a timeout to prevent indefinite hangs. The timeout
        can be specified per-call or defaults to CONFIG.command_timeout (30s).

        Args:
            command: Command and arguments to execute
            host: Remote host address
            username: SSH username
            timeout: Command timeout in seconds. Defaults to CONFIG.command_timeout.
                Use for commands that need longer execution time.
            encoding: Character encoding for stdout/stderr. Defaults to "utf-8".
                Set to None to receive raw bytes for commands that may output
                binary content.

        Returns:
            Tuple of (return_code, stdout, stderr) where stdout and stderr are strings
            if encoding is not None, otherwise bytes.

        Raises:
            ConnectionError: If SSH connection fails or command times out
        """
        conn = await self.get_connection(host)
        bin = command[0]
        if not Path(bin).is_absolute():
            bin = await get_remote_bin_path(bin, host, conn)

        full_command = [bin, *command[1:]]

        # Build command string with proper shell escaping
        # Use shlex.quote() to ensure special characters (like \n in printf format) are preserved
        cmd_str = shlex.join(full_command)

        # Start timing for command execution
        start_time = time.time()

        try:
            try:
                result = await conn.run(cmd_str, check=False, timeout=timeout, encoding=encoding)
            except asyncssh.TimeoutError:
                duration = time.time() - start_time
                logger.error(
                    f"Command timed out after {timeout}s",
                    extra={
                        "event": Event.REMOTE_EXEC_ERROR,
                        "command": cmd_str,
                        "host": host,
                        "duration": f"{duration:.3f}s",
                        "error": "timeout",
                    },
                )
                raise ConnectionError(
                    f"Command timed out after {timeout}s on {conn.get_extra_info('username')}@{host}: {cmd_str}"
                ) from None

            return_code = result.exit_status if result.exit_status is not None else 0

            stdout = result.stdout if result.stdout else b"" if encoding is None else ""
            stderr = result.stderr if result.stderr else b"" if encoding is None else ""
            # Calculate duration
            duration = time.time() - start_time

            # Use audit log for command execution
            log_ssh_command(cmd_str, host, exit_code=return_code, duration=duration)

            return return_code, stdout, stderr

        except asyncssh.Error as e:
            duration = time.time() - start_time
            logger.error(
                f"Error executing command on {host}: {e}",
                extra={
                    "event": Event.REMOTE_EXEC_ERROR,
                    "command": cmd_str,
                    "host": host,
                    "duration": f"{duration:.3f}s",
                    "error": str(e),
                },
            )
            raise ConnectionError(f"Failed to execute command on {host}: {e}") from e

    async def close_all(self):
        """Close all SSH connections."""
        connection_count = len(self._connections)
        logger.info(f"Closing {connection_count} SSH connections")

        for key, conn in list(self._connections.items()):
            try:
                logger.debug(f"SSH_CLOSE: {key}")
                conn.close()
                await conn.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection to {key}: {e}")

        self._connections.clear()
        self._compatibility.clear()
        self._logged_fallbacks.clear()
        logger.debug(f"SSH_POOL: cleared | closed_connections={connection_count}")


# Global connection manager instance
_connection_manager = SSHConnectionManager()


def get_bin_path(command: str) -> str:
    """Get the full path to an executable.

    Raises FileNotFoundError if not found.
    """
    sbin_paths = ("/sbin", "/usr/sbin", "/usr/local/sbin")
    path = os.getenv("PATH", "").split(os.pathsep)
    path.extend(new_path for new_path in sbin_paths if new_path not in path)
    path = os.pathsep.join(path)
    bin_path = shutil.which(command, path=path)
    if bin_path is None:
        raise FileNotFoundError(f"Unable to find '{command}'")

    return bin_path


async def get_remote_bin_path(
    command: str,
    hostname: Host,
    connection: asyncssh.SSHClientConnection,
    timeout: int = CONFIG.command_timeout,
) -> str:
    """Get the full path to an executable on a remote system.

    Raises FileNotFoundError if not found.
    """
    logger.debug(f"Getting path for {command} on {hostname}")
    try:
        result = await connection.run(shlex.join(["command", "-v", command]), timeout=timeout)
    except asyncssh.Error as err:
        raise ConnectionError(
            f"Error when trying to locate command '{command}' on {connection.get_extra_info('username')}@{hostname}: {err}"
        )

    if result.exit_status == 0 and result.stdout:
        stdout = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
        return stdout.strip()

    raise FileNotFoundError(f"Unable to find command '{command}' on {connection.get_extra_info('username')}@{hostname}")


async def execute_command(
    command: Sequence[str],
    host: str | None = None,
    encoding: str | None = "utf-8",
    **kwargs,
) -> tuple[int, str | bytes, str | bytes]:
    """
    Execute a command locally or remotely.

    This is the main entry point for command execution. It routes the command
    to either local subprocess execution or remote SSH execution based on
    whether host/username parameters are provided.

    Args:
        command: Command and arguments to execute. If the command is not an absolute path
                 it will be resolved to the full path before execution.
        host: Optional remote host address
        encoding: Character encoding for stdout/stderr. Defaults to "utf-8".
            Set to None to receive raw bytes for commands that may output
            binary content.
        **kwargs: Additional arguments (reserved for future use)

    Returns:
        Tuple of (return_code, stdout, stderr) where stdout and stderr are strings
        if encoding is not None, otherwise bytes.

    Raises:
        ValueError: If host is provided without username
        ConnectionError: If remote connection fails

    Examples:
        # Local execution
        >>> returncode, stdout, stderr = await execute_command(["ls", "-la"])

        # Remote execution
        >>> returncode, stdout, stderr = await execute_command(
        ...     ["ls", "-la"],
        ...     host="server.example.com",
        ...     username="admin"
        ... )
    """
    # Get execution context, fail-closed if not set
    context = get_execution_context()
    if context is None:
        raise RuntimeError("No execution context set cannot execute commands")

    cmd_str = " ".join(command)

    if host:
        # Remote execution, check permissions
        if not context.allow_ssh_default and context.ssh_key_path is None:
            raise RuntimeError("Remote execution not allowed")

        logger.debug(f"Routing to remote execution: {host} | command={cmd_str}")
        return await _connection_manager.execute_remote(command, host, encoding=encoding)

    # Local execution,check permissions
    if not context.allow_local:
        raise RuntimeError("Local execution not allowed")

    logger.debug(f"LOCAL_EXEC: {cmd_str}")
    return await _execute_local(command, encoding=encoding)


async def execute_compatible_command(
    capability: str,
    host: str | None = None,
    encoding: str | None = "utf-8",
) -> tuple[int, str | bytes, str | bytes, str]:
    """Execute the command variant selected by the remote capability probe."""

    try:
        variants = COMPATIBILITY_COMMANDS[capability]
    except KeyError as error:
        raise ValueError(f"Unknown compatibility capability: {capability}") from error

    selected = variants[0]
    profile = None
    if host:
        profile = await _connection_manager.get_compatibility(host)
        selected_name = profile.variants.get(capability)
        selected = next((variant for variant in variants if variant.name == selected_name), None)
        if selected is None:
            raise ConnectionError(f"No selected command variant for {capability} on {host}")

    returncode, stdout, stderr = await execute_command(selected.args, host=host, encoding=encoding)
    if host and profile is not None:
        _connection_manager.log_fallback(host, capability, profile)
    return returncode, stdout, stderr, selected.name


async def execute_with_fallback(
    args: Sequence[str],
    fallback: Sequence[str] | None = None,
    host: str | None = None,
    encoding: str | None = "utf-8",
    **kwargs,
) -> tuple[int, str | bytes, str | bytes]:
    """
    Execute a command with optional fallback if primary command fails.

    This function attempts to execute the primary command. If it fails
    (non-zero return code) and a fallback command is provided, it will
    attempt the fallback command.

    Args:
        args: Primary command and arguments to execute
        fallback: Optional fallback command if primary fails
        host: Optional remote host address
        username: Optional SSH username (required if host is provided)
        encoding: Character encoding for stdout/stderr. Defaults to "utf-8".
            Set to None to receive raw bytes for commands that may output
            binary content.
        **kwargs: Additional arguments passed to execute_command

    Returns:
        Tuple of (return_code, stdout, stderr)

    Examples:
        # Try ss, fall back to netstat
        >>> returncode, stdout, stderr = await execute_with_fallback(
        ...     ["ss", "-tunap"],
        ...     fallback=["netstat", "-tunap"],
        ...     host="server.example.com"
        ... )
    """
    returncode, stdout, stderr = await execute_command(args, host=host, encoding=encoding, **kwargs)

    # If primary command failed and we have a fallback, try it
    if returncode != 0 and fallback:
        logger.debug(f"Primary command failed (exit={returncode}), trying fallback: {' '.join(fallback)}")
        returncode, stdout, stderr = await execute_command(fallback, host=host, encoding=encoding, **kwargs)

    return returncode, stdout, stderr


async def _execute_local(
    command: Sequence[str], encoding: str | None = "utf-8"
) -> tuple[int, str | bytes, str | bytes]:
    """
    Execute a command locally using subprocess.

    Args:
        command: Command and arguments to execute
        encoding: Character encoding for stdout/stderr. Defaults to "utf-8".
            Set to None to receive raw bytes.

    Returns:
        Tuple of (return_code, stdout, stderr) where stdout and stderr are strings
        if encoding is not None, otherwise bytes.

    Raises:
        TimeoutError: If the command does not complete within ``CONFIG.command_timeout`` seconds.
    """
    cmd_str = " ".join(command)
    start_time = time.time()
    bin = command[0]
    if not Path(bin).is_absolute():
        bin = get_bin_path(bin)

    full_command = [bin, *command[1:]]
    timeout = CONFIG.command_timeout

    try:
        proc = await asyncio.create_subprocess_exec(
            *full_command,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.time() - start_time
            logger.error(
                f"Command timed out after {timeout}s",
                extra={
                    "event": Event.LOCAL_EXEC_ERROR,
                    "command": cmd_str,
                    "duration": f"{duration:.3f}s",
                    "error": "timeout",
                },
            )
            raise TimeoutError(f"Command timed out after {timeout}s on localhost: {cmd_str}") from None

        return_code = proc.returncode if proc.returncode is not None else 0
        stdout = stdout_bytes if encoding is None else stdout_bytes.decode(encoding, errors="replace")
        stderr = stderr_bytes if encoding is None else stderr_bytes.decode(encoding, errors="replace")

        duration = time.time() - start_time

        logger.debug(f"LOCAL_EXEC completed: {cmd_str} | exit_code={return_code} | duration={duration:.3f}s")

        return return_code, stdout, stderr

    except TimeoutError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"Error executing local command: {cmd_str}",
            extra={
                "event": Event.LOCAL_EXEC_ERROR,
                "command": cmd_str,
                "duration": f"{duration:.3f}s",
                "error": str(e),
            },
        )
        return 1, "", str(e)
