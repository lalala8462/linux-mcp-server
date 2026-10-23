"""Command registry for unified local and remote execution.

This module provides a centralized registry of commands used by tools,
enabling consistent execution across local and remote systems.
"""

from collections.abc import Mapping
from collections.abc import Sequence
from types import MappingProxyType

from pydantic import BaseModel
from pydantic import ConfigDict

from linux_mcp_server.compatibility import COMPATIBILITY_COMMANDS
from linux_mcp_server.connection.ssh import execute_compatible_command
from linux_mcp_server.connection.ssh import execute_with_fallback


class CommandSpec(BaseModel):
    """Specification for a single command with optional fallback.

    Attributes:
        args: Command arguments as a tuple of strings.
        fallback: Alternative command arguments if primary fails.
        compatibility_key: Fixed remote capability profile to use.
        optional_flags: Maps parameter names to flag arguments that are added
            when the parameter is truthy. For example:
            {"unit": ["--unit", "{unit}"]} adds "--unit <value>" when unit is provided.
    """

    model_config = ConfigDict(frozen=True)

    args: tuple[str, ...]
    fallback: tuple[str, ...] | None = None
    compatibility_key: str | None = None
    optional_flags: Mapping[str, tuple[str, ...]] | None = None

    def _render_args(self, **kwargs: object) -> tuple[str, ...]:
        args = list(substitute_command_args(self.args, **kwargs))
        if self.optional_flags:
            for param_name, flag_args in self.optional_flags.items():
                if kwargs.get(param_name):
                    args.extend(substitute_command_args(flag_args, **kwargs))
        return tuple(args)

    async def run_with_variant(
        self,
        host: str | None = None,
        **kwargs: object,
    ) -> tuple[int, str, str, str]:
        """Run a command and return the selected compatibility variant."""

        args = self._render_args(**kwargs)
        if host and self.compatibility_key:
            returncode, stdout, stderr, variant = await execute_compatible_command(
                self.compatibility_key,
                host=host,
            )
        else:
            returncode, stdout, stderr = await execute_with_fallback(args, fallback=self.fallback, host=host)
            variant = "primary"
        stdout = stdout if isinstance(stdout, str) else stdout.decode("utf-8", errors="replace")
        stderr = stderr if isinstance(stderr, str) else stderr.decode("utf-8", errors="replace")
        return returncode, stdout, stderr, variant

    async def run(self, host: str | None = None, **kwargs: object) -> tuple[int, str, str]:
        """Run the command with optional fallback."""

        returncode, stdout, stderr, _ = await self.run_with_variant(host=host, **kwargs)
        return returncode, stdout, stderr

    async def run_bytes(self, host: str | None = None, **kwargs: object) -> tuple[int, bytes, bytes]:
        """Run the command with optional fallback and return raw bytes.

        Args:
            host: Optional remote host address.
            **kwargs: Additional arguments passed to substitute_command_args.
        """
        args = self._render_args(**kwargs)

        if host and self.compatibility_key:
            returncode, stdout, stderr, _ = await execute_compatible_command(
                self.compatibility_key,
                host=host,
                encoding=None,
            )
        else:
            returncode, stdout, stderr = await execute_with_fallback(
                args,
                fallback=self.fallback,
                host=host,
                encoding=None,
            )
        stdout = stdout if isinstance(stdout, bytes) else stdout.encode("utf-8")
        stderr = stderr if isinstance(stderr, bytes) else stderr.encode("utf-8")
        return returncode, stdout, stderr


class CommandGroup(BaseModel):
    """Group of related commands for multi-command tool operations.

    Attributes:
        commands: Named commands within the group.
    """

    model_config = ConfigDict(frozen=True)

    commands: Mapping[str, CommandSpec]


# All commands are wrapped in CommandGroup for consistency and future expandability.
# Single-command tools use the "default" subcommand pattern, while multi-command
# tools (e.g., system_info, cpu_info, hardware_info) use named subcommands.
# This unified structure eliminates type-checking boilerplate in consuming code.
COMMANDS: Mapping[str, CommandGroup] = MappingProxyType(
    {
        # === Services ===
        "list_services": CommandGroup(
            commands={
                "default": CommandSpec(args=("systemctl", "list-units", "--type=service", "--all", "--no-pager")),
            }
        ),
        "running_services": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("systemctl", "list-units", "--type=service", "--state=running", "--no-pager")
                ),
            }
        ),
        "service_status": CommandGroup(
            commands={
                "default": CommandSpec(args=("systemctl", "status", "{service_name}", "--no-pager", "--full")),
            }
        ),
        "service_logs": CommandGroup(
            commands={
                "default": CommandSpec(args=("journalctl", "-u", "{service_name}", "-n", "{lines}", "--no-pager")),
            }
        ),
        # === Network ===
        "network_connections": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("ss", "-tunap"),
                    fallback=("netstat", "-tunap"),
                ),
            }
        ),
        "listening_ports": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("ss", "-tulnp"),
                    fallback=("netstat", "-tulnp"),
                ),
            }
        ),
        "network_interfaces": CommandGroup(
            commands={
                "brief": CommandSpec(args=("ip", "-brief", "address")),
                "detail": CommandSpec(args=("ip", "address")),
                "stats": CommandSpec(args=("cat", "/proc/net/dev")),
            }
        ),
        # === Logs ===
        "journal_logs": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("journalctl", "-n", "{lines}", "--no-pager"),
                    optional_flags={
                        "unit": ("--unit", "{unit}"),
                        "priority": ("--priority", "{priority}"),
                        "since": ("--since", "{since}"),
                        "transport": ("_TRANSPORT={transport}",),
                    },
                ),
            }
        ),
        "read_log_file": CommandGroup(
            commands={
                "default": CommandSpec(args=("tail", "-n", "{lines}", "{log_path}")),
            }
        ),
        # === Processes ===
        "list_processes": CommandGroup(
            commands={
                "default": CommandSpec(args=("ps", "aux", "--sort=-%cpu")),
            }
        ),
        "process_info": CommandGroup(
            commands={
                "ps_detail": CommandSpec(
                    args=("ps", "-p", "{pid}", "-o", "pid,user,stat,pcpu,pmem,vsz,rss,etime,comm,args")
                ),
                "proc_status": CommandSpec(args=("cat", "/proc/{pid}/status")),
            }
        ),
        # === Storage ===
        "list_block_devices": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=COMPATIBILITY_COMMANDS["block_devices"][0].args,
                    compatibility_key="block_devices",
                ),
            }
        ),
        "disk_usage": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=COMPATIBILITY_COMMANDS["disk_usage"][0].args,
                    compatibility_key="disk_usage",
                ),
            }
        ),
        "list_directories_size": CommandGroup(
            commands={
                "default": CommandSpec(args=("du", "--block-size=1", "--one-file-system", "--max-depth=1", "{path}")),
            }
        ),
        "list_directories_name": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("find", "{path}", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-printf", "%f\\n")
                ),
            }
        ),
        "list_directories_modified": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("find", "{path}", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-printf", "%T@\\t%f\\n")
                ),
            }
        ),
        "list_files_size": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("find", "{path}", "-mindepth", "1", "-maxdepth", "1", "-type", "f", "-printf", "%s\\t%f\\n")
                ),
            }
        ),
        "list_files_name": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("find", "{path}", "-mindepth", "1", "-maxdepth", "1", "-type", "f", "-printf", "%f\\n")
                ),
            }
        ),
        "list_files_modified": CommandGroup(
            commands={
                "default": CommandSpec(
                    args=("find", "{path}", "-mindepth", "1", "-maxdepth", "1", "-type", "f", "-printf", "%T@\\t%f\\n")
                ),
            }
        ),
        "read_file": CommandGroup(
            commands={
                "default": CommandSpec(args=("head", "--bytes", "{max_bytes}", "--", "{path}")),
            }
        ),
        "read_file_size": CommandGroup(
            commands={
                "default": CommandSpec(args=("stat", "--dereference", "--format", "%s", "--", "{path}")),
            }
        ),
        # === System Info ===
        "system_info": CommandGroup(
            commands={
                "hostname": CommandSpec(args=("hostname",)),
                "os_release": CommandSpec(args=("cat", "/etc/os-release")),
                "kernel": CommandSpec(args=("uname", "-r")),
                "arch": CommandSpec(args=("uname", "-m")),
                "uptime": CommandSpec(args=("uptime", "-p")),
                "boot_time": CommandSpec(args=("uptime", "-s")),
            }
        ),
        "cpu_info": CommandGroup(
            commands={
                "model": CommandSpec(args=("grep", "-m", "1", "model name", "/proc/cpuinfo")),
                "logical_cores": CommandSpec(args=("grep", "-c", "^processor", "/proc/cpuinfo")),
                "physical_cores": CommandSpec(args=("grep", "^core id", "/proc/cpuinfo")),
                "frequency": CommandSpec(args=("grep", "-m", "1", "cpu MHz", "/proc/cpuinfo")),
                "load_avg": CommandSpec(args=("cat", "/proc/loadavg")),
                "top_snapshot": CommandSpec(args=("top", "-bn1")),
            }
        ),
        "memory_info": CommandGroup(
            commands={
                "free": CommandSpec(
                    args=COMPATIBILITY_COMMANDS["memory_info"][0].args,
                    compatibility_key="memory_info",
                ),
            }
        ),
        "hardware_info": CommandGroup(
            commands={
                "lscpu": CommandSpec(args=("lscpu",)),
                "lspci": CommandSpec(args=("lspci",)),
                "lsusb": CommandSpec(args=("lsusb",)),
            }
        ),
    }
)


def get_command_group(name: str) -> CommandGroup:
    """Get a command group from the registry.

    Use this when you need to iterate over all subcommands in a group.

    Args:
        name: The command group name in the registry.

    Returns:
        The CommandGroup for the given name.

    Raises:
        KeyError: If the command name is not found in the registry.
    """
    try:
        return COMMANDS[name]
    except KeyError as e:
        available = ", ".join(sorted(COMMANDS.keys()))
        raise KeyError(f"Command '{name}' not found in registry. Available: {available}") from e


def get_command(name: str, subcommand: str = "default") -> CommandSpec:
    """Get a command spec from the registry.

    Args:
        name: The command name in the registry.
        subcommand: The subcommand key within the group (default: "default").

    Returns:
        The CommandSpec for the given name and subcommand.

    Raises:
        KeyError: If the command name or subcommand is not found.
    """
    group = get_command_group(name)
    try:
        return group.commands[subcommand]
    except KeyError as e:
        available = ", ".join(sorted(group.commands.keys()))
        raise KeyError(f"Subcommand '{subcommand}' not found for '{name}'. Available: {available}") from e


def substitute_command_args(args: Sequence[str], **kwargs: object) -> tuple[str, ...]:
    """Substitute placeholder values in command arguments.

    Args:
        args: Sequence of command arguments, possibly with {placeholder} values.
        **kwargs: Key-value pairs to substitute into placeholders.

    Returns:
        Tuple of command arguments with placeholders replaced.

    Raises:
        ValueError: If any placeholders are missing from kwargs or remain
            unsubstituted after replacement.

    Example:
        >>> substitute_command_args(("ps", "-p", "{pid}"), pid=1234)
        ("ps", "-p", "1234")
    """
    try:
        result = tuple(arg.format(**kwargs) for arg in args)
    except KeyError as e:
        raise ValueError(f"Missing required placeholder: {e}") from e

    # Validate all placeholders were replaced (catches edge cases like nested braces)
    for arg in result:
        if "{" in arg and "}" in arg:
            raise ValueError(f"Unsubstituted placeholder in command argument: {arg}")

    return result
