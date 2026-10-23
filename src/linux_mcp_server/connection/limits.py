"""流式限制诊断输出，避免远端或本机命令耗尽 MCP 内存。"""

import asyncio
import os
import signal
import weakref

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncssh

from linux_mcp_server.config import CONFIG


_slots: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[object, asyncio.Semaphore]] = (
    weakref.WeakKeyDictionary()
)


@asynccontextmanager
async def command_slot(identity: object) -> AsyncIterator[None]:
    loop_slots = _slots.setdefault(asyncio.get_running_loop(), {})
    semaphore = loop_slots.setdefault(identity, asyncio.Semaphore(CONFIG.max_concurrent_commands_per_host))
    async with semaphore:
        yield


async def read_bounded(reader: Any, limit: int) -> bytes:
    chunks = []
    size = 0
    while True:
        chunk = await reader.read(min(65536, limit + 1 - size))
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise ConnectionError(f"Command output exceeds {limit} bytes; partial output discarded")
        chunks.append(chunk)


async def collect_output(process: Any) -> tuple[bytes, bytes]:
    readers = [
        asyncio.create_task(read_bounded(process.stdout, CONFIG.max_command_output_bytes)),
        asyncio.create_task(read_bounded(process.stderr, CONFIG.max_command_stderr_bytes)),
    ]
    try:
        stdout, stderr = await asyncio.gather(*readers)
        return stdout, stderr
    finally:
        for reader in readers:
            reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)


async def run_bounded_remote(
    connection: asyncssh.SSHClientConnection,
    command: str,
    *,
    timeout: int,
    encoding: str | None = "utf-8",
    check: bool = False,
) -> asyncssh.SSHCompletedProcess:
    async def run() -> asyncssh.SSHCompletedProcess:
        async with command_slot(connection):
            process = await connection.create_process(command, encoding=None)
            try:
                process.stdin.write_eof()
                stdout, stderr = await collect_output(process)
                await process.wait_closed()
                code = process.exit_status if process.exit_status is not None else 255
                result = asyncssh.SSHCompletedProcess(
                    command=command,
                    exit_status=code,
                    stdout=stdout if encoding is None else stdout.decode(encoding, errors="replace"),
                    stderr=stderr if encoding is None else stderr.decode(encoding, errors="replace"),
                )
                if check and code:
                    raise ConnectionError(f"Command exited with status {code}")
                return result
            finally:
                # close 不等待远端配合；固定入口另有独立执行时限。
                process.close()

    try:
        return await asyncio.wait_for(run(), timeout)
    except TimeoutError:
        raise TimeoutError(f"Command timed out after {timeout}s") from None


async def run_bounded_local(command: list[str], timeout: int) -> tuple[int, bytes, bytes]:
    async def run() -> tuple[int, bytes, bytes]:
        async with command_slot("localhost"):
            process = await asyncio.create_subprocess_exec(
                *command,
                start_new_session=True,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await collect_output(process)
                await process.wait()
                return process.returncode if process.returncode is not None else 255, stdout, stderr
            finally:
                # 子进程可能继续持有管道，因此始终清理独立进程组。
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()

    return await asyncio.wait_for(run(), timeout)
