import pytest

from fastmcp.exceptions import ToolError

from linux_mcp_server.tools import storage


@pytest.mark.parametrize(
    ("path", "expected_error"),
    [
        pytest.param("/path/with\nnewline", "invalid characters", id="newline_injection"),
        pytest.param("/path/with\x00null", "invalid characters", id="null_byte_injection"),
    ],
)
async def test_path_validation_rejects_injection_characters(path, expected_error, mcp_client):
    with pytest.raises(ToolError, match=expected_error):
        await mcp_client.call_tool("read_file", arguments={"path": path})


def test_managed_path_accepts_each_profile_root_and_rejects_environment_expansion(mocker):
    mocker.patch.object(
        storage,
        "get_host_allowed_roots",
        autospec=True,
        return_value=(storage.Path("/data"), storage.Path("/usr")),
    )

    storage._require_managed_path(storage.Path("/data/app/config.yml"), "server-1")
    storage._require_managed_path(storage.Path("/usr/share/doc.txt"), "server-1")
    with pytest.raises(ToolError, match="outside the managed allowed_roots"):
        storage._require_managed_path(storage.Path("/etc/passwd"), "server-1")
