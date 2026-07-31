"""CentOS 6 iproute/net-tools parser tests."""

from linux_mcp_server.parsers import parse_ip_address
from linux_mcp_server.parsers import parse_netstat_connections
from linux_mcp_server.parsers import parse_netstat_listening


def test_parse_legacy_ip_address():
    output = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    inet 172.18.13.28/24 brd 172.18.13.255 scope global eth0
"""

    result = parse_ip_address(output)

    assert result["lo"].status == "UNKNOWN"
    assert result["eth0"].addresses == ["172.18.13.28/24"]


def test_parse_legacy_netstat_connections_and_listeners():
    output = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 100/sshd
tcp 0 0 172.18.13.28:22 172.18.13.1:50000 ESTABLISHED 101/sshd
udp 0 0 0.0.0.0:68 0.0.0.0:* 99/dhclient
"""

    connections = parse_netstat_connections(output)
    listeners = parse_netstat_listening(output)

    assert len(connections) == 3
    assert connections[1].state == "ESTABLISHED"
    assert {item.local_port for item in listeners} == {"22", "68"}
