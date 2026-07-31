#!/usr/bin/env python3
"""诊断公网 SOCKS5 UDP ASSOCIATE 返回的中继端点与数据报路径。"""

import importlib.util
import json
import socket
import struct
import sys
from pathlib import Path


acceptance_path = Path(sys.argv[1])
secrets_path = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("linklake_acceptance", acceptance_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
secrets = json.loads(secrets_path.read_text(encoding="utf-8-sig"))

control, relay = module.open_socks5(
    secrets["socks5"]["username"],
    secrets["socks5"]["password"],
    3,
    "0.0.0.0",
    0,
)
print(f"relay_address={relay[0]} relay_port={relay[1]}")
with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.settimeout(5)
    stream.bind(("0.0.0.0", 0))
    print(f"local_udp_port={stream.getsockname()[1]}")
    relay_host = module.SERVER_IP if relay[0] in ("0.0.0.0", "::") else relay[0]
    message = b"focused-socks5-udp"
    request = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton("127.0.0.1")
        + struct.pack("!H", 19091)
        + message
    )
    stream.sendto(request, (relay_host, relay[1]))
    print(f"sent_to={relay_host}:{relay[1]} bytes={len(request)}")
    try:
        response, source = stream.recvfrom(65535)
        print(f"received_from={source[0]}:{source[1]} bytes={len(response)}")
    except TimeoutError:
        print("receive_error=timeout")
