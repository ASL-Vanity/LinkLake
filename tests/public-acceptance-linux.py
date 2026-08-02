#!/usr/bin/env python3
"""从独立公网主机验证 LinkLake RC 的全部核心数据通道。"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import struct
import sys
import time
from pathlib import Path


SERVER_IP = "43.160.209.67"
HTTPS_HOSTNAME = "secure.link.odelake.com"
SNI_HOSTNAME = "sni.link.odelake.com"
TIMEOUT = 20


def receive_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("connection closed before the expected payload arrived")
        data.extend(chunk)
    return bytes(data)


def tcp_echo(host: str, port: int, message: bytes) -> None:
    with socket.create_connection((host, port), timeout=TIMEOUT) as stream:
        stream.settimeout(TIMEOUT)
        stream.sendall(message)
        if receive_exact(stream, len(message)) != message:
            raise RuntimeError(f"TCP echo mismatch on {host}:{port}")


def udp_echo(host: str, port: int, message: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(TIMEOUT / 3)
        last_error: Exception | None = None
        for _ in range(3):
            stream.sendto(message, (host, port))
            try:
                payload, _ = stream.recvfrom(65535)
            except TimeoutError as error:
                last_error = error
                continue
            if payload == message:
                return
            last_error = RuntimeError(f"UDP echo mismatch on {host}:{port}")
        raise RuntimeError(f"UDP echo failed after 3 attempts on {host}:{port}") from last_error


def read_http_response(stream: socket.socket) -> tuple[int, bytes, bytes]:
    payload = bytearray()
    while True:
        chunk = stream.recv(65536)
        if not chunk:
            break
        payload.extend(chunk)
    head, separator, body = bytes(payload).partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("HTTP response did not contain a header terminator")
    status_line = head.split(b"\r\n", 1)[0]
    status = int(status_line.split()[1])
    return status, head, body


def http_get(host: str, port: int, hostname: str, *, tls: bool, verify: bool) -> bytes:
    raw = socket.create_connection((host, port), timeout=TIMEOUT)
    raw.settimeout(TIMEOUT)
    stream: socket.socket = raw
    try:
        if tls:
            context = ssl.create_default_context() if verify else ssl._create_unverified_context()
            stream = context.wrap_socket(raw, server_hostname=hostname)
        stream.sendall(
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
        )
        status, _, body = read_http_response(stream)
        if status != 200:
            raise RuntimeError(f"HTTP GET {hostname} returned {status}")
        return body
    finally:
        stream.close()


def tls_echo(host: str, port: int, hostname: str, message: bytes) -> None:
    raw = socket.create_connection((host, port), timeout=TIMEOUT)
    raw.settimeout(TIMEOUT)
    context = ssl._create_unverified_context()
    with context.wrap_socket(raw, server_hostname=hostname) as stream:
        stream.settimeout(TIMEOUT)
        stream.sendall(message)
        if receive_exact(stream, len(message)) != message:
            raise RuntimeError(f"TLS echo mismatch on {host}:{port}")


def socks5_address(stream: socket.socket) -> tuple[str, int]:
    atyp = receive_exact(stream, 1)[0]
    if atyp == 1:
        address = socket.inet_ntoa(receive_exact(stream, 4))
    elif atyp == 3:
        address = receive_exact(stream, receive_exact(stream, 1)[0]).decode()
    elif atyp == 4:
        address = socket.inet_ntop(socket.AF_INET6, receive_exact(stream, 16))
    else:
        raise RuntimeError(f"unsupported SOCKS5 address type: {atyp}")
    port = struct.unpack("!H", receive_exact(stream, 2))[0]
    return address, port


def open_socks5(
    username: str, password: str, command: int, target_host: str, target_port: int
) -> tuple[socket.socket, tuple[str, int]]:
    stream = socket.create_connection((SERVER_IP, 32030), timeout=TIMEOUT)
    stream.settimeout(TIMEOUT)
    try:
        stream.sendall(b"\x05\x01\x02")
        if receive_exact(stream, 2) != b"\x05\x02":
            raise RuntimeError("SOCKS5 username/password authentication was not selected")
        user = username.encode()
        secret = password.encode()
        stream.sendall(bytes((1, len(user))) + user + bytes((len(secret),)) + secret)
        if receive_exact(stream, 2) != b"\x01\x00":
            raise RuntimeError("SOCKS5 authentication failed")
        address = socket.inet_aton(target_host)
        stream.sendall(b"\x05" + bytes((command,)) + b"\x00\x01" + address + struct.pack("!H", target_port))
        version, reply, reserved = receive_exact(stream, 3)
        if version != 5 or reserved != 0 or reply != 0:
            raise RuntimeError(f"SOCKS5 command {command} failed with reply {reply}")
        return stream, socks5_address(stream)
    except Exception:
        stream.close()
        raise


def socks5_tcp(username: str, password: str) -> None:
    stream, _ = open_socks5(username, password, 1, "127.0.0.1", 18081)
    with stream:
        message = b"linklake-socks5-tcp"
        stream.sendall(message)
        if receive_exact(stream, len(message)) != message:
            raise RuntimeError("SOCKS5 TCP echo mismatch")


def socks5_udp(username: str, password: str) -> None:
    control, relay = open_socks5(username, password, 3, "0.0.0.0", 0)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(TIMEOUT)
        relay_host = SERVER_IP if relay[0] in ("0.0.0.0", "::") else relay[0]
        message = b"linklake-socks5-udp"
        request = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 19091) + message
        stream.sendto(request, (relay_host, relay[1]))
        response, _ = stream.recvfrom(65535)
        if len(response) < 10 or response[:4] != b"\x00\x00\x00\x01" or response[10:] != message:
            raise RuntimeError("SOCKS5 UDP echo mismatch")


def http_proxy_get(username: str, password: str) -> None:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    with socket.create_connection((SERVER_IP, 32031), timeout=TIMEOUT) as stream:
        stream.settimeout(TIMEOUT)
        stream.sendall(
            (
                "GET http://127.0.0.1:18082/ HTTP/1.1\r\n"
                "Host: 127.0.0.1:18082\r\n"
                f"Proxy-Authorization: Basic {token}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
        )
        status, _, body = read_http_response(stream)
        if status != 200 or body != b"linklake-http-acceptance":
            raise RuntimeError("HTTP forward proxy GET failed")


def http_proxy_connect(username: str, password: str) -> None:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    with socket.create_connection((SERVER_IP, 32031), timeout=TIMEOUT) as stream:
        stream.settimeout(TIMEOUT)
        stream.sendall(
            (
                "CONNECT 127.0.0.1:18081 HTTP/1.1\r\n"
                "Host: 127.0.0.1:18081\r\n"
                f"Proxy-Authorization: Basic {token}\r\n\r\n"
            ).encode()
        )
        header = bytearray()
        while b"\r\n\r\n" not in header:
            header.extend(stream.recv(4096))
        if not bytes(header).startswith(b"HTTP/1.1 200"):
            raise RuntimeError("HTTP proxy CONNECT was rejected")
        message = b"linklake-http-connect"
        stream.sendall(message)
        if receive_exact(stream, len(message)) != message:
            raise RuntimeError("HTTP proxy CONNECT echo mismatch")


def run(name: str, operation, results: dict[str, dict]) -> None:
    started = time.monotonic()
    try:
        operation()
    except Exception as error:  # noqa: BLE001 - 验收需要继续执行并保存全部失败项
        results[name] = {
            "status": "failed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(error).__name__}: {error}",
        }
    else:
        results[name] = {
            "status": "passed",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }


def main() -> int:
    secrets_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/root/linklake-acceptance/secrets.json")
    output_path = Path(sys.argv[2] if len(sys.argv) > 2 else "/root/linklake-acceptance/results.json")
    secrets = json.loads(secrets_path.read_text(encoding="utf-8-sig"))
    results: dict[str, dict] = {}

    def check(name: str, operation) -> None:
        run(name, operation, results)
        temporary = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary.write_text(json.dumps(results, indent=2), encoding="utf-8")
        temporary.replace(output_path)

    check("tcp", lambda: tcp_echo(SERVER_IP, 32012, b"linklake-tcp"))
    check("udp", lambda: udp_echo(SERVER_IP, 32013, b"linklake-udp"))
    check("tcp_group_echo", lambda: tcp_echo(SERVER_IP, 32020, b"linklake-tcp-group"))
    check(
        "tcp_group_http",
        lambda: (
            http_get(SERVER_IP, 32021, "127.0.0.1", tls=False, verify=False)
            == b"linklake-http-acceptance"
            or (_ for _ in ()).throw(RuntimeError("TCP group HTTP body mismatch"))
        ),
    )
    check(
        "tcp_group_tls",
        lambda: tls_echo(SERVER_IP, 32022, SNI_HOSTNAME, b"linklake-tcp-group-tls"),
    )
    for index, port in enumerate((32020, 32021, 32022), start=1):
        check(
            f"udp_group_{index}",
            lambda port=port: udp_echo(
                SERVER_IP, port, f"linklake-udp-group-{port}".encode()
            ),
        )
    check(
        "http_route",
        lambda: (
            http_get(SERVER_IP, 80, HTTPS_HOSTNAME, tls=False, verify=False)
            == b"linklake-http-acceptance"
            or (_ for _ in ()).throw(RuntimeError("HTTP route body mismatch"))
        ),
    )
    check(
        "native_https_acme",
        lambda: (
            http_get(SERVER_IP, 443, HTTPS_HOSTNAME, tls=True, verify=True)
            == b"linklake-http-acceptance"
            or (_ for _ in ()).throw(RuntimeError("HTTPS route body mismatch"))
        ),
    )
    check(
        "tls_sni_passthrough",
        lambda: tls_echo(SERVER_IP, 32105, SNI_HOSTNAME, b"linklake-sni"),
    )
    check("secret_tunnel", lambda: tcp_echo("127.0.0.1", 32150, b"linklake-secret"))
    check(
        "socks5_tcp",
        lambda: socks5_tcp(
            secrets["socks5"]["username"], secrets["socks5"]["password"]
        ),
    )
    check(
        "socks5_udp",
        lambda: socks5_udp(
            secrets["socks5"]["username"], secrets["socks5"]["password"]
        ),
    )
    check(
        "http_proxy_get",
        lambda: http_proxy_get(secrets["http_proxy"]["username"], secrets["http_proxy"]["password"]),
    )
    check(
        "http_proxy_connect",
        lambda: http_proxy_connect(secrets["http_proxy"]["username"], secrets["http_proxy"]["password"]),
    )

    failed = [name for name, result in results.items() if result["status"] != "passed"]
    status = "passed" if not failed else "failed"
    print(json.dumps({"status": status, "checks": len(results), "failed": failed}))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
