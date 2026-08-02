#!/usr/bin/env python3
"""在服务端本机通过管理 API 创建 RC 全协议验收策略。"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BASE_URL = "https://127.0.0.1:32100/api/v1"
PROVIDER_NAME = "vm-win-129"
ACCEPTANCE_PREFIX = "rc-acceptance-"


def load_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


class Api:
    def __init__(self, management_token: str, enrollment_token: str):
        self.management_token = management_token
        self.enrollment_token = enrollment_token
        self.context = ssl._create_unverified_context()

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        enrollment: bool = False,
    ):
        headers = {
            "Authorization": "Bearer "
            + (self.enrollment_token if enrollment else self.management_token)
        }
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BASE_URL + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                payload = response.read()
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"{method} {path} failed with HTTP {error.code}: {detail}"
            ) from error

    def get(self, path: str):
        return self.request("GET", path)

    def post(self, path: str, body: dict | None = None, *, enrollment: bool = False):
        return self.request("POST", path, body, enrollment=enrollment)

    def put(self, path: str, body: dict):
        return self.request("PUT", path, body)

    def delete(self, path: str):
        return self.request("DELETE", path)


def remove_previous_acceptance_policies(api: Api) -> None:
    # 一次性密钥和代理密码无法从列表接口恢复，重跑时仅删除验收前缀策略后重建。
    for endpoint in (
        "secret-tunnels",
        "socks5-proxies",
        "http-proxies",
    ):
        for item in api.get(f"/{endpoint}"):
            if str(item.get("name", "")).startswith(ACCEPTANCE_PREFIX):
                api.delete(f"/{endpoint}/{item['id']}")


def get_or_create(api: Api, endpoint: str, name: str, body: dict) -> dict:
    current = next(
        (item for item in api.get(f"/{endpoint}") if item.get("name") == name),
        None,
    )
    return current if current is not None else api.post(f"/{endpoint}", body)


def wait_for_online(api: Api, checks: list[tuple[str, str]], timeout_seconds: int = 120) -> None:
    deadline = time.monotonic() + timeout_seconds
    pending = set(checks)
    while pending and time.monotonic() < deadline:
        for endpoint, policy_id in list(pending):
            items = api.get(f"/{endpoint}")
            current = next((item for item in items if item.get("id") == policy_id), None)
            if current and current.get("online") is True:
                pending.remove((endpoint, policy_id))
            elif current and endpoint == "port-groups":
                if (
                    current.get("mapping_count", 0) > 0
                    and current.get("online_mappings") == current.get("mapping_count")
                ):
                    pending.remove((endpoint, policy_id))
        if pending:
            time.sleep(2)
    if pending:
        names = ", ".join(f"{endpoint}/{policy_id}" for endpoint, policy_id in pending)
        raise RuntimeError(f"acceptance policies did not become online: {names}")


def main() -> int:
    environment_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/linklake/server.env")
    output_directory = Path(sys.argv[2] if len(sys.argv) > 2 else "/root/linklake-acceptance")
    environment = load_environment(environment_path)
    api = Api(
        environment["LINKLAKE_MANAGEMENT_TOKEN"],
        environment["LINKLAKE_ENROLLMENT_TOKEN"],
    )
    clients = api.get("/clients")
    provider = next((client for client in clients if client.get("name") == PROVIDER_NAME), None)
    if provider is None:
        raise RuntimeError(f"provider client not found: {PROVIDER_NAME}")
    provider_id = provider["client_id"]

    remove_previous_acceptance_policies(api)
    visitor = api.post(
        "/clients/enroll",
        {"name": f"{ACCEPTANCE_PREFIX}shanghai-{int(time.time())}", "platform": "linux-amd64"},
        enrollment=True,
    )

    created: dict[str, dict] = {}
    created["tcp"] = get_or_create(
        api,
        "tcp-tunnels",
        f"{ACCEPTANCE_PREFIX}tcp",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}tcp",
            "public_port": 32012,
            "target_addr": "127.0.0.1:18081",
            "max_connections": 16,
            "bandwidth_limit_bps": None,
        },
    )
    created["udp"] = get_or_create(
        api,
        "udp-tunnels",
        f"{ACCEPTANCE_PREFIX}udp",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}udp",
            "public_port": 32013,
            "target_addr": "127.0.0.1:19091",
            "max_sessions": 64,
            "session_idle_timeout_seconds": 30,
            "bandwidth_limit_bps": None,
        },
    )
    created["tcp_group"] = get_or_create(
        api,
        "port-groups",
        f"{ACCEPTANCE_PREFIX}tcp-group",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}tcp-group",
            "protocol": "tcp",
            "public_ports": "32020-32022",
            "target_host": "127.0.0.1",
            "target_ports": "18081,18082,18443",
            "max_connections": 16,
            "max_sessions": None,
            "session_idle_timeout_seconds": None,
            "bandwidth_limit_bps": None,
        },
    )
    created["udp_group"] = get_or_create(
        api,
        "port-groups",
        f"{ACCEPTANCE_PREFIX}udp-group",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}udp-group",
            "protocol": "udp",
            "public_ports": "32020-32022",
            "target_host": "127.0.0.1",
            "target_ports": "19091-19093",
            "max_connections": None,
            "max_sessions": 64,
            "session_idle_timeout_seconds": 30,
            "bandwidth_limit_bps": None,
        },
    )
    created["http"] = get_or_create(
        api,
        "http-routes",
        f"{ACCEPTANCE_PREFIX}https",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}https",
            "hostname": "secure.link.odelake.com",
            "target_addr": "127.0.0.1:18082",
            "max_connections": 16,
        },
    )
    created["sni"] = get_or_create(
        api,
        "sni-routes",
        f"{ACCEPTANCE_PREFIX}sni",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}sni",
            "hostname": "sni.link.odelake.com",
            "target_addr": "127.0.0.1:18443",
            "max_connections": 16,
            "bandwidth_limit_bps": None,
        },
    )
    created["secret"] = api.post(
        "/secret-tunnels",
        {
            "provider_client_id": provider_id,
            "allowed_client_id": visitor["client_id"],
            "name": f"{ACCEPTANCE_PREFIX}secret",
            "target_addr": "127.0.0.1:18081",
            "max_connections": 8,
            "bandwidth_limit_bps": None,
        },
    )
    created["socks5"] = api.post(
        "/socks5-proxies",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}socks5",
            "public_port": 32030,
            "username": "lltest",
            "max_connections": 16,
            "bandwidth_limit_bps": None,
        },
    )
    created["http_proxy"] = api.post(
        "/http-proxies",
        {
            "client_id": provider_id,
            "name": f"{ACCEPTANCE_PREFIX}http-proxy",
            "public_port": 32031,
            "username": "llhttp",
            "max_connections": 16,
            "bandwidth_limit_bps": None,
        },
    )

    output_directory.mkdir(parents=True, exist_ok=True)
    secret_state = {
        "visitor": visitor,
        "secret_access_key": created["secret"]["access_key"],
        "socks5": {
            "username": created["socks5"]["username"],
            "password": created["socks5"]["password"],
            "public_port": created["socks5"]["public_port"],
        },
        "http_proxy": {
            "username": created["http_proxy"]["username"],
            "password": created["http_proxy"]["password"],
            "public_port": created["http_proxy"]["public_port"],
        },
    }
    secret_path = output_directory / "secrets.json"
    secret_path.write_text(json.dumps(secret_state, indent=2), encoding="utf-8")
    os.chmod(secret_path, 0o600)

    api.put(
        "/acme/config",
        {
            "enabled": True,
            "environment": "production",
            "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
            "contact_email": "lakerskz@outlook.com",
            "terms_accepted": True,
            "renew_before_days": 30,
        },
    )
    api.put(
        f"/http-routes/{created['http']['id']}/tls",
        {"mode": "acme", "redirect_http_to_https": False},
    )

    wait_for_online(
        api,
        [
            ("tcp-tunnels", created["tcp"]["id"]),
            ("udp-tunnels", created["udp"]["id"]),
            ("port-groups", created["tcp_group"]["id"]),
            ("port-groups", created["udp_group"]["id"]),
            ("http-routes", created["http"]["id"]),
            ("sni-routes", created["sni"]["id"]),
            ("secret-tunnels", created["secret"]["id"]),
            ("socks5-proxies", created["socks5"]["id"]),
            ("http-proxies", created["http_proxy"]["id"]),
        ],
    )

    summary = {
        "provider_client_id": provider_id,
        "visitor_client_id": visitor["client_id"],
        "policies": {name: value["id"] for name, value in created.items()},
        "secret_path": str(secret_path),
    }
    summary_path = output_directory / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    os.chmod(summary_path, 0o600)
    print(json.dumps({"status": "ready", "policy_count": len(created)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
