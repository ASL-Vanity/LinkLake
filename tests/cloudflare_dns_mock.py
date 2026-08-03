#!/usr/bin/env python3
"""LinkLake DNS-01 E2E 使用的本地 Cloudflare 与 DoH Mock。"""

from __future__ import annotations

import argparse
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def _cloudflare_envelope(
    result: Any = None,
    *,
    success: bool = True,
    code: int = 0,
    message: str = "",
) -> dict[str, Any]:
    errors = [] if success else [{"code": code, "message": message}]
    return {
        "success": success,
        "errors": errors,
        "messages": [],
        "result": result,
    }


def _normalize_dns_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


@dataclass(frozen=True)
class MockZone:
    id: str
    name: str


class MockCloudflareState:
    """保存 Mock 状态；所有可变访问均由同一把锁保护。"""

    def __init__(
        self,
        *,
        expected_token: str,
        zones: list[MockZone],
        challenge_management_url: str | None = None,
    ) -> None:
        self.expected_token = expected_token
        self.zones = {
            _normalize_dns_name(zone.name): MockZone(zone.id, _normalize_dns_name(zone.name))
            for zone in zones
        }
        self.challenge_management_url = (
            challenge_management_url.rstrip("/") if challenge_management_url else None
        )
        self.lock = threading.RLock()
        self.records: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.next_record_id = 1
        self.publish_mode = "correct"
        self.zone_error_count = 0
        self.create_error_count = 0
        self.delete_error_count = 0

    def is_authorized(self, authorization: str | None) -> bool:
        return bool(self.expected_token) and authorization == f"Bearer {self.expected_token}"

    def append_event(self, kind: str, **details: Any) -> None:
        with self.lock:
            self.events.append({"kind": kind, **details})

    def take_failure(self, kind: str) -> bool:
        attribute = f"{kind}_error_count"
        with self.lock:
            remaining = int(getattr(self, attribute))
            if remaining <= 0:
                return False
            setattr(self, attribute, remaining - 1)
            return True

    def configure(self, payload: dict[str, Any]) -> None:
        allowed_modes = {"correct", "wrong", "none"}
        with self.lock:
            if "publish_mode" in payload:
                mode = str(payload["publish_mode"])
                if mode not in allowed_modes:
                    raise ValueError(f"unsupported publish_mode: {mode}")
                self.publish_mode = mode
            for key in ("zone_error_count", "create_error_count", "delete_error_count"):
                if key in payload:
                    value = int(payload[key])
                    if value < 0:
                        raise ValueError(f"{key} must not be negative")
                    setattr(self, key, value)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "zones": [
                    {"id": zone.id, "name": zone.name}
                    for zone in sorted(self.zones.values(), key=lambda item: item.name)
                ],
                "records": list(self.records.values()),
                "events": list(self.events),
                "publish_mode": self.publish_mode,
                "failures": {
                    "zone": self.zone_error_count,
                    "create": self.create_error_count,
                    "delete": self.delete_error_count,
                },
            }

    def clear(self) -> None:
        with self.lock:
            names = {record["name"] for record in self.records.values()}
            self.records.clear()
            self.events.clear()
            self.next_record_id = 1
            self.publish_mode = "correct"
            self.zone_error_count = 0
            self.create_error_count = 0
            self.delete_error_count = 0
        for name in names:
            self._post_challenge_server("clear-txt", {"host": f"{name}."})

    def create_record(self, zone_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        record_type = str(payload.get("type", "")).upper()
        name = _normalize_dns_name(str(payload.get("name", "")))
        content = str(payload.get("content", ""))
        if record_type != "TXT" or not name or not content:
            raise ValueError("TXT name and content are required")
        with self.lock:
            record_id = f"record-{self.next_record_id}"
            self.next_record_id += 1
            record = {
                "id": record_id,
                "zone_id": zone_id,
                "type": "TXT",
                "name": name,
                "content": content,
                "ttl": int(payload.get("ttl", 1)),
                "proxied": False,
            }
            self.records[record_id] = record
            mode = self.publish_mode
            self.events.append(
                {
                    "kind": "txt_created",
                    "record_id": record_id,
                    "zone_id": zone_id,
                    "name": name,
                    "content": content,
                    "publish_mode": mode,
                }
            )
        if mode == "correct":
            self._post_challenge_server(
                "set-txt", {"host": f"{name}.", "value": content}
            )
        elif mode == "wrong":
            self._post_challenge_server(
                "set-txt", {"host": f"{name}.", "value": f"wrong-{content}"}
            )
        return record

    def delete_record(self, zone_id: str, record_id: str) -> dict[str, str] | None:
        with self.lock:
            record = self.records.get(record_id)
            if record is None or record["zone_id"] != zone_id:
                return None
            del self.records[record_id]
            self.events.append(
                {
                    "kind": "txt_deleted",
                    "record_id": record_id,
                    "zone_id": zone_id,
                    "name": record["name"],
                }
            )
        self._post_challenge_server("clear-txt", {"host": f"{record['name']}."})
        return {"id": record_id}

    def dns_answers(self, name: str) -> list[dict[str, Any]]:
        normalized = _normalize_dns_name(name)
        with self.lock:
            records = [
                record
                for record in self.records.values()
                if record["type"] == "TXT" and record["name"] == normalized
            ]
        return [
            {
                "name": f"{normalized}.",
                "type": 16,
                "TTL": record["ttl"],
                "data": json.dumps(record["content"]),
            }
            for record in records
        ]

    def _post_challenge_server(self, action: str, payload: dict[str, str]) -> None:
        if self.challenge_management_url is None:
            return
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.challenge_management_url}/{action}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                response.read()
        except (OSError, urllib.error.URLError) as error:
            raise RuntimeError(f"challenge server {action} failed: {error}") from error


class MockCloudflareHandler(BaseHTTPRequestHandler):
    server_version = "LinkLakeCloudflareMock/1.0"
    state: MockCloudflareState

    def log_message(self, format_string: str, *args: Any) -> None:
        # 避免把 Authorization 等请求细节写入测试日志。
        print(f"{self.address_string()} - {format_string % args}", flush=True)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/__test/health":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/__test/state":
            self._write_json(HTTPStatus.OK, self.state.snapshot())
            return
        if parsed.path == "/dns-query":
            self._handle_dns_query(parsed)
            return
        if not self._authorize_cloudflare_request():
            return
        if parsed.path == "/client/v4/zones":
            self._handle_zone_lookup(parsed)
            return
        if parsed.path.startswith("/client/v4/zones/") and parsed.path.endswith(
            "/dns_records"
        ):
            self._handle_record_lookup(parsed)
            return
        self._write_json(
            HTTPStatus.NOT_FOUND,
            _cloudflare_envelope(
                None, success=False, code=7003, message="Could not route to the requested resource"
            ),
        )

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/__test/config":
            try:
                payload = self._read_json()
                self.state.configure(payload)
            except (ValueError, json.JSONDecodeError) as error:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._write_json(HTTPStatus.OK, self.state.snapshot())
            return
        if parsed.path == "/__test/reset":
            self.state.clear()
            self._write_json(HTTPStatus.OK, self.state.snapshot())
            return
        if not self._authorize_cloudflare_request():
            return
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 5 and parts[:3] == ["client", "v4", "zones"] and parts[4] == "dns_records":
            self._handle_record_create(parts[3])
            return
        self._write_json(
            HTTPStatus.NOT_FOUND,
            _cloudflare_envelope(
                None, success=False, code=7003, message="Could not route to the requested resource"
            ),
        )

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if not self._authorize_cloudflare_request():
            return
        parts = [part for part in parsed.path.split("/") if part]
        if (
            len(parts) == 6
            and parts[:3] == ["client", "v4", "zones"]
            and parts[4] == "dns_records"
        ):
            self._handle_record_delete(parts[3], parts[5])
            return
        self._write_json(
            HTTPStatus.NOT_FOUND,
            _cloudflare_envelope(
                None, success=False, code=7003, message="Could not route to the requested resource"
            ),
        )

    def _authorize_cloudflare_request(self) -> bool:
        if self.state.is_authorized(self.headers.get("Authorization")):
            return True
        self.state.append_event("authentication_rejected")
        self._write_json(
            HTTPStatus.FORBIDDEN,
            _cloudflare_envelope(
                None, success=False, code=9109, message="Invalid access token"
            ),
        )
        return False

    def _handle_zone_lookup(self, parsed: urllib.parse.SplitResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        name = _normalize_dns_name(query.get("name", [""])[0])
        self.state.append_event("zone_lookup", name=name)
        if self.state.take_failure("zone"):
            self._write_json(
                HTTPStatus.OK,
                _cloudflare_envelope(
                    [], success=False, code=10000, message="mock zone lookup failure"
                ),
            )
            return
        zone = self.state.zones.get(name)
        result = [] if zone is None else [{"id": zone.id, "name": zone.name, "status": "active"}]
        envelope = _cloudflare_envelope(result)
        envelope["result_info"] = {
            "page": 1,
            "per_page": 50,
            "count": len(result),
            "total_count": len(result),
            "total_pages": 1,
        }
        self._write_json(HTTPStatus.OK, envelope)

    def _handle_record_lookup(self, parsed: urllib.parse.SplitResult) -> None:
        parts = [part for part in parsed.path.split("/") if part]
        zone_id = parts[3]
        query = urllib.parse.parse_qs(parsed.query)
        name = _normalize_dns_name(query.get("name", [""])[0])
        record_type = query.get("type", [""])[0].upper()
        with self.state.lock:
            records = [
                record
                for record in self.state.records.values()
                if record["zone_id"] == zone_id
                and (not name or record["name"] == name)
                and (not record_type or record["type"] == record_type)
            ]
        self.state.append_event("record_lookup", zone_id=zone_id, name=name, type=record_type)
        self._write_json(HTTPStatus.OK, _cloudflare_envelope(records))

    def _handle_record_create(self, zone_id: str) -> None:
        if self.state.take_failure("create"):
            self.state.append_event("txt_create_rejected", zone_id=zone_id)
            self._write_json(
                HTTPStatus.OK,
                _cloudflare_envelope(
                    None, success=False, code=1004, message="mock record creation failure"
                ),
            )
            return
        try:
            record = self.state.create_record(zone_id, self._read_json())
        except (ValueError, json.JSONDecodeError, RuntimeError) as error:
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                _cloudflare_envelope(None, success=False, code=1004, message=str(error)),
            )
            return
        self._write_json(HTTPStatus.OK, _cloudflare_envelope(record))

    def _handle_record_delete(self, zone_id: str, record_id: str) -> None:
        if self.state.take_failure("delete"):
            self.state.append_event(
                "txt_delete_rejected", zone_id=zone_id, record_id=record_id
            )
            self._write_json(
                HTTPStatus.OK,
                _cloudflare_envelope(
                    None, success=False, code=1004, message="mock record deletion failure"
                ),
            )
            return
        try:
            result = self.state.delete_record(zone_id, record_id)
        except RuntimeError as error:
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                _cloudflare_envelope(None, success=False, code=1004, message=str(error)),
            )
            return
        if result is None:
            self._write_json(
                HTTPStatus.NOT_FOUND,
                _cloudflare_envelope(
                    None, success=False, code=81044, message="Record does not exist"
                ),
            )
            return
        self._write_json(HTTPStatus.OK, _cloudflare_envelope(result))

    def _handle_dns_query(self, parsed: urllib.parse.SplitResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        name = query.get("name", [""])[0]
        query_type = query.get("type", ["TXT"])[0].upper()
        self.state.append_event("dns_lookup", name=_normalize_dns_name(name), type=query_type)
        answers = self.state.dns_answers(name) if query_type in {"TXT", "16"} else []
        self._write_json(
            HTTPStatus.OK,
            {
                "Status": 0,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": False,
                "CD": False,
                "Question": [
                    {"name": f"{_normalize_dns_name(name)}.", "type": 16}
                ],
                "Answer": answers,
            },
        )

    def _read_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("invalid Content-Length") from error
        raw = self.rfile.read(content_length)
        payload = json.loads(raw.decode("utf-8") if raw else "{}")
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _write_json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_server(
    bind_host: str,
    bind_port: int,
    state: MockCloudflareState,
) -> ThreadingHTTPServer:
    class BoundHandler(MockCloudflareHandler):
        pass

    BoundHandler.state = state
    return ThreadingHTTPServer((bind_host, bind_port), BoundHandler)


def _parse_zone(value: str) -> MockZone:
    name, separator, zone_id = value.partition(":")
    if not separator or not name.strip() or not zone_id.strip():
        raise argparse.ArgumentTypeError("zone must use NAME:ID")
    return MockZone(id=zone_id.strip(), name=name.strip())


def _parse_bind(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise argparse.ArgumentTypeError("bind must use HOST:PORT")
    return host, int(port)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1:0", type=_parse_bind)
    parser.add_argument("--zone", action="append", type=_parse_zone, default=[])
    parser.add_argument("--challenge-management-url")
    args = parser.parse_args()
    expected_token = os.environ.get("MOCK_CLOUDFLARE_API_TOKEN", "")
    if not expected_token:
        parser.error("MOCK_CLOUDFLARE_API_TOKEN must be set")
    zones = args.zone or [MockZone(id="zone-example", name="example.test")]
    state = MockCloudflareState(
        expected_token=expected_token,
        zones=zones,
        challenge_management_url=args.challenge_management_url,
    )
    server = create_server(args.bind[0], args.bind[1], state)
    print(f"mock cloudflare listening on {server.server_address[0]}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
