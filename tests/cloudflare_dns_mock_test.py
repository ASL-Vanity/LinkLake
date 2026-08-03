#!/usr/bin/env python3
"""本地 Cloudflare Mock 固件自测。"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cloudflare_dns_mock import MockCloudflareState, MockZone, create_server  # noqa: E402


class ChallengeHandler(BaseHTTPRequestHandler):
    events: list[dict[str, Any]] = []
    lock = threading.Lock()

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        with self.lock:
            self.events.append({"path": self.path, "payload": payload})
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class MockCloudflareFixtureTests(unittest.TestCase):
    token = "fixture-token-that-must-not-be-returned"

    def setUp(self) -> None:
        ChallengeHandler.events = []
        self.challenge_server = ThreadingHTTPServer(("127.0.0.1", 0), ChallengeHandler)
        self.challenge_thread = threading.Thread(
            target=self.challenge_server.serve_forever, daemon=True
        )
        self.challenge_thread.start()
        challenge_url = f"http://127.0.0.1:{self.challenge_server.server_port}"
        self.state = MockCloudflareState(
            expected_token=self.token,
            zones=[
                MockZone("zone-example", "example.test"),
                MockZone("zone-sub", "sub.example.test"),
            ],
            challenge_management_url=challenge_url,
        )
        self.server = create_server("127.0.0.1", 0, self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.challenge_server.shutdown()
        self.challenge_server.server_close()
        self.challenge_thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        authorized: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def test_zone_lookup_uses_cloudflare_envelope_and_authentication(self) -> None:
        status, rejected = self.request(
            "GET", "/client/v4/zones?name=sub.example.test", authorized=False
        )
        self.assertEqual(status, 403)
        self.assertFalse(rejected["success"])
        self.assertEqual(rejected["errors"][0]["code"], 9109)

        status, found = self.request("GET", "/client/v4/zones?name=sub.example.test")
        self.assertEqual(status, 200)
        self.assertTrue(found["success"])
        self.assertEqual(found["result"], [{"id": "zone-sub", "name": "sub.example.test", "status": "active"}])

        _, missing = self.request("GET", "/client/v4/zones?name=deep.sub.example.test")
        self.assertTrue(missing["success"])
        self.assertEqual(missing["result"], [])

    def test_txt_create_lookup_delete_and_challenge_sync(self) -> None:
        record_payload = {
            "type": "TXT",
            "name": "_acme-challenge.sub.example.test",
            "content": "dns-authorization-value",
            "ttl": 60,
        }
        status, created = self.request(
            "POST", "/client/v4/zones/zone-sub/dns_records", record_payload
        )
        self.assertEqual(status, 200)
        self.assertTrue(created["success"])
        record_id = created["result"]["id"]

        _, lookup = self.request(
            "GET",
            "/client/v4/zones/zone-sub/dns_records?type=TXT&name=_acme-challenge.sub.example.test",
        )
        self.assertEqual([item["id"] for item in lookup["result"]], [record_id])

        _, dns = self.request(
            "GET",
            "/dns-query?name=_acme-challenge.sub.example.test&type=TXT",
            authorized=False,
        )
        self.assertEqual(dns["Status"], 0)
        self.assertEqual(dns["Answer"][0]["data"], '"dns-authorization-value"')

        status, deleted = self.request(
            "DELETE", f"/client/v4/zones/zone-sub/dns_records/{record_id}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(deleted["result"], {"id": record_id})
        self.assertEqual(self.state.snapshot()["records"], [])
        self.assertEqual(
            [event["path"] for event in ChallengeHandler.events],
            ["/set-txt", "/clear-txt"],
        )

    def test_wrong_authoritative_value_keeps_doh_value_correct_for_failure_cleanup(self) -> None:
        self.request("POST", "/__test/config", {"publish_mode": "wrong"}, authorized=False)
        _, created = self.request(
            "POST",
            "/client/v4/zones/zone-example/dns_records",
            {
                "type": "TXT",
                "name": "_acme-challenge.failure.example.test",
                "content": "expected-value",
            },
        )
        _, dns = self.request(
            "GET",
            "/dns-query?name=_acme-challenge.failure.example.test&type=TXT",
            authorized=False,
        )
        self.assertEqual(dns["Answer"][0]["data"], '"expected-value"')
        self.assertEqual(
            ChallengeHandler.events[0],
            {
                "path": "/set-txt",
                "payload": {
                    "host": "_acme-challenge.failure.example.test.",
                    "value": "wrong-expected-value",
                },
            },
        )
        record_id = created["result"]["id"]
        self.request("DELETE", f"/client/v4/zones/zone-example/dns_records/{record_id}")
        self.assertEqual(ChallengeHandler.events[-1]["path"], "/clear-txt")

    def test_injected_envelope_failures_do_not_mutate_records(self) -> None:
        self.request(
            "POST",
            "/__test/config",
            {"zone_error_count": 1, "create_error_count": 1},
            authorized=False,
        )
        _, zone = self.request("GET", "/client/v4/zones?name=example.test")
        self.assertFalse(zone["success"])
        self.assertEqual(zone["errors"][0]["code"], 10000)
        _, create = self.request(
            "POST",
            "/client/v4/zones/zone-example/dns_records",
            {"type": "TXT", "name": "_acme-challenge.example.test", "content": "x"},
        )
        self.assertFalse(create["success"])
        self.assertEqual(self.state.snapshot()["records"], [])

    def test_control_state_never_exposes_expected_bearer_token(self) -> None:
        _, state = self.request("GET", "/__test/state", authorized=False)
        self.assertNotIn(self.token, json.dumps(state))


if __name__ == "__main__":
    unittest.main()
