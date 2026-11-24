#!/usr/bin/env python3
"""Unit and integration tests for ops/status/status_server.py."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
import urllib.request

STATUS_DIR = Path(__file__).resolve().parent
if str(STATUS_DIR) not in sys.path:
    sys.path.insert(0, str(STATUS_DIR))

import status_server  # noqa: E402


class MockNodeState:
    def __init__(
        self,
        node: str,
        validator_id: str,
        height: int = 100,
        efficiency: float = 0.995,
        ready: bool = True,
        syncing: bool = False,
        mempool: int = 3,
        chain_id: str = "0x1e61",
        block_interval_count: int = 100,
        block_interval_sum: float = 150.0,
        validators_override: list[dict[str, str]] | None = None,
    ) -> None:
        self.lock = threading.Lock()
        self.node = node
        self.validator_id = validator_id
        self.height = height
        self.metrics_height: int | None = None  # defaults to self.height when None
        self.efficiency = efficiency
        self.ready = ready
        self.syncing = syncing
        self.mempool = mempool
        self.chain_id = chain_id
        self.block_interval_count = block_interval_count
        self.block_interval_sum = block_interval_sum
        self.validators_override = validators_override
        self.down = False
        self.drop_connection = False


class _MockNodeHandler(BaseHTTPRequestHandler):
    server: "_MockNodeHTTPServer"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802
        st = self.server.state
        with st.lock:
            if st.drop_connection:
                self.connection.close()
                return
            if st.down:
                self.send_response(503)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            req = json.loads(raw.decode("utf-8"))
            method = req.get("method")
            req_id = req.get("id", 1)

            if method in ("eth_blockNumber", "stell_blockNumber"):
                res: object = hex(st.height)
            elif method == "stell_syncing":
                res = st.syncing
            elif method == "stell_getStateRoot":
                res = "0x" + ("ab" * 32)
            elif method == "stell_getValidators":
                if st.validators_override is not None:
                    entries = st.validators_override
                else:
                    entries = [
                        {"validator": vid, "power": "1000"}
                        for vid in self.server.all_validator_ids
                    ]
                total_power = str(sum(int(e["power"]) for e in entries))
                quorum = str((int(total_power) * 2) // 3 + 1) if entries else "1"
                res = {
                    "validators": entries,
                    "total_power": total_power,
                    "quorum": quorum,
                    "fragile": len(entries) == 3,
                    "fragile_reason": "3-validator set requires 100%" if len(entries) == 3 else None,
                }
            elif method == "stell_mempoolSize":
                res = hex(st.mempool)
            elif method == "stell_chainId":
                res = st.chain_id
            elif method == "stell_nodeId":
                res = st.validator_id
            else:
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "not found"}}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        st = self.server.state
        with st.lock:
            if st.drop_connection:
                self.connection.close()
                return
            if st.down:
                self.send_response(503)
                self.end_headers()
                return

            path = self.path.split("?", 1)[0]
            if path == "/api/version":
                body = json.dumps(
                    {
                        "version": "0.1.0",
                        "git_hash": "deadbeef1234",
                        "dirty": False,
                        "height": st.height,
                        "node_id": st.validator_id,
                    }
                ).encode("utf-8")
                self._write(200, "application/json", body)
            elif path == "/readyz":
                body = json.dumps({"ready": st.ready, "height": st.height}).encode("utf-8")
                self._write(200 if st.ready else 503, "application/json", body)
            elif path == "/metrics":
                mh = st.metrics_height if st.metrics_height is not None else st.height
                n_total = st.block_interval_count
                # Put 95% under 1.0s, 99% under 2.0s, 1% between 2.0s and 5.0s
                b05 = int(n_total * 0.50)
                b10 = int(n_total * 0.95)
                b20 = int(n_total * 0.99)
                b50 = n_total
                metrics_txt = "\n".join(
                    [
                        f"stell_consensus_height {mh}",
                        f"stell_validator_efficiency_ratio {st.efficiency}",
                        f'stell_block_interval_seconds_bucket{{le="0.5"}} {b05}',
                        f'stell_block_interval_seconds_bucket{{le="1.0"}} {b10}',
                        f'stell_block_interval_seconds_bucket{{le="2.0"}} {b20}',
                        f'stell_block_interval_seconds_bucket{{le="5.0"}} {b50}',
                        f'stell_block_interval_seconds_bucket{{le="+Inf"}} {n_total}',
                        f"stell_block_interval_seconds_sum {st.block_interval_sum}",
                        f"stell_block_interval_seconds_count {n_total}",
                        f"stell_validator_set_size {len(self.server.all_validator_ids)}",
                        "stell_validator_set_fragile 0",
                        f"stell_ready {1 if st.ready else 0}",
                        "",
                    ]
                ).encode("utf-8")
                self._write(200, "text/plain; version=0.0.4", metrics_txt)
            else:
                self._write(404, "application/json", b'{"error":"not found"}')

    def _write(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _MockNodeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: MockNodeState, all_validator_ids: list[str]) -> None:
        self.state = state
        self.all_validator_ids = all_validator_ids
        super().__init__(("127.0.0.1", 0), _MockNodeHandler)


def _http_get(url: str, method: str = "GET") -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return int(resp.status), dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8") if exc.fp else ""
            return int(exc.code), dict(exc.headers), body
        finally:
            exc.close()


class StatusServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator_ids = [
            "aa" * 32,
            "bb" * 32,
            "cc" * 32,
            "dd" * 32,
        ]
        self.states: list[MockNodeState] = []
        self.servers: list[_MockNodeHTTPServer] = []
        self.targets: list[dict[str, object]] = []

        for idx, (label, vid) in enumerate(zip(["A", "B", "C", "D"], self.validator_ids)):
            st = MockNodeState(node=label, validator_id=vid, height=1000)
            srv = _MockNodeHTTPServer(st, self.validator_ids)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            port = srv.server_port
            base = f"http://127.0.0.1:{port}"
            self.states.append(st)
            self.servers.append(srv)
            self.targets.append(
                {
                    "node": label,
                    "name": f"Validator {label}",
                    "role": "validator",
                    "rpc_url": base,
                    "explorer_url": base,
                    "validator_id": vid,
                }
            )

    def tearDown(self) -> None:
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def test_healthy_4_of_4_and_finals_rate_10m(self) -> None:
        monitor = status_server.StatusMonitor(
            targets=self.targets,
            interval_secs=15.0,
            timeout_secs=2.0,
            history_len=40,
            expected_validators=4,
        )

        snap1 = monitor.poll_once(now_ts=1_700_000_000)
        self.assertEqual(snap1["verdict"], "HEALTHY")
        self.assertEqual(snap1["cluster"]["active_validators"], 4)
        self.assertEqual(snap1["cluster"]["reachable_validators"], 4)
        self.assertEqual(snap1["cluster"]["height"], 1000)
        self.assertIsNone(snap1["cluster"]["finals_rate_10m"])

        # Advance 10 minutes (600s) and 300 blocks -> 30.0 blocks/min
        for st in self.states:
            with st.lock:
                st.height = 1300
                st.block_interval_count = 400
                st.block_interval_sum = 600.0

        snap2 = monitor.poll_once(now_ts=1_700_000_600)
        self.assertEqual(snap2["verdict"], "HEALTHY")
        self.assertEqual(snap2["reasons"], ["all_checks_passing"])
        self.assertEqual(snap2["cluster"]["height"], 1300)
        self.assertEqual(snap2["cluster"]["height_lag"], 0)
        self.assertAlmostEqual(snap2["cluster"]["finals_rate_10m"], 30.0, places=2)
        self.assertEqual(snap2["cluster"]["active_validators"], 4)
        self.assertIsNotNone(snap2["cluster"]["block_interval_p99_ms"])
        self.assertIsNotNone(snap2["cluster"]["block_interval_avg_ms"])
        self.assertAlmostEqual(snap2["cluster"]["efficiency_avg"], 0.995, places=4)

        for node in snap2["nodes"]:
            self.assertTrue(node["ok"])
            self.assertEqual(node["status"], "up")
            self.assertEqual(node["height"], 1300)
            self.assertTrue(node["heights_agree"])
            self.assertTrue(node["in_set"])
            self.assertFalse(node["jailed"])
            self.assertAlmostEqual(node["finals_rate_10m"], 30.0, places=2)

    def test_partial_1_of_4_outage_degraded_and_no_fabricated_height(self) -> None:
        monitor = status_server.StatusMonitor(
            targets=self.targets,
            interval_secs=15.0,
            timeout_secs=2.0,
            history_len=40,
            expected_validators=4,
        )
        monitor.poll_once(now_ts=1_700_000_000)

        # Take node C completely offline (closed port) and verify honest reporting
        self.servers[2].shutdown()
        self.servers[2].server_close()

        for idx in (0, 1, 3):
            with self.states[idx].lock:
                self.states[idx].height = 1060

        snap = monitor.poll_once(now_ts=1_700_000_120)
        self.assertEqual(snap["verdict"], "DEGRADED")
        self.assertEqual(snap["cluster"]["reachable_validators"], 3)
        self.assertEqual(snap["cluster"]["active_validators"], 3)
        self.assertEqual(snap["cluster"]["height"], 1060)
        self.assertTrue(any("validators_unreachable" in r for r in snap["reasons"]))

        node_c = next(n for n in snap["nodes"] if n["node"] == "C")
        self.assertFalse(node_c["ok"])
        self.assertEqual(node_c["status"], "unknown")
        self.assertIsNone(node_c["height"])
        self.assertIsNotNone(node_c["error"])

    def test_quorum_loss_and_abrupt_disconnect_returns_down(self) -> None:
        monitor = status_server.StatusMonitor(
            targets=self.targets,
            interval_secs=15.0,
            timeout_secs=1.5,
            history_len=40,
            expected_validators=4,
        )
        # Drop connections abruptly on 2 of 4 validators -> quorum lost (2/4 < 3)
        with self.states[2].lock:
            self.states[2].drop_connection = True
        with self.states[3].lock:
            self.states[3].down = True

        snap = monitor.poll_once(now_ts=1_700_000_000)
        self.assertEqual(snap["verdict"], "DOWN")
        self.assertEqual(snap["cluster"]["active_validators"], 2)
        self.assertTrue(any("quorum_lost" in r for r in snap["reasons"]))
        for node_name in ("C", "D"):
            nd = next(n for n in snap["nodes"] if n["node"] == node_name)
            self.assertFalse(nd["ok"])
            self.assertIsNone(nd["height"])
            self.assertIsNotNone(nd["error"])

    def test_jailed_validator_detected_via_validator_set(self) -> None:
        # Remove validator D from active set returned by nodes
        subset = [
            {"validator": vid, "power": "1000"}
            for vid in self.validator_ids[:3]
        ]
        for st in self.states:
            with st.lock:
                st.validators_override = subset

        monitor = status_server.StatusMonitor(
            targets=self.targets,
            interval_secs=15.0,
            timeout_secs=2.0,
            expected_validators=4,
        )
        snap = monitor.poll_once(now_ts=1_700_000_000)
        self.assertEqual(snap["verdict"], "DEGRADED")
        node_d = next(n for n in snap["nodes"] if n["node"] == "D")
        self.assertTrue(node_d["ok"])
        self.assertFalse(node_d["in_set"])
        self.assertTrue(node_d["jailed"])
        self.assertTrue(any("validator_jailed (D)" in r for r in snap["reasons"]))

    def test_http_endpoints_html_json_health_readyz_metrics(self) -> None:
        monitor = status_server.StatusMonitor(
            targets=self.targets,
            interval_secs=15.0,
            timeout_secs=2.0,
            history_len=40,
            expected_validators=4,
        )
        http_srv = status_server.StatusHTTPServer(("127.0.0.1", 0), monitor)
        srv_thread = threading.Thread(target=http_srv.serve_forever, daemon=True)
        srv_thread.start()
        base_url = f"http://127.0.0.1:{http_srv.server_port}"

        try:
            # Before first poll completes: /readyz -> 503, /api/status.json -> 503, / -> 200 initializing
            code, _, body = _http_get(f"{base_url}/readyz")
            self.assertEqual(code, 503)
            self.assertFalse(json.loads(body)["ready"])

            code, _, body = _http_get(f"{base_url}/api/status.json")
            self.assertEqual(code, 503)
            self.assertEqual(json.loads(body)["verdict"], "DOWN")

            code, _, html_init = _http_get(f"{base_url}/")
            self.assertEqual(code, 200)
            self.assertIn("Collecting initial cluster snapshot", html_init)

            # Run two polls to populate finals_rate_10m
            monitor.poll_once(now_ts=1_700_000_000)
            for st in self.states:
                with st.lock:
                    st.height = 1120
                    st.block_interval_count = 220
                    st.block_interval_sum = 330.0
            monitor.poll_once(now_ts=1_700_000_240)

            code, headers, html_body = _http_get(f"{base_url}/")
            self.assertEqual(code, 200)
            self.assertIn("text/html", headers["Content-Type"])
            self.assertIn("HEALTHY", html_body)
            self.assertIn("Validator A", html_body)
            self.assertIn("30.00 / min", html_body)

            for json_path in ("/api/status.json", "/status.json"):
                code, headers, raw_json = _http_get(f"{base_url}{json_path}")
                self.assertEqual(code, 200)
                self.assertIn("application/json", headers["Content-Type"])
                data = json.loads(raw_json)
                self.assertEqual(data["verdict"], "HEALTHY")
                self.assertEqual(data["cluster"]["active_validators"], 4)
                self.assertAlmostEqual(data["cluster"]["finals_rate_10m"], 30.0, places=2)
                self.assertEqual(len(data["nodes"]), 4)

            for health_path in ("/health", "/healthz"):
                code, _, raw_health = _http_get(f"{base_url}{health_path}")
                self.assertEqual(code, 200)
                self.assertEqual(json.loads(raw_health)["status"], "ok")

            code, _, raw_ready = _http_get(f"{base_url}/readyz")
            self.assertEqual(code, 200)
            ready_obj = json.loads(raw_ready)
            self.assertTrue(ready_obj["ready"])
            self.assertEqual(ready_obj["verdict"], "HEALTHY")

            code, headers, metrics_body = _http_get(f"{base_url}/metrics")
            self.assertEqual(code, 200)
            self.assertIn("text/plain", headers["Content-Type"])
            self.assertIn("stell_status_up 1", metrics_body)
            self.assertIn("stell_status_cluster_healthy 1", metrics_body)
            self.assertIn("stell_status_active_validators 4", metrics_body)
            self.assertIn("stell_status_finals_rate_per_min 30.0", metrics_body)
            self.assertIn('stell_status_target_up{node="A",role="validator"} 1', metrics_body)

            code, _, _ = _http_get(f"{base_url}/health", method="HEAD")
            self.assertEqual(code, 200)

            code, _, _ = _http_get(f"{base_url}/does-not-exist")
            self.assertEqual(code, 404)
        finally:
            http_srv.shutdown()
            http_srv.server_close()

    def test_load_targets_variants(self) -> None:
        compact = status_server.load_targets(
            "A=http://127.0.0.1:8545,RPC-LB=https://rpc.stellereum.org"
        )
        self.assertEqual(len(compact), 2)
        self.assertEqual(compact[0]["role"], "validator")
        self.assertEqual(compact[1]["role"], "rpc")

        json_spec = json.dumps(
            [{"node": "X", "rpc_url": "http://127.0.0.1:8545/", "explorer_url": "http://127.0.0.1:9080/"}]
        )
        parsed = status_server.load_targets(json_spec)
        self.assertEqual(parsed[0]["rpc_url"], "http://127.0.0.1:8545")
        self.assertEqual(parsed[0]["explorer_url"], "http://127.0.0.1:9080")


if __name__ == "__main__":
    unittest.main(verbosity=2)
