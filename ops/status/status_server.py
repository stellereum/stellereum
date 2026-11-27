#!/usr/bin/env python3
"""
Standalone, zero-dependency public status service for Stellereum.

Polls a configurable list of validator RPC/explorer targets plus the public RPC
load balancer on a background interval, keeps a rolling ring buffer of snapshots
to compute 10-minute finalization rate and block-interval p99/avg, and serves:

  GET /                 Responsive self-contained HTML status page
  GET /api/status.json  Machine-readable cluster + per-node JSON snapshot
  GET /api/status       Alias for /api/status.json
  GET /status.json      Alias for /api/status.json
  GET /status           Alias for /api/status.json
  GET /health           Liveness check (200 OK while HTTP server is up)
  GET /healthz          Alias for /health
  GET /readyz           Readiness check (200 after initial poll completes)
  GET /metrics          Prometheus exposition metrics

Honest reporting contract (matches ops/status_page.md & scripts/status_snapshot.sh):
  Unreachable or invalid nodes report ok=false, status="unknown", height=null,
  and an explicit error message. Heights and metrics are never fabricated.
"""

from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait
import html
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
import os
import re
import signal
import ssl
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.request

LOG = logging.getLogger("stell-status")

DEFAULT_LISTEN = "127.0.0.1:8095"
DEFAULT_INTERVAL_SECS = 15.0
DEFAULT_TIMEOUT_SECS = 3.0
DEFAULT_HISTORY_LEN = 40  # 40 * 15s = 10 minutes
DEFAULT_EXPECTED_VALIDATORS = 4
DEFAULT_STALL_WINDOW_SECS = 120.0
DEFAULT_HEIGHT_LAG_WARN = 5
MAX_HTTP_BYTES = 8 * 1024 * 1024

DEFAULT_TARGETS: list[dict[str, Any]] = [
    {
        "node": "A",
        "name": "Validator A",
        "role": "validator",
        "rpc_url": "http://127.0.0.1:9080/rpc",
        "explorer_url": "http://127.0.0.1:9080",
        "validator_id": "48fd69d17c36d5391b7786f8091bce75e55f5b013344b60874090d53e8e8cdf7",
    },
    {
        "node": "B",
        "name": "Validator B",
        "role": "validator",
        "rpc_url": "http://127.0.0.1:8546",
        "explorer_url": "http://127.0.0.1:18081",
        "validator_id": "5762c3311356235a098ed7bc49026cf8f91ba9376f099ef2c7deabeadea88c5a",
    },
    {
        "node": "C",
        "name": "Validator C",
        "role": "validator",
        "rpc_url": "http://127.0.0.1:9081/rpc",
        "explorer_url": "http://127.0.0.1:9081",
        "validator_id": "9865d36eb93458ad7739e4de969e8c62b88e662b86f8ec38bd6ff3f83008162f",
    },
    {
        "node": "D",
        "name": "Validator D",
        "role": "validator",
        "rpc_url": "http://127.0.0.1:18552",
        "explorer_url": "http://127.0.0.1:9082",
        "validator_id": "df3d10f3549f492fa829553f9f0a1fe4e6daaf7a74aa532b5411db6eca6d2ba4",
    },
    {
        "node": "RPC-LB",
        "name": "Public RPC (rpc.stellereum.org)",
        "role": "rpc",
        "rpc_url": "https://rpc.stellereum.org",
        "explorer_url": None,
    },
]

_PROM_LINE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)(?:\s+[^\s]+)?$"
)
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"')


def parse_listen(listen: str) -> tuple[str, int]:
    listen = listen.strip()
    if listen.startswith("["):
        host_part, _, port_part = listen[1:].partition("]:")
        return host_part, int(port_part)
    if ":" in listen:
        host, _, port_str = listen.rpartition(":")
        return (host or "127.0.0.1"), int(port_str)
    return "127.0.0.1", int(listen)


def normalize_target(raw: dict[str, Any], idx: int) -> dict[str, Any]:
    node = str(raw.get("node") or raw.get("id") or f"node-{idx + 1}")
    role = str(raw.get("role") or "validator").lower()
    rpc_url = raw.get("rpc_url") or raw.get("url")
    explorer_url = raw.get("explorer_url")
    if isinstance(rpc_url, str):
        rpc_url = rpc_url.strip().rstrip("/") or None
    if isinstance(explorer_url, str):
        explorer_url = explorer_url.strip().rstrip("/") or None
    validator_id = raw.get("validator_id")
    if isinstance(validator_id, str):
        validator_id = validator_id.strip().lower().removeprefix("0x") or None
    return {
        "node": node,
        "name": str(raw.get("name") or f"Node {node}"),
        "role": role,
        "rpc_url": rpc_url,
        "explorer_url": explorer_url,
        "validator_id": validator_id,
    }


def load_targets(
    targets_spec: str | None = None, targets_file: str | None = None
) -> list[dict[str, Any]]:
    raw_list: Any = None
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as fh:
            raw_list = json.load(fh)
    elif targets_spec:
        spec = targets_spec.strip()
        if spec.startswith("["):
            raw_list = json.loads(spec)
        elif os.path.isfile(spec):
            with open(spec, "r", encoding="utf-8") as fh:
                raw_list = json.load(fh)
        else:
            # Allow compact comma-separated form: A=http://127.0.0.1:8545,B=...
            parsed: list[dict[str, Any]] = []
            for item in spec.split(","):
                item = item.strip()
                if not item:
                    continue
                if "=" in item:
                    node, url = item.split("=", 1)
                    node = node.strip()
                    url = url.strip()
                    role = "rpc" if "rpc" in node.lower() else "validator"
                    parsed.append({"node": node, "role": role, "rpc_url": url})
                else:
                    role = "rpc" if "rpc" in item.lower() else "validator"
                    parsed.append({"node": item, "role": role, "rpc_url": item})
            raw_list = parsed
    else:
        raw_list = DEFAULT_TARGETS

    if not isinstance(raw_list, list) or not raw_list:
        raise ValueError("targets must be a non-empty list")
    return [normalize_target(item, idx) for idx, item in enumerate(raw_list)]


def hex_to_int(val: Any) -> int | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        s = val.strip()
        try:
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            return int(s, 10)
        except ValueError:
            return None
    return None


def parse_prometheus_text(text: str) -> dict[str, Any]:
    """Extract relevant Stellereum gauges and histogram buckets from /metrics."""
    out: dict[str, Any] = {
        "metrics_height": None,
        "efficiency": None,
        "block_interval_sum_secs": None,
        "block_interval_count": None,
        "block_interval_buckets": {},  # float upper bound (or math.inf) -> float count
        "validator_set_size": None,
        "validator_set_fragile": None,
        "ready": None,
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PROM_LINE_RE.match(line)
        if not m:
            continue
        name, labels_raw, val_str = m.group(1), m.group(2) or "", m.group(3)
        try:
            val = float(val_str)
        except ValueError:
            continue
        if math.isnan(val):
            continue

        if name == "stell_consensus_height" and math.isfinite(val):
            out["metrics_height"] = int(val)
        elif name == "stell_validator_efficiency_ratio" and math.isfinite(val):
            out["efficiency"] = val
        elif name == "stell_block_interval_seconds_sum" and math.isfinite(val):
            out["block_interval_sum_secs"] = val
        elif name == "stell_block_interval_seconds_count" and math.isfinite(val):
            out["block_interval_count"] = int(val)
        elif name == "stell_block_interval_seconds_bucket" and math.isfinite(val):
            labels = dict(_LABEL_RE.findall(labels_raw))
            le_str = labels.get("le")
            if le_str is not None:
                try:
                    le_val = math.inf if le_str == "+Inf" else float(le_str)
                    out["block_interval_buckets"][le_val] = val
                except ValueError:
                    pass
        elif name == "stell_validator_set_size" and math.isfinite(val):
            out["validator_set_size"] = int(val)
        elif name == "stell_validator_set_fragile" and math.isfinite(val):
            out["validator_set_fragile"] = bool(int(val))
        elif name == "stell_ready" and math.isfinite(val) and out["ready"] is None:
            out["ready"] = bool(int(val))
    return out


def histogram_quantile(q: float, buckets: dict[float, float]) -> float | None:
    """Compute Prometheus-style histogram_quantile(q, buckets) in bucket units."""
    if not buckets:
        return None
    total = buckets.get(math.inf)
    finite_bounds = sorted(b for b in buckets if math.isfinite(b))
    if total is None:
        if not finite_bounds:
            return None
        total = buckets[finite_bounds[-1]]
    if total <= 0 or not finite_bounds:
        return None

    rank = q * total
    prev_bound = 0.0
    prev_count = 0.0
    for bound in finite_bounds:
        count = buckets[bound]
        if count >= rank:
            if count <= prev_count:
                return bound
            fraction = (rank - prev_count) / (count - prev_count)
            return prev_bound + fraction * (bound - prev_bound)
        prev_bound = bound
        prev_count = count
    return finite_bounds[-1]


def parse_validators_payload(payload: Any) -> dict[str, Any]:
    """Normalize stell_getValidators response across dict and list shapes."""
    if isinstance(payload, dict):
        raw_list = payload.get("validators")
        validators_list = raw_list if isinstance(raw_list, list) else []
        ids: list[str] = []
        for entry in validators_list:
            if isinstance(entry, dict) and isinstance(entry.get("validator"), str):
                ids.append(entry["validator"].strip().lower().removeprefix("0x"))
            elif isinstance(entry, str):
                ids.append(entry.strip().lower().removeprefix("0x"))
        return {
            "count": len(validators_list),
            "ids": ids,
            "total_power": (
                str(payload["total_power"])
                if payload.get("total_power") is not None
                else None
            ),
            "quorum": (
                str(payload["quorum"]) if payload.get("quorum") is not None else None
            ),
            "fragile": (
                bool(payload["fragile"])
                if isinstance(payload.get("fragile"), bool)
                else None
            ),
            "fragile_reason": payload.get("fragile_reason"),
            "entries": validators_list,
        }
    if isinstance(payload, list):
        ids = []
        for entry in payload:
            if isinstance(entry, dict) and isinstance(entry.get("validator"), str):
                ids.append(entry["validator"].strip().lower().removeprefix("0x"))
            elif isinstance(entry, str):
                ids.append(entry.strip().lower().removeprefix("0x"))
        return {
            "count": len(payload),
            "ids": ids,
            "total_power": None,
            "quorum": None,
            "fragile": None,
            "fragile_reason": None,
            "entries": payload,
        }
    return {
        "count": None,
        "ids": [],
        "total_power": None,
        "quorum": None,
        "fragile": None,
        "fragile_reason": None,
        "entries": [],
    }


def _ssl_context() -> ssl.SSLContext | None:
    return ssl.create_default_context()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP redirect disabled ({code} -> {newurl})",
            headers,
            fp,
        )


def _build_opener(url: str) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = [_NoRedirectHandler()]
    if url.startswith("https://"):
        handlers.append(urllib.request.HTTPSHandler(context=_ssl_context()))
    return urllib.request.build_opener(*handlers)


def _read_bounded(fp: Any, max_bytes: int | None = None) -> bytes:
    limit = MAX_HTTP_BYTES if max_bytes is None else max_bytes
    data = fp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"HTTP response exceeded {limit} bytes")
    return data


def _http_get_text(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json, text/plain, */*", "User-Agent": "stell-status/1.0"},
    )
    opener = _build_opener(url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = _read_bounded(resp).decode("utf-8", errors="replace")
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        try:
            body = _read_bounded(exc).decode("utf-8", errors="replace") if exc.fp else ""
            return int(exc.code), body
        finally:
            exc.close()


def _rpc_call(
    rpc_url: str,
    method: str,
    params: list[Any] | dict[str, Any] | None,
    timeout: float,
) -> tuple[Any, str | None]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params if params is not None else []}
    ).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "stell-status/1.0",
        },
    )
    opener = _build_opener(rpc_url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = _read_bounded(resp).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        code = int(exc.code)
        exc.close()
        return None, f"HTTP {code} from {rpc_url}"
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as exc:
        return None, f"unreachable {rpc_url}: {exc}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON from {rpc_url}: {exc}"
    if not isinstance(data, dict):
        return None, f"unexpected JSON-RPC payload from {rpc_url}"
    if "error" in data and data["error"] is not None:
        return None, f"RPC error on {method}: {data['error']}"
    if "result" not in data:
        return None, f"missing result on {method}"
    return data["result"], None


def probe_target(target: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Probe one node/RPC target honestly; never fabricate unreachable values."""
    ts = int(time.time())
    rpc_url = target.get("rpc_url")
    explorer_url = target.get("explorer_url")

    result: dict[str, Any] = {
        "ok": False,
        "status": "unknown",
        "ts": ts,
        "node": target["node"],
        "name": target["name"],
        "role": target["role"],
        "rpc_url": rpc_url,
        "explorer_url": explorer_url,
        "validator_id": target.get("validator_id"),
        "height": None,
        "metrics_height": None,
        "heights_agree": None,
        "efficiency": None,
        "ready": None,
        "syncing": None,
        "state_root": None,
        "validators": None,
        "validator_set": None,
        "mempool": None,
        "chain_id": None,
        "node_id": None,
        "version": None,
        "p99_ms": None,
        "avg_interval_ms": None,
        "rpc_latency_ms": None,
        "in_set": None,
        "jailed": None,
        "finals_rate_10m": None,
        "error": None,
        "_metrics_raw": None,
        "_validator_status": None,
    }

    timeout = max(0.2, float(timeout))
    overall_budget = max(timeout * 2.5, timeout + 1.0)
    deadline = time.monotonic() + overall_budget
    errors: list[str] = []

    def _remaining_timeout() -> float:
        return max(0.1, min(timeout, deadline - time.monotonic()))

    def _probe_height() -> tuple[int | None, float | None, str | None]:
        assert rpc_url is not None
        t0 = time.monotonic()
        height_raw, err = _rpc_call(rpc_url, "eth_blockNumber", [], _remaining_timeout())
        latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
        height = hex_to_int(height_raw) if err is None else None
        if height is None:
            # Fallback to stell_blockNumber if eth_blockNumber failed with RPC error (not network down)
            if err and "RPC error" in err and time.monotonic() < deadline:
                t1 = time.monotonic()
                height_raw2, err2 = _rpc_call(rpc_url, "stell_blockNumber", [], _remaining_timeout())
                latency_ms = round((time.monotonic() - t1) * 1000.0, 2)
                height = hex_to_int(height_raw2) if err2 is None else None
                if height is None:
                    return None, None, (err2 or f"bad blockNumber from {rpc_url}")
            else:
                return None, None, (err or f"bad eth_blockNumber from {rpc_url}")
        return height, latency_ms, None

    def _probe_rpc_method(
        method: str, params: list[Any] | dict[str, Any] | None = None
    ) -> tuple[Any, str | None]:
        assert rpc_url is not None
        val, err = _rpc_call(rpc_url, method, params, _remaining_timeout())
        if err is not None and method not in err:
            err = f"{method}: {err}"
        return val, err

    def _probe_version() -> tuple[dict[str, Any] | None, str | None]:
        try:
            code, body = _http_get_text(f"{explorer_url}/api/version", _remaining_timeout())
            if 200 <= code < 300:
                parsed_v = json.loads(body)
                if isinstance(parsed_v, dict):
                    return parsed_v, None
                return None, "explorer /api/version unexpected JSON payload"
            return None, f"explorer /api/version HTTP {code}"
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            return None, f"explorer /api/version unreachable: {exc}"

    def _probe_readyz() -> tuple[bool | None, str | None]:
        try:
            code, body = _http_get_text(f"{explorer_url}/readyz", _remaining_timeout())
            err_msg: str | None = None
            ready_val: bool | None = None
            if not (200 <= code < 300):
                err_msg = f"explorer /readyz HTTP {code}"
            if not (300 <= code < 400) and body:
                readyz = json.loads(body)
                if isinstance(readyz, dict) and "ready" in readyz:
                    ready_val = bool(readyz["ready"])
                elif err_msg is None:
                    err_msg = "explorer /readyz missing 'ready' field"
            elif err_msg is None:
                err_msg = "explorer /readyz empty response"
            return ready_val, err_msg
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            return None, f"explorer /readyz unreachable: {exc}"

    def _probe_metrics() -> tuple[dict[str, Any] | None, str | None]:
        try:
            code, body = _http_get_text(f"{explorer_url}/metrics", _remaining_timeout())
            if 200 <= code < 300:
                if body:
                    return parse_prometheus_text(body), None
                return None, "explorer /metrics empty response"
            return None, f"explorer /metrics HTTP {code}"
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            ValueError,
        ) as exc:
            return None, f"explorer /metrics unreachable: {exc}"

    pool = ThreadPoolExecutor(max_workers=10)
    timed_out = False
    try:
        explorer_futures: dict[str, Future[Any]] = {}
        if explorer_url:
            explorer_futures["version"] = pool.submit(_probe_version)
            explorer_futures["readyz"] = pool.submit(_probe_readyz)
            explorer_futures["metrics"] = pool.submit(_probe_metrics)

        height_future: Future[tuple[int | None, float | None, str | None]] | None = None
        if rpc_url:
            height_future = pool.submit(_probe_height)

        rpc_futures: dict[str, Future[tuple[Any, str | None]]] = {}

        if height_future is not None:
            rem = max(0.0, deadline - time.monotonic())
            done_h, _ = wait({height_future}, timeout=rem)
            if height_future in done_h:
                height, latency_ms, h_err = height_future.result()
                if h_err:
                    errors.append(h_err)
                if height is not None:
                    result["height"] = height
                    result["rpc_latency_ms"] = latency_ms
                    if time.monotonic() < deadline:
                        for method in (
                            "stell_syncing",
                            "stell_getStateRoot",
                            "stell_getValidators",
                            "stell_mempoolSize",
                            "stell_chainId",
                            "stell_nodeId",
                        ):
                            rpc_futures[method] = pool.submit(_probe_rpc_method, method, [])
                    else:
                        errors.append(
                            f"secondary RPC probes skipped (per-target budget {overall_budget:.1f}s exceeded)"
                        )
            else:
                timed_out = True
                errors.append(
                    f"eth_blockNumber timed out (per-target budget {overall_budget:.1f}s exceeded)"
                )

        if rpc_futures:
            rem = max(0.0, deadline - time.monotonic())
            done_rpc, not_done_rpc = wait(rpc_futures.values(), timeout=rem)
            if not_done_rpc:
                timed_out = True
            for method, fut in rpc_futures.items():
                if fut not in done_rpc:
                    errors.append(
                        f"{method} timed out (per-target budget {overall_budget:.1f}s exceeded)"
                    )
                    continue
                val, err = fut.result()
                if err:
                    errors.append(err)
                if method == "stell_syncing":
                    result["syncing"] = val if isinstance(val, bool) else None
                elif method == "stell_getStateRoot":
                    result["state_root"] = val if isinstance(val, str) else None
                elif method == "stell_getValidators" and val is not None:
                    vset = parse_validators_payload(val)
                    result["validators"] = vset["count"]
                    result["validator_set"] = vset
                elif method == "stell_mempoolSize":
                    result["mempool"] = hex_to_int(val)
                elif method == "stell_chainId":
                    result["chain_id"] = val
                elif method == "stell_nodeId":
                    result["node_id"] = val

            vid = target.get("validator_id")
            vset_cur = result["validator_set"]
            if (
                result["height"] is not None
                and target["role"] == "validator"
                and isinstance(vid, str)
                and vid
                and (vset_cur is None or vid not in vset_cur["ids"])
            ):
                if time.monotonic() < deadline:
                    vstatus_future = pool.submit(
                        _probe_rpc_method,
                        "stell_getValidatorStatus",
                        {"validator": vid},
                    )
                    rem = max(0.0, deadline - time.monotonic())
                    done_vs, _ = wait({vstatus_future}, timeout=rem)
                    if vstatus_future in done_vs:
                        vstatus, vs_err = vstatus_future.result()
                        if vs_err:
                            errors.append(vs_err)
                        if isinstance(vstatus, dict):
                            result["_validator_status"] = vstatus
                    else:
                        timed_out = True
                        errors.append(
                            f"stell_getValidatorStatus timed out (per-target budget {overall_budget:.1f}s exceeded)"
                        )
                else:
                    errors.append(
                        f"stell_getValidatorStatus skipped (per-target budget {overall_budget:.1f}s exceeded)"
                    )

        if explorer_futures:
            rem = max(0.0, deadline - time.monotonic())
            done_exp, not_done_exp = wait(explorer_futures.values(), timeout=rem)
            if not_done_exp:
                timed_out = True

            fut_v = explorer_futures["version"]
            if fut_v in done_exp:
                parsed_v, v_err = fut_v.result()
                if v_err:
                    errors.append(v_err)
                if isinstance(parsed_v, dict):
                    result["version"] = parsed_v
                    if result["node_id"] is None and isinstance(parsed_v.get("node_id"), str):
                        result["node_id"] = parsed_v["node_id"]
            else:
                errors.append(
                    f"explorer /api/version timed out (per-target budget {overall_budget:.1f}s exceeded)"
                )

            fut_r = explorer_futures["readyz"]
            if fut_r in done_exp:
                ready_val, r_err = fut_r.result()
                if r_err:
                    errors.append(r_err)
                if ready_val is not None:
                    result["ready"] = ready_val
            else:
                errors.append(
                    f"explorer /readyz timed out (per-target budget {overall_budget:.1f}s exceeded)"
                )

            fut_m = explorer_futures["metrics"]
            if fut_m in done_exp:
                parsed_m, m_err = fut_m.result()
                if m_err:
                    errors.append(m_err)
                if isinstance(parsed_m, dict):
                    result["_metrics_raw"] = parsed_m
                    result["metrics_height"] = parsed_m["metrics_height"]
                    result["efficiency"] = parsed_m["efficiency"]
                    if result["ready"] is None:
                        result["ready"] = parsed_m["ready"]
            else:
                errors.append(
                    f"explorer /metrics timed out (per-target budget {overall_budget:.1f}s exceeded)"
                )
    finally:
        pool.shutdown(wait=not timed_out, cancel_futures=timed_out)

    height = result["height"]
    metrics_height = result["metrics_height"]
    if height is not None and metrics_height is not None:
        result["heights_agree"] = height == metrics_height
    else:
        result["heights_agree"] = None

    if height is not None:
        result["ok"] = True
        result["status"] = "up"
        if errors:
            result["error"] = "; ".join(errors)
    else:
        result["ok"] = False
        result["status"] = "unknown"
        if errors:
            result["error"] = "; ".join(errors)
        else:
            result["error"] = f"unreachable or bad eth_blockNumber from {rpc_url} (no values fabricated)"

    return result


class StatusMonitor:
    """Thread-safe poller, ring-buffer aggregator, and cluster verdict engine."""

    def __init__(
        self,
        targets: list[dict[str, Any]],
        interval_secs: float = DEFAULT_INTERVAL_SECS,
        timeout_secs: float = DEFAULT_TIMEOUT_SECS,
        history_len: int = DEFAULT_HISTORY_LEN,
        expected_validators: int = DEFAULT_EXPECTED_VALIDATORS,
        stall_window_secs: float = DEFAULT_STALL_WINDOW_SECS,
        height_lag_warn: int = DEFAULT_HEIGHT_LAG_WARN,
    ) -> None:
        self.targets = targets
        self.interval_secs = max(1.0, float(interval_secs))
        self.timeout_secs = max(0.2, float(timeout_secs))
        self.history_len = max(2, int(history_len))
        self.expected_validators = max(1, int(expected_validators))
        self.stall_window_secs = max(1.0, float(stall_window_secs))
        self.height_lag_warn = max(1, int(height_lag_warn))

        self._lock = threading.Lock()
        self._history: deque[dict[str, Any]] = deque(maxlen=self.history_len)
        self._latest_snapshot: dict[str, Any] | None = None
        self._stop_event = threading.Event()
        self._initial_poll_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run_loop, name="stell-status-poller", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def is_ready(self) -> bool:
        return self._initial_poll_event.is_set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # pragma: no cover - defensive guard
                LOG.exception("poll_once failed unexpectedly: %s", exc)
            finally:
                self._initial_poll_event.set()
            self._stop_event.wait(self.interval_secs)

    def poll_once(self, now_ts: int | None = None) -> dict[str, Any]:
        ts = int(now_ts if now_ts is not None else time.time())
        results_by_idx: dict[int, dict[str, Any]] = {}
        max_workers = min(16, max(1, len(self.targets)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {
                pool.submit(probe_target, target, self.timeout_secs): idx
                for idx, target in enumerate(self.targets)
            }
            for future in as_completed(future_map):
                idx = future_map[future]
                try:
                    res = future.result()
                except Exception as exc:
                    t = self.targets[idx]
                    res = {
                        "ok": False,
                        "status": "unknown",
                        "ts": ts,
                        "node": t["node"],
                        "name": t["name"],
                        "role": t["role"],
                        "rpc_url": t.get("rpc_url"),
                        "explorer_url": t.get("explorer_url"),
                        "validator_id": t.get("validator_id"),
                        "height": None,
                        "metrics_height": None,
                        "heights_agree": None,
                        "efficiency": None,
                        "ready": None,
                        "syncing": None,
                        "state_root": None,
                        "validators": None,
                        "validator_set": None,
                        "mempool": None,
                        "chain_id": None,
                        "node_id": None,
                        "version": None,
                        "p99_ms": None,
                        "avg_interval_ms": None,
                        "rpc_latency_ms": None,
                        "in_set": None,
                        "jailed": None,
                        "finals_rate_10m": None,
                        "error": f"probe exception: {exc}",
                        "_metrics_raw": None,
                        "_validator_status": None,
                    }
                res["ts"] = ts
                results_by_idx[idx] = res

        ordered_nodes = [results_by_idx[i] for i in range(len(self.targets))]
        best_vset = self._pick_validator_set(ordered_nodes)
        best_ids = set(best_vset["ids"]) if best_vset else set()
        if best_ids:
            for n in ordered_nodes:
                vid = n.get("validator_id")
                if (
                    n["ok"]
                    and n["role"] == "validator"
                    and isinstance(vid, str)
                    and vid
                    and vid not in best_ids
                    and n.get("_validator_status") is None
                    and n.get("rpc_url")
                ):
                    vstatus, vstatus_err = _rpc_call(
                        n["rpc_url"],
                        "stell_getValidatorStatus",
                        {"validator": vid},
                        self.timeout_secs,
                    )
                    if isinstance(vstatus, dict):
                        n["_validator_status"] = vstatus
                    elif vstatus_err:
                        err_msg = (
                            vstatus_err
                            if "stell_getValidatorStatus" in vstatus_err
                            else f"stell_getValidatorStatus: {vstatus_err}"
                        )
                        n["error"] = (
                            f"{n['error']}; {err_msg}" if n.get("error") else err_msg
                        )

        with self._lock:
            snapshot = self._aggregate_locked(ts, ordered_nodes)
            self._latest_snapshot = snapshot
            self._initial_poll_event.set()
            return snapshot

    def latest_snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            return self._latest_snapshot

    def _aggregate_locked(
        self, ts: int, nodes: list[dict[str, Any]]
    ) -> dict[str, Any]:
        # Record raw per-node history entry for rate & histogram-delta math.
        raw_entry: dict[str, Any] = {
            "ts": ts,
            "nodes": {},
            "cluster_height": None,
        }
        reachable_heights = [n["height"] for n in nodes if n["ok"] and n["height"] is not None]
        cluster_height = max(reachable_heights) if reachable_heights else None
        raw_entry["cluster_height"] = cluster_height
        for n in nodes:
            raw_entry["nodes"][n["node"]] = {
                "ts": ts,
                "height": n["height"],
                "metrics_raw": n.get("_metrics_raw"),
            }
        self._history.append(raw_entry)

        # Determine consensus validator set across reachable nodes.
        validator_set_info = self._pick_validator_set(nodes)
        active_set_ids: set[str] = set(validator_set_info["ids"]) if validator_set_info else set()

        # Enrich per-node fields: in_set, jailed, finals_rate_10m, p99_ms, avg_interval_ms.
        cluster_delta_buckets: dict[float, float] = {}
        cluster_delta_sum = 0.0
        cluster_delta_count = 0
        cum_fallback_buckets: dict[float, float] = {}
        cum_fallback_sum = 0.0
        cum_fallback_count = 0

        public_nodes: list[dict[str, Any]] = []
        for n in nodes:
            node_name = n["node"]
            node_rate = self._compute_node_finals_rate(node_name)
            p99_ms, avg_ms, delta_buckets, d_sum, d_cnt, is_delta = self._compute_node_intervals(
                node_name
            )
            if d_cnt > 0 and n["role"] == "validator":
                if is_delta:
                    cluster_delta_sum += d_sum
                    cluster_delta_count += d_cnt
                    for le, cnt in delta_buckets.items():
                        cluster_delta_buckets[le] = cluster_delta_buckets.get(le, 0.0) + cnt
                else:
                    cum_fallback_sum += d_sum
                    cum_fallback_count += d_cnt
                    for le, cnt in delta_buckets.items():
                        cum_fallback_buckets[le] = cum_fallback_buckets.get(le, 0.0) + cnt

            in_set: bool | None = None
            jailed: bool | None = None
            if n["role"] == "validator":
                vid = n.get("validator_id")
                if isinstance(vid, str):
                    vid = vid.strip().lower().removeprefix("0x") or None
                if active_set_ids and vid:
                    in_set = vid in active_set_ids
                if in_set is True:
                    jailed = False
                elif in_set is False:
                    vstatus = n.get("_validator_status")
                    if isinstance(vstatus, dict):
                        if vstatus.get("jailed") is True:
                            jailed = True
                        elif vstatus.get("known") is False:
                            jailed = None
                        elif vstatus.get("jailed") is False:
                            jailed = False

            cleaned = {
                k: v
                for k, v in n.items()
                if k not in ("_metrics_raw", "_validator_status", "validator_set")
            }
            cleaned["in_set"] = in_set
            cleaned["jailed"] = jailed
            cleaned["finals_rate_10m"] = node_rate
            cleaned["p99_ms"] = p99_ms
            cleaned["avg_interval_ms"] = avg_ms
            public_nodes.append(cleaned)

        cluster_finals_rate, history_span_secs = self._compute_cluster_finals_rate()
        cluster_p99_ms: float | None = None
        cluster_avg_ms: float | None = None
        if cluster_delta_count > 0:
            q99 = histogram_quantile(0.99, cluster_delta_buckets)
            if q99 is not None:
                cluster_p99_ms = round(q99 * 1000.0, 1)
            cluster_avg_ms = round((cluster_delta_sum / cluster_delta_count) * 1000.0, 1)
        elif cum_fallback_count > 0:
            q99 = histogram_quantile(0.99, cum_fallback_buckets)
            if q99 is not None:
                cluster_p99_ms = round(q99 * 1000.0, 1)
            cluster_avg_ms = round((cum_fallback_sum / cum_fallback_count) * 1000.0, 1)
        else:
            # Fallback to per-node cumulative p99/avg if available
            node_p99s = [n["p99_ms"] for n in public_nodes if n["role"] == "validator" and n["p99_ms"] is not None]
            node_avgs = [n["avg_interval_ms"] for n in public_nodes if n["role"] == "validator" and n["avg_interval_ms"] is not None]
            if node_p99s:
                cluster_p99_ms = round(max(node_p99s), 1)
            if node_avgs:
                cluster_avg_ms = round(sum(node_avgs) / len(node_avgs), 1)

        validator_nodes = [n for n in public_nodes if n["role"] == "validator"]
        reachable_validators = [n for n in validator_nodes if n["ok"]]
        if active_set_ids:
            active_validators = [
                n
                for n in reachable_validators
                if n["in_set"] is True and n["jailed"] is not True
            ]
        else:
            active_validators = []

        efficiencies = [
            n["efficiency"]
            for n in reachable_validators
            if n["efficiency"] is not None
        ]
        eff_avg = round(sum(efficiencies) / len(efficiencies), 4) if efficiencies else None
        eff_min = round(min(efficiencies), 4) if efficiencies else None

        height_lag: int | None = None
        if len(reachable_heights) >= 2:
            height_lag = max(reachable_heights) - min(reachable_heights)
        elif len(reachable_heights) == 1:
            height_lag = 0

        chain_ids = [n["chain_id"] for n in public_nodes if n["ok"] and n["chain_id"] is not None]
        cluster_chain_id = chain_ids[0] if chain_ids else None

        verdict, reasons = self._evaluate_verdict(
            public_nodes=public_nodes,
            validator_nodes=validator_nodes,
            reachable_validators=reachable_validators,
            active_validators=active_validators,
            validator_set_info=validator_set_info,
            height_lag=height_lag,
            cluster_finals_rate=cluster_finals_rate,
            history_span_secs=history_span_secs,
        )

        return {
            "service": "stell-status",
            "ts": ts,
            "poll_interval_secs": self.interval_secs,
            "history_samples": len(self._history),
            "history_window_secs": history_span_secs,
            "verdict": verdict,
            "reasons": reasons,
            "cluster": {
                "expected_validators": self.expected_validators,
                "configured_validators": len(validator_nodes),
                "reachable_validators": len(reachable_validators),
                "active_validators": len(active_validators),
                "validator_set_size": validator_set_info["count"] if validator_set_info else None,
                "total_power": validator_set_info["total_power"] if validator_set_info else None,
                "quorum": validator_set_info["quorum"] if validator_set_info else None,
                "fragile": validator_set_info["fragile"] if validator_set_info else None,
                "fragile_reason": validator_set_info["fragile_reason"] if validator_set_info else None,
                "height": cluster_height,
                "height_lag": height_lag,
                "chain_id": cluster_chain_id,
                "finals_rate_10m": cluster_finals_rate,
                "efficiency_avg": eff_avg,
                "efficiency_min": eff_min,
                "block_interval_p99_ms": cluster_p99_ms,
                "block_interval_avg_ms": cluster_avg_ms,
            },
            "nodes": public_nodes,
        }

    def _pick_validator_set(self, nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
        candidates = [
            (n.get("height") or -1, n["validator_set"])
            for n in nodes
            if n["ok"] and isinstance(n.get("validator_set"), dict)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    def _compute_cluster_finals_rate(self) -> tuple[float | None, int]:
        valid = [
            (entry["ts"], entry["cluster_height"])
            for entry in self._history
            if entry["cluster_height"] is not None
        ]
        if len(valid) < 2:
            return None, 0
        t1, h1 = valid[0]
        t2, h2 = valid[-1]
        dt = t2 - t1
        if dt <= 0:
            return None, 0
        dh = h2 - h1
        if dh < 0:
            return None, dt
        return round((dh * 60.0) / dt, 2), dt

    def _compute_node_finals_rate(self, node_name: str) -> float | None:
        valid: list[tuple[int, int]] = []
        for entry in self._history:
            nd = entry["nodes"].get(node_name)
            if nd and nd["height"] is not None:
                valid.append((nd["ts"], nd["height"]))
        if len(valid) < 2:
            return None
        t1, h1 = valid[0]
        t2, h2 = valid[-1]
        dt = t2 - t1
        if dt <= 0 or h2 < h1:
            return None
        return round(((h2 - h1) * 60.0) / dt, 2)

    def _compute_node_intervals(
        self, node_name: str
    ) -> tuple[float | None, float | None, dict[float, float], float, int, bool]:
        samples: list[dict[str, Any]] = []
        for entry in self._history:
            nd = entry["nodes"].get(node_name)
            if nd and isinstance(nd.get("metrics_raw"), dict):
                samples.append(nd["metrics_raw"])
        if not samples:
            return None, None, {}, 0.0, 0, False

        newest = samples[-1]
        new_count = newest.get("block_interval_count")
        new_sum = newest.get("block_interval_sum_secs")
        new_buckets: dict[float, float] = newest.get("block_interval_buckets") or {}

        if new_count is None or new_count == 0 or not new_buckets:
            return None, None, {}, 0.0, 0, False

        delta_buckets: dict[float, float] = {}
        delta_sum = 0.0
        delta_count = 0
        is_delta = False

        if len(samples) >= 2:
            oldest = samples[0]
            old_count = oldest.get("block_interval_count")
            old_sum = oldest.get("block_interval_sum_secs")
            old_buckets: dict[float, float] = oldest.get("block_interval_buckets") or {}
            if (
                old_count is not None
                and old_sum is not None
                and new_sum is not None
                and new_count > old_count
                and new_sum >= old_sum
            ):
                delta_count = new_count - old_count
                delta_sum = new_sum - old_sum
                for le, val in new_buckets.items():
                    delta_buckets[le] = max(0.0, val - old_buckets.get(le, 0.0))
                is_delta = True

        # Fall back to cumulative histogram when window has single sample or zero new blocks
        if delta_count == 0:
            delta_count = int(new_count)
            delta_sum = float(new_sum or 0.0)
            delta_buckets = dict(new_buckets)

        q99 = histogram_quantile(0.99, delta_buckets)
        p99_ms = round(q99 * 1000.0, 1) if q99 is not None else None
        avg_ms = (
            round((delta_sum / delta_count) * 1000.0, 1)
            if delta_count > 0 and delta_sum >= 0
            else None
        )
        return p99_ms, avg_ms, delta_buckets, delta_sum, delta_count, is_delta

    def _evaluate_verdict(
        self,
        public_nodes: list[dict[str, Any]],
        validator_nodes: list[dict[str, Any]],
        reachable_validators: list[dict[str, Any]],
        active_validators: list[dict[str, Any]],
        validator_set_info: dict[str, Any] | None,
        height_lag: int | None,
        cluster_finals_rate: float | None,
        history_span_secs: int,
    ) -> tuple[str, list[str]]:
        reasons: list[str] = []

        # Minimum quorum threshold for BFT safety (2f+1; for 4 validators -> 3).
        quorum_nodes = (self.expected_validators * 2) // 3 + 1
        any_reachable = any(n["ok"] for n in public_nodes)

        # Check voting power quorum if validator_set is available
        power_quorum_lost = False
        if validator_set_info and validator_set_info.get("quorum") and validator_set_info.get("entries"):
            try:
                quorum_power = int(validator_set_info["quorum"])
                power_by_id: dict[str, int] = {}
                for entry in validator_set_info["entries"]:
                    if isinstance(entry, dict) and entry.get("validator") and entry.get("power") is not None:
                        vid = str(entry["validator"]).strip().lower().removeprefix("0x")
                        power_by_id[vid] = int(entry["power"])
                reachable_power = 0
                for n in active_validators:
                    vid = n.get("validator_id")
                    if isinstance(vid, str):
                        vid_norm = vid.strip().lower().removeprefix("0x")
                        if vid_norm in power_by_id:
                            reachable_power += power_by_id[vid_norm]
                if power_by_id and reachable_power < quorum_power:
                    power_quorum_lost = True
                    reasons.append(
                        f"reachable_power_below_quorum ({reachable_power} < {quorum_power})"
                    )
            except (ValueError, TypeError):
                pass

        if not any_reachable:
            reasons.append("all_targets_unreachable")
            return "DOWN", reasons

        if len(reachable_validators) == 0:
            reasons.append("no_validators_reachable")
            return "DOWN", reasons

        if validator_set_info is None:
            reasons.append("validator_set_unavailable")
        else:
            for n in reachable_validators:
                if n.get("in_set") is None:
                    reasons.append(f"validator_id_unknown ({n['node']})")

        if len(active_validators) < quorum_nodes or power_quorum_lost:
            reasons.append(
                f"quorum_lost ({len(active_validators)}/{self.expected_validators} active validators, need {quorum_nodes})"
            )
            return "DOWN", reasons

        # Non-quorum-fatal degradations -> DEGRADED
        if len(reachable_validators) < self.expected_validators:
            down_names = [n["node"] for n in validator_nodes if not n["ok"]]
            reasons.append(
                f"validators_unreachable ({len(reachable_validators)}/{self.expected_validators}; down={','.join(down_names)})"
            )

        if len(active_validators) < self.expected_validators and len(reachable_validators) >= self.expected_validators:
            reasons.append(
                f"active_validators_below_expected ({len(active_validators)}/{self.expected_validators})"
            )

        if validator_set_info is not None:
            vcount = validator_set_info.get("count")
            if vcount is not None and vcount < self.expected_validators:
                reasons.append(
                    f"validator_set_size_low ({vcount} < {self.expected_validators})"
                )
            if validator_set_info.get("fragile") is True:
                fr = validator_set_info.get("fragile_reason") or "quorum requires 100% of set"
                reasons.append(f"validator_set_fragile ({fr})")

        for n in public_nodes:
            if not n["ok"] and n["role"] != "validator":
                reasons.append(f"target_unreachable ({n['node']})")
            if n["ok"]:
                if n.get("jailed") is True:
                    reasons.append(f"validator_jailed ({n['node']})")
                elif n.get("in_set") is False:
                    reasons.append(f"validator_not_in_set ({n['node']})")
                if n.get("syncing") is True:
                    reasons.append(f"node_syncing ({n['node']})")
                if n.get("ready") is False:
                    reasons.append(f"node_not_ready ({n['node']})")
                if n.get("heights_agree") is False:
                    reasons.append(
                        f"rpc_metrics_height_mismatch ({n['node']}: rpc={n['height']} metrics={n['metrics_height']})"
                    )
                if n.get("efficiency") is not None and n["efficiency"] < 0.9:
                    reasons.append(
                        f"efficiency_low ({n['node']}={n['efficiency']:.3f})"
                    )

        chain_ids = {str(n["chain_id"]) for n in public_nodes if n["ok"] and n["chain_id"] is not None}
        if len(chain_ids) > 1:
            reasons.append(f"chain_id_mismatch ({','.join(sorted(chain_ids))})")

        if height_lag is not None and height_lag > self.height_lag_warn:
            reasons.append(f"height_lag_high ({height_lag} blocks)")

        if (
            cluster_finals_rate is not None
            and cluster_finals_rate <= 0.0
            and history_span_secs >= self.stall_window_secs
        ):
            reasons.append(f"finalization_stalled (0.0 blocks/min over {history_span_secs}s)")

        if reasons:
            return "DEGRADED", reasons
        return "HEALTHY", ["all_checks_passing"]


def render_prometheus_metrics(snapshot: dict[str, Any] | None) -> str:
    lines: list[str] = [
        "# HELP stell_status_up Whether the stell-status service has completed at least one poll (1=yes, 0=no)",
        "# TYPE stell_status_up gauge",
    ]
    if snapshot is None:
        lines.append("stell_status_up 0")
        return "\n".join(lines) + "\n"

    lines.append("stell_status_up 1")
    cluster = snapshot["cluster"]
    verdict = snapshot["verdict"]
    healthy_int = 1 if verdict == "HEALTHY" else 0
    verdict_code = {"HEALTHY": 2, "DEGRADED": 1, "DOWN": 0}.get(verdict, 0)

    lines.extend(
        [
            "# HELP stell_status_cluster_healthy Cluster health verdict (1=HEALTHY, 0=DEGRADED or DOWN)",
            "# TYPE stell_status_cluster_healthy gauge",
            f"stell_status_cluster_healthy {healthy_int}",
            "# HELP stell_status_cluster_verdict Cluster verdict code (2=HEALTHY, 1=DEGRADED, 0=DOWN)",
            "# TYPE stell_status_cluster_verdict gauge",
            f"stell_status_cluster_verdict {verdict_code}",
            "# HELP stell_status_active_validators Reachable, unjailed validators in the active set",
            "# TYPE stell_status_active_validators gauge",
            f"stell_status_active_validators {cluster['active_validators']}",
            "# HELP stell_status_expected_validators Expected validator count for HEALTHY verdict",
            "# TYPE stell_status_expected_validators gauge",
            f"stell_status_expected_validators {cluster['expected_validators']}",
        ]
    )

    if cluster["finals_rate_10m"] is not None:
        lines.extend(
            [
                "# HELP stell_status_finals_rate_per_min Blocks finalized per minute over the rolling 10m window",
                "# TYPE stell_status_finals_rate_per_min gauge",
                f"stell_status_finals_rate_per_min {cluster['finals_rate_10m']}",
            ]
        )

    if cluster["height"] is not None:
        lines.extend(
            [
                "# HELP stell_status_cluster_height Highest observed finalized block height across reachable targets",
                "# TYPE stell_status_cluster_height gauge",
                f"stell_status_cluster_height {cluster['height']}",
            ]
        )

    if cluster["block_interval_p99_ms"] is not None:
        lines.extend(
            [
                "# HELP stell_status_cluster_block_interval_p99_ms Cluster p99 block interval in milliseconds",
                "# TYPE stell_status_cluster_block_interval_p99_ms gauge",
                f"stell_status_cluster_block_interval_p99_ms {cluster['block_interval_p99_ms']}",
            ]
        )

    if cluster["block_interval_avg_ms"] is not None:
        lines.extend(
            [
                "# HELP stell_status_cluster_block_interval_avg_ms Cluster average block interval in milliseconds",
                "# TYPE stell_status_cluster_block_interval_avg_ms gauge",
                f"stell_status_cluster_block_interval_avg_ms {cluster['block_interval_avg_ms']}",
            ]
        )

    lines.extend(
        [
            "# HELP stell_status_target_up Whether each configured status target is reachable and returning a valid height (1=up, 0=unknown/down)",
            "# TYPE stell_status_target_up gauge",
        ]
    )
    for node in snapshot["nodes"]:
        lbl = _prom_label(node["node"])
        role = _prom_label(node["role"])
        up_val = 1 if node["ok"] else 0
        lines.append(f'stell_status_target_up{{node="{lbl}",role="{role}"}} {up_val}')

    height_lines = [
        f'stell_status_target_height{{node="{_prom_label(n["node"])}",role="{_prom_label(n["role"])}"}} {n["height"]}'
        for n in snapshot["nodes"]
        if n["height"] is not None
    ]
    if height_lines:
        lines.extend(
            [
                "# HELP stell_status_target_height Observed block height per reachable target",
                "# TYPE stell_status_target_height gauge",
                *height_lines,
            ]
        )

    eff_lines = [
        f'stell_status_target_efficiency{{node="{_prom_label(n["node"])}"}} {n["efficiency"]}'
        for n in snapshot["nodes"]
        if n["efficiency"] is not None
    ]
    if eff_lines:
        lines.extend(
            [
                "# HELP stell_status_target_efficiency Validator proposal efficiency ratio [0..1]",
                "# TYPE stell_status_target_efficiency gauge",
                *eff_lines,
            ]
        )

    p99_lines = [
        f'stell_status_target_block_interval_p99_ms{{node="{_prom_label(n["node"])}"}} {n["p99_ms"]}'
        for n in snapshot["nodes"]
        if n["p99_ms"] is not None
    ]
    if p99_lines:
        lines.extend(
            [
                "# HELP stell_status_target_block_interval_p99_ms Block interval p99 in milliseconds per target",
                "# TYPE stell_status_target_block_interval_p99_ms gauge",
                *p99_lines,
            ]
        )

    return "\n".join(lines) + "\n"


def _prom_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_opt(value: Any, suffix: str = "") -> str:
    if value is None:
        return '<span class="muted">unknown</span>'
    return f"{html.escape(str(value))}{html.escape(suffix)}"


def render_html_page(snapshot: dict[str, Any] | None) -> str:
    if snapshot is None:
        return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>Stellereum Public Status — Initializing</title>
<style>
  :root { color-scheme: light dark; --bg:#f8fafc; --fg:#0f172a; --card:#ffffff; --border:#e2e8f0; --muted:#64748b; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b1120; --fg:#e2e8f0; --card:#111827; --border:#1f2937; --muted:#94a3b8; }
  }
  body { font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--fg); margin:0; padding:2rem; }
  .box { max-width:44rem; margin:4rem auto; padding:2rem; background:var(--card); border:1px solid var(--border); border-radius:12px; }
  .muted { color:var(--muted); }
</style>
</head>
<body>
  <div class="box">
    <h1>Stellereum Network Status</h1>
    <p class="muted">Collecting initial cluster snapshot&hellip; refreshing automatically.</p>
  </div>
</body>
</html>"""

    verdict = snapshot["verdict"]
    verdict_cls = {
        "HEALTHY": "healthy",
        "DEGRADED": "degraded",
        "DOWN": "down",
    }.get(verdict, "degraded")

    cluster = snapshot["cluster"]
    ts_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(snapshot["ts"]))
    refresh_secs = max(5, int(snapshot.get("poll_interval_secs", 15)))

    eff_pct = (
        f"{cluster['efficiency_avg'] * 100:.2f}%"
        if cluster["efficiency_avg"] is not None
        else "unknown"
    )
    finals_str = (
        f"{cluster['finals_rate_10m']:.2f} / min"
        if cluster["finals_rate_10m"] is not None
        else "warming up"
    )
    p99_str = (
        f"{cluster['block_interval_p99_ms']:.1f} ms"
        if cluster["block_interval_p99_ms"] is not None
        else "unknown"
    )
    avg_str = (
        f"{cluster['block_interval_avg_ms']:.1f} ms"
        if cluster["block_interval_avg_ms"] is not None
        else "unknown"
    )
    height_str = f"{cluster['height']:,}" if cluster["height"] is not None else "unknown"
    vset_str = (
        f"{cluster['validator_set_size']}"
        if cluster["validator_set_size"] is not None
        else "unknown"
    )
    if cluster["fragile"] is True:
        vset_str += " (fragile)"

    reasons_html = "".join(
        f"<li><code>{html.escape(r)}</code></li>" for r in snapshot["reasons"]
    )

    rows_html: list[str] = []
    for n in snapshot["nodes"]:
        ok = n["ok"]
        badge_cls = "ok" if ok else "err"
        badge_txt = "UP" if ok else "UNKNOWN"

        if not ok:
            state_txt = '<span class="err">unreachable</span>'
        elif n["jailed"] is True:
            state_txt = '<span class="err">jailed</span>'
        elif n["in_set"] is False:
            state_txt = '<span class="warn">out of set</span>'
        elif n["syncing"] is True:
            state_txt = '<span class="warn">syncing</span>'
        elif n["ready"] is False:
            state_txt = '<span class="warn">not ready</span>'
        elif n["role"] == "validator" and n["in_set"] is None:
            state_txt = '<span class="warn">set unknown</span>'
        else:
            state_txt = '<span class="ok">active</span>'

        h_txt = f"{n['height']:,}" if n["height"] is not None else '<span class="muted">unknown</span>'
        if n["heights_agree"] is False:
            h_txt += f' <span class="warn">(metrics: {n["metrics_height"]})</span>'

        eff_txt = (
            f"{n['efficiency'] * 100:.2f}%"
            if n["efficiency"] is not None
            else '<span class="muted">unknown</span>'
        )
        ready_txt = (
            "ready"
            if n["ready"] is True
            else ("not ready" if n["ready"] is False else '<span class="muted">unknown</span>')
        )
        p99_txt = (
            f"{n['p99_ms']:.1f} ms"
            if n["p99_ms"] is not None
            else '<span class="muted">unknown</span>'
        )
        if n["role"] == "validator":
            if n["in_set"] is True:
                set_txt = "yes"
            elif n["in_set"] is False:
                set_txt = "NO (jailed)" if n["jailed"] is True else "NO (out of set)"
            else:
                set_txt = '<span class="muted">unknown</span>'
        else:
            set_txt = '<span class="muted">n/a</span>'

        ver_obj = n.get("version")
        if isinstance(ver_obj, dict):
            ver_s = str(ver_obj.get("version") or "?")
            gh = str(ver_obj.get("git_hash") or "")[:8]
            dirty = "-dirty" if ver_obj.get("dirty") else ""
            ver_txt = f"<code>{html.escape(ver_s)} ({html.escape(gh)}{dirty})</code>"
        else:
            ver_txt = '<span class="muted">unknown</span>'

        err_txt = (
            f'<span class="err">{html.escape(n["error"])}</span>'
            if n.get("error")
            else '<span class="muted">&mdash;</span>'
        )

        rows_html.append(
            "<tr>"
            f"<td><strong>{html.escape(n['node'])}</strong><div class=\"sub\">{html.escape(n['name'])}</div></td>"
            f"<td><code>{html.escape(n['role'])}</code></td>"
            f"<td><span class=\"pill {badge_cls}\">{badge_txt}</span></td>"
            f"<td>{state_txt}</td>"
            f"<td class=\"num\">{h_txt}</td>"
            f"<td class=\"num\">{eff_txt}</td>"
            f"<td>{ready_txt}</td>"
            f"<td class=\"num\">{p99_txt}</td>"
            f"<td>{set_txt}</td>"
            f"<td>{ver_txt}</td>"
            f"<td class=\"errcol\">{err_txt}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="{refresh_secs}">
<title>Stellereum Status — {html.escape(verdict)}</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg: #f8fafc;
    --fg: #0f172a;
    --card: #ffffff;
    --border: #e2e8f0;
    --muted: #64748b;
    --code-bg: #f1f5f9;
    --ok: #15803d;
    --ok-bg: #dcfce7;
    --warn: #b45309;
    --warn-bg: #fef3c7;
    --err: #b91c1c;
    --err-bg: #fee2e2;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0b1120;
      --fg: #e2e8f0;
      --card: #111827;
      --border: #1f2937;
      --muted: #94a3b8;
      --code-bg: #1e293b;
      --ok: #4ade80;
      --ok-bg: rgba(34, 197, 94, 0.15);
      --warn: #fbbf24;
      --warn-bg: rgba(245, 158, 11, 0.15);
      --err: #f87171;
      --err-bg: rgba(239, 68, 68, 0.15);
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: var(--bg);
    color: var(--fg);
    margin: 0;
    padding: 1.5rem;
    line-height: 1.45;
  }}
  .wrap {{ max-width: 78rem; margin: 0 auto; }}
  header {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.25rem;
  }}
  h1 {{ margin: 0; font-size: 1.5rem; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; }}
  .verdict {{
    padding: 0.45rem 0.9rem;
    border-radius: 999px;
    font-weight: 700;
    letter-spacing: 0.04em;
    font-size: 0.95rem;
  }}
  .verdict.healthy {{ background: var(--ok-bg); color: var(--ok); }}
  .verdict.degraded {{ background: var(--warn-bg); color: var(--warn); }}
  .verdict.down {{ background: var(--err-bg); color: var(--err); }}
  .kpis {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
    gap: 0.85rem;
    margin-bottom: 1.25rem;
  }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.9rem 1rem;
  }}
  .card .label {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
  .card .value {{ font-size: 1.35rem; font-weight: 700; margin-top: 0.25rem; }}
  .card .sub {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.15rem; }}
  .table-wrap {{
    overflow-x: auto;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 1.25rem;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th, td {{ padding: 0.65rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
  tr:last-child td {{ border-bottom: none; }}
  .num {{ font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .sub {{ font-size: 0.78rem; color: var(--muted); }}
  .muted {{ color: var(--muted); }}
  .ok {{ color: var(--ok); font-weight: 600; }}
  .warn {{ color: var(--warn); font-weight: 600; }}
  .err {{ color: var(--err); font-weight: 600; }}
  .pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }}
  .pill.ok {{ background: var(--ok-bg); color: var(--ok); }}
  .pill.err {{ background: var(--err-bg); color: var(--err); }}
  .errcol {{ max-width: 18rem; word-break: break-word; font-size: 0.82rem; }}
  code {{ background: var(--code-bg); padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }}
  ul.reasons {{ margin: 0.4rem 0 0; padding-left: 1.2rem; }}
  footer {{ color: var(--muted); font-size: 0.85rem; display: flex; flex-wrap: wrap; gap: 0.75rem; justify-content: space-between; }}
  a {{ color: inherit; }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Stellereum Network Status</h1>
        <div class="meta">Updated {html.escape(ts_utc)} &middot; Chain ID {html.escape(str(cluster['chain_id'] if cluster['chain_id'] is not None else 'unknown'))} &middot; Auto-refresh {refresh_secs}s</div>
      </div>
      <div class="verdict {verdict_cls}">{html.escape(verdict)}</div>
    </header>

    <section class="kpis">
      <div class="card">
        <div class="label">Active Validators</div>
        <div class="value">{cluster['active_validators']} / {cluster['expected_validators']}</div>
        <div class="sub">Set size: {html.escape(vset_str)}</div>
      </div>
      <div class="card">
        <div class="label">Finalized Height</div>
        <div class="value">{html.escape(height_str)}</div>
        <div class="sub">Lag: {html.escape(str(cluster['height_lag'] if cluster['height_lag'] is not None else 'unknown'))} blocks</div>
      </div>
      <div class="card">
        <div class="label">Finals Rate (10m)</div>
        <div class="value">{html.escape(finals_str)}</div>
        <div class="sub">{snapshot['history_samples']} snapshots</div>
      </div>
      <div class="card">
        <div class="label">Validator Efficiency</div>
        <div class="value">{html.escape(eff_pct)}</div>
        <div class="sub">Cluster mean ratio</div>
      </div>
      <div class="card">
        <div class="label">Block Interval p99</div>
        <div class="value">{html.escape(p99_str)}</div>
        <div class="sub">Avg: {html.escape(avg_str)}</div>
      </div>
    </section>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Target</th>
            <th>Role</th>
            <th>Reachable</th>
            <th>State</th>
            <th>Height</th>
            <th>Efficiency</th>
            <th>Ready</th>
            <th>Block p99</th>
            <th>In Set</th>
            <th>Version</th>
            <th>Notes / Error</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows_html)}
        </tbody>
      </table>
    </div>

    <div class="card" style="margin-bottom:1.25rem;">
      <div class="label">Verdict Reasons</div>
      <ul class="reasons">{reasons_html}</ul>
    </div>

    <footer>
      <div>Independent observer &middot; unreachable nodes always report <code>unknown</code>, never fabricated values.</div>
      <div>
        <a href="/api/status.json">/api/status.json</a> &middot;
        <a href="/metrics">/metrics</a> &middot;
        <a href="/health">/health</a> &middot;
        <a href="/readyz">/readyz</a>
      </div>
    </footer>
  </div>
</body>
</html>"""


class StatusHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64
    timeout = 10.0

    def __init__(self, server_address: tuple[str, int], monitor: StatusMonitor) -> None:
        self.monitor = monitor
        super().__init__(server_address, StatusRequestHandler)


class StatusRequestHandler(BaseHTTPRequestHandler):
    server: StatusHTTPServer
    timeout = 10.0

    def address_string(self) -> str:
        return str(self.client_address[0])

    def log_message(self, format: str, *args: Any) -> None:
        LOG.info("%s - %s", self.address_string(), format % args)

    def _send(self, status_code: int, content_type: str, body: bytes) -> None:
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError) as exc:
            LOG.debug("client disconnected during response to %s: %s", self.path, exc)
            self.close_connection = True

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        raw_path = self.path.split("?", 1)[0]
        path = raw_path.rstrip("/") or "/"
        snap = self.server.monitor.latest_snapshot()

        if path == "/":
            body = render_html_page(snap).encode("utf-8")
            self._send(200, "text/html; charset=utf-8", body)
            return

        if path in ("/api/status.json", "/status.json", "/api/status", "/status"):
            if snap is None:
                payload = {
                    "service": "stell-status",
                    "ready": False,
                    "verdict": "DOWN",
                    "reasons": ["initial_poll_pending"],
                    "nodes": [],
                }
                self._send(503, "application/json; charset=utf-8", json.dumps(payload, indent=2).encode("utf-8"))
                return
            self._send(200, "application/json; charset=utf-8", json.dumps(snap, indent=2).encode("utf-8"))
            return

        if path in ("/health", "/healthz"):
            payload = {
                "status": "ok",
                "service": "stell-status",
                "ts": int(time.time()),
                "last_poll_ts": snap["ts"] if snap else None,
            }
            self._send(200, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))
            return

        if path == "/readyz":
            if not self.server.monitor.is_ready() or snap is None:
                payload = {"ready": False, "reason": "initial_poll_pending"}
                self._send(503, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))
                return
            payload = {
                "ready": True,
                "verdict": snap["verdict"],
                "last_poll_ts": snap["ts"],
                "reachable_validators": snap["cluster"]["reachable_validators"],
            }
            self._send(200, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))
            return

        if path == "/metrics":
            body = render_prometheus_metrics(snap).encode("utf-8")
            self._send(200, "text/plain; version=0.0.4; charset=utf-8", body)
            return

        self._send(404, "application/json; charset=utf-8", b'{"error":"not found"}\n')


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Stellereum standalone public status server")
    p.add_argument(
        "--listen",
        default=os.environ.get("STELL_STATUS_LISTEN", DEFAULT_LISTEN),
        help=f"Bind address host:port (default: {DEFAULT_LISTEN})",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("STELL_STATUS_INTERVAL", DEFAULT_INTERVAL_SECS)),
        help=f"Poll interval in seconds (default: {DEFAULT_INTERVAL_SECS})",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("STELL_STATUS_TIMEOUT", DEFAULT_TIMEOUT_SECS)),
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT_SECS})",
    )
    p.add_argument(
        "--history",
        type=int,
        default=int(os.environ.get("STELL_STATUS_HISTORY", DEFAULT_HISTORY_LEN)),
        help=f"Rolling snapshot ring buffer size (default: {DEFAULT_HISTORY_LEN})",
    )
    p.add_argument(
        "--expected-validators",
        type=int,
        default=int(
            os.environ.get("STELL_STATUS_EXPECTED_VALIDATORS", DEFAULT_EXPECTED_VALIDATORS)
        ),
        help=f"Expected validator count for HEALTHY verdict (default: {DEFAULT_EXPECTED_VALIDATORS})",
    )
    p.add_argument(
        "--targets",
        default=os.environ.get("STELL_STATUS_TARGETS"),
        help="JSON list, JSON file path, or comma-separated node=url pairs",
    )
    p.add_argument(
        "--targets-file",
        default=os.environ.get("STELL_STATUS_TARGETS_FILE"),
        help="Path to JSON targets file",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Run a single poll, print JSON snapshot to stdout, and exit",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("STELL_STATUS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        args = build_arg_parser().parse_args(argv)
        targets = load_targets(args.targets, args.targets_file)
        monitor = StatusMonitor(
            targets=targets,
            interval_secs=args.interval,
            timeout_secs=args.timeout,
            history_len=args.history,
            expected_validators=args.expected_validators,
        )

        if args.once:
            snap = monitor.poll_once()
            print(json.dumps(snap, indent=2))
            return 0

        host, port = parse_listen(args.listen)
        server = StatusHTTPServer((host, port), monitor)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        LOG.error("configuration or startup failed: %s", exc)
        return 1

    monitor.start()

    def _shutdown(signum: int, _frame: Any) -> None:
        LOG.info("received signal %d, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    LOG.info(
        "stell-status listening on http://%s:%d polling %d targets every %.1fs",
        host,
        server.server_port,
        len(targets),
        args.interval,
    )
    try:
        server.serve_forever()
    finally:
        monitor.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
