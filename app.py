#!/usr/bin/env python3
"""Local network-flow anomaly analysis API and web server."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import random
import re
import statistics
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sensor import CaptureSensor, available_interfaces


ROOT = Path(__file__).resolve().parent
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_ROWS = 10_000
MAX_COLUMNS = 100
MAX_FIELD_LENGTH = 512
NUMERIC_KEY = re.compile(r"^[a-zA-Z][a-zA-Z0-9_. -]{0,63}$")
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PORT_FEATURES = {
    "src_port", "source_port", "sport", "dst_port", "destination_port",
    "dest_port", "dport",
}
DESTINATION_PORT_FEATURES = {"dst_port", "destination_port", "dest_port", "dport"}
PACKET_FEATURES = {
    "total_packets", "packets", "packet_count", "total_fwd_packets",
    "total_backward_packets", "fwd_packets", "bwd_packets",
}
BYTE_FEATURES = {
    "total_bytes", "bytes", "byte_count", "total_length_of_fwd_packets",
    "total_length_of_bwd_packets", "fwd_bytes", "bwd_bytes",
}
SUSPICIOUS_PORTS = {23, 2323, 4444, 31337}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(str(value).strip().replace(",", ""))
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _feature_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _valid_rows(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        raise ValueError("Provide at least one flow record.")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"At most {MAX_ROWS:,} flow records can be analyzed at once.")

    clean: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"Flow record {index + 1} must be an object.")
        if len(row) > MAX_COLUMNS:
            raise ValueError(f"Flow record {index + 1} has too many fields.")
        safe: dict[str, Any] = {}
        for key, value in row.items():
            if not isinstance(key, str) or not NUMERIC_KEY.fullmatch(key):
                raise ValueError(f"Flow record {index + 1} contains an invalid field name.")
            if isinstance(value, (dict, list)):
                raise ValueError(f"Field {key!r} must contain a scalar value.")
            text = str(value) if value is not None else ""
            if len(text) > MAX_FIELD_LENGTH:
                raise ValueError(f"Field {key!r} exceeds the {MAX_FIELD_LENGTH}-character limit.")
            safe[key] = text
        clean.append(safe)
    return clean


def _feature_baseline(values: list[float]) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median(abs(item - median) for item in values)
    if mad:
        return median, mad / 0.6745
    ordered = sorted(values)
    lower = ordered[: len(ordered) // 2]
    upper = ordered[(len(ordered) + 1) // 2 :]
    spread = statistics.median(upper) - statistics.median(lower)
    return median, spread / 1.349 if spread else 0.0


def _robust_z(value: float, baseline: tuple[float, float]) -> float:
    median, scale = baseline
    if scale:
        return abs(value - median) / scale
    return 10.0 if value != median else 0.0


def _rule_signals(row: dict[str, Any], values: dict[str, float]) -> list[tuple[str, int]]:
    signals: list[tuple[str, int]] = []
    for key, value in values.items():
        normalized = _feature_key(key)
        if normalized in DESTINATION_PORT_FEATURES and value.is_integer() and int(value) in SUSPICIOUS_PORTS:
            signals.append((f"Connection to unusual service port {int(value)}", 88))
    packet_count = sum(value for key, value in values.items() if _feature_key(key) in PACKET_FEATURES)
    byte_count = sum(value for key, value in values.items() if _feature_key(key) in BYTE_FEATURES)
    if packet_count > 5000:
        signals.append(("Very high packet volume in a single flow", 84))
    if byte_count > 500_000:
        signals.append(("Very high byte volume in a single flow", 82))
    if packet_count >= 20 and byte_count and byte_count / packet_count > 12_000:
        signals.append(("Unusually large average packet size", 80))
    for key, value in row.items():
        normalized = _feature_key(key)
        if normalized in {"tcp_flag", "tcp_flags", "flags", "label"}:
            flag = str(value).strip().lower()
            if flag in {"rst", "reset", "syn_only", "syn-only"} or (
                normalized in {"tcp_flag", "tcp_flags", "flags"} and "r" in flag
            ):
                signals.append((f"Unusual connection flag: {str(value)[:24]}", 79))
            elif normalized in {"tcp_flag", "tcp_flags", "flags"} and "s" in flag and "a" not in flag:
                signals.append(("SYN packet without an ACK flag", 76))
    return signals


def analyze(rows: Any, threshold: Any = 72, selected_features: Any = None) -> dict[str, Any]:
    clean_rows = _valid_rows(rows)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("Threshold must be a number between 1 and 100.")
    if not math.isfinite(threshold) or not 1 <= threshold <= 100:
        raise ValueError("Threshold must be a number between 1 and 100.")

    feature_values: dict[str, list[float]] = {}
    display_names: dict[str, str] = {}
    for row in clean_rows:
        for key, value in row.items():
            number = _number(value)
            if number is not None:
                feature_values.setdefault(key, []).append(number)
                display_names[key] = key
    available = sorted(
        key for key, values in feature_values.items()
        if len(values) >= max(4, math.ceil(len(clean_rows) * 0.6))
        and len(set(values)) > 1
        and _feature_key(key) not in PORT_FEATURES
    )
    if selected_features is not None:
        if not isinstance(selected_features, list) or not all(
            isinstance(item, str) for item in selected_features
        ):
            raise ValueError("Selected features must be a list of field names.")
        unknown = set(selected_features) - set(available)
        if unknown:
            raise ValueError("Selected features include fields that are not numeric in this dataset.")
        active = set(selected_features)
    else:
        active = set(available)

    baselines = {feature: _feature_baseline(feature_values[feature]) for feature in active}
    results: list[dict[str, Any]] = []
    for index, row in enumerate(clean_rows):
        numeric = {key: number for key, raw in row.items() if (number := _number(raw)) is not None}
        scores: list[tuple[str, float]] = []
        for feature in active:
            value = numeric.get(feature)
            if value is None:
                continue
            z_score = _robust_z(value, baselines[feature])
            if z_score >= 2.5:
                feature_score = min(97.0, 65.0 + (z_score - 2.5) * 9.0)
                scores.append((feature, feature_score))
        signals = _rule_signals(row, numeric)
        score = max([item[1] for item in scores] + [float(item[1]) for item in signals] + [0.0])
        reasons = [f"{display_names[key]} is a statistical outlier" for key, _ in sorted(scores, key=lambda item: item[1], reverse=True)[:2]]
        reasons.extend(reason for reason, _ in signals)
        reasons = list(dict.fromkeys(reasons))
        results.append({
            "id": index + 1,
            "score": round(score),
            "status": "anomaly" if score >= threshold else "normal",
            "severity": "critical" if score >= 92 else "high" if score >= 82 else "medium",
            "reasons": reasons,
            "record": row,
        })

    anomalies = [item for item in results if item["status"] == "anomaly"]
    sources = {row.get(key, "") for row in clean_rows for key in row if _feature_key(key) in {"src_ip", "source_ip", "srcip"}}
    protocols: dict[str, int] = {}
    for row in clean_rows:
        for key, value in row.items():
            if _feature_key(key) in {"protocol", "proto"} and value:
                protocols[str(value)] = protocols.get(str(value), 0) + 1

    return {
        "summary": {
            "total_flows": len(results),
            "anomalies": len(anomalies),
            "normal": len(results) - len(anomalies),
            "anomaly_rate": round(len(anomalies) / len(results) * 100, 1),
            "unique_sources": len(sources),
            "threshold": threshold,
        },
        "features": available,
        "protocols": protocols,
        "results": results,
    }


def demo_rows() -> list[dict[str, str]]:
    rng = random.Random(27)
    now = datetime.now(timezone.utc)
    rows: list[dict[str, str]] = []
    for index in range(64):
        packets = max(2, int(rng.gauss(42, 12)))
        bytes_total = max(200, int(packets * rng.gauss(620, 100)))
        row = {
            "timestamp": (now - timedelta(minutes=63 - index)).isoformat(timespec="seconds"),
            "src_ip": f"10.0.{index % 4}.{10 + index % 200}",
            "dst_ip": f"172.16.{index % 8}.{20 + index % 220}",
            "src_port": str(rng.randint(1024, 65535)),
            "dst_port": str(rng.choice([53, 80, 443, 8080])),
            "protocol": rng.choice(["TCP", "TCP", "UDP", "HTTPS"]),
            "duration_ms": str(max(1, int(rng.gauss(220, 55)))),
            "total_packets": str(packets),
            "total_bytes": str(bytes_total),
        }
        if index in {12, 29, 47, 58}:
            row.update({
                "dst_port": "4444" if index != 29 else "23",
                "duration_ms": str(rng.randint(3, 8)),
                "total_packets": str(rng.randint(6500, 9000)),
                "total_bytes": str(rng.randint(700000, 900000)),
                "protocol": "TCP",
            })
        rows.append(row)
    return rows


class Handler(BaseHTTPRequestHandler):
    server_version = "Strata/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _is_local_request(self) -> bool:
        host = self.headers.get("Host", "").lower()
        port = self.server.server_port
        valid_hosts = {
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
        }
        if host not in valid_hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise ValueError("A valid Content-Length header is required.")
        length = int(raw_length)
        if length > MAX_BODY_BYTES:
            raise OverflowError("Request is too large (maximum 5 MB).")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("Request body was incomplete.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Send data as application/json.")
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def do_GET(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Only local browser requests are allowed."})
            return
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json(200, {"status": "ok", "service": "Strata"})
        elif path == "/api/live/interfaces":
            self._json(200, {"interfaces": available_interfaces()})
        elif path == "/api/live/status":
            self._json(200, self.server.sensor.status())
        elif path == "/api/live/data":
            rows = self.server.sensor.snapshot()
            self._json(200, {"status": self.server.sensor.status(), "rows": rows})
        elif path == "/api/demo":
            self._json(200, {"rows": demo_rows()})
        elif path in {"/", "/index.html", "/app.js", "/styles.css"}:
            target = ROOT / ("index.html" if path in {"/", "/index.html"} else path.lstrip("/"))
            if not target.is_file() or target.parent != ROOT:
                self.send_error(404)
                return
            body = target.read_bytes()
            content_type = "text/html; charset=utf-8" if target.suffix == ".html" else "text/javascript; charset=utf-8" if target.suffix == ".js" else "text/css; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Only local browser requests are allowed."})
            return
        path = urlparse(self.path).path
        if path not in {"/api/analyze", "/api/live/analyze", "/api/live/start", "/api/live/stop"}:
            self._json(404, {"error": "Endpoint not found."})
            return
        try:
            payload = self._read_json()
            if path == "/api/live/start":
                self._json(200, self.server.sensor.start(payload.get("interface")))
                return
            if path == "/api/live/stop":
                self._json(200, self.server.sensor.stop())
                return
            if path == "/api/live/analyze":
                rows = self.server.sensor.snapshot()
                if rows:
                    result = analyze(rows, payload.get("threshold", 72), payload.get("features"))
                else:
                    result = {
                        "summary": {
                            "total_flows": 0, "anomalies": 0, "normal": 0,
                            "anomaly_rate": 0, "unique_sources": 0,
                            "threshold": payload.get("threshold", 72),
                        },
                        "features": [], "protocols": {}, "results": [],
                    }
                result["capture"] = self.server.sensor.status()
                self._json(200, result)
                return
            if "csv" in payload:
                csv_text = payload["csv"]
                if not isinstance(csv_text, str) or len(csv_text.encode("utf-8")) > MAX_BODY_BYTES:
                    raise ValueError("CSV content is invalid or too large.")
                reader = csv.DictReader(io.StringIO(csv_text, newline=""), strict=True)
                headers = reader.fieldnames
                if not headers or len(headers) > MAX_COLUMNS or any(not header for header in headers):
                    raise ValueError("CSV must have a header row with valid fields.")
                rows = []
                for row in reader:
                    if len(rows) == MAX_ROWS:
                        raise ValueError(f"At most {MAX_ROWS:,} flow records can be analyzed at once.")
                    if None in row:
                        raise ValueError("CSV rows contain more fields than the header.")
                    rows.append(row)
                result = analyze(rows, payload.get("threshold", 72), payload.get("features"))
            else:
                result = analyze(payload.get("rows"), payload.get("threshold", 72), payload.get("features"))
            self._json(200, result)
        except OverflowError as error:
            self._json(413, {"error": str(error)})
        except PermissionError as error:
            self._json(503, {"error": str(error)})
        except RuntimeError as error:
            self._json(503, {"error": str(error)})
        except (ValueError, json.JSONDecodeError, csv.Error, UnicodeDecodeError) as error:
            self._json(400, {"error": str(error)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Strata network anomaly dashboard.")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000).")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.sensor = CaptureSensor()
    print(f"Strata dashboard: http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Strata.")
    finally:
        server.sensor.stop()
        server.server_close()


if __name__ == "__main__":
    main()
