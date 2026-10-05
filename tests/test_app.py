import json
import socket
import struct
import unittest
from unittest.mock import mock_open, patch
from http.client import HTTPConnection
from threading import Thread

import app
import sensor
import demo_server


def ipv4_tcp_frame(source="192.168.1.10", destination="1.1.1.1", source_port=51000, destination_port=443, flags=0x18):
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, 1, 0, (5 << 12) | flags, 8192, 0, 0)
    total_length = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0, socket.inet_aton(source), socket.inet_aton(destination))
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + tcp


class CaptureParserTests(unittest.TestCase):
    def test_extracts_ipv4_tcp_metadata_without_payload(self):
        observation = sensor.decode_packet(ipv4_tcp_frame())
        self.assertEqual(observation["src_ip"], "192.168.1.10")
        self.assertEqual(observation["dst_port"], 443)
        self.assertEqual(observation["protocol"], "TCP")
        self.assertEqual(observation["tcp_flags"], "AP")
        self.assertEqual(observation["packet_bytes"], 40)
        self.assertNotIn("payload", observation)

    def test_ignores_malformed_and_unsupported_frames(self):
        self.assertIsNone(sensor.decode_packet(b"short"))
        self.assertIsNone(sensor.decode_packet(bytes.fromhex("00112233445566778899aabb0806") + b"\0" * 28))
        self.assertIsNone(sensor.decode_packet(ipv4_tcp_frame()[:20]))

    def test_decodes_vlan_and_ipv6_udp_frames(self):
        ipv4 = ipv4_tcp_frame()
        vlan = bytes.fromhex("00112233445566778899aabb810000640800") + ipv4[14:]
        self.assertEqual(sensor.decode_packet(vlan)["protocol"], "TCP")

        udp = struct.pack("!HHHH", 5353, 53, 8, 0)
        source = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        destination = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, source, destination)
        ethernet = bytes.fromhex("00112233445566778899aabb86dd")
        observation = sensor.decode_packet(ethernet + ipv6 + udp)
        self.assertEqual(observation["src_ip"], "2001:db8::1")
        self.assertEqual(observation["dst_port"], 53)
        self.assertEqual(observation["protocol"], "UDP")

    def test_aggregates_both_directions_into_a_bounded_flow_record(self):
        capture = sensor.CaptureSensor()
        forward = sensor.decode_packet(ipv4_tcp_frame(), timestamp=100)
        reverse = sensor.decode_packet(ipv4_tcp_frame("1.1.1.1", "192.168.1.10", 443, 51000), timestamp=101)
        capture._record_observation(forward)
        capture._record_observation(reverse)
        rows = capture.snapshot()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["total_packets"], "2")
        self.assertEqual(rows[0]["fwd_packets"], "1")
        self.assertEqual(rows[0]["bwd_packets"], "1")
        self.assertEqual(rows[0]["total_bytes"], "80")

    def test_lists_interfaces_from_sysfs_without_netlink(self):
        with (
            patch("sensor.os.listdir", return_value=["wlp2s0", "lo", "enp1s0f0"]),
            patch("builtins.open", mock_open(read_data="up\n")),
            patch("sensor.socket.if_nameindex", side_effect=OSError("netlink unavailable")),
        ):
            self.assertEqual(
                sensor.available_interfaces(),
                [
                    {"name": "enp1s0f0", "label": "enp1s0f0 · up"},
                    {"name": "wlp2s0", "label": "wlp2s0 · up"},
                ],
            )


class AnalysisTests(unittest.TestCase):
    def test_demo_contains_detectable_anomalies_and_available_features(self):
        result = app.analyze(app.demo_rows())
        self.assertGreater(result["summary"]["anomalies"], 0)
        self.assertIn("total_packets", result["features"])
        self.assertEqual(result["summary"]["total_flows"], 64)
        self.assertTrue(all(item["status"] == "anomaly" for item in result["results"] if item["score"] >= 72))

    def test_threshold_and_feature_selection(self):
        rows = app.demo_rows()
        strict = app.analyze(rows, threshold=98)
        self.assertLessEqual(strict["summary"]["anomalies"], app.analyze(rows)["summary"]["anomalies"])
        selected = app.analyze(rows, selected_features=["total_packets"])
        self.assertEqual(selected["features"], ["duration_ms", "total_bytes", "total_packets"])
        self.assertEqual(selected["summary"]["total_flows"], 64)

    def test_rejects_invalid_parameters_and_oversized_records(self):
        with self.assertRaises(ValueError):
            app.analyze(app.demo_rows(), threshold=0)
        with self.assertRaises(ValueError):
            app.analyze([{"packets": {"nested": True}}])
        with self.assertRaises(ValueError):
            app.analyze([{}] * (app.MAX_ROWS + 1))

    def test_untrusted_non_finite_values_do_not_leak_into_json(self):
        rows = [{"bytes": "NaN"}, {"bytes": "Infinity"}, {"bytes": "-Infinity"}, {"bytes": "1"}]
        result = app.analyze(rows)
        json.dumps(result, allow_nan=False)

    def test_cicflowmeter_headers_and_sparse_outliers(self):
        rows = [{"Destination Port": "443", "Total Fwd Packets": "0"} for _ in range(12)]
        rows[-1] = {"Destination Port": "4444", "Total Fwd Packets": "7000"}
        result = app.analyze(rows)
        self.assertIn("anomaly", [item["status"] for item in result["results"]])
        flagged = result["results"][-1]
        self.assertEqual(flagged["status"], "anomaly")
        self.assertTrue(any("port 4444" in reason for reason in flagged["reasons"]))

    def test_tcp_flags_from_live_sensor_are_explained(self):
        rows = [{"tcp_flags": "A", "total_packets": "3"} for _ in range(5)]
        rows.append({"tcp_flags": "R", "total_packets": "1"})
        result = app.analyze(rows)
        self.assertTrue(any("connection flag" in reason.lower() for reason in result["results"][-1]["reasons"]))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.server.sensor = sensor.CaptureSensor()
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.server.sensor.stop()

    def test_health_and_analysis_endpoints(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["status"], "ok")
        payload = json.dumps({"rows": app.demo_rows(), "threshold": 72})
        connection.request("POST", "/api/analyze", payload, {"Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.loads(response.read())
        self.assertEqual(response.status, 200)
        self.assertEqual(result["summary"]["total_flows"], 64)
        connection.close()

    def test_live_endpoints_are_local_and_report_capture_state(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request("GET", "/api/live/status")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["state"], "stopped")
        connection.request("GET", "/api/live/status", headers={"Origin": "http://attacker.example"})
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        payload = json.dumps({"threshold": 72})
        connection.request("POST", "/api/live/analyze", payload, {"Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.loads(response.read())
        self.assertEqual(response.status, 200)
        self.assertEqual(result["capture"]["state"], "stopped")
        self.assertEqual(result["summary"]["total_flows"], 0)
        connection.close()

    def test_live_interfaces_endpoint_returns_discovered_interfaces(self):
        interfaces = [{"name": "wlp2s0", "label": "wlp2s0 · up"}]
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        with patch("app.available_interfaces", return_value=interfaces):
            connection.request("GET", "/api/live/interfaces")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"interfaces": interfaces})
        connection.close()

    def test_dashboard_assets_and_csv_import(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn("Network overview", page)
        self.assertIn("default-src 'self'", response.getheader("Content-Security-Policy"))
        connection.request("GET", "/app.js")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn("function render()", response.read().decode())
        payload = json.dumps({
            "csv": "timestamp,Destination Port,Total Fwd Packets\n"
            + "".join("2026-10-05T10:00:00Z,443,40\n" for _ in range(8))
            + "2026-10-05T10:00:00Z,4444,7000\n",
            "threshold": 72,
        })
        connection.request("POST", "/api/analyze", payload, {"Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.loads(response.read())
        self.assertEqual(response.status, 200)
        self.assertEqual(result["summary"]["total_flows"], 9)
        self.assertEqual(result["results"][-1]["status"], "anomaly")
        connection.close()

    def test_csv_endpoint_rejects_malformed_rows(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        payload = json.dumps({"csv": "packets,bytes\n1,2,3\n"})
        connection.request("POST", "/api/analyze", payload, {"Content-Type": "application/json"})
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        self.assertIn("more fields", json.loads(response.read())["error"])
        connection.close()


class PublicDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = demo_server.ThreadedDemoServer(("127.0.0.1", 0), demo_server.DemoHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port)
        self.headers = {
            "Host": "strata.example",
            "Origin": "https://strata.example",
        }

    def tearDown(self):
        self.connection.close()

    def test_public_page_disables_live_and_import_controls(self):
        self.connection.request("GET", "/", headers=self.headers)
        response = self.connection.getresponse()
        page = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn("Public demo", page)
        self.assertIn("SYNTHETIC DATA ONLY", page)
        self.assertIn('href="/demo.css"', page)
        self.assertIn("Demo uses synthetic traffic only", page)

        self.connection.request("GET", "/demo.css", headers=self.headers)
        response = self.connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn("#traffic-upload-trigger", response.read().decode())

        self.connection.request("GET", "/app.js", headers=self.headers)
        response = self.connection.getresponse()
        script = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn('$(