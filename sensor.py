"""Linux host-interface packet metadata capture; packet payloads are never retained."""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any


MAX_ACTIVE_FLOWS = 2_000
MAX_RECENT_FLOWS = 1_000
FLOW_IDLE_SECONDS = 90
MAX_FRAME_BYTES = 65_535
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
IPV6_EXTENSIONS = {0, 43, 44, 51, 60, 135, 139, 140}


def _ipv6_transport(packet: bytes, next_header: int, offset: int) -> tuple[int, int] | None:
    for _ in range(8):
        if next_header not in IPV6_EXTENSIONS:
            return next_header, offset
        if offset + 2 > len(packet):
            return None
        extension = packet[offset]
        length_byte = packet[offset + 1]
        if next_header == 44:
            size = 8
            fragment_offset = struct.unpack_from("!H", packet, offset + 2)[0] & 0xFFF8
            if fragment_offset:
                return None
        elif next_header == 51:
            size = (length_byte + 2) * 4
        else:
            size = (length_byte + 1) * 8
        if size < 8 or offset + size > len(packet):
            return None
        next_header, offset = extension, offset + size
    return None


def decode_packet(frame: bytes, timestamp: float | None = None) -> dict[str, Any] | None:
    """Extract a flow observation from an Ethernet frame without reading payload content."""
    if len(frame) < 14 or len(frame) > MAX_FRAME_BYTES:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    for _ in range(2):
        if ether_type not in VLAN_TYPES:
            break
        if offset + 4 > len(frame):
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ether_type == ETH_P_IP:
        if offset + 20 > len(frame):
            return None
        version_ihl = frame[offset]
        ihl = (version_ihl & 0x0F) * 4
        if version_ihl >> 4 != 4 or ihl < 20 or offset + ihl > len(frame):
            return None
        total_length = struct.unpack_from("!H", frame, offset + 2)[0]
        if total_length < ihl or offset + total_length > len(frame):
            return None
        fragment = struct.unpack_from("!H", frame, offset + 6)[0]
        if fragment & 0x1FFF:
            return None
        protocol_number = frame[offset + 9]
        source = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
        destination = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
        transport_offset = offset + ihl
        packet_length = total_length
    elif ether_type == ETH_P_IPV6:
        if offset + 40 > len(frame) or frame[offset] >> 4 != 6:
            return None
        payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
        if offset + 40 + payload_length > len(frame):
            return None
        protocol_number = frame[offset + 6]
        source = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
        destination = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
        transport = _ipv6_transport(frame, protocol_number, offset + 40)
        if transport is None:
            return None
        protocol_number, transport_offset = transport
        packet_length = 40 + payload_length
    else:
        return None

    protocol = IP_PROTOCOLS.get(protocol_number, f"IP-{protocol_number}")
    source_port = destination_port = 0
    tcp_flags = ""
    if protocol_number in {6, 17}:
        if transport_offset + 4 > len(frame):
            return None
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_offset)
        if protocol_number == 6:
            if transport_offset + 14 > len(frame):
                return None
            tcp_header_length = (frame[transport_offset + 12] >> 4) * 4
            if tcp_header_length < 20 or transport_offset + tcp_header_length > len(frame):
                return None
            flags = frame[transport_offset + 13]
            tcp_flags = "".join(name for bit, name in (
                (0x02, "S"), (0x10, "A"), (0x01, "F"),
                (0x04, "R"), (0x08, "P"), (0x20, "U"),
            ) if flags & bit) or "NONE"

    current = time.time() if timestamp is None else timestamp
    return {
        "src_ip": source,
        "dst_ip": destination,
        "src_port": source_port,
        "dst_port": destination_port,
        "protocol": protocol,
        "tcp_flags": tcp_flags,
        "packet_bytes": min(packet_length, len(frame)),
        "timestamp": current,
    }


def available_interfaces() -> list[dict[str, str]]:
    if not hasattr(socket, "AF_PACKET"):
        return []
    interfaces = []
    for name in sorted(os.listdir("/sys/class/net")):
        if name == "lo":
            continue
        try:
            with open(f"/sys/class/net/{name}/operstate", encoding="ascii") as file:
                state = file.read(32).strip()
        except OSError:
            state = "unknown"
        if state not in {"up", "unknown"}:
            continue
        interfaces.append({"name": name, "label": f"{name} · {state}"})
    return interfaces


def _time_text(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class CaptureSensor:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._interface = ""
        self._state = "stopped"
        self._error = ""
        self._started_at = 0.0
        self._packets_seen = 0
        self._bytes_seen = 0
        self._unsupported = 0
        self._flows: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
        self._recent: deque[dict[str, str]] = deque(maxlen=MAX_RECENT_FLOWS)
        self._next_flow_id = 1

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state,
                "interface": self._interface,
                "started_at": _time_text(self._started_at) if self._started_at else None,
                "packets_seen": self._packets_seen,
                "bytes_seen": self._bytes_seen,
                "active_flows": len(self._flows),
                "error": self._error,
            }

    def start(self, interface: Any) -> dict[str, Any]:
        if not isinstance(interface, str) or interface not in {
            item["name"] for item in available_interfaces()
        }:
            raise ValueError("Choose an active network interface from the list.")
        with self._lock:
            if self._state == "running":
                if self._interface == interface:
                    return self.status()
                raise ValueError("Stop the current capture before switching interfaces.")
            if self._thread and self._thread.is_alive():
                raise ValueError("The previous capture is still shutting down.")
            if not hasattr(socket, "AF_PACKET"):
                raise RuntimeError("Live capture is supported on Linux only.")
            capture_socket: socket.socket | None = None
            try:
                capture_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                capture_socket.settimeout(0.5)
                capture_socket.bind((interface, 0))
            except OSError as error:
                if capture_socket is not None:
                    try:
                        capture_socket.close()
                    except OSError:
                        pass
                raise PermissionError(
                    "Could not open this interface for packet capture. Grant the Strata process "
                    "CAP_NET_RAW, or run it with an administrator-approved capture setup."
                ) from error
            self._socket = capture_socket
            self._interface = interface
            self._state = "running"
            self._error = ""
            self._started_at = time.time()
            self._packets_seen = 0
            self._bytes_seen = 0
            self._unsupported = 0
            self._flows.clear()
            self._recent.clear()
            self._next_flow_id = 1
            self._stop.clear()
            self._thread = threading.Thread(target=self._capture, name="strata-capture", daemon=True)
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            thread = self._thread
            self._stop.set()
            if self._socket:
                self._socket.close()
                self._socket = None
        if thread and thread.is_alive():
            thread.join(timeout=2)
        with self._lock:
            if thread and thread.is_alive():
                self._state = "stopping"
            elif self._state != "error":
                self._state = "stopped"
            self._thread = None if not thread or not thread.is_alive() else thread
            return self.status()

    def snapshot(self) -> list[dict[str, str]]:
        now = time.time()
        with self._lock:
            for key, flow in list(self._flows.items()):
                if now - flow["last_seen"] > FLOW_IDLE_SECONDS:
                    self._recent.append(self._flow_record(flow))
                    del self._flows[key]
            combined = list(self._recent)
            combined.extend(self._flow_record(flow) for flow in self._flows.values())
            return combined[-MAX_RECENT_FLOWS:]

    @staticmethod
    def _flow_record(flow: dict[str, Any]) -> dict[str, str]:
        return {
            "flow_id": flow["flow_id"],
            "timestamp": _time_text(flow["last_seen"]),
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": str(flow["src_port"]),
            "dst_port": str(flow["dst_port"]),
            "protocol": flow["protocol"],
            "duration_ms": str(max(0, round((flow["last_seen"] - flow["first_seen"]) * 1000))),
            "total_packets": str(flow["total_packets"]),
            "total_bytes": str(flow["total_bytes"]),
            "fwd_packets": str(flow["fwd_packets"]),
            "bwd_packets": str(flow["bwd_packets"]),
            "tcp_flags": flow["tcp_flags"],
        }

    def _capture(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                capture_socket = self._socket
            if capture_socket is None:
                break
            try:
                frame = capture_socket.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._fail("The capture socket stopped unexpectedly.")
                break
            observation = decode_packet(frame)
            with self._lock:
                self._packets_seen += 1
                self._bytes_seen += len(frame)
                if observation is None:
                    self._unsupported += 1
                    continue
                self._record_observation(observation)
        with self._lock:
            if self._state == "running":
                self._state = "stopped"

    def _record_observation(self, observation: dict[str, Any]) -> None:
        src = (observation["src_ip"], observation["src_port"])
        dst = (observation["dst_ip"], observation["dst_port"])
        first, second = sorted((src, dst))
        key = (observation["protocol"], first, second)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= MAX_ACTIVE_FLOWS:
                _, oldest = self._flows.popitem(last=False)
                self._recent.append(self._flow_record(oldest))
            flow = {
                "flow_id": f"LIVE-{self._next_flow_id:06d}",
                "src_ip": observation["src_ip"],
                "dst_ip": observation["dst_ip"],
                "src_port": observation["src_port"],
                "dst_port": observation["dst_port"],
                "protocol": observation["protocol"],
                "tcp_flags": observation["tcp_flags"],
                "first_seen": observation["timestamp"],
                "last_seen": observation["timestamp"],
                "total_packets": 0,
                "total_bytes": 0,
                "fwd_packets": 0,
                "bwd_packets": 0,
            }
            self._next_flow_id += 1
            self._flows[key] = flow
        if (observation["src_ip"], observation["src_port"]) == (flow["src_ip"], flow["src_port"]):
            direction = "fwd_packets"
        else:
            direction = "bwd_packets"
        flow["last_seen"] = observation["timestamp"]
        flow["total_packets"] += 1
        flow["total_bytes"] += observation["packet_bytes"]
        flow[direction] += 1
        if observation["tcp_flags"]:
            flow["tcp_flags"] = observation["tcp_flags"]

    def _fail(self, message: str) -> None:
        with self._lock:
            self._state = "error"
            self._error = message
            self._stop.set()
            if self._socket:
                try:
                    self._socket.close()
                except OSError:
                    pass
            self._socket = None
