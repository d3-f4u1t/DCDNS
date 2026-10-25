"""Authoritative DNS front-end for the registry.

This is a real DNS server: it parses and emits the wire format defined by
RFC 1035, so an ordinary resolver (`nslookup`, `dig`, a browser's resolver) can
query it directly. It does not read the registry database; it only ever serves
records from a *committed* registry revision that it has polled from the
cluster. Names are published only when:

  * the domain is ``active``, and
  * the namespace that governs it is also ``active``.

A name that is revoked therefore stops resolving, and the delay between a
committed update and the new answer is measurable (that is the DNS propagation
metric in the evaluation report).

Two protocols are exposed:
  * UDP/5353 (default) - DNS
  * TCP/5380        - JSON metrics for the dashboard
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .client import ClusterClient

DNS_TTL = 30
TYPE_A = 1
TYPE_ANY = 255
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4


# --------------------------------------------------------------------------- #
# wire format
# --------------------------------------------------------------------------- #
def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end_offset = offset
    jumped = False
    seen = 0

    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 32:
                raise ValueError("compression loop")
            continue
        end = offset + 1 + length
        if end > len(data):
            raise ValueError("truncated label")
        labels.append(data[offset + 1:end].decode("ascii", errors="replace"))
        offset = end
        if not jumped:
            end_offset = offset

    return ".".join(labels).lower(), end_offset


def encode_answer(name: str, address: str) -> bytes:
    # 0xC00C points at the question name, which is always at offset 12 in a
    # single-question query.
    rdata = socket.inet_aton(address)
    return (
        b"\xc0\x0c"
        + struct.pack("!HHIH", TYPE_A, CLASS_IN, DNS_TTL, len(rdata))
        + rdata
    )


class DNSEngine:
    """Stateless-ish query engine over a published zone snapshot."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.zone: dict[str, str] = {}
        self.published_revision = 0
        self.source = "-"
        self.last_publish_at = 0.0
        self.published_at_monotonic = time.monotonic()
        self.last_poll_monotonic = time.monotonic()
        self.queries = 0
        self.answered = 0
        self.nxdomain = 0
        self.recent: list[dict] = []

    # -- publication ----------------------------------------------------- #
    def publish(self, zone: dict[str, str], revision: int, source: str) -> None:
        with self._lock:
            changed = revision != self.published_revision or zone != self.zone
            self.zone = dict(zone)
            if changed:
                self.published_revision = revision
                self.published_at_monotonic = time.monotonic()
            self.source = source
            self.last_publish_at = time.time()
            self.last_poll_monotonic = time.monotonic()

    # -- query handling --------------------------------------------------- #
    def handle(self, data: bytes) -> bytes | None:
        if len(data) < 17:
            return None
        try:
            transaction_id = data[:2]
            flags = struct.unpack("!H", data[2:4])[0]
            qdcount = struct.unpack("!H", data[4:6])[0]
            if qdcount < 1:
                return self._error(transaction_id, data, RCODE_FORMERR)

            question_start = 12
            qname, offset = parse_name(data, question_start)
            if offset + 4 > len(data):
                return self._error(transaction_id, data, RCODE_FORMERR)
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            question_end = offset + 4

            self.queries += 1
            answers: list[bytes] = []
            rcode = RCODE_NOERROR

            with self._lock:
                address = self.zone.get(qname)

            if qclass != CLASS_IN or qtype not in (TYPE_A, TYPE_ANY):
                rcode = RCODE_NOTIMP if qclass == CLASS_IN else RCODE_FORMERR
            elif address is None:
                rcode = RCODE_NXDOMAIN
                self.nxdomain += 1
            else:
                answers.append(encode_answer(qname, address))
                self.answered += 1

            entry = {
                "name": qname,
                "qtype": qtype,
                "answer": address,
                "rcode": "NOERROR" if address else ("NXDOMAIN" if rcode == 3 else "ERROR"),
                "at": time.time(),
            }
            # Collapse repeated polling of the same name so the dashboard shows
            # distinct lookups rather than one experiment's retry loop.
            if (self.recent
                    and self.recent[-1]["name"] == entry["name"]
                    and self.recent[-1]["answer"] == entry["answer"]
                    and self.recent[-1]["rcode"] == entry["rcode"]):
                self.recent[-1] = entry
            else:
                self.recent.append(entry)
            self.recent = self.recent[-50:]

            # QR=1, AA=1, RD copied from query, RA=0
            response_flags = 0x8000 | 0x0400 | (flags & 0x0100) | (rcode & 0x0F)
            header = transaction_id + struct.pack(
                "!HHHHH", response_flags, 1, len(answers), 0, 0
            )
            body = data[question_start:question_end] + b"".join(answers)
            return header + body
        except Exception:
            return self._error(data[:2], data, RCODE_FORMERR)

    def _error(self, transaction_id: bytes, data: bytes, rcode: int) -> bytes:
        flags = 0x8000 | 0x0400 | (rcode & 0x0F)
        header = transaction_id + struct.pack("!HHHHH", flags, 0, 0, 0, 0)
        return header

    # -- introspection ---------------------------------------------------- #
    def metrics(self) -> dict:
        with self._lock:
            zone = dict(self.zone)
            revision = self.published_revision
            age = time.monotonic() - self.published_at_monotonic
            since_poll = time.monotonic() - self.last_poll_monotonic
        return {
            "published_revision": revision,
            "zone_size": len(zone),
            "zone": zone,
            "source": self.source,
            "seconds_since_publish": round(age, 3),
            "seconds_since_poll": round(since_poll, 3),
            "poll_interval_seconds": POLL_INTERVAL,
            "queries": self.queries,
            "answered": self.answered,
            "nxdomain": self.nxdomain,
            "recent": self.recent[-15:],
        }


# --------------------------------------------------------------------------- #
# zone publication loop
# --------------------------------------------------------------------------- #
POLL_INTERVAL = 0.4


class Publisher(threading.Thread):
    def __init__(self, engine: DNSEngine, urls: list[str], zone_path: Path | None):
        super().__init__(daemon=True)
        self.engine = engine
        self.client = ClusterClient(urls, timeout=2.0)
        self.zone_path = zone_path
        self.last_revision: int | None = None
        self.errors = 0
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                state = self.client.consistent_state()
                zone: dict[str, str] = {}
                for name, domain in state.get("domains", {}).items():
                    if domain.get("status") != "active":
                        continue
                    address = domain.get("records", {}).get("A")
                    if not address:
                        continue
                    if not self._namespace_active(state, domain.get("namespace")):
                        continue
                    zone[name] = address
                revision = int(state.get("revision", 0))
                self.engine.publish(zone, revision, state.get("_source", "-"))
                if self.zone_path and revision != self.last_revision:
                    self._write_zone(zone, revision)
                self.last_revision = revision
                self.errors = 0
            except Exception:
                self.errors += 1
            self.stop_event.wait(POLL_INTERVAL)

    @staticmethod
    def _namespace_active(state: dict, namespace: str | None) -> bool:
        if not namespace:
            return False
        ns = state.get("namespaces", {}).get(namespace)
        return bool(ns and ns.get("status") == "active")

    def _write_zone(self, zone: dict[str, str], revision: int) -> None:
        try:
            lines = [
                f"; DCDNS published zone - registry revision {revision}",
                f"; written {time.strftime('%Y-%m-%d %H:%M:%S')}",
                "",
            ]
            for name, address in sorted(zone.items()):
                lines.append(f"{name}. {DNS_TTL} IN A {address}")
            self.zone_path.parent.mkdir(parents=True, exist_ok=True)
            self.zone_path.write_text("\n".join(lines) + "\n", "utf-8")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# servers
# --------------------------------------------------------------------------- #
class MetricsHandler(BaseHTTPRequestHandler):
    engine: DNSEngine

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] not in ("/metrics", "/zone"):
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(self.engine.metrics(), indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:  # silence per-request logging
        return


def serve_udp(sock: socket.socket, engine: DNSEngine, stop: threading.Event) -> None:
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        response = engine.handle(data)
        if response:
            try:
                sock.sendto(response, addr)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="DCDNS authoritative DNS front-end")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--metrics-port", type=int, default=5380)
    parser.add_argument("--nodes", default="http://127.0.0.1:9101,http://127.0.0.1:9102,http://127.0.0.1:9103")
    parser.add_argument("--zone-file", default="data/zone.txt")
    args = parser.parse_args()

    engine = DNSEngine()
    publisher = Publisher(engine, [u.strip() for u in args.nodes.split(",")],
                          Path(args.zone_file))
    publisher.start()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.host, args.port))

    metrics = ThreadingHTTPServer((args.host, args.metrics_port), MetricsHandler)
    MetricsHandler.engine = engine
    metrics.daemon_threads = True
    threading.Thread(target=metrics.serve_forever, daemon=True).start()

    print(f"DNS      listening on udp://{args.host}:{args.port}")
    print(f"metrics  listening on http://{args.host}:{args.metrics_port}/metrics")
    stop = threading.Event()
    try:
        serve_udp(udp, engine, stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        publisher.stop_event.set()
        udp.close()
        metrics.shutdown()


if __name__ == "__main__":
    main()
