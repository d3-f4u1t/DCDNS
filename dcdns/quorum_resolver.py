"""Client-facing DNS resolver with majority agreement.

The registry nodes are not just database replicas: each one is an authoritative
DNS server for the committed registry state it holds. This process is the
client-facing resolver. It forwards the original DNS query to *every* configured
node and only returns an answer when at least a majority of the nodes agree on
the same answer.

Why this exists
---------------
A single DNS server polling the cluster would still be a single point of trust:
whoever controls that process decides what clients see. Fanning the query out
and requiring a majority means one lying or compromised node cannot change the
answer a client receives. A minority can only cause a disagreement, not a
false answer.

This is deliberately *not* a P2P/DHT discovery layer. The set of nodes is still
configured, just as registry membership is. What is decentralized is DNS
serving and the decision about which answer to believe.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from .dns_server import (
    RCODE_FORMERR,
    RCODE_NXDOMAIN,
    RCODE_NOERROR,
    build_query,
    parse_name,
)

RCODE_SERVFAIL = 2


# --------------------------------------------------------------------------- #
# DNS response semantics
# --------------------------------------------------------------------------- #
def semantic_answer(response: bytes | None) -> tuple[int, tuple[tuple[int, int, bytes], ...]] | None:
    """Reduce a DNS response to what a client would actually act on.

    Transaction ids, flags unrelated to the answer, and record order are
    deliberately excluded. Two nodes that return the same address agree even if
    their packets differ in harmless ways.
    """
    if not response or len(response) < 12:
        return None
    try:
        flags = struct.unpack("!H", response[2:4])[0]
        qdcount, ancount = struct.unpack("!HH", response[4:8])
        if qdcount < 1:
            return None
        _, offset = parse_name(response, 12)
        offset += 4  # qtype + qclass
        records: list[tuple[int, int, bytes]] = []
        for _ in range(ancount):
            _, offset = parse_name(response, offset)
            if offset + 10 > len(response):
                return None
            rtype, rclass, _ttl, rdlength = struct.unpack(
                "!HHIH", response[offset:offset + 10]
            )
            offset += 10
            if offset + rdlength > len(response):
                return None
            records.append((rtype, rclass, response[offset:offset + rdlength]))
            offset += rdlength
        return flags & 0x000F, tuple(sorted(records))
    except Exception:
        return None


def answer_text(semantic: tuple[int, tuple[tuple[int, int, bytes], ...]] | None) -> str:
    """Human-readable label for metrics and the dashboard."""
    if semantic is None:
        return "malformed"
    rcode, records = semantic
    if rcode == RCODE_NXDOMAIN:
        return "NXDOMAIN"
    if rcode != RCODE_NOERROR:
        return f"RCODE{rcode}"
    if not records:
        return "NODATA"
    addresses = []
    for rtype, _rclass, rdata in records:
        if rtype == 1 and len(rdata) == 4:
            addresses.append(socket.inet_ntoa(rdata))
    return ", ".join(addresses) if addresses else "OTHER"


def query_name(data: bytes) -> tuple[str, int]:
    try:
        name, offset = parse_name(data, 12)
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        return name, qtype
    except Exception:
        return "<malformed>", 0


@dataclass
class Decision:
    ok: bool
    response: bytes | None
    winner: tuple[int, tuple[tuple[int, int, bytes], ...]] | None
    winner_nodes: list[str]
    votes: dict[str, str]
    disagreement: bool
    required: int


def evaluate_responses(
    responses: dict[str, bytes | None],
    required: int,
) -> Decision:
    """Decide whether a majority agrees, using only semantic DNS content."""
    groups: dict[tuple[int, tuple[tuple[int, int, bytes], ...]], list[str]] = {}
    votes: dict[str, str] = {}
    malformed = False

    for node_id in sorted(responses):
        response = responses[node_id]
        if response is None:
            votes[node_id] = "no-answer"
            continue
        semantic = semantic_answer(response)
        if semantic is None:
            malformed = True
            votes[node_id] = "malformed"
            continue
        votes[node_id] = answer_text(semantic)
        groups.setdefault(semantic, []).append(node_id)

    winner: tuple[int, tuple[tuple[int, int, bytes], ...]] | None = None
    winner_nodes: list[str] = []
    for semantic, nodes in groups.items():
        if len(nodes) >= required:
            winner = semantic
            winner_nodes = sorted(nodes)
            break

    # More than one distinct answer (or a node that could not answer at all)
    # means the nodes did not speak with one voice. It does not by itself mean
    # the query failed: a majority may still have agreed.
    disagreement = len(groups) > 1 or malformed
    if winner is None:
        return Decision(False, None, None, [], votes, disagreement, required)
    return Decision(
        True,
        responses[winner_nodes[0]],
        winner,
        winner_nodes,
        votes,
        disagreement,
        required,
    )


def decision_rcode(decision: Decision) -> str:
    if not decision.ok:
        return "SERVFAIL"
    if decision.winner is None:
        return "ERROR"
    if decision.winner[0] == RCODE_NOERROR:
        return "NOERROR"
    if decision.winner[0] == RCODE_NXDOMAIN:
        return "NXDOMAIN"
    return f"RCODE{decision.winner[0]}"


def build_servfail(query: bytes) -> bytes:
    """Return a valid SERVFAIL, preserving the question when possible."""
    transaction_id = query[:2] if len(query) >= 2 else b"\x00\x00"
    rd = 0
    if len(query) >= 4:
        rd = struct.unpack("!H", query[2:4])[0] & 0x0100
    flags = 0x8000 | rd | 0x0080 | RCODE_SERVFAIL
    question = b""
    qdcount = 0
    try:
        _, offset = parse_name(query, 12)
        end = offset + 4
        if end <= len(query):
            question = query[12:end]
            qdcount = 1
    except Exception:
        pass
    header = transaction_id + struct.pack("!HHHHH", flags, qdcount, 0, 0, 0)
    return header + question


def patch_id(response: bytes, transaction_id: bytes) -> bytes:
    if len(response) >= 2:
        return transaction_id + response[2:]
    return response


# --------------------------------------------------------------------------- #
# resolver
# --------------------------------------------------------------------------- #
class QuorumResolver:
    def __init__(
        self,
        nodes: dict[str, tuple[str, int]],
        api_urls: dict[str, str] | None = None,
        required: int | None = None,
        timeout: float = 0.75,
        poll_interval: float = 0.5,
        query_node: Callable[[str, int, bytes, float], bytes | None] | None = None,
    ) -> None:
        if not nodes:
            raise ValueError("at least one DNS node is required")
        self.nodes = dict(nodes)
        self.api_urls = dict(api_urls or {})
        self.required = required or (len(self.nodes) // 2 + 1)
        if self.required < 1 or self.required > len(self.nodes):
            raise ValueError("quorum must be between 1 and the number of nodes")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._query_node = query_node or self._udp_query
        self._executor = ThreadPoolExecutor(max_workers=max(1, len(self.nodes)))

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._poll_thread: threading.Thread | None = None
        self.last_poll = time.monotonic()
        self.last_majority = time.monotonic()

        self.queries = 0
        self.answered = 0
        self.nxdomain = 0
        self.servfail = 0
        self.disagreements = 0
        self.recent: list[dict] = []

        self.node_info: dict[str, dict] = {}
        for node_id, (host, port) in self.nodes.items():
            self.node_info[node_id] = {
                "node_id": node_id,
                "host": host,
                "dns_port": port,
                "api_url": self.api_urls.get(node_id),
                "reachable": False,
                "revision": 0,
                "zone_size": 0,
                "overrides": {},
                "paused": False,
                "last_seen": 0.0,
                "error": "not polled yet",
            }

    # -- transport ------------------------------------------------------- #
    @staticmethod
    def _udp_query(host: str, port: int, data: bytes, timeout: float) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(data, (host, port))
            response, _ = sock.recvfrom(4096)
            return response
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _ask_all(self, data: bytes) -> dict[str, bytes | None]:
        futures = {
            node_id: self._executor.submit(
                self._query_node, host, port, data, self.timeout
            )
            for node_id, (host, port) in self.nodes.items()
        }
        responses: dict[str, bytes | None] = {}
        for node_id, future in futures.items():
            try:
                responses[node_id] = future.result(timeout=self.timeout + 0.5)
            except Exception:
                responses[node_id] = None
        return responses

    # -- query path ------------------------------------------------------ #
    def _resolve(self, data: bytes) -> tuple[str, int, Decision, float]:
        name, qtype = query_name(data)
        started = time.perf_counter()
        responses = self._ask_all(data)
        decision = evaluate_responses(responses, self.required)
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return name, qtype, decision, elapsed_ms

    def _record(self, name: str, qtype: int, decision: Decision) -> None:
        with self._lock:
            self.queries += 1
            if decision.ok:
                self.answered += 1
                self.last_majority = time.monotonic()
                if decision.winner is not None and decision.winner[0] == RCODE_NXDOMAIN:
                    self.nxdomain += 1
            else:
                self.servfail += 1
            if decision.disagreement:
                self.disagreements += 1

            entry = {
                "name": name,
                "qtype": qtype,
                "answer": answer_text(decision.winner) if decision.ok else "SERVFAIL",
                "rcode": decision_rcode(decision),
                "votes": dict(decision.votes),
                "winner": list(decision.winner_nodes),
                "disagreement": decision.disagreement,
                "at": time.time(),
            }
            # Collapse repeated polling of the same name/answer so the dashboard
            # shows distinct lookups instead of an experiment's retry loop.
            if (self.recent
                    and self.recent[-1]["name"] == entry["name"]
                    and self.recent[-1]["answer"] == entry["answer"]
                    and self.recent[-1]["votes"] == entry["votes"]):
                self.recent[-1] = entry
            else:
                self.recent.append(entry)
            self.recent = self.recent[-50:]

    def resolve(self, data: bytes) -> bytes:
        name, qtype, decision, _elapsed_ms = self._resolve(data)
        self._record(name, qtype, decision)
        if decision.ok and decision.response is not None:
            return patch_id(decision.response, data[:2])
        return build_servfail(data)

    def resolve_detail(self, data: bytes) -> dict:
        """Resolve a query and return the decision that the client would see.

        This is the same code path as :meth:`resolve`; the extra return value is
        the per-node vote map, so the dashboard can show the resolver's actual
        decision without correlating a separate metrics entry.
        """
        name, qtype, decision, elapsed_ms = self._resolve(data)
        self._record(name, qtype, decision)
        return {
            "ok": decision.ok,
            "name": name,
            "qtype": qtype,
            "qtype_name": "A" if qtype == 1 else str(qtype),
            "answer": answer_text(decision.winner) if decision.ok else "SERVFAIL",
            "rcode": decision_rcode(decision),
            "votes": dict(decision.votes),
            "winner": list(decision.winner_nodes),
            "disagreement": decision.disagreement,
            "required": decision.required,
            "responders": len(self.nodes),
            "latency_ms": elapsed_ms,
            "at": time.time(),
            "source": "resolver /query (same decision path as udp/5353)",
        }

    # -- status polling -------------------------------------------------- #
    def start_polling(self) -> None:
        if not self.api_urls or self._poll_thread is not None:
            return
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="dns-quorum-poll"
        )
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.poll_interval)

    def poll_once(self) -> None:
        try:
            client = httpx.Client(timeout=1.0)
        except Exception:
            return
        try:
            for node_id, url in self.api_urls.items():
                info = self.node_info.get(node_id)
                if info is None:
                    continue
                try:
                    response = client.get(f"{url}/status")
                    if response.status_code != 200:
                        raise RuntimeError(f"HTTP {response.status_code}")
                    status = response.json()
                    dns = status.get("dns") or {}
                    info.update(
                        {
                            "reachable": True,
                            "revision": int(dns.get("revision", status.get("revision", 0))),
                            "zone_size": int(dns.get("zone_size", 0)),
                            "overrides": dict(dns.get("overrides") or {}),
                            "paused": bool(dns.get("paused", False)),
                            "last_seen": time.time(),
                            "error": None,
                        }
                    )
                except Exception as exc:
                    info.update(
                        {
                            "reachable": False,
                            "last_seen": time.time(),
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
        finally:
            client.close()
            with self._lock:
                self.last_poll = time.monotonic()

    # -- introspection --------------------------------------------------- #
    def metrics(self) -> dict:
        with self._lock:
            nodes = [dict(item) for item in self.node_info.values()]
            recent = [dict(item) for item in self.recent[-15:]]
            queries = self.queries
            answered = self.answered
            nxdomain = self.nxdomain
            servfail = self.servfail
            disagreements = self.disagreements
            since_poll = time.monotonic() - self.last_poll
            since_majority = time.monotonic() - self.last_majority

        reachable = [item for item in nodes if item["reachable"]]
        revisions = [item["revision"] for item in reachable]
        return {
            "published_revision": min(revisions) if revisions else 0,
            "zone_size": max((item["zone_size"] for item in reachable), default=0),
            "source": f"majority of {self.required} of {len(nodes)} nodes",
            "seconds_since_poll": round(since_poll, 3),
            "seconds_since_publish": round(since_majority, 3),
            "poll_interval_seconds": self.poll_interval,
            "queries": queries,
            "answered": answered,
            "nxdomain": nxdomain,
            "servfail": servfail,
            "disagreements": disagreements,
            "quorum": self.required,
            "nodes": nodes,
            "recent": recent,
        }

    def stop(self) -> None:
        self._stop.set()
        self._executor.shutdown(wait=False, cancel_futures=True)


# --------------------------------------------------------------------------- #
# servers
# --------------------------------------------------------------------------- #
class MetricsHandler(BaseHTTPRequestHandler):
    resolver: QuorumResolver

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/metrics", "/nodes"):
            self._json(200, self.resolver.metrics())
            return
        if path == "/query":
            name = (parse_qs(parsed.query).get("name") or [""])[0].strip()
            if not name:
                self._json(400, {"ok": False, "error": "name is required"})
                return
            try:
                packet = build_query(name)
                self._json(200, self.resolver.resolve_detail(packet))
            except Exception as exc:
                self._json(
                    400,
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                )
            return
        self._json(404, {"ok": False, "error": "not found"})

    def log_message(self, *args) -> None:  # silence per-request logging
        return


def serve_udp(sock: socket.socket, resolver: QuorumResolver, stop: threading.Event) -> None:
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        response = resolver.resolve(data)
        if response:
            try:
                sock.sendto(response, addr)
            except OSError:
                pass


def parse_nodes(spec: str) -> dict[str, tuple[str, int]]:
    nodes: dict[str, tuple[str, int]] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        node_id, address = chunk.split("=", 1)
        host, port = address.rsplit(":", 1)
        nodes[node_id.strip()] = (host.strip(), int(port))
    return nodes


def parse_urls(spec: str) -> dict[str, str]:
    urls: dict[str, str] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        node_id, url = chunk.split("=", 1)
        urls[node_id.strip()] = url.strip()
    return urls


def main() -> None:
    parser = argparse.ArgumentParser(description="DCDNS quorum DNS resolver")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--metrics-port", type=int, default=5380)
    parser.add_argument(
        "--nodes",
        default="n1=127.0.0.1:5354,n2=127.0.0.1:5355,n3=127.0.0.1:5356",
        help="comma separated id=host:udp-port entries",
    )
    parser.add_argument(
        "--api-nodes",
        default="n1=http://127.0.0.1:9101,n2=http://127.0.0.1:9102,n3=http://127.0.0.1:9103",
        help="comma separated id=http-url entries, used for revision metrics",
    )
    parser.add_argument("--quorum", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=0.75)
    args = parser.parse_args()

    resolver = QuorumResolver(
        parse_nodes(args.nodes),
        parse_urls(args.api_nodes),
        required=args.quorum,
        timeout=args.timeout,
    )
    resolver.start_polling()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.host, args.port))

    metrics = ThreadingHTTPServer((args.host, args.metrics_port), MetricsHandler)
    MetricsHandler.resolver = resolver
    metrics.daemon_threads = True
    threading.Thread(target=metrics.serve_forever, daemon=True).start()

    print(f"quorum DNS   udp://{args.host}:{args.port}")
    print(f"quorum       {resolver.required} of {len(resolver.nodes)} nodes must agree")
    print(f"metrics      http://{args.host}:{args.metrics_port}/metrics")
    for node_id, (host, port) in resolver.nodes.items():
        print(f"  {node_id:>3}        udp://{host}:{port}")

    stop = threading.Event()
    try:
        serve_udp(udp, resolver, stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        resolver.stop()
        udp.close()
        metrics.shutdown()


if __name__ == "__main__":
    main()
