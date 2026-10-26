"""Live DNS probes used by the portal console.

The console must never invent a node answer. This module performs ordinary UDP
DNS queries against each configured authoritative responder and one HTTP query
against the quorum resolver's introspection endpoint (which uses the same
decision path as its UDP listener). The results carry their source so the UI can
label direct node answers separately from the resolver's decision.
"""

from __future__ import annotations

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Mapping

import httpx

from .dns_server import build_query, parse_name
from .experiments import DEFAULT_DNS_NODES

RCODE_NAMES = {
    -1: "NO RESPONSE",
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def decode_response(data: bytes) -> tuple[int, str | None]:
    """Return ``(rcode, answer)`` from a DNS response.

    Only an A record is rendered as an address. A NOERROR response with no
    answers is labelled ``NODATA`` so the console does not display an empty cell
    that could be mistaken for a timeout.
    """
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0x000F
    qdcount, ancount = struct.unpack("!HH", data[4:8])
    if qdcount < 1:
        return rcode, None
    _, offset = parse_name(data, 12)
    offset += 4
    if ancount == 0:
        return rcode, "NODATA" if rcode == 0 else None
    _, offset = parse_name(data, offset)
    if offset + 10 > len(data):
        return rcode, None
    rtype, _rclass, _ttl, rdlength = struct.unpack(
        "!HHIH", data[offset:offset + 10]
    )
    offset += 10
    if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
        return rcode, socket.inet_ntoa(data[offset:offset + 4])
    return rcode, "OTHER"


def query_dns(
    host: str,
    port: int,
    name: str,
    timeout: float = 0.8,
) -> dict:
    """Query one DNS endpoint and measure the round trip."""
    try:
        packet = build_query(name)
    except Exception as exc:
        return {
            "node_id": None,
            "host": host,
            "port": port,
            "rcode": -1,
            "rcode_name": "INVALID",
            "answer": None,
            "latency_ms": 0.0,
            "error": f"{type(exc).__name__}: {exc}",
            "source": f"direct UDP {host}:{port}",
        }

    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        rcode, answer = decode_response(data)
        return {
            "node_id": None,
            "host": host,
            "port": port,
            "rcode": rcode,
            "rcode_name": RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
            "answer": answer,
            "latency_ms": elapsed_ms,
            "error": None,
            "source": f"direct UDP {host}:{port}",
        }
    except (socket.timeout, OSError) as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return {
            "node_id": None,
            "host": host,
            "port": port,
            "rcode": -1,
            "rcode_name": "NO RESPONSE",
            "answer": None,
            "latency_ms": elapsed_ms,
            "error": type(exc).__name__,
            "source": f"direct UDP {host}:{port}",
        }
    finally:
        sock.close()


def probe_nodes(
    name: str,
    nodes: Mapping[str, tuple[str, int]] | None = None,
    timeout: float = 0.8,
) -> list[dict]:
    """Query every configured node in parallel, preserving node-id order."""
    configured = dict(nodes or DEFAULT_DNS_NODES)
    with ThreadPoolExecutor(max_workers=max(1, len(configured))) as pool:
        futures = {
            node_id: pool.submit(query_dns, host, port, name, timeout)
            for node_id, (host, port) in configured.items()
        }
        results = []
        for node_id in sorted(configured):
            result = futures[node_id].result()
            result["node_id"] = node_id
            results.append(result)
    return results


def probe_resolver(
    metrics_url: str,
    name: str,
    timeout: float = 2.0,
    http_client: httpx.Client | None = None,
) -> dict:
    """Ask the resolver for its actual decision and per-node vote map.

    The endpoint calls :meth:`QuorumResolver.resolve_detail`, which shares the
    UDP resolver's ``_resolve``/``_record`` code path. It is not a cached
    dashboard value and it does not read the registry API.
    """
    started = time.perf_counter()
    try:
        url = f"{metrics_url.rstrip('/')}/query"
        if http_client is not None:
            response = http_client.get(url, params={"name": name}, timeout=timeout)
        else:
            response = httpx.get(url, params={"name": name}, timeout=timeout)
        http_ms = round((time.perf_counter() - started) * 1000.0, 2)
        if response.status_code != 200:
            return {
                "ok": False,
                "name": name,
                "rcode": "ERROR",
                "answer": None,
                "votes": {},
                "winner": [],
                "disagreement": False,
                "required": None,
                "responders": None,
                "latency_ms": http_ms,
                "http_ms": http_ms,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "source": "resolver /query",
            }
        payload = response.json()
        payload["http_ms"] = http_ms
        payload.setdefault("source", "resolver /query")
        return payload
    except Exception as exc:
        http_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return {
            "ok": False,
            "name": name,
            "rcode": "ERROR",
            "answer": None,
            "votes": {},
            "winner": [],
            "disagreement": False,
            "required": None,
            "responders": None,
            "latency_ms": http_ms,
            "http_ms": http_ms,
            "error": f"{type(exc).__name__}: {exc}",
            "source": "resolver /query",
        }
