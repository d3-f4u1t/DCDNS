"""DNS responder embedded in every registry node.

There is no separate DNS server process. Each registry node answers queries
directly from its own committed state, on its own port. If a node is down, the
others keep answering.

A node can only answer for what it has committed. Followers therefore answer
from a state that may be a fraction of a second behind the leader, which is
visible in the per-node revision reported on the dashboard.
"""

from __future__ import annotations

import socket
import threading

from .dns_server import DNSEngine


class NodeDNSResponder(threading.Thread):
    """UDP DNS listener bound to one registry node."""

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        zone_provider,
        revision_provider,
        chaos_enabled: bool = False,
    ) -> None:
        super().__init__(daemon=True, name=f"dns-{node_id}")
        self.node_id = node_id
        self.host = host
        self.port = port
        self.zone_provider = zone_provider
        self.revision_provider = revision_provider
        self.chaos_enabled = chaos_enabled
        self.overrides: dict[str, str] = {}
        self.paused = False
        self.paused_queries = 0
        self.engine = DNSEngine()
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.error: str | None = None

    # ------------------------------------------------------------------ #
    def zone(self) -> dict[str, str]:
        published = self.zone_provider() or {}
        zone: dict[str, str] = {}
        for name, value in published.items():
            # The cluster exposes a flattened name -> address mapping. Accept
            # the record-set shape too, so the responder is easy to test and
            # can be fed from either representation.
            address = value.get("A") if isinstance(value, dict) else value
            if address:
                zone[str(name)] = str(address)
        if self.overrides:
            zone.update(self.overrides)
        return zone

    def set_paused(self, paused: bool) -> bool:
        """Stop answering DNS queries without stopping the registry node.

        A paused responder drops the datagram. It deliberately does not return
        SERVFAIL: the quorum resolver must see an absent vote, not a vote for
        SERVFAIL, or two paused nodes could accidentally form a majority.
        """
        self.paused = bool(paused)
        return self.paused

    def handle(self, data: bytes) -> bytes | None:
        if self.paused:
            self.paused_queries += 1
            return None
        self.engine.publish(self.zone(), self.revision_provider(), self.node_id)
        return self.engine.handle(data)

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(1.0)
            self.sock = sock
        except OSError as exc:
            self.error = f"could not bind udp/{self.port}: {exc}"
            return

        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            response = self.handle(data)
            if response:
                try:
                    sock.sendto(response, addr)
                except OSError:
                    pass

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def metrics(self) -> dict:
        data = self.engine.metrics()
        data["node_id"] = self.node_id
        data["port"] = self.port
        data["overrides"] = dict(self.overrides)
        data["paused"] = self.paused
        data["paused_queries"] = self.paused_queries
        data["error"] = self.error
        return data

    def summary(self) -> dict:
        """Small status payload embedded in ``GET /status``."""
        metrics = self.engine.metrics()
        return {
            "enabled": True,
            "node_id": self.node_id,
            "port": self.port,
            "revision": self.revision_provider(),
            "zone_size": len(self.zone()),
            "queries": metrics["queries"],
            "answered": metrics["answered"],
            "nxdomain": metrics["nxdomain"],
            "overrides": dict(self.overrides),
            "paused": self.paused,
            "paused_queries": self.paused_queries,
            "error": self.error,
        }
