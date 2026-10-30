"""DNS responder embedded in every registry node.

There is no separate DNS server process. Each registry node answers queries
directly from its own committed state, on its own port. If a node is down, the
others keep answering.

A node can only answer for what it has committed. Followers therefore answer
from a state that may be a fraction of a second behind the leader, which is
visible in the per-node revision reported on the dashboard.

The responder can also be *frozen* for a controlled stale-majority experiment:
it keeps serving the exact zone snapshot it had at the moment of the freeze,
while the registry keeps committing and replicating. The frozen snapshot is a
real committed state at a real revision, not a fabricated answer. The freeze is
loopback-only fault injection and is disabled unless the node was started with
``--chaos``.
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
        signer=None,
        snapshot_provider=None,
    ) -> None:
        super().__init__(daemon=True, name=f"dns-{node_id}")
        self.node_id = node_id
        self.host = host
        self.port = port
        self.zone_provider = zone_provider
        self.revision_provider = revision_provider
        self.snapshot_provider = snapshot_provider
        self.chaos_enabled = chaos_enabled
        self.signer = signer
        self.overrides: dict[str, str] = {}
        self.paused = False
        self.paused_queries = 0

        # Controlled replication-lag fault: while frozen, the responder serves
        # this committed snapshot and revision instead of the live one.
        self.frozen = False
        self.frozen_snapshot: dict[str, str] | None = None
        self.frozen_revision: int | None = None

        self.engine = DNSEngine()
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.error: str | None = None

    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_zone(published: dict) -> dict[str, str]:
        zone: dict[str, str] = {}
        for name, value in (published or {}).items():
            # The cluster exposes a flattened name -> address mapping. Accept
            # the record-set shape too, so the responder is easy to test and
            # can be fed from either representation.
            address = value.get("A") if isinstance(value, dict) else value
            if address:
                zone[str(name)] = str(address)
        return zone

    def _published_zone(self) -> dict[str, str]:
        """Return the base zone without chaos overrides."""
        if self.snapshot_provider is not None:
            zone, _ = self.snapshot_provider()
        else:
            zone = self.zone_provider() or {}
        return self._normalize_zone(zone)

    def zone(self) -> dict[str, str]:
        zone = self._published_zone()
        if self.overrides:
            zone.update(self.overrides)
        return zone

    def _base_snapshot(self) -> tuple[dict[str, str], int]:
        """Return the live zone and revision as one consistent pair."""
        if self.snapshot_provider is not None:
            zone, revision = self.snapshot_provider()
            zone = self._normalize_zone(zone)
            revision = int(revision or 0)
        else:
            zone = self._normalize_zone(self.zone_provider() or {})
            revision = int(self.revision_provider() or 0)
        if self.overrides:
            zone.update(self.overrides)
        return zone, revision

    def serving_snapshot(self) -> tuple[dict[str, str], int]:
        """Return the zone and revision this responder will use for a query."""
        if self.frozen and self.frozen_snapshot is not None:
            return dict(self.frozen_snapshot), int(self.frozen_revision or 0)
        return self._base_snapshot()

    def set_paused(self, paused: bool) -> bool:
        """Stop answering DNS queries without stopping the registry node.

        A paused responder drops the datagram. It deliberately does not return
        SERVFAIL: the quorum resolver must see an absent vote, not a vote for
        SERVFAIL, or two paused nodes could accidentally form a majority.
        """
        self.paused = bool(paused)
        return self.paused

    def set_frozen(self, frozen: bool) -> bool:
        """Pin (or release) the DNS snapshot for a stale-majority experiment.

        Freezing captures the exact zone and committed revision currently being
        served. The registry keeps running and committing; only this DNS
        responder keeps answering from the older committed snapshot. This
        reproduces the failure mode in which a majority of DNS nodes lag behind
        the committed registry revision without inventing any answer.
        """
        want = bool(frozen)
        if want:
            if not self.frozen or self.frozen_snapshot is None:
                zone, revision = self._base_snapshot()
                self.frozen_snapshot = dict(zone)
                self.frozen_revision = revision
            self.frozen = True
            self.engine.publish(
                self.frozen_snapshot,
                int(self.frozen_revision or 0),
                self.node_id,
                node_id=self.node_id,
                signer=self.signer,
            )
        else:
            self.frozen = False
            self.frozen_snapshot = None
            self.frozen_revision = None
            zone, revision = self.serving_snapshot()
            self.engine.publish(
                zone,
                revision,
                self.node_id,
                node_id=self.node_id,
                signer=self.signer,
            )
        return self.frozen

    def handle(self, data: bytes) -> bytes | None:
        if self.paused:
            self.paused_queries += 1
            return None
        zone, revision = self.serving_snapshot()
        self.engine.publish(
            zone,
            revision,
            self.node_id,
            node_id=self.node_id,
            signer=self.signer,
        )
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
        data["frozen"] = self.frozen
        data["frozen_revision"] = self.frozen_revision
        data["error"] = self.error
        return data

    def summary(self) -> dict:
        """Small status payload embedded in ``GET /status``."""
        # Publish the snapshot the responder would use right now, so a status
        # poll reports the same revision a DNS query would carry even before the
        # first query arrives. While frozen this is the pinned revision.
        zone, revision = self.serving_snapshot()
        self.engine.publish(
            zone,
            revision,
            self.node_id,
            node_id=self.node_id,
            signer=self.signer,
        )
        metrics = self.engine.metrics()
        registry_revision = int(self.revision_provider() or 0)
        serving_revision = int(metrics.get("published_revision", 0))
        snapshot = self.frozen_snapshot if self.frozen else self.zone()
        return {
            "enabled": True,
            "node_id": self.node_id,
            "port": self.port,
            # ``revision`` is the registry's committed DNS revision. The
            # ``serving_revision`` is what this responder last published.
            "revision": registry_revision,
            "serving_revision": serving_revision,
            "revision_lag": max(0, registry_revision - serving_revision),
            "frozen": self.frozen,
            "frozen_revision": self.frozen_revision,
            "signed": bool(metrics.get("revision_token_signed")),
            "public_key": self.signer.public_key if self.signer else None,
            "serving_digest": metrics.get("serving_digest"),
            "zone_size": len(snapshot),
            "queries": metrics["queries"],
            "answered": metrics["answered"],
            "nxdomain": metrics["nxdomain"],
            "overrides": dict(self.overrides),
            "paused": self.paused,
            "paused_queries": self.paused_queries,
            "error": self.error,
        }
