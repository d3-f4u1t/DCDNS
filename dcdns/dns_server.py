"""DNS wire format and query engine.

This is a real DNS implementation: it parses and emits the RFC 1035 wire
format, so an ordinary resolver (`dig`, a stub resolver, a test client) can
query it. It contains **no server loop and no publication loop**. Each registry
node embeds a :class:`DNSEngine` inside ``NodeDNSResponder`` and feeds it that
node's own committed zone snapshot. A client-facing quorum resolver asks all
nodes and requires a majority of semantically identical answers.

The publication rule is decided by the registry state
(``state.snapshot_for_dns``), not here: a name is published when the domain is
not revoked and its governing namespace is active. A ``pending_transfer`` name
keeps resolving from its frozen record.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

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
def build_query(
    name: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    transaction_id: bytes = b"\x7f\x01",
) -> bytes:
    """Build a single-question DNS query packet.

    Used by the portal probe, the resolver's ``/query`` introspection endpoint
    and the command-line client. Keeping one encoder here means the probe sees
    exactly the same wire format as an ordinary client.
    """
    if not isinstance(transaction_id, bytes) or len(transaction_id) != 2:
        raise ValueError("transaction_id must be two bytes")
    labels = name.strip().rstrip(".").split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS name")
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in labels
    ) + b"\x00"
    return (
        transaction_id
        + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", qtype, qclass)
    )


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
    """Stateless-ish query engine over one node's committed zone snapshot."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.zone: dict[str, str] = {}
        self.published_revision = 0
        self.source = "-"
        self.published_at_monotonic = time.monotonic()
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
        return {
            "published_revision": revision,
            "zone_size": len(zone),
            "zone": zone,
            "source": self.source,
            "seconds_since_publish": round(age, 3),
            "queries": self.queries,
            "answered": self.answered,
            "nxdomain": self.nxdomain,
            "recent": self.recent[-15:],
        }
