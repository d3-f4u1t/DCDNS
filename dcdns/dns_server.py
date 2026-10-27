"""DNS wire format and query engine.

This is a real DNS implementation: it parses and emits the RFC 1035 wire
format, so an ordinary resolver (`dig`, a stub resolver, a test client) can
query it. It contains **no server loop and no publication loop**. Each registry
node embeds a :class:`DNSEngine` inside ``NodeDNSResponder`` and feeds it that
node's own committed zone snapshot. A client-facing quorum resolver asks all
nodes and requires a majority of semantically identical answers.

Revision metadata
-----------------
A node can attach the committed revision that produced its answer to the DNS
response as a private EDNS(0) option (``EDNS_OPTION_REVISION``). The option
carries the node id, the revision, a digest of the exact zone snapshot, and an
optional Ed25519 signature by the node's registry key. This is the transport
for the revision-aware majority DNS (RAM-DNS) freshness check. The resolver can
also fall back to the node status API when a response has no EDNS metadata.

The publication rule is decided by the registry state
(``state.snapshot_for_dns``), not here: a name is published when the domain is
not revoked and its governing namespace is active. A ``pending_transfer`` name
keeps resolving from its frozen record.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import time
from dataclasses import dataclass

DNS_TTL = 30
TYPE_A = 1
TYPE_OPT = 41
TYPE_ANY = 255
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4

# EDNS(0) local/experimental option range (RFC 6891 reserves 65001-65534 for
# local use). Both options are private to this prototype.
EDNS_UDP_PAYLOAD = 1232
EDNS_OPTION_REVISION = 65001
EDNS_OPTION_STALE = 65002

REVISION_TOKEN_VERSION = 1
STALE_MARKER_VERSION = 1
REVISION_SIGNING_CONTEXT = b"DCDNS-DNS-REV-V1\n"

REVISION_DIGEST_BYTES = 16
SIGNATURE_BYTES = 64


# --------------------------------------------------------------------------- #
# revision metadata
# --------------------------------------------------------------------------- #
def zone_digest(zone: dict[str, str]) -> bytes:
    """Deterministic digest binding a revision token to an exact zone snapshot."""
    payload = json.dumps(
        sorted((str(name), str(address)) for name, address in zone.items()),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.blake2b(payload, digest_size=REVISION_DIGEST_BYTES).digest()


def revision_signing_bytes(
    version: int,
    node_id: str,
    revision: int,
    digest: bytes,
) -> bytes:
    """Domain-separated bytes signed by a node's registry key."""
    payload = json.dumps(
        {
            "v": int(version),
            "node": str(node_id),
            "revision": int(revision),
            "digest": bytes(digest).hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return REVISION_SIGNING_CONTEXT + payload


@dataclass(frozen=True)
class RevisionMetadata:
    """Decoded EDNS revision option."""

    version: int
    node_id: str
    revision: int
    digest: bytes
    signature: bytes

    @property
    def signed(self) -> bool:
        return bool(self.signature)

    @property
    def digest_hex(self) -> str:
        return self.digest.hex()

    def signing_payload(self) -> bytes:
        return revision_signing_bytes(
            self.version, self.node_id, self.revision, self.digest
        )


def _signer_bytes(signer, payload: bytes) -> bytes:
    """Accept a KeyPair-like object whose ``sign`` returns base64 text."""
    signature = signer.sign(payload)
    if isinstance(signature, str):
        return base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    return bytes(signature)


def encode_revision_token(
    node_id: str,
    revision: int,
    digest: bytes,
    signer=None,
) -> bytes:
    """Encode the private EDNS revision option payload.

    Layout::

        u8  version
        u8  node_id_len
        ..  node_id (UTF-8)
        u64 revision (big endian)
        16  zone digest (BLAKE2b-128)
        u8  signature_len (0 or 64)
        ..  Ed25519 signature over revision_signing_bytes(...)
    """
    node_bytes = str(node_id).encode("utf-8")[:255]
    if len(digest) != REVISION_DIGEST_BYTES:
        raise ValueError("revision digest must be 16 bytes")
    signature = b""
    if signer is not None:
        signature = _signer_bytes(
            signer,
            revision_signing_bytes(
                REVISION_TOKEN_VERSION, node_id, int(revision), digest
            ),
        )
        if len(signature) != SIGNATURE_BYTES:
            raise ValueError("unexpected Ed25519 signature length")
    return (
        bytes([REVISION_TOKEN_VERSION, len(node_bytes)])
        + node_bytes
        + struct.pack("!Q", int(revision))
        + digest
        + bytes([len(signature)])
        + signature
    )


def decode_revision_token(data: bytes) -> RevisionMetadata | None:
    if not data or len(data) < 2:
        return None
    version = data[0]
    if version != REVISION_TOKEN_VERSION:
        return None
    node_len = data[1]
    offset = 2
    if offset + node_len + 8 + REVISION_DIGEST_BYTES + 1 > len(data):
        return None
    node_id = data[offset:offset + node_len].decode("utf-8", errors="replace")
    offset += node_len
    revision = struct.unpack("!Q", data[offset:offset + 8])[0]
    offset += 8
    digest = data[offset:offset + REVISION_DIGEST_BYTES]
    offset += REVISION_DIGEST_BYTES
    signature_len = data[offset]
    offset += 1
    if offset + signature_len != len(data):
        return None
    if signature_len not in (0, SIGNATURE_BYTES):
        return None
    return RevisionMetadata(
        version=version,
        node_id=node_id,
        revision=revision,
        digest=digest,
        signature=data[offset:offset + signature_len],
    )


def encode_stale_marker(
    watermark: int,
    majority_revision: int,
    retries: int,
) -> bytes:
    """Payload of the private stale-answer marker EDNS option."""
    return (
        bytes([STALE_MARKER_VERSION])
        + struct.pack("!QQB", int(watermark), int(majority_revision), int(retries) & 0xFF)
    )


def decode_stale_marker(data: bytes) -> dict | None:
    if not data or len(data) < 18 or data[0] != STALE_MARKER_VERSION:
        return None
    watermark, majority_revision, retries = struct.unpack("!QQB", data[1:18])
    return {
        "version": data[0],
        "watermark": watermark,
        "majority_revision": majority_revision,
        "retries": retries,
    }


# --------------------------------------------------------------------------- #
# wire format
# --------------------------------------------------------------------------- #
def build_query(
    name: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    transaction_id: bytes = b"\x7f\x01",
    edns: bool = True,
) -> bytes:
    """Build a single-question DNS query packet.

    Used by the portal probe, the resolver's ``/query`` introspection endpoint
    and the command-line client. Keeping one encoder here means the probe sees
    exactly the same wire format as an ordinary client.

    When ``edns`` is true (the default) the query advertises EDNS(0) and asks
    for revision metadata with an empty private option. A node that understands
    the option returns its signed revision token in the response.
    """
    if not isinstance(transaction_id, bytes) or len(transaction_id) != 2:
        raise ValueError("transaction_id must be two bytes")
    labels = name.strip().rstrip(".").split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS name")
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in labels
    ) + b"\x00"
    arcount = 1 if edns else 0
    packet = (
        transaction_id
        + struct.pack("!HHHHH", 0x0100, 1, 0, 0, arcount)
        + qname
        + struct.pack("!HH", qtype, qclass)
    )
    if edns:
        packet += build_opt_record([(EDNS_OPTION_REVISION, b"")])
    return packet


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


def build_opt_record(
    options: list[tuple[int, bytes]] | None = None,
    udp_payload: int = EDNS_UDP_PAYLOAD,
) -> bytes:
    """Build an EDNS(0) OPT pseudo-record (root name, type 41)."""
    rdata = b"".join(
        struct.pack("!HH", int(code), len(data)) + bytes(data)
        for code, data in (options or [])
    )
    return (
        b"\x00"
        + struct.pack("!HHIH", TYPE_OPT, udp_payload, 0, len(rdata))
        + rdata
    )


def _parse_sections(data: bytes) -> dict:
    """Parse a DNS packet into raw section records.

    Raw records retain any compression pointers. Rebuilding a packet from them
    is safe as long as the question section is unchanged and records stay in
    their original order, which is true for the operations in this module.
    """
    if len(data) < 12:
        raise ValueError("truncated header")
    transaction_id = data[:2]
    flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHH", data[2:12])
    offset = 12

    questions: list[bytes] = []
    for _ in range(qdcount):
        start = offset
        _, offset = parse_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("truncated question")
        offset += 4
        questions.append(data[start:offset])

    def read_records(count: int) -> list[dict]:
        nonlocal offset
        records: list[dict] = []
        for _ in range(count):
            start = offset
            _, name_end = parse_name(data, offset)
            if name_end + 10 > len(data):
                raise ValueError("truncated record")
            rtype, rclass, ttl, rdlength = struct.unpack(
                "!HHIH", data[name_end:name_end + 10]
            )
            rdata_start = name_end + 10
            end = rdata_start + rdlength
            if end > len(data):
                raise ValueError("truncated rdata")
            records.append(
                {
                    "start": start,
                    "name_end": name_end,
                    "type": rtype,
                    "class": rclass,
                    "ttl": ttl,
                    "rdata": data[rdata_start:end],
                    "raw": data[start:end],
                }
            )
            offset = end
        return records

    answers = read_records(ancount)
    authority = read_records(nscount)
    additional = read_records(arcount)
    return {
        "id": transaction_id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authority": authority,
        "additional": additional,
    }


def _rebuild(
    parsed: dict,
    answers: list[bytes],
    authority: list[bytes],
    additional: list[bytes],
    flags: int | None = None,
) -> bytes:
    header = parsed["id"] + struct.pack(
        "!HHHHH",
        parsed["flags"] if flags is None else flags,
        len(parsed["questions"]),
        len(answers),
        len(authority),
        len(additional),
    )
    return (
        header
        + b"".join(parsed["questions"])
        + b"".join(answers)
        + b"".join(authority)
        + b"".join(additional)
    )


def parse_edns_options(data: bytes) -> list[tuple[int, bytes]]:
    """Return ``(option_code, option_data)`` pairs from the OPT record."""
    try:
        parsed = _parse_sections(data)
    except Exception:
        return []
    options: list[tuple[int, bytes]] = []
    for record in parsed["additional"]:
        if record["type"] != TYPE_OPT:
            continue
        rdata = record["rdata"]
        offset = 0
        while offset + 4 <= len(rdata):
            code, length = struct.unpack("!HH", rdata[offset:offset + 4])
            offset += 4
            if offset + length > len(rdata):
                break
            options.append((code, rdata[offset:offset + length]))
            offset += length
    return options


def parse_revision_metadata(response: bytes) -> RevisionMetadata | None:
    for code, data in parse_edns_options(response):
        if code == EDNS_OPTION_REVISION:
            return decode_revision_token(data)
    return None


def parse_stale_marker(response: bytes) -> dict | None:
    for code, data in parse_edns_options(response):
        if code == EDNS_OPTION_STALE:
            return decode_stale_marker(data)
    return None


def has_edns(data: bytes) -> bool:
    try:
        parsed = _parse_sections(data)
    except Exception:
        return False
    return any(record["type"] == TYPE_OPT for record in parsed["additional"])


def ensure_edns(query: bytes) -> bytes:
    """Return ``query`` with an EDNS OPT record, adding one if necessary.

    The quorum resolver uses this so a client query that predates EDNS still
    receives revision metadata from every node. Existing EDNS queries are
    forwarded unchanged.
    """
    if len(query) < 12:
        return query
    try:
        parsed = _parse_sections(query)
    except Exception:
        return query
    if any(record["type"] == TYPE_OPT for record in parsed["additional"]):
        return query
    additional = [record["raw"] for record in parsed["additional"]]
    additional.append(build_opt_record([]))
    return _rebuild(
        parsed,
        [record["raw"] for record in parsed["answers"]],
        [record["raw"] for record in parsed["authority"]],
        additional,
    )


def mark_stale_response(
    response: bytes,
    watermark: int,
    majority_revision: int,
    retries: int,
    ttl: int = 5,
) -> bytes:
    """Return a copy of a DNS response explicitly marked as stale.

    The answer records keep their content but get a reduced TTL, and a private
    EDNS option carries the watermark, the majority's revision, and the number
    of retries. The original revision option (if any) is preserved. A client
    that does not understand the option sees a short-TTL answer; a RAM-DNS
    aware client can distinguish it from a fresh answer.
    """
    try:
        parsed = _parse_sections(response)
    except Exception:
        return response

    answers: list[bytes] = []
    for record in parsed["answers"]:
        raw = record["raw"]
        name_len = record["name_end"] - record["start"]
        rtype, rclass, _old_ttl, rdlength = struct.unpack(
            "!HHIH", raw[name_len:name_len + 10]
        )
        new_header = struct.pack("!HHIH", rtype, rclass, int(ttl), rdlength)
        answers.append(raw[:name_len] + new_header + raw[name_len + 10:])

    options = [
        (code, data)
        for code, data in parse_edns_options(response)
        if code != EDNS_OPTION_STALE
    ]
    options.append(
        (EDNS_OPTION_STALE, encode_stale_marker(watermark, majority_revision, retries))
    )
    additional = [
        record["raw"]
        for record in parsed["additional"]
        if record["type"] != TYPE_OPT
    ]
    additional.append(build_opt_record(options))
    return _rebuild(
        parsed,
        answers,
        [record["raw"] for record in parsed["authority"]],
        additional,
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

        self.node_id = ""
        self.signer = None
        self.zone_digest = zone_digest({})
        self.revision_token = b""
        self.revision_token_signed = False
        self._token_key: tuple | None = None

    # -- publication ----------------------------------------------------- #
    def publish(
        self,
        zone: dict[str, str],
        revision: int,
        source: str,
        node_id: str | None = None,
        signer=None,
    ) -> None:
        with self._lock:
            changed = revision != self.published_revision or zone != self.zone
            self.zone = dict(zone)
            if changed:
                self.published_revision = revision
                self.published_at_monotonic = time.monotonic()
            self.source = source
            if node_id is not None:
                self.node_id = str(node_id)
            self.signer = signer

            digest = zone_digest(self.zone)
            token_key = (
                self.node_id,
                int(self.published_revision),
                digest,
                id(self.signer),
            )
            if token_key != self._token_key:
                self.zone_digest = digest
                if self.node_id:
                    self.revision_token = encode_revision_token(
                        self.node_id,
                        self.published_revision,
                        digest,
                        self.signer,
                    )
                else:
                    self.revision_token = b""
                self.revision_token_signed = bool(self.signer)
                self._token_key = token_key

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
            wants_edns = has_edns(data)

            self.queries += 1
            answers: list[bytes] = []
            rcode = RCODE_NOERROR

            with self._lock:
                address = self.zone.get(qname)
                revision = self.published_revision
                token = self.revision_token

            if qclass != CLASS_IN or qtype not in (TYPE_A, TYPE_ANY):
                rcode = RCODE_NOTIMP if qclass == CLASS_IN else RCODE_FORMERR
            elif address is None:
                rcode = RCODE_NXDOMAIN
                self.nxdomain += 1
            else:
                answers.append(encode_answer(qname, address))
                self.answered += 1

            additional: list[bytes] = []
            if wants_edns:
                options: list[tuple[int, bytes]] = []
                if token:
                    options.append((EDNS_OPTION_REVISION, token))
                additional.append(build_opt_record(options))

            entry = {
                "name": qname,
                "qtype": qtype,
                "answer": address,
                "rcode": "NOERROR" if address else ("NXDOMAIN" if rcode == 3 else "ERROR"),
                "revision": revision,
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
                "!HHHHH", response_flags, 1, len(answers), 0, len(additional)
            )
            body = (
                data[question_start:question_end]
                + b"".join(answers)
                + b"".join(additional)
            )
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
            digest = self.zone_digest.hex()
            signed = self.revision_token_signed
            node_id = self.node_id
        return {
            "published_revision": revision,
            "serving_revision": revision,
            "zone_size": len(zone),
            "zone": zone,
            "source": self.source,
            "seconds_since_publish": round(age, 3),
            "queries": self.queries,
            "answered": self.answered,
            "nxdomain": self.nxdomain,
            "recent": self.recent[-15:],
            "node_id": node_id,
            "serving_digest": digest,
            "revision_token_signed": signed,
        }
