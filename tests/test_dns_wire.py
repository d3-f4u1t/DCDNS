"""Wire-level tests for the DNS engine (no network required)."""

from __future__ import annotations

import socket
import struct

import pytest

from dcdns.dns_server import DNSEngine, parse_name


def build_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    header = b"\xab\xcd" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return header + qname + b"\x00" + struct.pack("!HH", qtype, qclass)


def parse_response(data: bytes) -> dict:
    tid = data[:2]
    flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHH", data[2:12])
    _, offset = parse_name(data, 12)
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    answers = []
    for _ in range(ancount):
        _, offset = parse_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        answers.append(
            {"type": rtype, "class": rclass, "ttl": ttl,
             "address": socket.inet_ntoa(rdata) if rtype == 1 else rdata}
        )
    return {
        "id": tid,
        "qr": bool(flags & 0x8000),
        "aa": bool(flags & 0x0400),
        "rcode": flags & 0x000F,
        "ancount": ancount,
        "qtype": qtype,
        "answers": answers,
    }


@pytest.fixture
def engine():
    eng = DNSEngine()
    eng.publish(
        {"techfest.cs.test": "10.20.5.42", "library.test": "10.20.6.10"},
        revision=7,
        source="http://n1",
    )
    return eng


def test_a_record_resolves(engine):
    response = parse_response(engine.handle(build_query("techfest.cs.test")))
    assert response["qr"] is True
    assert response["aa"] is True
    assert response["rcode"] == 0
    assert response["ancount"] == 1
    assert response["answers"][0]["address"] == "10.20.5.42"
    assert response["answers"][0]["ttl"] == 30


def test_query_is_case_insensitive(engine):
    response = parse_response(engine.handle(build_query("TechFest.CS.Test")))
    assert response["answers"][0]["address"] == "10.20.5.42"


def test_unknown_name_returns_nxdomain(engine):
    response = parse_response(engine.handle(build_query("nope.cs.test")))
    assert response["rcode"] == 3
    assert response["ancount"] == 0


def test_transaction_id_is_echoed(engine):
    response = parse_response(engine.handle(build_query("techfest.cs.test")))
    assert response["id"] == b"\xab\xcd"


def test_any_query_returns_the_a_record(engine):
    response = parse_response(engine.handle(build_query("techfest.cs.test", qtype=255)))
    assert response["ancount"] == 1


def test_unsupported_type_is_rejected_without_lying(engine):
    response = parse_response(engine.handle(build_query("techfest.cs.test", qtype=28)))
    assert response["rcode"] == 4  # NOTIMP
    assert response["ancount"] == 0


def test_malformed_packet_does_not_crash(engine):
    assert engine.handle(b"\x00") is None
    assert engine.handle(b"\x00" * 40) is not None


def test_publishing_a_new_revision_changes_answers(engine):
    engine.publish({"techfest.cs.test": "10.20.5.99"}, revision=8, source="http://n2")
    response = parse_response(engine.handle(build_query("techfest.cs.test")))
    assert response["answers"][0]["address"] == "10.20.5.99"


def test_revoked_names_disappear_from_the_zone(engine):
    engine.publish({}, revision=9, source="http://n1")
    response = parse_response(engine.handle(build_query("techfest.cs.test")))
    assert response["rcode"] == 3


def test_metrics_report_publication_state(engine):
    engine.handle(build_query("techfest.cs.test"))
    metrics = engine.metrics()
    assert metrics["published_revision"] == 7
    assert metrics["answered"] == 1
    assert metrics["zone_size"] == 2
