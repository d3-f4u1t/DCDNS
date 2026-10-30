"""Tests for the decentralized DNS layer.

The important property is not "a DNS server answers". It is that the
client-facing resolver only accepts an answer when a majority of independent
nodes agree, so a single lying node cannot change what a name resolves to.
"""

from __future__ import annotations

import socket
import struct

import pytest

from dcdns.dns_node import NodeDNSResponder
from dcdns.dns_server import DNSEngine, parse_name
from dcdns.quorum_resolver import (
    QuorumResolver,
    answer_text,
    build_servfail,
    evaluate_responses,
    semantic_answer,
)


def build_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    header = b"\xab\xcd" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return header + qname + b"\x00" + struct.pack("!HH", qtype, qclass)


def parse_response(data: bytes) -> dict:
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
        "flags": flags,
        "rcode": flags & 0x000F,
        "qdcount": qdcount,
        "ancount": ancount,
        "qtype": qtype,
        "answers": answers,
        "ra": bool(flags & 0x0080),
        "aa": bool(flags & 0x0400),
    }


def engine_with(zone: dict[str, str]) -> DNSEngine:
    engine = DNSEngine()
    engine.publish(zone, revision=1, source="test")
    return engine


# --------------------------------------------------------------------------- #
# majority decision
# --------------------------------------------------------------------------- #
def test_majority_answer_wins_over_one_liar():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    liar = engine_with({"techfest.cs.test": "10.20.5.66"})

    responses = {
        "n1": good.handle(query),
        "n2": good.handle(query),
        "n3": liar.handle(query),
    }
    decision = evaluate_responses(responses, required=2)

    assert decision.ok is True
    assert decision.winner_nodes == ["n1", "n2"]
    assert decision.votes["n3"] == "10.20.5.66"
    assert decision.disagreement is True
    assert answer_text(decision.winner) == "10.20.5.42"


def test_two_of_three_is_enough_when_one_node_is_down():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    responses = {"n1": good.handle(query), "n2": good.handle(query), "n3": None}

    decision = evaluate_responses(responses, required=2)

    assert decision.ok is True
    assert decision.winner_nodes == ["n1", "n2"]
    assert decision.disagreement is False


def test_one_node_cannot_answer_for_the_cluster():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    responses = {"n1": good.handle(query), "n2": None, "n3": None}

    decision = evaluate_responses(responses, required=2)

    assert decision.ok is False
    assert decision.winner is None
    assert decision.votes["n1"] == "10.20.5.42"


def test_split_vote_produces_no_majority():
    query = build_query("techfest.cs.test")
    a = engine_with({"techfest.cs.test": "10.20.5.42"})
    b = engine_with({"techfest.cs.test": "10.20.5.66"})
    responses = {"n1": a.handle(query), "n2": b.handle(query), "n3": None}

    decision = evaluate_responses(responses, required=2)

    assert decision.ok is False
    assert decision.disagreement is True


def test_agreement_on_nxdomain():
    query = build_query("missing.cs.test")
    empty = engine_with({})
    responses = {
        "n1": empty.handle(query),
        "n2": empty.handle(query),
        "n3": empty.handle(query),
    }

    decision = evaluate_responses(responses, required=2)

    assert decision.ok is True
    assert decision.winner[0] == 3
    assert answer_text(decision.winner) == "NXDOMAIN"


def test_malformed_response_is_not_a_vote():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    responses = {
        "n1": good.handle(query),
        "n2": good.handle(query),
        "n3": b"\x00\x01\x02",
    }

    decision = evaluate_responses(responses, required=2)

    assert decision.ok is True
    assert decision.votes["n3"] == "malformed"
    assert decision.disagreement is True


def test_servfail_response_is_valid_dns_with_the_question():
    query = build_query("techfest.cs.test")
    response = build_servfail(query)
    parsed = parse_response(response)

    assert parsed["rcode"] == 2
    assert parsed["qdcount"] == 1
    assert parsed["ancount"] == 0
    assert parsed["ra"] is True
    assert response[:2] == b"\xab\xcd"


# --------------------------------------------------------------------------- #
# resolver over an injected transport
# --------------------------------------------------------------------------- #
def test_resolver_returns_majority_answer_and_ignores_liar():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    liar = engine_with({"techfest.cs.test": "10.20.5.66"})
    engines = {"n1": good, "n2": good, "n3": liar}

    def fake_query(host, port, data, timeout):
        return engines[host].handle(data)

    resolver = QuorumResolver(
        nodes={"n1": ("n1", 5354), "n2": ("n2", 5355), "n3": ("n3", 5356)},
        required=2,
        query_node=fake_query,
    )
    try:
        response = resolver.resolve(query)
        parsed = parse_response(response)
        metrics = resolver.metrics()
    finally:
        resolver.stop()

    assert parsed["rcode"] == 0
    assert parsed["answers"][0]["address"] == "10.20.5.42"
    assert metrics["queries"] == 1
    assert metrics["answered"] == 1
    assert metrics["disagreements"] == 1
    assert metrics["servfail"] == 0


def test_resolver_returns_servfail_without_a_majority():
    query = build_query("techfest.cs.test")
    a = engine_with({"techfest.cs.test": "10.20.5.42"})
    b = engine_with({"techfest.cs.test": "10.20.5.66"})
    engines = {"n1": a, "n2": b}

    def fake_query(host, port, data, timeout):
        return engines[host].handle(data)

    resolver = QuorumResolver(
        nodes={"n1": ("n1", 5354), "n2": ("n2", 5355), "n3": ("n3", 5356)},
        required=2,
        query_node=fake_query,
    )
    try:
        response = resolver.resolve(query)
        parsed = parse_response(response)
        metrics = resolver.metrics()
    finally:
        resolver.stop()

    assert parsed["rcode"] == 2
    assert parsed["ancount"] == 0
    assert metrics["servfail"] == 1
    assert metrics["answered"] == 0


# --------------------------------------------------------------------------- #
# per-node responder
# --------------------------------------------------------------------------- #
def test_node_responder_serves_its_own_committed_zone():
    zone = {"techfest.cs.test": "10.20.5.42"}
    responder = NodeDNSResponder(
        "n1", "127.0.0.1", 0,
        zone_provider=lambda: zone,
        revision_provider=lambda: 7,
    )
    parsed = parse_response(responder.handle(build_query("techfest.cs.test")))

    assert parsed["rcode"] == 0
    assert parsed["answers"][0]["address"] == "10.20.5.42"
    assert responder.metrics()["published_revision"] == 7


def test_node_responder_can_be_made_to_lie_for_the_demo():
    zone = {"techfest.cs.test": "10.20.5.42"}
    responder = NodeDNSResponder(
        "n3", "127.0.0.1", 0,
        zone_provider=lambda: zone,
        revision_provider=lambda: 7,
        chaos_enabled=True,
    )
    responder.overrides["techfest.cs.test"] = "10.20.5.66"
    parsed = parse_response(responder.handle(build_query("techfest.cs.test")))

    assert parsed["answers"][0]["address"] == "10.20.5.66"
    assert responder.summary()["overrides"] == {"techfest.cs.test": "10.20.5.66"}


def test_node_responder_pause_drops_queries_and_reports_state():
    zone = {"techfest.cs.test": "10.20.5.42"}
    responder = NodeDNSResponder(
        "n2", "127.0.0.1", 0,
        zone_provider=lambda: zone,
        revision_provider=lambda: 7,
    )

    assert responder.set_paused(True) is True
    assert responder.handle(build_query("techfest.cs.test")) is None
    assert responder.summary()["paused"] is True
    assert responder.summary()["paused_queries"] == 1

    assert responder.set_paused(False) is False
    parsed = parse_response(responder.handle(build_query("techfest.cs.test")))
    assert parsed["answers"][0]["address"] == "10.20.5.42"
    assert responder.summary()["paused"] is False


def test_resolve_detail_exposes_the_same_decision_and_vote_map():
    query = build_query("techfest.cs.test")
    good = engine_with({"techfest.cs.test": "10.20.5.42"})
    liar = engine_with({"techfest.cs.test": "10.20.5.66"})
    engines = {"n1": good, "n2": good, "n3": liar}

    def fake_query(host, port, data, timeout):
        return engines[host].handle(data)

    resolver = QuorumResolver(
        nodes={"n1": ("n1", 5354), "n2": ("n2", 5355), "n3": ("n3", 5356)},
        required=2,
        query_node=fake_query,
    )
    try:
        detail = resolver.resolve_detail(query)
        metrics = resolver.metrics()
    finally:
        resolver.stop()

    assert detail["ok"] is True
    assert detail["answer"] == "10.20.5.42"
    assert detail["votes"] == {
        "n1": "10.20.5.42",
        "n2": "10.20.5.42",
        "n3": "10.20.5.66",
    }
    assert detail["winner"] == ["n1", "n2"]
    assert detail["disagreement"] is True
    assert detail["required"] == 2
    assert detail["latency_ms"] >= 0
    assert metrics["queries"] == 1
    assert metrics["recent"][-1]["votes"] == detail["votes"]
