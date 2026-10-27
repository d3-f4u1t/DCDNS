"""Tests for revision-aware majority DNS (RAM-DNS).

The semantic majority tests live in ``test_quorum_resolver.py``. These tests
cover the freshness layer that sits on top of that decision:

* the private EDNS(0) revision token and its signature;
* the F1/F2/F3 freshness conditions and watermark sources;
* bounded retries and the fail-closed / marked-stale policies;
* the real DNS-snapshot freeze used by the stale-majority experiment.

No test fabricates an answer. The stale-majority cases build responses from
:class:`~dcdns.dns_server.DNSEngine` instances that really hold an older
committed revision, and the freeze test pins a real provider snapshot.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from dcdns import crypto
from dcdns.dns_node import NodeDNSResponder
from dcdns.dns_server import (
    DNSEngine,
    EDNS_OPTION_REVISION,
    EDNS_OPTION_STALE,
    RCODE_NXDOMAIN,
    build_opt_record,
    build_query,
    decode_revision_token,
    decode_stale_marker,
    encode_revision_token,
    ensure_edns,
    has_edns,
    mark_stale_response,
    parse_edns_options,
    parse_name,
    parse_revision_metadata,
    parse_stale_marker,
    revision_signing_bytes,
    zone_digest,
)
from dcdns.quorum_resolver import (
    FreshnessPolicy,
    QuorumResolver,
    RevisionEvidence,
    evaluate_responses,
    revision_evidence,
)

NAME = "techfest.cs.test"
OLD = "10.20.5.42"
NEW = "10.20.5.99"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def engine(
    zone: dict[str, str],
    revision: int,
    node_id: str = "",
    signer=None,
) -> DNSEngine:
    item = DNSEngine()
    item.publish(
        zone,
        revision=revision,
        source="test",
        node_id=node_id or None,
        signer=signer,
    )
    return item


def response(
    zone: dict[str, str],
    revision: int,
    node_id: str = "",
    signer=None,
    name: str = NAME,
) -> bytes:
    return engine(zone, revision, node_id, signer).handle(build_query(name))


def first_answer(data: bytes) -> tuple[int, int, bytes]:
    _flags, _qdcount, ancount = struct.unpack("!HHH", data[2:8])
    assert ancount >= 1
    _, offset = parse_name(data, 12)
    offset += 4
    _, offset = parse_name(data, offset)
    rtype, _rclass, ttl, rdlength = struct.unpack(
        "!HHIH", data[offset:offset + 10]
    )
    offset += 10
    return rtype, ttl, data[offset:offset + rdlength]


def answer_address(data: bytes) -> str:
    rtype, _ttl, rdata = first_answer(data)
    assert rtype == 1
    return socket.inet_ntoa(rdata)


def revisions(responses: dict[str, bytes | None]) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for node_id, packet in responses.items():
        metadata = parse_revision_metadata(packet) if packet else None
        result[node_id] = metadata.revision if metadata else None
    return result


def stale_majority_responses() -> dict[str, bytes]:
    """n1/n2 agree on the old address at revision 7; n3 has revision 8."""
    return {
        "n1": response({NAME: OLD}, 7, "n1"),
        "n2": response({NAME: OLD}, 7, "n2"),
        "n3": response({NAME: NEW}, 8, "n3"),
    }


def fresh_majority_responses() -> dict[str, bytes]:
    """n1/n2 agree on the new address at revision 8; n3 is behind."""
    return {
        "n1": response({NAME: NEW}, 8, "n1"),
        "n2": response({NAME: NEW}, 8, "n2"),
        "n3": response({NAME: OLD}, 7, "n3"),
    }


# --------------------------------------------------------------------------- #
# EDNS revision token
# --------------------------------------------------------------------------- #
def test_revision_token_roundtrip_and_signature():
    key = crypto.KeyPair.generate(label="n1")
    digest = zone_digest({NAME: OLD})
    token = encode_revision_token("n1", 7, digest, key)

    metadata = decode_revision_token(token)
    assert metadata is not None
    assert metadata.version == 1
    assert metadata.node_id == "n1"
    assert metadata.revision == 7
    assert metadata.digest == digest
    assert metadata.signed is True
    assert crypto.verify_signature(
        key.public_key,
        metadata.signing_payload(),
        crypto.b64encode(metadata.signature),
    )


def test_revision_token_rejects_bad_lengths():
    assert decode_revision_token(b"") is None
    assert decode_revision_token(b"\x01") is None
    assert decode_revision_token(b"\x02" + b"\x00" * 40) is None
    assert decode_revision_token(b"\x01\x03n1") is None


def test_engine_attaches_signed_revision_to_positive_answer():
    key = crypto.KeyPair.generate(label="n1")
    packet = response({NAME: OLD}, 7, "n1", key)

    metadata = parse_revision_metadata(packet)
    assert metadata is not None
    assert metadata.revision == 7
    assert metadata.node_id == "n1"
    assert metadata.digest == zone_digest({NAME: OLD})
    assert metadata.signed is True
    assert parse_stale_marker(packet) is None


def test_engine_attaches_revision_to_nxdomain():
    packet = response({}, 9, "n2")
    metadata = parse_revision_metadata(packet)
    assert metadata is not None
    assert metadata.revision == 9
    assert struct.unpack("!H", packet[2:4])[0] & 0x000F == RCODE_NXDOMAIN


def test_engine_without_node_id_does_not_attach_a_token():
    packet = response({NAME: OLD}, 7, "")
    assert parse_revision_metadata(packet) is None
    # The response still carries an OPT record because the query advertised
    # EDNS, it just has no revision option.
    assert has_edns(packet)
    assert all(code != EDNS_OPTION_REVISION for code, _ in parse_edns_options(packet))


def test_revision_evidence_verifies_signed_token():
    key = crypto.KeyPair.generate(label="n1")
    packet = response({NAME: OLD}, 7, "n1", key)
    evidence = revision_evidence(
        packet, expected_node="n1", node_keys={"n1": key.public_key}
    )
    assert evidence.revision == 7
    assert evidence.source == "edns"
    assert evidence.verified is True
    assert evidence.error is None
    assert evidence.digest == zone_digest({NAME: OLD}).hex()


def test_revision_evidence_rejects_wrong_signature():
    signer = crypto.KeyPair.generate(label="n1")
    other = crypto.KeyPair.generate(label="n2")
    packet = response({NAME: OLD}, 7, "n1", signer)
    evidence = revision_evidence(
        packet, expected_node="n1", node_keys={"n1": other.public_key}
    )
    assert evidence.revision == 7
    assert evidence.verified is False
    assert evidence.error == "invalid-signature"


def test_revision_evidence_rejects_missing_signature_when_key_configured():
    key = crypto.KeyPair.generate(label="n1")
    packet = response({NAME: OLD}, 7, "n1", None)
    evidence = revision_evidence(
        packet, expected_node="n1", node_keys={"n1": key.public_key}
    )
    assert evidence.error == "missing-signature"
    assert evidence.verified is False


def test_revision_evidence_rejects_node_id_mismatch():
    key = crypto.KeyPair.generate(label="n1")
    packet = response({NAME: OLD}, 7, "n1", key)
    evidence = revision_evidence(
        packet, expected_node="n2", node_keys={"n2": key.public_key}
    )
    assert evidence.error == "node-id-mismatch"


def test_revision_evidence_accepts_unsigned_token_without_configured_key():
    packet = response({NAME: OLD}, 7, "n1", None)
    evidence = revision_evidence(packet, expected_node="n1", node_keys={})
    assert evidence.revision == 7
    assert evidence.verified is False
    assert evidence.error is None


def test_token_digest_is_bound_to_the_exact_zone():
    key = crypto.KeyPair.generate(label="n1")
    first = parse_revision_metadata(response({NAME: OLD}, 7, "n1", key))
    second = parse_revision_metadata(response({NAME: NEW}, 7, "n1", key))
    assert first is not None and second is not None
    assert first.digest != second.digest
    assert first.digest == zone_digest({NAME: OLD})
    assert second.digest == zone_digest({NAME: NEW})


def test_zone_digest_is_order_independent():
    assert zone_digest({"a.test": "10.0.0.1", "b.test": "10.0.0.2"}) == zone_digest(
        {"b.test": "10.0.0.2", "a.test": "10.0.0.1"}
    )
    assert zone_digest({"a.test": "10.0.0.1"}) != zone_digest(
        {"a.test": "10.0.0.2"}
    )


def test_revision_signing_bytes_are_domain_separated():
    digest = zone_digest({NAME: OLD})
    payload = revision_signing_bytes(1, "n1", 7, digest)
    assert payload.startswith(b"DCDNS-DNS-REV-V1\n")
    assert b'"node":"n1"' in payload
    assert b'"revision":7' in payload


# --------------------------------------------------------------------------- #
# EDNS transport helpers
# --------------------------------------------------------------------------- #
def test_ensure_edns_adds_one_opt_and_preserves_existing_edns():
    plain = build_query(NAME, edns=False)
    assert has_edns(plain) is False
    upgraded = ensure_edns(plain)
    assert has_edns(upgraded) is True
    assert ensure_edns(upgraded) == upgraded

    already = build_query(NAME)
    assert ensure_edns(already) == already


def test_opt_record_roundtrip_uses_private_option_numbers():
    packet = build_opt_record([(EDNS_OPTION_REVISION, b"x"), (EDNS_OPTION_STALE, b"y")])
    # Wrap it in a minimal response header so the section parser can read it.
    wrapped = (
        b"\xab\xcd"
        + struct.pack("!HHHHH", 0x8000, 0, 0, 0, 1)
        + packet
    )
    options = parse_edns_options(wrapped)
    assert options == [(EDNS_OPTION_REVISION, b"x"), (EDNS_OPTION_STALE, b"y")]


def test_mark_stale_response_keeps_answer_and_revision_but_reduces_ttl():
    key = crypto.KeyPair.generate(label="n1")
    packet = response({NAME: OLD}, 8, "n1", key)
    marked = mark_stale_response(
        packet, watermark=10, majority_revision=8, retries=2, ttl=5
    )

    assert answer_address(marked) == OLD
    rtype, ttl, _rdata = first_answer(marked)
    assert rtype == 1
    assert ttl == 5

    metadata = parse_revision_metadata(marked)
    assert metadata is not None
    assert metadata.revision == 8
    assert metadata.node_id == "n1"

    marker = parse_stale_marker(marked)
    assert marker == {
        "version": 1,
        "watermark": 10,
        "majority_revision": 8,
        "retries": 2,
    }


def test_stale_marker_decoder_rejects_malformed_payloads():
    assert decode_stale_marker(b"") is None
    assert decode_stale_marker(b"\x02" + b"\x00" * 17) is None
    assert decode_stale_marker(b"\x01" + b"\x00" * 10) is None


# --------------------------------------------------------------------------- #
# freshness conditions
# --------------------------------------------------------------------------- #
def test_f1_rejects_a_stale_majority():
    decision = evaluate_responses(
        stale_majority_responses(),
        2,
        FreshnessPolicy(condition="F1", delta=0, watermark_source="responses"),
    )

    assert decision.ok is False
    assert decision.fresh is False
    assert decision.stale_majority is True
    assert decision.winner_nodes == ["n1", "n2"]
    assert decision.watermark == 8
    assert decision.majority_revisions == [7, 7]
    assert decision.revisions == {"n1": 7, "n2": 7, "n3": 8}
    assert decision.final_reason == "stale-majority"


def test_f1_accepts_a_fresh_majority():
    decision = evaluate_responses(
        fresh_majority_responses(),
        2,
        FreshnessPolicy(condition="F1", delta=0, watermark_source="responses"),
    )

    assert decision.ok is True
    assert decision.fresh is True
    assert decision.stale_majority is False
    assert decision.winner_nodes == ["n1", "n2"]
    assert decision.watermark == 8
    assert decision.majority_revisions == [8, 8]
    assert decision.final_reason == "ok"


def test_f2_and_f3_apply_the_bounded_delta():
    # All three nodes agree semantically, so the majority group is all three.
    responses = {
        "n1": response({NAME: OLD}, 10, "n1"),
        "n2": response({NAME: OLD}, 8, "n2"),
        "n3": response({NAME: OLD}, 9, "n3"),
    }

    f1 = evaluate_responses(responses, 2, FreshnessPolicy(condition="F1", delta=0))
    assert f1.ok is True  # n1 is exactly at the watermark

    f2_strict = evaluate_responses(
        responses, 2, FreshnessPolicy(condition="F2", delta=0)
    )
    assert f2_strict.ok is False
    assert f2_strict.stale_majority is True

    f2_delta_one = evaluate_responses(
        responses, 2, FreshnessPolicy(condition="F2", delta=1)
    )
    assert f2_delta_one.ok is True  # n1 and n3 are within 1 of the watermark

    f3_strict = evaluate_responses(
        responses, 2, FreshnessPolicy(condition="F3", delta=1)
    )
    assert f3_strict.ok is False  # n2 is two revisions behind

    f3_delta_two = evaluate_responses(
        responses, 2, FreshnessPolicy(condition="F3", delta=2)
    )
    assert f3_delta_two.ok is True


def test_quorum_watermark_resists_a_single_fake_high_revision():
    responses = {
        "n1": response({NAME: OLD}, 10, "n1"),
        "n2": response({NAME: OLD}, 9, "n2"),
        "n3": response({NAME: OLD}, 8, "n3"),
    }
    decision = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(condition="F1", watermark_source="quorum"),
    )
    # The second-highest revision is the watermark, so one node cannot move it.
    assert decision.watermark == 9
    assert decision.ok is True

    f3 = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(condition="F3", delta=0, watermark_source="quorum"),
    )
    assert f3.ok is False  # n3 is below the quorum watermark


def test_no_majority_is_not_a_freshness_failure():
    responses = {
        "n1": response({NAME: OLD}, 7, "n1"),
        "n2": response({NAME: NEW}, 8, "n2"),
        "n3": None,
    }
    decision = evaluate_responses(responses, 2, FreshnessPolicy())
    assert decision.ok is False
    assert decision.winner is None
    assert decision.stale_majority is False
    assert decision.final_reason == "no-majority"


def test_stale_nxdomain_majority_is_rejected_by_default():
    responses = {
        "n1": response({}, 7, "n1", name="missing.cs.test"),
        "n2": response({}, 7, "n2", name="missing.cs.test"),
        "n3": response(
            {"missing.cs.test": NEW}, 8, "n3", name="missing.cs.test"
        ),
    }
    decision = evaluate_responses(responses, 2, FreshnessPolicy())
    assert decision.winner is not None
    assert decision.winner[0] == RCODE_NXDOMAIN
    assert decision.ok is False
    assert decision.stale_majority is True

    unchecked = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(apply_to_negative=False),
    )
    assert unchecked.ok is True
    assert unchecked.fresh is True
    assert unchecked.final_reason == "ok-negative-unchecked"


# --------------------------------------------------------------------------- #
# metadata policy and status fallback
# --------------------------------------------------------------------------- #
def test_missing_metadata_can_fail_closed_or_preserve_semantics():
    packet = response({NAME: OLD}, 7, "")
    responses = {"n1": packet, "n2": packet, "n3": packet}

    strict = evaluate_responses(
        responses, 2, FreshnessPolicy(require_metadata=True)
    )
    assert strict.ok is False
    assert strict.metadata_missing is True
    assert strict.final_reason == "missing-revision"

    lenient = evaluate_responses(
        responses, 2, FreshnessPolicy(require_metadata=False)
    )
    assert lenient.ok is True
    assert lenient.fresh is True
    assert lenient.watermark is None
    assert lenient.final_reason == "ok-no-watermark"


def test_status_api_fallback_supplies_revision_evidence():
    packet = response({NAME: OLD}, 7, "")
    responses = {"n1": packet, "n2": packet, "n3": packet}
    decision = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(require_metadata=True, allow_status_fallback=True),
        status_revisions={"n1": 8, "n2": 8, "n3": 7},
    )
    assert decision.ok is True
    assert decision.fresh is True
    assert decision.watermark == 8
    assert decision.revision_sources == {
        "n1": "status",
        "n2": "status",
        "n3": "status",
    }
    assert decision.majority_revisions == [7, 8, 8]


def test_status_fallback_can_be_disabled():
    packet = response({NAME: OLD}, 7, "")
    responses = {"n1": packet, "n2": packet, "n3": packet}
    decision = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(require_metadata=True, allow_status_fallback=False),
        status_revisions={"n1": 8, "n2": 8, "n3": 8},
    )
    assert decision.ok is False
    assert decision.final_reason == "missing-revision"


def test_invalid_revision_signature_fails_closed_even_with_majority():
    signer = crypto.KeyPair.generate(label="n1")
    wrong = crypto.KeyPair.generate(label="wrong")
    responses = {
        "n1": response({NAME: OLD}, 7, "n1", signer),
        "n2": response({NAME: OLD}, 7, "n2", signer),
        "n3": response({NAME: OLD}, 7, "n3", signer),
    }
    decision = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(),
        node_keys={
            "n1": wrong.public_key,
            "n2": wrong.public_key,
            "n3": wrong.public_key,
        },
    )
    assert decision.ok is False
    assert decision.metadata_invalid is True
    assert decision.final_reason == "invalid-revision-metadata"
    assert decision.revision_errors["n1"] == "invalid-signature"


def test_revision_overrides_allow_deterministic_policy_tests():
    responses = {
        "n1": response({NAME: OLD}, 7, "n1"),
        "n2": response({NAME: OLD}, 7, "n2"),
        "n3": response({NAME: NEW}, 9, "n3"),
    }
    decision = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(condition="F1"),
        revision_overrides={
            "n1": 7,
            "n2": 7,
            "n3": 9,
        },
    )
    assert decision.ok is False
    assert decision.stale_majority is True
    assert decision.watermark == 9

    invalid = evaluate_responses(
        responses,
        2,
        FreshnessPolicy(),
        revision_overrides={
            "n1": RevisionEvidence(revision=7, source="edns", error="invalid-signature"),
            "n2": 7,
            "n3": 9,
        },
    )
    assert invalid.ok is False
    assert invalid.metadata_invalid is True


# --------------------------------------------------------------------------- #
# resolver retries and stale policy
# --------------------------------------------------------------------------- #
def make_resolver(policy: FreshnessPolicy, engines: dict[str, DNSEngine]) -> QuorumResolver:
    def fake_query(host, port, data, timeout):
        return engines[host].handle(data)

    return QuorumResolver(
        nodes={node_id: (node_id, 1) for node_id in engines},
        required=2,
        query_node=fake_query,
        freshness=policy,
    )


def test_resolver_retries_stale_majority_then_fails_closed():
    engines = {
        "n1": engine({NAME: OLD}, 7, "n1"),
        "n2": engine({NAME: OLD}, 7, "n2"),
        "n3": engine({NAME: NEW}, 8, "n3"),
    }
    resolver = make_resolver(
        FreshnessPolicy(
            condition="F1",
            retry_budget=2,
            retry_interval=0.0,
            stale_policy="servfail",
        ),
        engines,
    )
    try:
        detail = resolver.resolve_detail(build_query(NAME))
        metrics = resolver.metrics()
    finally:
        resolver.stop()

    assert detail["ok"] is False
    assert detail["rcode"] == "SERVFAIL"
    assert detail["retries"] == 2
    assert detail["freshness"]["stale_majority"] is True
    assert detail["freshness"]["watermark"] == 8
    assert metrics["servfail"] == 1
    assert metrics["freshness"]["stale_majority_queries"] == 1
    assert metrics["freshness"]["freshness_failures"] == 1
    assert metrics["freshness"]["retries"] == 2


def test_resolver_retries_until_the_lagging_nodes_catch_up():
    old = {
        "n1": engine({NAME: OLD}, 7, "n1"),
        "n2": engine({NAME: OLD}, 7, "n2"),
    }
    new = {
        "n1": engine({NAME: NEW}, 8, "n1"),
        "n2": engine({NAME: NEW}, 8, "n2"),
        "n3": engine({NAME: NEW}, 8, "n3"),
    }
    calls = {"n1": 0, "n2": 0, "n3": 0}
    lock = threading.Lock()

    def fake_query(host, port, data, timeout):
        with lock:
            calls[host] += 1
            count = calls[host]
        if host in old and count <= 2:
            return old[host].handle(data)
        return new[host].handle(data)

    resolver = QuorumResolver(
        nodes={"n1": ("n1", 1), "n2": ("n2", 1), "n3": ("n3", 1)},
        required=2,
        query_node=fake_query,
        freshness=FreshnessPolicy(
            condition="F1",
            retry_budget=3,
            retry_interval=0.0,
            stale_policy="servfail",
        ),
    )
    try:
        detail = resolver.resolve_detail(build_query(NAME))
    finally:
        resolver.stop()

    assert detail["ok"] is True
    assert detail["rcode"] == "NOERROR"
    assert detail["answer"] == NEW
    assert detail["retries"] == 2
    assert detail["freshness"]["fresh"] is True


def test_marked_stale_policy_returns_old_answer_with_private_marker():
    engines = {
        "n1": engine({NAME: OLD}, 7, "n1"),
        "n2": engine({NAME: OLD}, 7, "n2"),
        "n3": engine({NAME: NEW}, 8, "n3"),
    }
    resolver = make_resolver(
        FreshnessPolicy(
            condition="F1",
            retry_budget=0,
            retry_interval=0.0,
            stale_policy="marked-stale",
            marked_stale_ttl=7,
        ),
        engines,
    )
    try:
        detail = resolver.resolve_detail(build_query(NAME))
        packet = resolver.resolve(build_query(NAME))
    finally:
        resolver.stop()

    assert detail["ok"] is True
    assert detail["stale"] is True
    assert detail["rcode"] == "NOERROR"
    assert detail["answer"] == OLD
    assert detail["reason"] == "stale-majority-marked"

    assert answer_address(packet) == OLD
    _rtype, ttl, _rdata = first_answer(packet)
    assert ttl == 7
    marker = parse_stale_marker(packet)
    assert marker is not None
    assert marker["watermark"] == 8
    assert marker["majority_revision"] == 7
    assert marker["retries"] == 0


def test_resolver_default_is_semantic_only_for_backward_compatibility():
    engines = {
        "n1": engine({NAME: OLD}, 7, "n1"),
        "n2": engine({NAME: OLD}, 7, "n2"),
        "n3": engine({NAME: NEW}, 8, "n3"),
    }
    resolver = make_resolver(FreshnessPolicy(enabled=False), engines)
    try:
        detail = resolver.resolve_detail(build_query(NAME))
    finally:
        resolver.stop()

    assert detail["ok"] is True
    assert detail["answer"] == OLD
    assert detail["freshness"]["enabled"] is False
    assert detail["freshness"]["stale_majority"] is False


# --------------------------------------------------------------------------- #
# per-node freeze fault
# --------------------------------------------------------------------------- #
def test_frozen_responder_serves_a_real_pinned_snapshot():
    key = crypto.KeyPair.generate(label="n1")
    state = {"zone": {NAME: OLD}, "revision": 7}
    responder = NodeDNSResponder(
        "n1",
        "127.0.0.1",
        0,
        zone_provider=lambda: state["zone"],
        revision_provider=lambda: state["revision"],
        chaos_enabled=True,
        signer=key,
    )

    before = responder.handle(build_query(NAME))
    assert answer_address(before) == OLD
    assert parse_revision_metadata(before).revision == 7

    assert responder.set_frozen(True) is True
    state["zone"] = {NAME: NEW}
    state["revision"] = 8

    frozen = responder.handle(build_query(NAME))
    assert answer_address(frozen) == OLD
    metadata = parse_revision_metadata(frozen)
    assert metadata is not None
    assert metadata.revision == 7

    summary = responder.summary()
    assert summary["frozen"] is True
    assert summary["frozen_revision"] == 7
    assert summary["serving_revision"] == 7
    assert summary["revision"] == 8
    assert summary["revision_lag"] == 1
    assert summary["signed"] is True

    # Freezing again must not silently adopt the newer committed state.
    responder.set_frozen(True)
    assert responder.summary()["frozen_revision"] == 7

    assert responder.set_frozen(False) is False
    live = responder.handle(build_query(NAME))
    assert answer_address(live) == NEW
    assert parse_revision_metadata(live).revision == 8
    assert responder.summary()["frozen"] is False


def test_snapshot_provider_binds_zone_and_revision_in_one_read():
    key = crypto.KeyPair.generate(label="n1")
    # Deliberately inconsistent fallback providers: if the responder consults
    # them instead of the atomic snapshot, the test will expose the mismatch.
    responder = NodeDNSResponder(
        "n1",
        "127.0.0.1",
        0,
        zone_provider=lambda: {NAME: NEW},
        revision_provider=lambda: 99,
        snapshot_provider=lambda: ({NAME: OLD}, 7),
        chaos_enabled=True,
        signer=key,
    )

    packet = responder.handle(build_query(NAME))
    assert answer_address(packet) == OLD
    metadata = parse_revision_metadata(packet)
    assert metadata is not None
    assert metadata.revision == 7

    responder.set_frozen(True)
    assert responder.frozen_snapshot == {NAME: OLD}
    assert responder.frozen_revision == 7


def test_frozen_responder_still_answers_nxdomain_from_the_pinned_zone():
    state = {"zone": {}, "revision": 4}
    responder = NodeDNSResponder(
        "n2",
        "127.0.0.1",
        0,
        zone_provider=lambda: state["zone"],
        revision_provider=lambda: state["revision"],
        chaos_enabled=True,
    )
    responder.set_frozen(True)
    state["zone"] = {NAME: NEW}
    state["revision"] = 9

    packet = responder.handle(build_query(NAME))
    assert struct.unpack("!H", packet[2:4])[0] & 0x000F == RCODE_NXDOMAIN
    metadata = parse_revision_metadata(packet)
    assert metadata is not None
    assert metadata.revision == 4


def test_freezing_requires_a_real_provider_not_a_fabricated_answer():
    state = {"zone": {NAME: OLD}, "revision": 5}
    responder = NodeDNSResponder(
        "n3",
        "127.0.0.1",
        0,
        zone_provider=lambda: state["zone"],
        revision_provider=lambda: state["revision"],
        chaos_enabled=True,
    )
    responder.set_frozen(True)
    # The frozen snapshot is exactly the provider's committed state at freeze
    # time, including its revision; nothing is invented by the responder.
    assert responder.frozen_snapshot == {NAME: OLD}
    assert responder.frozen_revision == 5
