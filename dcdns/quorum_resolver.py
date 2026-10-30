"""Client-facing DNS resolver with majority agreement and revision freshness.

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

Revision-aware majority DNS (RAM-DNS)
-------------------------------------
Semantic agreement alone does not prove freshness. Two lagging nodes can agree
on the previous answer while a third node has already committed a newer one:

    n1: revision 10 -> 10.20.5.42   (lagging)
    n2: revision 10 -> 10.20.5.42   (lagging)
    n3: revision 11 -> 10.20.5.99   (current)

The semantic majority is stale. The resolver therefore also reads the revision
identifier attached to each answer (a signed EDNS(0) option, with the node
status API as a fallback), computes a freshness watermark, and evaluates a
freshness condition over the majority group:

    F1  at least one majority node is at the watermark;
    F2  at least a quorum of the majority is within ``delta`` of the watermark;
    F3  every majority node is within ``delta`` of the watermark.

If the majority is fresh, the answer is returned. If it is stale, the resolver
retries for a bounded time; if the nodes do not converge it returns SERVFAIL or
an explicitly marked stale answer, depending on policy. It never silently
presents old data as current.

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
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from . import crypto
from .dns_server import (
    EDNS_OPTION_REVISION,
    RCODE_FORMERR,
    RCODE_NXDOMAIN,
    RCODE_NOERROR,
    build_query,
    ensure_edns,
    mark_stale_response,
    parse_name,
    parse_revision_metadata,
    parse_stale_marker,
)

RCODE_SERVFAIL = 2


# --------------------------------------------------------------------------- #
# freshness policy
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FreshnessPolicy:
    """Configuration for the revision-coherence test.

    ``watermark_source`` selects how the best-known committed revision is
    determined:

    ``responses``
        Maximum revision among the DNS responses (default). This is the
        smallest set of evidence and matches the patent's worked example.
    ``status``
        Maximum ``serving_revision`` reported by the node status API.
    ``combined``
        Maximum of both. A DNS-silent node whose status is current can still
        raise the watermark, which is fail-closed but can reduce availability.
    ``quorum``
        Highest revision attested by at least ``required`` responses. This
        resists a single node claiming a fake high revision, but it cannot
        detect the stale-majority case because the majority itself is the
        stale group. It is provided as an alternative policy.
    """

    enabled: bool = True
    condition: str = "F1"
    delta: int = 0
    watermark_source: str = "responses"
    require_metadata: bool = False
    allow_status_fallback: bool = True
    stale_policy: str = "servfail"
    retry_budget: int = 2
    retry_interval: float = 0.1
    marked_stale_ttl: int = 5
    apply_to_negative: bool = True

    def __post_init__(self) -> None:
        if self.condition not in {"F1", "F2", "F3"}:
            raise ValueError("freshness condition must be F1, F2 or F3")
        if self.watermark_source not in {
            "responses", "status", "combined", "quorum"
        }:
            raise ValueError(
                "watermark_source must be responses, status, combined or quorum"
            )
        if self.stale_policy not in {"servfail", "marked-stale"}:
            raise ValueError("stale_policy must be servfail or marked-stale")
        if self.delta < 0:
            raise ValueError("delta must be non-negative")
        if self.retry_budget < 0:
            raise ValueError("retry_budget must be non-negative")
        if self.retry_interval < 0:
            raise ValueError("retry_interval must be non-negative")
        if self.marked_stale_ttl < 0:
            raise ValueError("marked_stale_ttl must be non-negative")


@dataclass(frozen=True)
class RevisionEvidence:
    """Revision metadata attached to one node's DNS answer."""

    revision: int | None = None
    source: str = "none"
    verified: bool = False
    node_id: str | None = None
    digest: str | None = None
    error: str | None = None


def revision_evidence(
    response: bytes | None,
    expected_node: str | None = None,
    node_keys: dict[str, str] | None = None,
) -> RevisionEvidence:
    """Decode and, when a configured key exists, verify one revision token.

    A token with a bad signature, a mismatched node id, or a missing signature
    when a key is configured is *not* silently ignored: it is returned with an
    ``error`` so the freshness decision can fail closed. A token with no
    configured key is accepted as unverified evidence and reported as such.
    """
    if response is None:
        return RevisionEvidence(source="none", error="no-answer")
    metadata = parse_revision_metadata(response)
    if metadata is None:
        return RevisionEvidence(source="none")
    if expected_node and metadata.node_id and metadata.node_id != expected_node:
        return RevisionEvidence(
            revision=metadata.revision,
            source="edns",
            node_id=metadata.node_id,
            digest=metadata.digest_hex,
            error="node-id-mismatch",
        )

    verified = False
    if node_keys and expected_node and expected_node in node_keys:
        if not metadata.signature:
            return RevisionEvidence(
                revision=metadata.revision,
                source="edns",
                node_id=metadata.node_id,
                digest=metadata.digest_hex,
                error="missing-signature",
            )
        signature_b64 = crypto.b64encode(metadata.signature)
        if not crypto.verify_signature(
            node_keys[expected_node],
            metadata.signing_payload(),
            signature_b64,
        ):
            return RevisionEvidence(
                revision=metadata.revision,
                source="edns",
                node_id=metadata.node_id,
                digest=metadata.digest_hex,
                error="invalid-signature",
            )
        verified = True

    return RevisionEvidence(
        revision=metadata.revision,
        source="edns",
        verified=verified,
        node_id=metadata.node_id,
        digest=metadata.digest_hex,
    )


# --------------------------------------------------------------------------- #
# DNS response semantics
# --------------------------------------------------------------------------- #
def semantic_answer(response: bytes | None) -> tuple[int, tuple[tuple[int, int, bytes], ...]] | None:
    """Reduce a DNS response to what a client would actually act on.

    Transaction ids, flags unrelated to the answer, and record order are
    deliberately excluded. Two nodes that return the same address agree even if
    their packets differ in harmless ways. EDNS additional records (including
    the revision token) are not part of the semantic answer.
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

    # Freshness diagnostics. Defaults keep the pure semantic decision API
    # backward compatible for callers that do not enable a policy.
    freshness_enabled: bool = False
    fresh: bool = True
    stale: bool = False
    stale_majority: bool = False
    watermark: int | None = None
    watermark_source: str = "off"
    condition: str = "off"
    delta: int = 0
    majority_revisions: list[int] = field(default_factory=list)
    revisions: dict[str, int | None] = field(default_factory=dict)
    revision_sources: dict[str, str] = field(default_factory=dict)
    revision_errors: dict[str, str] = field(default_factory=dict)
    metadata_missing: bool = False
    metadata_invalid: bool = False
    retries: int = 0
    final_reason: str = ""


def _watermark(
    evidence: dict[str, RevisionEvidence],
    required: int,
    source: str,
    status_revisions: dict[str, int] | None,
) -> int | None:
    response_revisions = [
        item.revision
        for item in evidence.values()
        if item.revision is not None and item.error is None
    ]
    status_values = [
        int(value)
        for value in (status_revisions or {}).values()
        if value is not None
    ]
    if source == "responses":
        pool = response_revisions
    elif source == "status":
        pool = status_values
    elif source == "combined":
        pool = response_revisions + status_values
    else:  # quorum
        ordered = sorted(response_revisions, reverse=True)
        return ordered[required - 1] if len(ordered) >= required else None
    return max(pool) if pool else None


def evaluate_responses(
    responses: dict[str, bytes | None],
    required: int,
    freshness: FreshnessPolicy | None = None,
    *,
    node_keys: dict[str, str] | None = None,
    status_revisions: dict[str, int] | None = None,
    revision_overrides: dict[str, RevisionEvidence | int | None] | None = None,
) -> Decision:
    """Decide whether a majority agrees and whether that majority is fresh.

    ``freshness=None`` preserves the original semantic-only behaviour. With a
    policy, the function attaches revision evidence, computes the watermark,
    and evaluates F1/F2/F3 over the majority group. It does not retry; the
    retry loop belongs to :class:`QuorumResolver`.
    """
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

    # Choose the largest qualifying group, with a deterministic tie-break.
    candidates = [
        (semantic, nodes)
        for semantic, nodes in groups.items()
        if len(nodes) >= required
    ]
    winner: tuple[int, tuple[tuple[int, int, bytes], ...]] | None = None
    winner_nodes: list[str] = []
    if candidates:
        winner, winner_nodes = max(candidates, key=lambda item: (len(item[1]), item[0]))
        winner_nodes = sorted(winner_nodes)

    # More than one distinct answer (or a node that could not answer at all)
    # means the nodes did not speak with one voice. It does not by itself mean
    # the query failed: a majority may still have agreed.
    disagreement = len(groups) > 1 or malformed

    # -- revision evidence ------------------------------------------------ #
    evidence: dict[str, RevisionEvidence] = {}
    for node_id in sorted(responses):
        if revision_overrides is not None and node_id in revision_overrides:
            override = revision_overrides[node_id]
            if isinstance(override, RevisionEvidence):
                evidence[node_id] = override
            elif override is None:
                evidence[node_id] = RevisionEvidence()
            else:
                evidence[node_id] = RevisionEvidence(
                    revision=int(override), source="override", verified=True
                )
            continue
        item = revision_evidence(
            responses.get(node_id), expected_node=node_id, node_keys=node_keys
        )
        if (
            item.revision is None
            and item.error is None
            and freshness is not None
            and freshness.allow_status_fallback
            and status_revisions
            and node_id in status_revisions
        ):
            item = RevisionEvidence(
                revision=int(status_revisions[node_id]),
                source="status",
                verified=False,
            )
        evidence[node_id] = item

    revisions = {node_id: item.revision for node_id, item in evidence.items()}
    revision_sources = {node_id: item.source for node_id, item in evidence.items()}
    revision_errors = {
        node_id: item.error
        for node_id, item in evidence.items()
        if item.error and item.error != "no-answer"
    }

    if freshness is None or not freshness.enabled:
        return Decision(
            ok=winner is not None,
            response=responses[winner_nodes[0]] if winner is not None and winner_nodes else None,
            winner=winner,
            winner_nodes=winner_nodes,
            votes=votes,
            disagreement=disagreement,
            required=required,
            freshness_enabled=False,
            fresh=True,
            watermark=None,
            watermark_source="off",
            condition="off",
            delta=0,
            majority_revisions=[
                revisions[node_id]
                for node_id in winner_nodes
                if revisions.get(node_id) is not None
            ],
            revisions=revisions,
            revision_sources=revision_sources,
            revision_errors=revision_errors,
            final_reason="ok" if winner is not None else "no-majority",
        )

    watermark = _watermark(
        evidence, required, freshness.watermark_source, status_revisions
    )
    majority_revisions = [
        revisions[node_id]
        for node_id in winner_nodes
        if revisions.get(node_id) is not None
    ]
    invalid_in_winner = any(
        evidence[node_id].error not in (None, "no-answer")
        for node_id in winner_nodes
    )
    missing_in_winner = any(
        evidence[node_id].revision is None
        and evidence[node_id].error is None
        for node_id in winner_nodes
    )
    metadata_invalid = invalid_in_winner
    metadata_missing = missing_in_winner

    fresh = False
    reason = "no-majority"
    if winner is None:
        fresh = False
        reason = "no-majority"
    elif winner[0] == RCODE_NXDOMAIN and not freshness.apply_to_negative:
        fresh = True
        reason = "ok-negative-unchecked"
    elif metadata_invalid:
        fresh = False
        reason = "invalid-revision-metadata"
    elif metadata_missing and freshness.require_metadata:
        fresh = False
        reason = "missing-revision"
    elif watermark is None:
        # No revision evidence at all. The default is to preserve the old
        # semantic-only behaviour; require_metadata makes it fail closed.
        fresh = not freshness.require_metadata
        reason = "ok-no-watermark" if fresh else "missing-revision"
    elif not majority_revisions:
        fresh = not freshness.require_metadata
        reason = "ok-no-watermark" if fresh else "missing-revision"
    else:
        if freshness.condition == "F1":
            fresh = any(value >= watermark for value in majority_revisions)
        elif freshness.condition == "F2":
            threshold = watermark - freshness.delta
            fresh = sum(
                1 for value in majority_revisions if value >= threshold
            ) >= required
        else:  # F3
            threshold = watermark - freshness.delta
            fresh = min(majority_revisions) >= threshold
        reason = "ok" if fresh else "stale-majority"

    stale_majority = (
        winner is not None and not fresh and reason == "stale-majority"
    )
    ok = winner is not None and fresh
    return Decision(
        ok=ok,
        response=responses[winner_nodes[0]] if winner is not None and winner_nodes else None,
        winner=winner,
        winner_nodes=winner_nodes,
        votes=votes,
        disagreement=disagreement,
        required=required,
        freshness_enabled=True,
        fresh=fresh,
        stale=False,
        stale_majority=stale_majority,
        watermark=watermark,
        watermark_source=freshness.watermark_source,
        condition=freshness.condition,
        delta=freshness.delta,
        majority_revisions=sorted(majority_revisions),
        revisions=revisions,
        revision_sources=revision_sources,
        revision_errors=revision_errors,
        metadata_missing=metadata_missing,
        metadata_invalid=metadata_invalid,
        final_reason=reason,
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
        freshness: FreshnessPolicy | bool | None = None,
        node_keys: dict[str, str] | None = None,
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

        if freshness is None:
            # Preserve the original semantic-majority behaviour for library
            # callers that do not opt in. The CLI and demo pass an explicit
            # FreshnessPolicy, so RAM-DNS is on by default there.
            self.policy = FreshnessPolicy(enabled=False)
        elif isinstance(freshness, FreshnessPolicy):
            self.policy = freshness
        else:
            self.policy = FreshnessPolicy(enabled=bool(freshness))
        self.node_keys = dict(node_keys or {})

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
        self.stale_majority_queries = 0
        self.freshness_failures = 0
        self.stale_answers = 0
        self.retries_total = 0
        self.missing_revision = 0
        self.invalid_revision = 0
        self.recent: list[dict] = []
        self.last_decision: Decision | None = None

        self.node_info: dict[str, dict] = {}
        for node_id, (host, port) in self.nodes.items():
            self.node_info[node_id] = {
                "node_id": node_id,
                "host": host,
                "dns_port": port,
                "api_url": self.api_urls.get(node_id),
                "reachable": False,
                "revision": 0,
                "serving_revision": 0,
                "revision_lag": 0,
                "frozen": False,
                "frozen_revision": None,
                "signed": False,
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
        # A client query may predate EDNS. Add our revision request so every
        # node can attach its committed revision to the answer.
        packet = ensure_edns(data)
        futures = {
            node_id: self._executor.submit(
                self._query_node, host, port, packet, self.timeout
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

    def _status_revisions(self) -> dict[str, int]:
        with self._lock:
            return {
                node_id: int(info["serving_revision"])
                for node_id, info in self.node_info.items()
                if info.get("reachable") and info.get("serving_revision") is not None
            }

    # -- query path ------------------------------------------------------ #
    def _resolve(self, data: bytes) -> tuple[str, int, Decision, float]:
        name, qtype = query_name(data)
        started = time.perf_counter()
        attempts = 0
        decision: Decision | None = None

        while True:
            responses = self._ask_all(data)
            decision = evaluate_responses(
                responses,
                self.required,
                self.policy,
                node_keys=self.node_keys,
                status_revisions=self._status_revisions(),
            )
            attempts += 1
            if not self.policy.enabled:
                break
            if decision.ok:
                break
            # Only a stale majority is retried. A missing majority or invalid
            # metadata fails closed immediately.
            if not decision.stale_majority:
                break
            if attempts > self.policy.retry_budget:
                break
            if self.policy.retry_interval > 0:
                time.sleep(self.policy.retry_interval)

        assert decision is not None
        decision.retries = attempts - 1
        if (
            decision.stale_majority
            and not decision.ok
            and self.policy.stale_policy == "marked-stale"
            and decision.response is not None
        ):
            decision = replace(
                decision,
                ok=True,
                stale=True,
                final_reason="stale-majority-marked",
            )
        elif decision.stale_majority and not decision.ok:
            decision.final_reason = "stale-majority"

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
            if decision.stale_majority:
                self.stale_majority_queries += 1
            if decision.freshness_enabled and not decision.fresh:
                self.freshness_failures += 1
            if decision.stale:
                self.stale_answers += 1
            if decision.metadata_missing:
                self.missing_revision += 1
            if decision.metadata_invalid:
                self.invalid_revision += 1
            self.retries_total += decision.retries
            self.last_decision = decision

            entry = {
                "name": name,
                "qtype": qtype,
                "answer": answer_text(decision.winner) if decision.ok else "SERVFAIL",
                "rcode": decision_rcode(decision),
                "votes": dict(decision.votes),
                "winner": list(decision.winner_nodes),
                "disagreement": decision.disagreement,
                "freshness_enabled": decision.freshness_enabled,
                "fresh": decision.fresh,
                "stale": decision.stale,
                "stale_majority": decision.stale_majority,
                "watermark": decision.watermark,
                "condition": decision.condition,
                "delta": decision.delta,
                "retries": decision.retries,
                "reason": decision.final_reason,
                "revisions": dict(decision.revisions),
                "at": time.time(),
            }
            # Collapse repeated polling of the same decision so the dashboard
            # shows distinct lookups instead of an experiment's retry loop.
            if (self.recent
                    and self.recent[-1]["name"] == entry["name"]
                    and self.recent[-1]["answer"] == entry["answer"]
                    and self.recent[-1]["votes"] == entry["votes"]
                    and self.recent[-1]["watermark"] == entry["watermark"]
                    and self.recent[-1]["reason"] == entry["reason"]):
                self.recent[-1] = entry
            else:
                self.recent.append(entry)
            self.recent = self.recent[-50:]

    def resolve(self, data: bytes) -> bytes:
        name, qtype, decision, _elapsed_ms = self._resolve(data)
        self._record(name, qtype, decision)
        if decision.ok and decision.response is not None:
            response = decision.response
            if decision.stale:
                response = mark_stale_response(
                    response,
                    watermark=decision.watermark or 0,
                    majority_revision=max(decision.majority_revisions, default=0),
                    retries=decision.retries,
                    ttl=self.policy.marked_stale_ttl,
                )
            return patch_id(response, data[:2])
        return build_servfail(data)

    def resolve_detail(self, data: bytes) -> dict:
        """Resolve a query and return the decision that the client would see.

        This is the same code path as :meth:`resolve`; the extra return value is
        the per-node vote map and freshness evidence, so the dashboard can show
        the resolver's actual decision without correlating a separate metrics
        entry.
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
            "watermark": decision.watermark,
            "fresh": decision.fresh,
            "stale": decision.stale,
            "stale_majority": decision.stale_majority,
            "retries": decision.retries,
            "reason": decision.final_reason,
            "freshness": {
                "enabled": decision.freshness_enabled,
                "condition": decision.condition,
                "delta": decision.delta,
                "watermark": decision.watermark,
                "watermark_source": decision.watermark_source,
                "fresh": decision.fresh,
                "stale": decision.stale,
                "stale_majority": decision.stale_majority,
                "retries": decision.retries,
                "reason": decision.final_reason,
                "majority_revisions": list(decision.majority_revisions),
                "revisions": dict(decision.revisions),
                "revision_sources": dict(decision.revision_sources),
                "revision_errors": dict(decision.revision_errors),
                "metadata_missing": decision.metadata_missing,
                "metadata_invalid": decision.metadata_invalid,
            },
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
                    registry_revision = int(
                        dns.get("revision", status.get("revision", 0))
                    )
                    serving_revision = int(
                        dns.get("serving_revision", registry_revision)
                    )
                    info.update(
                        {
                            "reachable": True,
                            "revision": registry_revision,
                            "serving_revision": serving_revision,
                            "revision_lag": int(
                                dns.get(
                                    "revision_lag",
                                    max(0, registry_revision - serving_revision),
                                )
                            ),
                            "frozen": bool(dns.get("frozen", False)),
                            "frozen_revision": dns.get("frozen_revision"),
                            "signed": bool(dns.get("signed", False)),
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
            stale_majority_queries = self.stale_majority_queries
            freshness_failures = self.freshness_failures
            stale_answers = self.stale_answers
            retries_total = self.retries_total
            missing_revision = self.missing_revision
            invalid_revision = self.invalid_revision
            since_poll = time.monotonic() - self.last_poll
            since_majority = time.monotonic() - self.last_majority
            last_decision = self.last_decision

        reachable = [item for item in nodes if item["reachable"]]
        revisions = [item["revision"] for item in reachable]
        serving_revisions = [item["serving_revision"] for item in reachable]
        return {
            "published_revision": min(revisions) if revisions else 0,
            "serving_revision": min(serving_revisions) if serving_revisions else 0,
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
            "watermark": last_decision.watermark if last_decision else None,
            "freshness": {
                "enabled": self.policy.enabled,
                "condition": self.policy.condition,
                "delta": self.policy.delta,
                "watermark_source": self.policy.watermark_source,
                "stale_policy": self.policy.stale_policy,
                "retry_budget": self.policy.retry_budget,
                "retry_interval": self.policy.retry_interval,
                "marked_stale_ttl": self.policy.marked_stale_ttl,
                "require_metadata": self.policy.require_metadata,
                "stale_majority_queries": stale_majority_queries,
                "freshness_failures": freshness_failures,
                "stale_answers": stale_answers,
                "retries": retries_total,
                "missing_revision": missing_revision,
                "invalid_revision": invalid_revision,
                "watermark": last_decision.watermark if last_decision else None,
                "last_reason": last_decision.final_reason if last_decision else None,
            },
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
    parser.add_argument(
        "--freshness",
        choices=["off", "f1", "f2", "f3"],
        default="f1",
        help="revision freshness condition (default: f1); 'off' restores semantic-only voting",
    )
    parser.add_argument("--lag-delta", type=int, default=0,
                        help="bounded lag in revisions for F2/F3")
    parser.add_argument(
        "--watermark",
        choices=["responses", "status", "combined", "quorum"],
        default="responses",
        help="how the freshness watermark is determined",
    )
    parser.add_argument(
        "--stale-policy",
        choices=["servfail", "marked-stale"],
        default="servfail",
        help="what to return when a stale majority does not converge",
    )
    parser.add_argument("--retries", type=int, default=2,
                        help="bounded retries after a stale majority")
    parser.add_argument("--retry-interval", type=float, default=0.1)
    parser.add_argument("--marked-stale-ttl", type=int, default=5)
    parser.add_argument(
        "--require-revision",
        action="store_true",
        help="fail closed when an answer has no revision metadata",
    )
    parser.add_argument(
        "--no-status-fallback",
        action="store_true",
        help="do not use the node status API when EDNS metadata is missing",
    )
    parser.add_argument(
        "--node-keys",
        default="",
        help="comma separated id=public-key entries for verifying signed revision tokens",
    )
    args = parser.parse_args()

    policy = FreshnessPolicy(
        enabled=args.freshness != "off",
        condition=args.freshness.upper() if args.freshness != "off" else "F1",
        delta=args.lag_delta,
        watermark_source=args.watermark,
        require_metadata=args.require_revision,
        allow_status_fallback=not args.no_status_fallback,
        stale_policy=args.stale_policy,
        retry_budget=args.retries,
        retry_interval=args.retry_interval,
        marked_stale_ttl=args.marked_stale_ttl,
    )

    resolver = QuorumResolver(
        parse_nodes(args.nodes),
        parse_urls(args.api_nodes),
        required=args.quorum,
        timeout=args.timeout,
        freshness=policy,
        node_keys=parse_urls(args.node_keys) if args.node_keys else {},
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
    if policy.enabled:
        print(
            f"freshness    {policy.condition} delta={policy.delta} "
            f"watermark={policy.watermark_source} stale={policy.stale_policy} "
            f"retries={policy.retry_budget}"
        )
    else:
        print("freshness    off (semantic majority only)")
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
