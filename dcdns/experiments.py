"""Live security and behaviour experiments.

Every experiment performs a real signed operation against the running cluster
and reports what the system actually did. The same module powers the portal's
Experiments page and the command-line evaluation script, so the numbers in the
report and the buttons in the demo cannot drift apart.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

import httpx

from . import crypto
from .client import ClusterClient, ClusterError
from .dns_server import (
    build_query,
    parse_name,
    parse_revision_metadata,
    parse_stale_marker,
)
from .quorum_resolver import FreshnessPolicy, QuorumResolver

DEFAULT_DNS_NODES = {
    "n1": ("127.0.0.1", 5354),
    "n2": ("127.0.0.1", 5355),
    "n3": ("127.0.0.1", 5356),
}

DEFAULT_NODE_APIS = {
    "n1": "http://127.0.0.1:9101",
    "n2": "http://127.0.0.1:9102",
    "n3": "http://127.0.0.1:9103",
}

EXPERIMENTS = [
    {
        "id": "duplicate_registration",
        "title": "Duplicate registration",
        "description": "A second participant tries to register a name that is already taken.",
        "expectation": "exactly one registration succeeds; the second is rejected with NAME_TAKEN",
    },
    {
        "id": "forged_update",
        "title": "Forged record update",
        "description": "An unaffiliated participant submits a signed update for someone else's domain.",
        "expectation": "rejected with UNAUTHORIZED; the stored record is unchanged",
    },
    {
        "id": "cross_namespace",
        "title": "Cross-namespace write",
        "description": "The Library administrator registers a name inside the CS namespace.",
        "expectation": "rejected with UNAUTHORIZED",
    },
    {
        "id": "unauthorized_delegation",
        "title": "Unauthorized delegation",
        "description": "A department tries to carve a new namespace out of another department's subtree.",
        "expectation": "rejected with UNAUTHORIZED",
    },
    {
        "id": "invalid_signature",
        "title": "Tampered signature",
        "description": "A signed operation is modified after signing, then submitted.",
        "expectation": "rejected with INVALID_SIGNATURE",
    },
    {
        "id": "replay",
        "title": "Replay of a valid operation",
        "description": "A previously accepted, correctly signed operation is submitted a second time byte-for-byte.",
        "expectation": "rejected with REPLAY_DETECTED",
    },
    {
        "id": "malicious_record",
        "title": "Prohibited destination",
        "description": "A registration points a campus name at a public internet address.",
        "expectation": "rejected with RECORD_NOT_ALLOWED by the record policy",
    },
    {
        "id": "ownership_transfer",
        "title": "Two-party ownership transfer",
        "description": "The owner initiates a transfer; the recipient must explicitly accept it.",
        "expectation": "ownership moves only after acceptance",
    },
    {
        "id": "revocation",
        "title": "Revocation removes the name from DNS",
        "description": "The owner revokes a domain and the quorum resolver is observed until the name stops resolving.",
        "expectation": "the name stops resolving within the propagation window",
    },
    {
        "id": "dns_propagation",
        "title": "DNS propagation latency",
        "description": "An A record is updated and the quorum resolver is polled until the new address appears.",
        "expectation": "the new answer is served within a few seconds",
    },
    {
        "id": "quorum_dns",
        "title": "Majority DNS resists a lying node",
        "description": "One registry node is made to return a forged A record; the quorum resolver must still return the honest majority answer.",
        "expectation": "the resolver returns the honest address even though the lying node answers directly with the forgery",
    },
    {
        "id": "stale_majority",
        "title": "Stale majority is detected, not served",
        "description": "Two nodes keep serving an older committed DNS snapshot while a third has the new address; the semantic-only resolver returns the stale answer, while RAM-DNS detects the freshness failure.",
        "expectation": "baseline returns the stale address; RAM-DNS retries and returns SERVFAIL (or a marked stale answer), then serves the new address after the lagging nodes catch up",
    },
]


@dataclass
class Result:
    passed: bool
    observed: str
    detail: dict | None = None

    def as_dict(self) -> dict:
        return {"passed": self.passed, "observed": self.observed, "detail": self.detail or {}}


class Resolver:
    """Tiny UDP DNS client used to observe the quorum resolver and individual nodes."""

    RCODE_NAMES = {
        -1: "NO RESPONSE",
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }

    def __init__(self, host: str, port: int, timeout: float = 1.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def query_raw(self, name: str) -> bytes | None:
        packet = build_query(name)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(packet, (self.host, self.port))
            data, _ = sock.recvfrom(4096)
            return data
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def query_detail(self, name: str) -> dict:
        """Return the answer plus any revision or stale marker in the packet."""
        data = self.query_raw(name)
        if data is None:
            return {
                "rcode": -1,
                "rcode_name": "NO RESPONSE",
                "answer": None,
                "revision": None,
                "node_id": None,
                "signed": False,
                "stale": None,
                "raw": None,
            }

        flags = struct.unpack("!H", data[2:4])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        rcode = flags & 0x000F
        _, offset = parse_name(data, 12)
        offset += 4  # qtype + qclass
        answer = None
        if ancount:
            _, offset = parse_name(data, offset)
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlength == 4:
                answer = socket.inet_ntoa(data[offset:offset + 4])

        metadata = parse_revision_metadata(data)
        return {
            "rcode": rcode,
            "rcode_name": self.RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
            "answer": answer,
            "revision": metadata.revision if metadata else None,
            "node_id": metadata.node_id if metadata else None,
            "signed": bool(metadata and metadata.signed),
            "stale": parse_stale_marker(data),
            "raw": data,
        }

    def query(self, name: str) -> tuple[int, str | None]:
        detail = self.query_detail(name)
        return detail["rcode"], detail["answer"]

    def wait_for(self, name: str, address: str, timeout: float = 8.0) -> float | None:
        """Return seconds until ``name`` resolves to ``address``, or None."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            rcode, answer = self.query(name)
            if rcode == 0 and answer == address:
                return time.monotonic() - start
            time.sleep(0.1)
        return None

    def wait_for_nxdomain(self, name: str, timeout: float = 8.0) -> float | None:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            rcode, _answer = self.query(name)
            # A quorum resolver can legitimately return SERVFAIL while the
            # nodes are converging. That is not proof of revocation; only an
            # explicit NXDOMAIN is.
            if rcode == 3:
                return time.monotonic() - start
            time.sleep(0.1)
        return None


class ExperimentRunner:
    def __init__(
        self,
        client: ClusterClient,
        keys: dict[str, crypto.KeyPair],
        resolver: Resolver,
        dns_nodes: dict[str, tuple[str, int]] | None = None,
        node_apis: dict[str, str] | None = None,
        node_keys: dict[str, str] | None = None,
    ) -> None:
        self.client = client
        self.keys = keys
        self.resolver = resolver
        self.dns_nodes = dict(dns_nodes or DEFAULT_DNS_NODES)
        self.node_apis = dict(node_apis or DEFAULT_NODE_APIS)
        self.node_keys = dict(node_keys or {})

    # -- helpers --------------------------------------------------------- #
    def _submit(self, signer: str, op: str, body: dict) -> dict:
        return self.client.submit(crypto.sign_op(self.keys[signer], op, body))

    def _expect_rejection(self, signer: str, op: str, body: dict, code: str) -> Result:
        try:
            self._submit(signer, op, body)
        except ClusterError as exc:
            if exc.code == code:
                return Result(True, f"rejected with {exc.code}", {"code": exc.code})
            return Result(False, f"rejected with {exc.code}, expected {code}", {"code": exc.code})
        return Result(False, "operation was accepted, expected rejection", {})

    def _unique(self, prefix: str) -> str:
        return f"{prefix}-{int(time.time() * 1000) % 1000000}.cs.test"

    def _ensure_domain(self, name: str, address: str = "10.20.5.42") -> bool:
        try:
            self.client.get(f"/domains/{name}")
            return True
        except ClusterError:
            pass
        try:
            self._submit("alice", "register_domain",
                         {"name": name, "records": {"A": address}})
            return True
        except ClusterError:
            return False

    def _domain(self, name: str) -> dict | None:
        try:
            return self.client.get(f"/domains/{name}")["domain"]
        except ClusterError:
            return None

    def _freeze_dns(self, node_id: str, frozen: bool) -> dict:
        """Pin or release one node's DNS snapshot (loopback fault injection)."""
        api = self.node_apis.get(node_id)
        if not api:
            raise RuntimeError(f"no API URL configured for {node_id}")
        response = httpx.post(
            f"{api}/internal/dns/freeze",
            json={"frozen": frozen},
            timeout=3.0,
        )
        if response.status_code == 404:
            raise RuntimeError(
                f"freeze endpoint on {node_id} is disabled; "
                "start the demo with node chaos enabled"
            )
        response.raise_for_status()
        return response.json()

    # -- experiments ------------------------------------------------------ #
    def run(self, experiment_id: str) -> Result:
        handler = getattr(self, f"_run_{experiment_id}", None)
        if handler is None:
            return Result(False, f"unknown experiment {experiment_id!r}")
        try:
            return handler()
        except Exception as exc:  # a crashed experiment is a failed experiment
            return Result(False, f"{type(exc).__name__}: {exc}")

    def _run_duplicate_registration(self) -> Result:
        name = self._unique("duplicate")
        first = self._submit("alice", "register_domain",
                             {"name": name, "records": {"A": "10.20.5.61"}})
        second = self._expect_rejection(
            "cs-admin", "register_domain",
            {"name": name, "records": {"A": "10.20.5.62"}}, "NAME_TAKEN",
        )
        if not first.get("committed"):
            return Result(False, "setup registration did not commit")
        return Result(second.passed,
                      f"first registration committed at revision {first['revision']}; "
                      f"second {second.observed}")

    def _run_forged_update(self) -> Result:
        name = "techfest.cs.test"
        if not self._ensure_domain(name):
            return Result(False, "could not create the fixture domain")
        before = self._domain(name)["records"]["A"]
        result = self._expect_rejection(
            "mallory", "update_records",
            {"name": name, "records": {"A": "10.20.5.66"}}, "UNAUTHORIZED",
        )
        after = self._domain(name)["records"]["A"]
        unchanged = before == after
        return Result(result.passed and unchanged,
                      f"{result.observed}; record {'unchanged' if unchanged else 'CHANGED'} ({after})")

    def _run_cross_namespace(self) -> Result:
        name = self._unique("library-intrusion")
        return self._expect_rejection(
            "library-admin", "register_domain",
            {"name": name, "records": {"A": "10.20.6.5"}}, "UNAUTHORIZED",
        )

    def _run_unauthorized_delegation(self) -> Result:
        name = self._unique("intruder")
        return self._expect_rejection(
            "library-admin", "delegate_namespace",
            {"name": name, "controller": self.keys["library-admin"].public_key},
            "UNAUTHORIZED",
        )

    def _run_invalid_signature(self) -> Result:
        op = crypto.sign_op(self.keys["alice"], "register_domain", {
            "name": self._unique("tampered"), "records": {"A": "10.20.5.70"},
        })
        op["body"]["records"]["A"] = "10.20.5.71"
        try:
            self.client.submit(op)
        except ClusterError as exc:
            return Result(exc.code == "INVALID_SIGNATURE",
                          f"rejected with {exc.code}", {"code": exc.code})
        return Result(False, "tampered operation was accepted", {})

    def _run_replay(self) -> Result:
        op = crypto.sign_op(self.keys["alice"], "register_domain", {
            "name": self._unique("replay"), "records": {"A": "10.20.5.72"},
        })
        first = self.client.submit(op)
        try:
            self.client.submit(op)
        except ClusterError as exc:
            return Result(
                exc.code == "REPLAY_DETECTED",
                f"first submission committed at revision {first['revision']}; "
                f"replay rejected with {exc.code}",
                {"code": exc.code},
            )
        return Result(False, "replayed operation was accepted", {})

    def _run_malicious_record(self) -> Result:
        return self._expect_rejection(
            "alice", "register_domain",
            {"name": self._unique("public-ip"), "records": {"A": "8.8.8.8"}},
            "RECORD_NOT_ALLOWED",
        )

    def _run_ownership_transfer(self) -> Result:
        name = self._unique("transfer")
        self._submit("alice", "register_domain",
                     {"name": name, "records": {"A": "10.20.5.80"}})
        self._submit("alice", "transfer_initiate",
                     {"name": name, "new_owner": self.keys["bob"].public_key})
        mid = self._domain(name)
        self._submit("bob", "transfer_accept", {"name": name})
        final = self._domain(name)
        ok = (
            mid is not None and mid["status"] == "pending_transfer"
            and final is not None
            and final["owner"] == self.keys["bob"].public_key
            and final["status"] == "active"
        )
        return Result(
            ok,
            f"status after initiate: {mid['status'] if mid else 'missing'}; "
            f"owner after accept: "
            f"{'bob' if final and final['owner'] == self.keys['bob'].public_key else 'unchanged'}",
        )

    def _run_revocation(self) -> Result:
        name = self._unique("revoke")
        address = "10.20.5.90"
        self._submit("alice", "register_domain",
                     {"name": name, "records": {"A": address}})
        if self.resolver.wait_for(name, address, timeout=8.0) is None:
            return Result(False, "fixture domain never became resolvable")

        self._submit("alice", "revoke_domain",
                     {"name": name, "reason": "experiment"})
        elapsed = self.resolver.wait_for_nxdomain(name, timeout=8.0)
        if elapsed is None:
            return Result(False, "name still resolves after revocation")
        return Result(True, f"withdrawn from DNS {elapsed:.2f}s after revocation")

    def _run_dns_propagation(self) -> Result:
        name = "techfest.cs.test"
        if not self._ensure_domain(name):
            return Result(False, "could not create the fixture domain")
        current = self._domain(name)["records"]["A"]
        target = "10.20.5.123" if current != "10.20.5.123" else "10.20.5.124"

        started = time.monotonic()
        self._submit("alice", "update_records",
                     {"name": name, "records": {"A": target}})
        committed = time.monotonic()
        elapsed = self.resolver.wait_for(name, target, timeout=8.0)
        if elapsed is None:
            return Result(False, f"DNS never served {target} for {name}")
        return Result(
            True,
            f"new answer {target} live {elapsed:.2f}s after the client response "
            f"(commit took {(committed - started) * 1000:.0f}ms)",
            {"propagation_seconds": round(elapsed, 3),
             "commit_ms": round((committed - started) * 1000, 1)},
        )

    def _run_quorum_dns(self) -> Result:
        """Make one node lie and prove the client-facing answer does not move."""
        name = "techfest.cs.test"
        if not self._ensure_domain(name):
            return Result(False, "could not create the fixture domain")
        honest = self._domain(name)["records"]["A"]
        forged = "10.20.5.66" if honest != "10.20.5.66" else "10.20.5.67"

        liar_id = sorted(self.dns_nodes)[-1]
        liar_host, liar_port = self.dns_nodes[liar_id]
        liar_api = self.node_apis.get(liar_id)
        if not liar_api:
            return Result(False, f"no API URL configured for {liar_id}")
        direct = Resolver(liar_host, liar_port)

        try:
            response = httpx.post(
                f"{liar_api}/internal/chaos",
                json={"name": name, "address": forged},
                timeout=3.0,
            )
            if response.status_code != 200:
                return Result(
                    False,
                    f"chaos endpoint on {liar_id} returned HTTP {response.status_code}; "
                    "start the demo with node chaos enabled",
                )

            quorum_rcode, quorum_answer = self.resolver.query(name)
            direct_rcode, direct_answer = direct.query(name)
            passed = (
                quorum_rcode == 0
                and quorum_answer == honest
                and direct_rcode == 0
                and direct_answer == forged
            )
            return Result(
                passed,
                f"quorum returned {quorum_answer!r}; {liar_id} answered directly "
                f"with {direct_answer!r} (forged {forged!r}, honest {honest!r})",
                {
                    "liar": liar_id,
                    "honest": honest,
                    "forged": forged,
                    "quorum_answer": quorum_answer,
                    "liar_answer": direct_answer,
                },
            )
        finally:
            try:
                httpx.post(f"{liar_api}/internal/chaos", json={"clear": True}, timeout=3.0)
            except httpx.HTTPError:
                pass

    def _run_stale_majority(self) -> Result:
        """Freeze two DNS snapshots, commit a new address, compare resolvers.

        The two frozen responders keep serving the exact committed zone and
        revision they had at freeze time. The third responder sees the new
        commit. This is a real stale majority: no answer is fabricated, the
        registry keeps replicating, and the frozen nodes' HTTP status still
        shows the newer committed revision.
        """
        name = "techfest.cs.test"
        if not self._ensure_domain(name):
            return Result(False, "could not create the fixture domain")
        domain = self._domain(name)
        if domain is None:
            return Result(False, "could not read the fixture domain")
        stale_address = domain["records"]["A"]
        target = "10.20.5.123" if stale_address != "10.20.5.123" else "10.20.5.124"

        node_ids = sorted(self.dns_nodes)
        if len(node_ids) < 3:
            return Result(False, "stale-majority experiment needs three DNS nodes")
        lagging = node_ids[:2]
        current = node_ids[-1]

        baseline: QuorumResolver | None = None
        ram: QuorumResolver | None = None
        try:
            for node_id in lagging:
                self._freeze_dns(node_id, True)

            commit = self._submit(
                "alice", "update_records",
                {"name": name, "records": {"A": target}},
            )

            # Wait until the unfrozen node serves the new answer.
            direct = Resolver(*self.dns_nodes[current])
            deadline = time.monotonic() + 6.0
            fresh_seen = False
            while time.monotonic() < deadline:
                detail = direct.query_detail(name)
                if detail["rcode"] == 0 and detail["answer"] == target:
                    fresh_seen = True
                    break
                time.sleep(0.1)
            if not fresh_seen:
                return Result(
                    False,
                    f"{current} never served the new answer {target}",
                )

            baseline = QuorumResolver(
                self.dns_nodes,
                required=2,
                freshness=False,
                timeout=1.0,
            )
            ram = QuorumResolver(
                self.dns_nodes,
                required=2,
                freshness=FreshnessPolicy(
                    enabled=True,
                    condition="F1",
                    delta=0,
                    watermark_source="responses",
                    stale_policy="servfail",
                    retry_budget=2,
                    retry_interval=0.05,
                ),
                node_keys=self.node_keys,
                timeout=1.0,
            )
            packet = build_query(name)
            baseline_detail = baseline.resolve_detail(packet)
            ram_detail = ram.resolve_detail(packet)
            live_detail = self.resolver.query_detail(name)
        finally:
            for node_id in lagging:
                try:
                    self._freeze_dns(node_id, False)
                except Exception:
                    pass
            if baseline is not None:
                baseline.stop()
            if ram is not None:
                ram.stop()

        convergence = self.resolver.wait_for(name, target, timeout=8.0)
        freshness = ram_detail.get("freshness") or {}
        majority_revisions = freshness.get("majority_revisions") or []
        watermark = freshness.get("watermark")

        baseline_stale = (
            baseline_detail.get("ok") is True
            and baseline_detail.get("answer") == stale_address
        )
        ram_detected = (
            ram_detail.get("ok") is False
            and bool(freshness.get("stale_majority"))
            and watermark is not None
            and watermark > max(majority_revisions or [0])
        )
        live_blocked = (
            live_detail.get("rcode") == 2
            or (
                live_detail.get("rcode") == 0
                and live_detail.get("stale") is not None
            )
        )
        passed = (
            baseline_stale
            and ram_detected
            and live_blocked
            and convergence is not None
        )
        observed = (
            f"baseline returned stale {baseline_detail.get('answer')!r} "
            f"(majority rev {majority_revisions}); "
            f"RAM-DNS watermark {watermark} -> {ram_detail.get('rcode')} "
            f"({ram_detail.get('reason')}); "
            f"live resolver {live_detail.get('rcode_name')}"
            + (", marked stale" if live_detail.get("stale") else "")
            + (
                f"; fresh answer after {convergence:.2f}s"
                if convergence is not None
                else "; did not converge after unfreeze"
            )
        )
        return Result(
            passed,
            observed,
            {
                "stale_address": stale_address,
                "target": target,
                "lagging_nodes": lagging,
                "current_node": current,
                "commit_revision": commit.get("revision"),
                "baseline": baseline_detail,
                "ram_dns": ram_detail,
                "live": {
                    key: value
                    for key, value in live_detail.items()
                    if key != "raw"
                },
                "convergence_seconds": (
                    round(convergence, 3) if convergence is not None else None
                ),
            },
        )


def run_all(client: ClusterClient, keys: dict[str, crypto.KeyPair],
            resolver: Resolver,
            node_keys: dict[str, str] | None = None) -> dict[str, dict]:
    runner = ExperimentRunner(client, keys, resolver, node_keys=node_keys)
    return {exp["id"]: runner.run(exp["id"]).as_dict() for exp in EXPERIMENTS}
