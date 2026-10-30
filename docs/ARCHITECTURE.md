# Architecture and Decisions

This document records the decisions behind the prototype, the alternatives that
were considered, and what would change in a production deployment. Each decision
lists its consequences, including the unwelcome ones.

---

## ADR-1 — Coordination: purpose-built quorum log instead of etcd

**Context.** The registry needs a total order over operations and majority
durability. etcd provides both, plus transactions and watches.

**Decision.** Implement a small leader-based replicated log in `cluster.py`.

**Why.**

1. The prototype must run on a machine with no Docker and no external services.
   A demo that fails because a container image cannot be pulled is worthless.
2. The safety argument for this specific workload is unusually simple, because
   the registry has a **single writer** and followers never originate entries:

   * the leader is the lowest-id node among a reachable majority;
   * any two majorities of a three-node cluster intersect;
   * therefore at most one node can lead while holding a majority;
   * therefore every node's log is a prefix of the leader's log;
   * therefore catch-up is append-only and no log truncation is ever required.

3. etcd's compare-and-swap would still not implement the registry's
   authorization rules. The valuable logic — namespace delegation, ownership,
   record policy — lives in `state.py` either way. Using etcd would remove
   roughly 250 lines of replication and add an operational dependency.

**Consequences.**

* We own the failure modes. They are documented and tested, but the code is not
  battle-hardened like etcd.
* No automatic membership change, no snapshot compaction, no watch API.
* **Byzantine faults are not tolerated.** A malicious node could violate the
  protocol. This is stated in the threat model rather than papered over.
* A write that times out after partial replication is reported as *ambiguous*
  rather than failed, because it may still commit.

**Production path.** Replace `cluster.py` with etcd (or a Raft library) while
keeping `state.py` unchanged. The state machine is deliberately storage- and
transport-agnostic: it takes an operation and returns a result, with no I/O.

---

## ADR-2 — DNS: per-node authoritative service with client-side majority agreement

**Context.** CoreDNS ships an `etcd` plugin that serves SkyDNS-formatted keys
directly, and a single central DNS front-end is the simplest way to publish a
replicated registry. Both leave DNS trust in one place: either the key-value
store's contents are served verbatim, or one publisher/front-end process decides
what clients see.

**Decision.** Implement a small DNS wire engine (`dns_server.py`), run an
authoritative responder inside every registry node (`dns_node.py`), and put a
client-facing majority resolver (`quorum_resolver.py`) in front of the node set.
Each node serves its own committed DNS snapshot and attaches its serving revision
to the answer as a signed EDNS(0) token. The resolver asks all configured nodes,
returns an answer only when at least 2 of 3 agree, and then checks that the
winning majority is fresh relative to the committed revision watermark.

**Why.**

* **No central DNS trust.** A single publisher or front-end is a single point of
  failure and a single point of lies. With per-node serving, the client answer is
  decided by majority agreement over independent committed states.
* **Freshness.** Majority agreement alone can select a stale group of nodes that
  agree on an older committed snapshot. The per-answer revision token lets the
  resolver compare the majority against a watermark and fail closed instead of
  presenting old data as current.
* **Publication semantics.** The CoreDNS plugin serves whatever key exists at a
  path. It has no concept of `pending_transfer` or `revoked`, so a
  retained-but-revoked key would still answer. The registry needs a publication
  rule, not a key lookup. DCDNS publishes every non-revoked domain in an active
  namespace; a pending transfer keeps its frozen record live.
* **Schema coupling.** Using the plugin would make the internal key layout a
  public interface, constraining how records are versioned and audited.
* **Measurability.** Each node reports its DNS revision and zone size, and the
  resolver records per-node votes, disagreements and `SERVFAIL` counts. This
  makes both convergence and lying-node behaviour observable.
* **Independence.** Each responder reads a flat snapshot built from that node's
  committed state, so it works regardless of how replication is implemented.

**Consequences.**

* We implement name parsing and response encoding ourselves (~200 lines) and
  must get compression pointers and RCODEs right. This is covered by wire-level
  tests.
* The quorum resolver is one process in the demo. It has no zone and cannot
  invent an answer, but clients pointed at it depend on it being up. It may hold
  node public keys to verify revision tokens; those keys cannot change an answer.
  Multiple resolvers can be run; in production the comparison would be replicated
  or built into stub resolvers.
* **Majority trust is the boundary.** One lying node is outvoted; two colluding
  nodes can lie. RAM-DNS detects a stale majority but cannot defeat a colluding
  majority. There is no DNSSEC, so answers are not cryptographically signed; the
  revision token attests revision metadata, not the answer.
* No zone transfers, no recursive resolution, no `AAAA`/`TXT`.
* Each node is authoritative for one zone and one record type.

**Production path.** Sign zone snapshots (DNSSEC or an equivalent signed-zone
scheme) so a resolver can verify rather than merely outvote. Keep the per-node
responder and majority comparison, and optionally render a zone file for
BIND/CoreDNS or push through RFC 2136 dynamic updates at each node.

---

## ADR-3 — Identity: Ed25519 over canonical JSON

**Decision.** Identity is a raw Ed25519 public key. Signatures cover a
domain-separated, canonical serialisation of the full operation.

**Why.**

* Small keys and signatures; fast verification; no parameter choices to get
  wrong (unlike ECDSA).
* Canonical JSON (sorted keys, no whitespace) means the bytes signed are the
  bytes stored. Re-serialising a parsed object is a classic source of
  signature-bypass bugs.
* Domain separation prevents cross-protocol replay.
* The nonce makes each accepted operation single-use.

**Consequences.**

* JSON canonicalisation is a real dependency risk in general; here both signer
  and verifier use the same implementation, and the tests tamper with signed
  payloads to prove detection.
* Key distribution is out of band. The root authority is the trust anchor.

---

## ADR-4 — Trust bootstrap: a root authority that certifies departments

**Decision.** A configured root public key authorises top-level namespaces.

**Why.** A key's existence proves nothing about who holds it. Without a trust
anchor, "the CS department" is just whoever registered `cs.test` first. The root
models the university's existing ability to say "this is the CS department's
key".

**Consequences.**

* The system distributes *administration*, not ultimate authority. This is the
  honest description of the project and is stated in the README.
* Root compromise is a total compromise of delegation. Mitigation (2-of-3 root
  signatures, offline storage) is specified but not implemented.
* The root cannot forge an owner's signature, so record-level forgery would
  still be detectable in the audit log.

---

## ADR-5 — Portal: server-rendered pages, no front-end build

**Decision.** FastAPI + Jinja2 with a ~50-line vanilla JavaScript file. No
framework, no bundler, no CDN.

**Why.** The demonstration must work offline and on any machine. Every action is
a normal form POST, so the portal remains fully usable if JavaScript fails; the
script only adds live status polling and confirmation dialogs.

**Consequences.** No rich client-side state, no optimistic updates. Acceptable
for a registry administration tool, where explicit confirmation is a feature.

---

## ADR-6 — Namespace: `.test`

**Decision.** The prototype is authoritative for `.test`.

**Why.** `.test` is reserved by RFC 6761 for testing and will never collide with
a real public name. `.local` was rejected because it triggers multicast DNS
behaviour; `.campus` is not a delegated TLD and would require inventing a root.

**Consequences.** Clients must be pointed at the lab resolver explicitly
(`python -m dcdns.dig name --all`, or `dig @127.0.0.1 -p 5353 name`). A real
deployment would use a subdomain of a university-owned zone and integrate with
existing DNS/DHCP.

---

## ADR-7 — Write acknowledgement: publication barrier before success

**Context.** The replicated log separates *commit* (a majority has stored an
entry) from *apply* (the deterministic state machine has executed it and
refreshed the DNS snapshot). The baseline acknowledged as soon as the commit
index advanced. Followers learned the new commit index only on a later
replication push, so an immediate DNS query could see the leader at revision
`i` and a majority at revision `i - 1`. The semantic resolver then returned the
old address even though the client had been told the write succeeded.

**Decision.** Add an optional publication barrier B. With
`--publication-barrier`, a write is acknowledged only after a majority of live
nodes reports a `dns_revision` at least as high as the committed index. The
leader counts itself only after refreshing its own DNS snapshot, and counts a
follower only when the append response reports the applied revision. If the
entry commits but the applied majority is not reached before the deadline, the
API returns `NO_QUORUM` with `"ambiguous": true`.

**Why.** The acknowledgement should describe the state the DNS layer can
actually serve, not merely the state that has been stored. B is the standard
commit/apply discipline applied to the publication boundary. In the controlled
comparison it removed the normal-path stale majority: 3 of 3 control writes
acknowledged with zero stale majorities, versus 12 of 12 stale in the baseline.
The cost was one replication round trip: control ack p50 14.80 ms versus
7.87 ms.

**Consequences.**

* B is currently **opt-in**; the baseline remains available for comparison.
  Making B the default is the audit's first recommendation.
* A timeout after commit is reported honestly as ambiguous, but a
  non-idempotent client must not retry blindly. Operation de-duplication is a
  documented next step, not an implemented guarantee.
* B checks the registry's `dns_revision`, not the responder's
  `serving_revision`. A responder frozen after the registry applied the
  revision can still let B acknowledge; RAM-DNS C covers that case only when a
  newer revision is visible.
* B trusts self-reported peer revisions and is not Byzantine-safe. Two
  colluding nodes can defeat it, as they can defeat the DNS majority.
* Held writes fail closed with `NO_QUORUM` and converge after the fault is
  released; this is tested by `tests/test_commit_hold.py` and the A/B/C harness.

**Production path.** Make B the default, add a regression test that queries a
majority of DNS responders immediately after a successful write, and add
idempotency keys or operation de-duplication so an ambiguous timeout is safe to
retry.

---

## Module boundaries

```text
crypto.py     pure functions: keys, canonical bytes, signatures
names.py      pure functions: syntax and record policy
state.py      pure state machine: apply(operation) -> result | error
cluster.py    I/O and ordering only; calls state.apply; publishes DNS snapshots;
              commit hold and publication barrier
node.py       HTTP surface and DNS responder lifecycle; no business rules
dns_server.py DNS wire format, query engine, EDNS revision token; reads a committed snapshot only
dns_node.py   per-node UDP responder; reads the node's committed snapshot; optional token signing
quorum_resolver.py  client-side majority + freshness decision; no zone
experiments.py shared by portal and CLI so evidence cannot drift
```

The rule that keeps the design honest: **business rules never live in the HTTP
layer or the replication layer.** If a rule matters, it is in `state.py`, where
every node applies it and every test can reach it.

---

## Known simplifications

| Simplification | Risk | Production change |
|---|---|---|
| Portal holds private keys | Demo only; server could sign arbitrary operations | Client-side signing, hardware-backed keys |
| Static cluster membership | Cannot add a node without config change | Membership protocol or orchestrated config |
| No log compaction | Log grows without bound | Snapshots + truncation |
| No key recovery | Lost owner key means lost domain | 2-of-3 root break-glass, audited |
| Single record type | Limited DNS usefulness | `AAAA`, `TXT`, `CNAME` with per-type validation |
| In-memory read path | Reads may be stale on followers | Lease-based linearizable reads |
| Publication barrier is opt-in | The unsafe baseline remains the default write path | Make B the default and add a majority-visibility regression test |
| Barrier timeout is ambiguous | A client cannot know whether a committed write will become visible | Idempotency keys or operation de-duplication |
| Response-only watermark | A commit no responder has seen cannot raise it | Coordinate with the write path or use a trusted revision source |
| Majority DNS trust | Two colluding nodes can lie | DNSSEC or signed zone snapshots |
| One resolver process in the demo | Clients pointed at it depend on it | Replicate the resolver or compare in the stub |
