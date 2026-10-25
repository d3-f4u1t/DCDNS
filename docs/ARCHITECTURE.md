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

## ADR-2 — DNS: purpose-built authoritative front-end, not the CoreDNS etcd plugin

**Context.** CoreDNS ships an `etcd` plugin that serves SkyDNS-formatted keys
directly. That is the shortest path from a key-value store to working DNS.

**Decision.** Implement a small authoritative server (`dns_server.py`) that
speaks the RFC 1035 wire format, fed by a publisher that polls committed state.

**Why.**

* **Publication semantics.** The plugin serves whatever key exists at a path. It
  has no concept of `pending_transfer` or `revoked`, so a retained-but-revoked
  key would still answer. The registry needs a publication rule, not a key
  lookup.
* **Schema coupling.** Using the plugin would make the internal key layout a
  public interface, constraining how records are versioned and audited.
* **Measurability.** A publisher that records `published_revision` lets us
  report propagation lag precisely. The plugin offers no such hook.
* **Independence.** The DNS layer consumes *committed state over HTTP*, so it
  works identically regardless of how the cluster is implemented.

**Consequences.**

* We implement name parsing and response encoding ourselves (~200 lines) and
  must get compression pointers and RCODEs right. This is covered by wire-level
  tests.
* No DNSSEC, no zone transfers, no recursive resolution, no `AAAA`/`TXT`.
* The server is authoritative for one zone and one record type.

**Production path.** Keep the publisher contract (`committed state → zone`) and
swap the sink: render a zone file for BIND/CoreDNS, or push through RFC 2136
dynamic updates. The publisher, not the DNS engine, is the reusable part.

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
(`nslookup -port=5353 ... 127.0.0.1`). A real deployment would use a subdomain
of a university-owned zone and integrate with existing DNS/DHCP.

---

## Module boundaries

```text
crypto.py     pure functions: keys, canonical bytes, signatures
names.py      pure functions: syntax and record policy
state.py      pure state machine: apply(operation) -> result | error
cluster.py    I/O and ordering only; calls state.apply
node.py       HTTP surface; no business rules
dns_server.py publication and wire format; reads committed state only
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
