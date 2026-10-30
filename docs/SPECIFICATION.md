# DCDNS Protocol Specification

Version 1.0 · applies to the implementation in this repository.

This document defines the registry's participants, data model, operations,
authorization rules, error codes and guarantees. It is the contract that the
state machine (`dcdns/state.py`) implements and the test suite verifies.

---

## 1. Goals

1. Authorized participants can register and manage campus domain names without
   a central administrator approving each routine change.
2. A name resolves to exactly one authoritative record set at any revision.
3. Ownership and permission changes are authenticated and auditable.
4. The registry survives the loss of any single node without losing committed
   state or the ability to accept writes.
5. Committed state is served as standard DNS by every registry node, and clients
   accept an answer only when a majority of nodes agrees and that majority is
   fresh relative to the committed revision watermark.
6. With the optional publication barrier B, a successful write means that a
   majority of registry nodes has applied the committed revision to the state
   used for DNS answers, not merely stored it.

## 2. Non-goals

* Trustless operation. A root authority bootstraps trust (see §9).
* Byzantine fault tolerance. Nodes are assumed honest but possibly crashed.
* General-purpose DNS. v1 publishes IPv4 `A` records only, under `.test`.
* Public internet deployment. The namespace is lab-local by design.

---

## 3. Participants

| Role | Technical meaning | May do |
|---|---|---|
| Root authority | Holder of the root private key | Create/revoke top-level namespaces; rotate any controller |
| Department administrator | Controller key of a delegated namespace | Manage its subtree: delegate, grant, register, revoke |
| Domain owner | Key recorded as `owner` of a domain | Update records, initiate transfer, revoke |
| Registrar (member) | Key granted `can_register` in a namespace | Register names inside that namespace |
| Registry node | A process running the state machine | Store and order operations; no authority of its own |
| DNS client | Any resolver | Read published records only |

A registry node is **not** an authority. Being able to reach a node confers no
right to change state: every node verifies every signature and every rule.

---

## 4. Identity and operation format

An identity **is** an Ed25519 public key, base64url encoded (32 raw bytes).

Every operation is a JSON object:

```json
{
  "v": 1,
  "op": "register_domain",
  "actor": "<base64url public key>",
  "nonce": "<32 hex chars>",
  "ts": 1761264000,
  "body": { "name": "techfest.cs.test", "records": { "A": "10.20.5.42" } },
  "sig": "<base64url signature>"
}
```

The signature is computed over:

```text
"DCDNS-OP-V1\n" || canonical_json(op without "sig")
```

where `canonical_json` is UTF-8 JSON with sorted keys, no whitespace, and no
ASCII escaping. Domain separation (`DCDNS-OP-V1\n`) prevents a signature from
being replayed in another protocol.

`ts` is an ingress freshness bound only (rejected outside ±900 s). It is **not**
part of state-machine decisions, which keeps the machine time-independent and
therefore deterministic across nodes.

`nonce` is recorded on acceptance. Re-submitting an accepted operation fails
with `REPLAY_DETECTED`. Rejected operations consume nothing, so they fail the
same deterministic way every time.

---

## 5. Data model

### 5.1 Namespace

```json
{
  "name": "cs.test",
  "controller": "<public key>",
  "parent": "test",
  "status": "active",
  "delegated_by": "<public key>",
  "created_revision": 2,
  "members": { "<public key>": { "can_register": true } }
}
```

`status` is `active` or `revoked`. Revocation is terminal for v1.

### 5.2 Domain

```json
{
  "name": "techfest.cs.test",
  "owner": "<public key>",
  "namespace": "cs.test",
  "records": { "A": "10.20.5.42" },
  "status": "active",
  "created_revision": 4,
  "updated_revision": 4,
  "transfer": null
}
```

`status` is `active`, `pending_transfer` or `revoked`.
`transfer`, when present, is `{ "new_owner": key, "initiated_by": key,
"initiated_revision": n }`.

### 5.3 Namespace resolution

The governing namespace of a name is the **longest** delegated namespace that is
a suffix of it. `robotics.cs.test` → `cs.test`; `project.team.cs.test` →
`team.cs.test`. A name with no governing namespace cannot be registered.

### 5.4 Domain lifecycle

```text
            register_domain
                  |
                  v
               ACTIVE  <---------------------+
             /   |    \                       |
   update_records |   transfer_initiate       | transfer_cancel
             |    |         v                 |
             |    |   PENDING_TRANSFER -------+
             |    |         | transfer_accept
             |    |         v
             |    +----> ACTIVE (new owner)
             |
        revoke_domain
             v
          REVOKED  (terminal)
```

Records are frozen while `pending_transfer`, so an owner cannot alter a domain
mid-handover.

---

## 6. Operations

| Operation | Body fields | Required authorization |
|---|---|---|
| `delegate_namespace` | `name`, `controller` | Root for `*.test`; otherwise controller of the parent namespace |
| `grant_member` | `namespace`, `member`, `can_register` | Controller of the namespace |
| `register_domain` | `name`, `records` | Controller, root, or a member with `can_register` in the governing namespace |
| `update_records` | `name`, `records` | Domain owner, or controller of the governing namespace |
| `transfer_initiate` | `name`, `new_owner` | Domain owner |
| `transfer_accept` | `name` | The proposed `new_owner` only |
| `transfer_cancel` | `name` | Current owner |
| `revoke_domain` | `name`, `reason` | Owner, namespace controller, or root |
| `revoke_namespace` | `name`, `reason` | Namespace controller or root |
| `rotate_controller` | `name`, `new_controller` | Namespace controller or root |

All operations are validated in full before any state is mutated, so a rejection
is always side-effect free.

### 6.1 Record policy

Only `A` records are supported in v1. The address must parse as IPv4 and fall
inside campus address space:

```text
10.0.0.0/8   172.16.0.0/12   192.168.0.0/16   127.0.0.0/8
```

Public, multicast, unspecified and reserved addresses are rejected with
`RECORD_NOT_ALLOWED`. This is a policy rule enforced by the registry, not a
suggestion to the client.

### 6.2 Name syntax

* total length ≤ 253 characters, at least two labels;
* labels 1–63 characters of `a-z`, `0-9`, `-`, not starting or ending with `-`;
* must end in `.test` (the root zone of this registry);
* normalised to lower case, trailing dot removed;
* wildcards are not permitted.

---

## 7. Error codes

| Code | Meaning |
|---|---|
| `MALFORMED_OPERATION` | Envelope missing fields or wrong types |
| `UNSUPPORTED_VERSION` | `v` is not 1 |
| `UNKNOWN_OPERATION` | `op` not in the operation table |
| `INVALID_SIGNATURE` | Signature does not verify against `actor` |
| `REPLAY_DETECTED` | `(actor, nonce)` already accepted |
| `STALE_OPERATION` | Timestamp outside the ingress freshness window |
| `INVALID_NAME` / `OUTSIDE_ROOT_ZONE` | Name syntax or zone violation |
| `INVALID_RECORDS` / `UNSUPPORTED_RECORD_TYPE` / `RECORD_NOT_ALLOWED` | Record policy violation |
| `INVALID_KEY` | Supplied key is not a 32-byte Ed25519 public key |
| `NAMESPACE_TAKEN` / `NAME_TAKEN` | Name already delegated or registered |
| `NAMESPACE_NOT_FOUND` / `PARENT_NAMESPACE_NOT_FOUND` / `NO_NAMESPACE` | No governing authority |
| `NAMESPACE_REVOKED` / `NAME_REVOKED` | Authority or name withdrawn |
| `UNAUTHORIZED` | Signer lacks the required authority |
| `TRANSFER_PENDING` / `NO_PENDING_TRANSFER` / `INVALID_TRANSFER` | Transfer state violation |
| `NOT_LEADER` / `NO_QUORUM` | Cluster-level condition, not a protocol violation |

---

## 8. Replication and consistency

* Nodes hold an ordered log of signed operations. Followers never originate
  entries, so every log is a prefix of the leader's log.
* The leader is the lowest-id node among a reachable majority. Any two
  majorities of three nodes intersect, so two nodes cannot both lead while both
  hold a majority.
* **Baseline acknowledgement (A).** A write is acknowledged after a majority has
  durably stored the entry. Followers apply it only when a later replication
  push advertises the new commit index, so an immediate DNS query can observe a
  stale semantic majority.
* **Publication barrier (B).** With `--publication-barrier`, a write is
  acknowledged only after a majority reports applying the committed revision to
  the state used for DNS answers. If the entry commits but the applied majority
  is not reached before the deadline, the API returns `NO_QUORUM` with
  `"ambiguous": true`. The operation may still become visible later, so a
  non-idempotent retry requires client-side de-duplication. B is currently
  opt-in; making it the default is the audit's first recommendation.
* A follower applies entries only up to the leader's committed index.
* Reads are served from local committed state and may lag briefly;
  `GET /domains/{name}?consistent=true` forces a leader read.

Guarantees provided: **majority durability**, **total order of accepted
operations**, **convergence after reconnection**, **continued writes while one
of three nodes is down**, **write refusal without a majority**, and, with B
enabled, **acknowledgement only after an applied majority**.

For DNS, every node serves the committed state it holds. A lagging follower may
answer from a slightly older revision; the quorum resolver exposes this by
requiring agreement and by reporting each node's revision. A majority of
agreeing answers is required for a client answer; no majority means `SERVFAIL`.

Not provided: Byzantine tolerance, cross-datacenter latency bounds, automatic
membership changes.

---

## 9. Trust bootstrap and residual central power

The root key authorises departmental keys. This is a deliberate trust anchor:

* compromise of the root key compromises namespace delegation (not individual
  domain records directly);
* the root can revoke an entire namespace, which withdraws all names inside it
  from DNS;
* the root cannot forge a domain owner's signature, so it cannot silently
  rewrite an individual record without leaving an audit entry signed by itself.

Key-loss recovery is documented but **not implemented** in v1. The intended
policy is 2-of-3 root signatures for break-glass recovery, with mandatory audit
entries.

---

## 10. DNS boundary

The registry is authoritative for state. DNS is served independently by every
registry node from that node's committed state, and a client-facing resolver
requires majority agreement plus revision freshness. There is no separate
publisher and no central DNS front-end.

**Publication rule.** A name is present in a node's DNS snapshot when the domain
is not `revoked` and its governing namespace is `active`. Therefore:

* `active` domains are published;
* `pending_transfer` domains are published with their frozen records, so a
  handover does not cause downtime;
* revoked domains are absent;
* all domains in a revoked namespace are absent.

**Per-node responder.** Each node runs a UDP responder on its own port
(`5354`, `5355`, `5356` in the demo). It answers `A` and `ANY` queries, sets the
authoritative-answer bit, uses a 30-second TTL, returns `NXDOMAIN` for unknown
names, and returns `NOTIMP` for unsupported types. Each answer carries the
node's serving revision, a zone digest and an optional Ed25519 signature in EDNS
option `65001`.

**Quorum resolver.** The resolver on UDP `5353` forwards the same query to every
configured node, reduces each response to its semantic content (RCODE plus sorted
answer records), and accepts an answer only if at least a majority agrees (2 of 3
in the demo). It ignores transaction IDs, harmless flags, TTL differences and
record order for grouping. It then reads revision evidence from the EDNS token
(or the node status API as a fallback), computes a committed revision watermark,
and applies the configured freshness condition:

* **F1** (default): at least one node in the winning majority is at the
  watermark.
* **F2**: at least `required` majority nodes are within `delta` of the watermark.
* **F3**: every majority node is within `delta` of the watermark.

A stale majority is retried up to the configured budget, then the resolver
returns `SERVFAIL` (default) or a marked-stale answer with EDNS option `65002`
and a reduced TTL. The resolver has no zone and cannot invent an answer; it may
hold node public keys to verify revision tokens.

**Write-path publication barrier (B).** The primary fix for the
acknowledged-write stale-majority window is B, not the read-side freshness
check. With `--publication-barrier`, a write is acknowledged only when a
majority of live nodes reports a DNS revision at least as high as the committed
index. The barrier checks the registry's `dns_revision`, not the responder's
`serving_revision`; a responder frozen after the registry applied the revision
can therefore still let B acknowledge. B is non-Byzantine and trusts
self-reported peer revisions. Its cost is one replication round trip, and its
timeout can be ambiguous after commit.

**Read-side freshness (C).** RAM-DNS is an optional detector layered on the
resolver. It can refuse a stale majority, including a frozen responder, when a
newer revision is visible somewhere. It does not repair the write path and can
return `SERVFAIL` during a transient window. B and C are complementary: B is the
correctness fix, C is defence in depth.

**Failure semantics.** One node down: the remaining two agree and the resolver
answers if the majority is fresh. One node lying: the honest two outvote it. Two
nodes down or three different answers: `SERVFAIL`. A semantically agreeing but
stale majority is retried, then refused under the default policy. Two colluding
nodes can produce a majority lie; this is the documented boundary of majority
trust, because DNSSEC is not implemented. A single node claiming a false high
revision can force fail-closed behaviour under the `responses` watermark.

**Observability.** Each node reports committed revision, serving revision,
revision lag, frozen state and zone size. The resolver reports
`published_revision` (the lowest committed revision among reachable nodes),
`serving_revision`, `watermark`, query counts, `NXDOMAIN`, `SERVFAIL`,
disagreements, freshness failures, stale-majority queries, retries, stale
answers and per-node revision evidence. End-to-end propagation is measured in the
evaluation suite.

---

## 11. Audit

Each accepted operation appends a record:

```json
{
  "seq": 12,
  "revision": 12,
  "op": "update_records",
  "target": "techfest.cs.test",
  "actor": "<public key>",
  "detail": { "...": "operation-specific" },
  "prev_hash": "<hash of record 11>",
  "hash": "sha256(canonical_json(record without hash))"
}
```

`verify_audit_chain()` recomputes the chain. Changing any historical record
invalidates every hash after it, which is what the Audit page displays.

---

## 12. Success criteria

The implementation is considered correct when all of the following hold, and
each is covered by an automated check:

1. Duplicate registration yields exactly one owner.
2. A forged update is rejected and leaves the record unchanged.
3. Cross-namespace writes and delegations are rejected.
4. A tampered signature is rejected.
5. A replayed operation is rejected.
6. Prohibited destinations are rejected.
7. Transfer requires both parties.
8. Revocation removes the name from DNS.
9. A record update appears in DNS within the measured window.
10. Writes survive one node failure and stop without a majority.
11. A pending-transfer name keeps resolving from its frozen record.
12. One lying DNS node cannot change the majority answer.
13. Without a DNS majority, the resolver returns `SERVFAIL` rather than trusting
    one node.
14. A semantically agreeing but stale majority is detected, retried, and refused
    under the default policy rather than served as current.
15. Revision metadata is bound to the node, revision and zone digest, and an
    invalid signature fails closed when a key is configured.
16. With the publication barrier enabled, an acknowledged write is followed by a
    majority whose DNS revision includes the committed revision; if that
    condition cannot be met, the write fails closed with an ambiguous timeout.
