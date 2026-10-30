# Threat Model

Scope: the registry prototype as implemented in this repository, deployed as
three nodes on one machine. Each node also runs a lab DNS responder, and clients
query a quorum resolver that requires 2 of 3 nodes to agree. The optional
publication barrier B changes the write acknowledgement; RAM-DNS C is a
read-side detector, not a substitute for B.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Namespace delegation records | Whoever controls a namespace controls every name inside it |
| Domain ownership records | Determines who may change where a name points |
| Record contents (`A`) | Redirects traffic for a campus name |
| Audit log | Evidence of who changed what, and when |
| Private keys | Possession *is* identity in this system |
| DNS answers | What users and browsers actually act on |

## 2. Adversaries

| Adversary | Capability assumed |
|---|---|
| Unaffiliated network user | Can call the API, submit arbitrary signed operations, read public state |
| Malicious student | Holds a valid key but no authority over the target namespace |
| Compromised department key | Can act fully within that department's subtree |
| Network attacker | Can drop, delay or reorder packets between nodes |
| Node operator (honest-but-curious) | Can read local state and logs |
| Crashed node | Stops responding; may restart with stale state |
| Lying DNS node | Returns a forged answer while still participating in replication |

**Out of scope:** a node that actively lies while participating in registry
consensus (Byzantine), two colluding DNS nodes, a compromised root key, and
physical access to the host.

---

## 3. Threats and mitigations

### T1 — Impersonation
*Attack:* submit an operation claiming to be another participant.
*Mitigation:* the actor field is bound into the signed bytes. Changing the actor
invalidates the signature. Verified on every node, not just the entry point.
*Residual:* none beyond private-key compromise.
*Test:* `test_impersonation_rejected`.

### T2 — Tampering with an operation in flight
*Attack:* modify the record value after signing.
*Mitigation:* canonical serialisation over the full envelope; any change breaks
verification. There is no unsigned field that affects state.
*Test:* `test_invalid_signature_rejected`, experiment *Tampered signature*.

### T3 — Replay
*Attack:* resubmit a previously accepted operation.
*Mitigation:* each operation carries a nonce; accepted nonces are recorded in
state. Replay is rejected deterministically on every node.
*Residual:* nonces are stored indefinitely, so state grows with operation count.
*Test:* `test_replayed_operation_rejected`, experiment *Replay*.

### T4 — Cross-namespace modification
*Attack:* a department modifies another department's names.
*Mitigation:* authorization is computed from the *longest enclosing namespace*,
and the signer must be that namespace's controller (or a granted member). A node
cannot be tricked by sending the request elsewhere, because every node applies
the same rule to the same state.
*Test:* `test_cross_department_registration_rejected`,
`test_unauthorized_namespace_delegation_rejected`.

### T5 — Duplicate registration / race
*Attack:* two participants register the same name concurrently.
*Mitigation:* the leader serialises operations and the state machine rejects the
second with `NAME_TAKEN`. Because writes require majority commit before being
acknowledged, there is no window in which both callers see success.
*Test:* experiment *Duplicate registration*.

### T6 — Record hijack via a prohibited destination
*Attack:* point a campus name at an external host for phishing or exfiltration.
*Mitigation:* the record policy rejects addresses outside campus space at the
state-machine level.
*Test:* `test_public_or_reserved_addresses_rejected`, experiment *Prohibited
destination*.

### T7 — Unauthorized revocation or transfer
*Attack:* revoke or steal someone else's name.
*Mitigation:* revocation requires owner, namespace controller or root; transfer
requires the owner to initiate **and** the recipient to accept, with records
frozen in between.
*Test:* `test_transfer_requires_owner`, `test_transfer_accept_requires_new_owner`,
`test_records_frozen_during_pending_transfer`.

### T8 — Reaching a single node to bypass policy
*Attack:* send a write directly to a follower.
*Mitigation:* followers forward to the leader and never apply uncommitted
entries. Policy is evaluated by the state machine on every node.
*Test:* cluster smoke phase 2 submits the same forged operation to all nodes.

### T9 — Node failure
*Attack/fault:* crash a node, or partition it.
*Mitigation:* majority commit; continued writes with one of three nodes down;
refusal without a majority; append-only catch-up on rejoin.
*Test:* `scripts/cluster_smoke.py` phases 3–6.

### T10 — Silent history editing
*Attack:* alter or delete an audit record on one node.
*Mitigation:* hash chain; verification reports the first broken record. Nodes
that diverge are detectable by comparing revisions and chain heads.
*Test:* `test_audit_chain_detects_tampering`.

### T11 — Stale DNS data after revocation
*Attack/fault:* a revoked name keeps resolving.
*Mitigation:* every node's DNS snapshot excludes revoked domains and names in
revoked namespaces. The snapshot refreshes on commit, so withdrawal is observed
as soon as the revocation commits on that node.
*Residual:* resolver caches may serve the old answer until the 30-second TTL
expires. This is inherent to DNS, not a defect, and is measured rather than
hidden.
*Test:* experiment *Revocation removes the name from DNS*.

### T12 — Lying DNS node
*Attack:* one registry node returns a forged `A` record while continuing to
participate in replication.
*Mitigation:* the client-facing quorum resolver queries all three node responders
and returns an answer only when at least two nodes return semantically identical
results. One liar is outvoted and the disagreement is recorded in metrics.
*Residual:* two colluding nodes can form a lying majority. DNSSEC or signed zone
snapshots are not implemented, so the resolver cannot prove an answer
cryptographically. The signed EDNS revision token proves which node made a
revision claim; it does not prove the answer itself.
*Test:* experiment *Majority DNS resists a lying node*, plus
`tests/test_quorum_resolver.py`.

### T13 — DNS availability without a majority
*Attack/fault:* two nodes are down and only one responder is reachable.
*Mitigation:* the resolver requires 2 of 3 configured nodes and returns
`SERVFAIL` rather than trusting the single survivor. This prefers no answer over
a potentially compromised one.
*Residual:* clients cannot resolve while no majority is available. This is a
deliberate availability trade-off.
*Test:* `tests/test_quorum_resolver.py` single-node `SERVFAIL` cases.

### T14 — Stale majority
*Attack/fault:* two nodes agree on an old answer while the third has already
applied a newer committed revision. The stale nodes are not lying; they are
serving a real older snapshot.
*Mitigation:* each answer carries the serving revision in EDNS option `65001`.
After the semantic majority is found, the resolver computes a committed revision
watermark and applies F1/F2/F3 to the majority. A stale majority is retried a
bounded number of times, then refused with `SERVFAIL` (default) or returned with
a stale marker (EDNS option `65002`) and a reduced TTL.
*Residual:* the watermark can only reflect commits that some responder has seen.
A single node can raise the `responses` watermark with a false high revision and
force fail-closed behaviour; `watermark=quorum` resists that but cannot detect a
stale majority. A stale majority that omits revision tokens entirely is accepted
under the default lenient metadata policy; `--require-revision` fails closed.
RAM-DNS is not BFT. It is a read-side detector; the write-path fix is B.
*Test:* experiment *Stale majority is detected, not served*, plus
`tests/test_ram_dns.py`.

### T15 — Acknowledged write not yet publishable to DNS
*Fault:* the baseline acknowledges a write after a majority has stored the log
entry, while the followers apply it only on a later replication push. For a short
window the coordinator serves the new revision and the followers serve the old
one, so a semantic DNS majority can return the old address after the client was
told the write succeeded. This is a commit/apply gap, not Byzantine behaviour.
*Mitigation:* the publication barrier B (`--publication-barrier`) acknowledges
only after a majority reports applying the committed revision to the DNS state.
If that condition cannot be met before the deadline, the API returns `NO_QUORUM`
with `"ambiguous": true` rather than falsely succeeding. RAM-DNS C can detect a
remaining stale majority on the read side, but it does not repair the write path.
*Residual:* B adds one replication round trip and can time out after commit, so
non-idempotent retries need client-side de-duplication. B checks the registry's
`dns_revision`, not the responder's `serving_revision`, so a frozen responder can
still let B acknowledge. B trusts self-reported peer revisions and is not
Byzantine-safe. B is currently opt-in.
*Test:* A/B/C harness (`scripts/commit_lag_repro.py`), `tests/test_commit_hold.py`,
and `docs/CONSISTENCY_AUDIT.md`.

---

## 4. Trust boundaries

```text
  untrusted                     trust boundary                  trusted
  ---------                     --------------                  -------
  any client  --signed op-->  [ verify signature ]  -->  state machine
  any client  --signed op-->  [ namespace policy ]  -->  state machine
  follower    --append RPC->  [ term / log rules ]  -->  replicated log
  registry client --write-->  [ commit + applied majority (B) ] --> ack or ambiguous
  DNS client  --query------>  [ 2-of-3 agreement + freshness ] --> answer or SERVFAIL
```

The registry never trusts the transport. A node that receives an operation
verifies it itself; it does not rely on the forwarding node having done so.

---

## 5. Residual risk register

| Risk | Severity | Status |
|---|---|---|
| Root key compromise | Critical | Accepted for prototype; 2-of-3 root signatures specified, not built |
| Unauthenticated internal RPC | High if exposed | `/internal/*` is bound to loopback only; production requires mutual TLS between nodes |
| Owner key loss (no recovery) | High | Documented; break-glass policy specified, not built |
| Byzantine node | High | Out of scope; explicitly not claimed |
| Two colluding DNS nodes | High | Majority trust boundary; DNSSEC/signed zones not built |
| Stale majority | High | Detected by RAM-DNS F1/F2/F3; fails closed after bounded retries |
| Acknowledged write not yet publishable | High | B closes the normal path but is opt-in; C can detect the read-side symptom; see the audit |
| Ambiguous barrier timeout | Medium | The write may commit after `NO_QUORUM`; idempotency/de-duplication is not implemented |
| Single false-high revision | Medium | Can force fail-closed under `responses` watermark; signed tokens identify the claimant, `quorum` watermark is an alternative |
| Watermark completeness | Medium | Response-based watermark cannot see a commit no responder has seen |
| Portal holds private keys | High in production | Demo-only; documented in the UI |
| Nonce table grows unbounded | Low | Acceptable at prototype scale |
| Log never compacted | Low | Acceptable at prototype scale |
| `.test` only, no public delegation | Low | Deliberate isolation |
| DNS cache holds revoked records for TTL | Low | Measured, inherent to DNS |
| DNS unavailable without a majority | Medium | Deliberate: `SERVFAIL` instead of trusting one node |

---

## 6. What we deliberately do not claim

* That the system eliminates central authority. The root authority remains.
* That it resists a malicious registry node.
* That two colluding DNS nodes cannot lie.
* That B is currently the default. It is opt-in through
  `--publication-barrier`; the audit recommends making it the default.
* That B or C is Byzantine fault tolerance. B trusts self-reported peer
  revisions; C's signature proves authorship, not truth.
* That DNS answers are DNSSEC-signed. The EDNS revision token attests revision
  metadata, not the answer; DNSSEC is not implemented.
* That it is a production PKI. Key enrolment and recovery are specified, not
  implemented.
* That every client can resolve these names. Only clients pointed at the lab
  resolver can.
