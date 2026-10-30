# DCDNS — A Replicated Campus Registry and a Study of DNS Publication Freshness

DCDNS is a permissioned registry for campus DNS namespaces. A root authority
delegates subtrees such as `cs.test` and `library.test`; departments and students
register names such as `techfest.cs.test`; ownership is proven with Ed25519
signatures; and every accepted operation is ordered by a majority-replicated log.
Each registry node is also an authoritative DNS responder, so there is no separate
DNS publisher and no single DNS process that owns the zone.

The repository is organised around one systems result:

> **A replicated registry can acknowledge a write before a majority of its DNS
> responders can serve the new state. The primary fix is a write-path publication
> barrier (B). Revision-aware majority DNS (C, “RAM-DNS”) is a read-side detector
> that complements B but does not replace it.**

That result is not merely asserted. It was reproduced deterministically,
implemented as a write-path barrier, and compared against the read-side
alternative in
[`docs/CONSISTENCY_AUDIT.md`](docs/CONSISTENCY_AUDIT.md). The literature and
novelty assessment is in [`docs/ACADEMIC_REVIEW.md`](docs/ACADEMIC_REVIEW.md).

---

## Abstract

Distributed registries commonly separate two events: an entry becomes *committed*
when a quorum has stored it, and it becomes *applied* when the deterministic state
machine has executed it. If the registry also publishes state through a second
interface — here, authoritative DNS — a third event matters: the moment a
responder can actually serve the new state. Collapsing these events into a single
`committed: true` response creates a read-your-writes violation even when every
node is honest and every committed prefix is internally consistent.

This project makes the gap observable, measures it, and evaluates two responses.
Variant **B**, a publication barrier, delays the write acknowledgement until a
majority reports applying the committed revision to the state used for DNS
answers. Variant **C**, RAM-DNS, leaves the write path unchanged and adds
per-answer revision evidence plus a freshness condition to the client-facing
resolver. The experiment finds that B removes the normal-path stale-majority
window at the cost of one replication round trip, while C converts the window
into `SERVFAIL` at a substantial lookup-latency cost. B is the correctness fix;
C is defence in depth for responder-level staleness and partial connectivity.

The current code keeps B behind an explicit `--publication-barrier` flag so the
unsafe baseline remains available for comparison. **B is not yet the default.**
Making it the default is the first recommendation of the audit.

---

## 1. The problem

### 1.1 A write that is “committed” but not yet publishable

Consider three registry nodes, a quorum of two, and an update from
`10.20.5.42` to `10.20.5.99` at log index `i`.

1. The coordinator appends entry `i` and replicates it. The replication payload
   carries the coordinator's *previous* commit index, `i - 1`.
2. The followers durably store entry `i`, but they do not apply it, because the
   coordinator has not yet told them that `i` is committed.
3. The coordinator observes that a majority has stored `i`, advances its own
   commit index to `i`, applies the entry locally, and — in the baseline —
   returns success to the client.
4. An immediate DNS query sees the coordinator at revision `i` with the new
   address, and the two followers at revision `i - 1` with the old address.
5. The semantic-majority resolver sees two votes for the old address and one for
   the new address. It returns the old address, because two of three nodes agree.

Nothing in this sequence is Byzantine, and no node is lying. All three nodes are
serving a genuine committed prefix. The defect is a mismatch between the
acknowledgement contract and the publication state: the API says “committed”
while the DNS read path can still select the previous prefix.

### 1.2 Why majority agreement is not freshness

The resolver's semantic rule — identical `RCODE` and identical sorted answer
records — is correct for *agreement*. It is insufficient for *freshness*. A
majority can agree on an old value while a newer value is already committed. This
is the DNS analogue of the bare-quorum-read problem identified by Charapko,
Ailijiang and Demirbas (HotStorage 2019), and of the commit/apply distinction in
Raft (USENIX ATC 2014). The phenomenon class is well known; the deterministic
100% reproduction here is a property of this prototype's acknowledgement design
and immediate-query harness.

### 1.3 Observed baseline

In the final baseline run, **12 of 12 acknowledged writes** left a stale
semantic majority, and the semantic resolver returned the old address in **12 of
12** cases. A larger natural run reproduced the failure in **20 of 20** trials.
The median time from acknowledgement to all-node convergence was **251.88 ms**,
while the median write acknowledgement took **7.87 ms**. The client was therefore
told that the write had succeeded roughly 240 ms before the DNS read path could
be trusted to reflect it.

The full timeline, raw records and code-level explanation are in
[`docs/CONSISTENCY_AUDIT.md`](docs/CONSISTENCY_AUDIT.md).

---

## 2. System model

DCDNS is a **permissioned, non-Byzantine** system. The model is deliberately
small enough to reason about and to demonstrate on one host.

| Element | Assumption |
|---|---|
| Membership | Three registry nodes with statically configured identities and URLs |
| Quorum | `floor(N/2) + 1`, i.e. two of three |
| Faults | Crash, omission, delay, restart, and a single lying DNS responder |
| Not assumed | Byzantine registry consensus; two colluding DNS nodes; a compromised root key |
| Registry state | Deterministic state machine over an ordered log of signed operations |
| DNS publication | Each node serves a flat zone snapshot derived from its own committed state |
| Client resolution | A resolver queries all configured nodes and applies semantic majority plus optional freshness |
| Trust bootstrap | A root key certifies departmental controllers; the root remains a residual authority |
| Scope | `.test` names and IPv4 `A` records only; no DNSSEC, recursion, or global DNS delegation |

The two planes are intentionally separate:

```text
                       signed operations (Ed25519)
                                  |
                                  v
                 +----------------+----------------+
                 |                |                |
            Registry n1      Registry n2      Registry n3
            API 9101         API 9102         API 9103
            DNS 5354         DNS 5355         DNS 5356
                 |                |                |
                 +---- quorum-replicated log -----+
                                  |
                       committed registry state
                                  |
                 +----------------+----------------+
                 |                |                |
            DNS responder    DNS responder    DNS responder
                 |                |                |
                 +------ client quorum resolver ---+
                              UDP 5353
                                  |
                         dig / DNS client
```

Registry quorum and DNS quorum are different decisions. A write can commit while
the DNS resolver still returns `SERVFAIL` because too few responders answer. The
console labels the two panels separately for exactly this reason.

---

## 3. The write path and publication barrier B

### 3.1 Baseline protocol

The coordinator validates an operation against a clone of the state, appends it
to the log, persists it, and replicates. It advances `commit_index` when a
majority has *stored* the entry. The baseline acknowledges as soon as
`commit_index >= index`.

This is sufficient for durability and total order. It is not sufficient for the
publication contract that the HTTP API implies.

### 3.2 Barrier protocol

With `--publication-barrier`, the acknowledgement condition becomes:

```text
commit_index >= index
AND
a majority of live nodes report dns_revision >= index
```

`_applied_majority(index)` counts the coordinator only after its own
`_refresh_dns_zone()` has exposed the applied revision, and counts each live
follower only when its append response reports a `dns_revision` at least as high
as `index`. If the first replication round commits the entry but the followers
have not yet applied it, the coordinator performs a second replication push that
advertises the new commit index, then re-checks the applied majority before
returning success.

The result is a stronger acknowledgement:

> A successful write means the operation is committed **and** a majority of
> registry nodes have applied the committed revision to the state from which they
> serve DNS.

If the deadline expires after the entry has committed but before the applied
majority is reached, the API returns `NO_QUORUM` with `"ambiguous": true`. The
operation may still become visible later. This is an honest failure contract, but
it requires client-side idempotency or operation de-duplication before retries
are safe for non-idempotent operations such as transfers and revocations.

### 3.3 Cost and coverage

The barrier adds one replication round trip to the acknowledgement. In the final
comparison, control writes acknowledged at a p50 of **14.80 ms**, versus
**7.87 ms** for the baseline. The trade is explicit: a slightly later success,
but success now means the DNS state is actually published.

B closes the ordinary commit/apply window. It does **not** cover a DNS responder
that is frozen at an older snapshot: the barrier checks the registry's
`dns_revision`, not the responder's `serving_revision`. That residual gap is one
reason C remains useful.

---

## 4. The read path and RAM-DNS C

RAM-DNS (“revision-aware majority DNS”) keeps the semantic majority as its first
condition and adds a second condition over revision evidence.

```text
query
  |
  v
ask every configured node (UDP)
  |
  v
semantic majority? ---- no ---> SERVFAIL
  |
 yes
  |
  v
extract revision evidence (EDNS option 65001, or status fallback)
  |
  v
compute watermark W (best-known committed revision)
  |
  v
evaluate F1 / F2 / F3 over the winning majority
  |
  +-- fresh ----> return the majority answer
  |
  +-- stale ----> bounded retry (default 2)
                    |
                    +-- converged ----> return the new majority answer
                    |
                    +-- still stale --> servfail (default)
                                        or marked-stale
```

Each DNS answer may carry a signed EDNS(0) token containing the node id, the
serving revision, a BLAKE2b-128 zone digest, and an optional Ed25519 signature.
The resolver computes a watermark from the responses (by default the highest
revision observed) and applies one of three conditions:

| Condition | Rule | Interpretation |
|---|---|---|
| **F1** (default) | `max(M) >= W` | At least one member of the majority is at the watermark |
| **F2** | a quorum of `M` is within `W - Δ` | Tolerates bounded lag |
| **F3** | `min(M) >= W - Δ` | Strictest; highest availability cost |

A stale majority is retried up to a configured budget, then either fails closed
with `SERVFAIL` or returns an explicitly marked stale answer with EDNS option
`65002` and a reduced TTL. The default is fail-closed because an ordinary DNS
client cannot interpret the private marker.

C is a **detector**, not a repair. On the unfixed baseline it prevents the stale
answer from being returned, but it does so by failing the lookup: **0 of 12**
stale answers, **12 of 12** `SERVFAIL`, 24 retries, and a p50 lookup latency of
**117.84 ms**. It is valuable when the resolver cannot trust that the write path
was fixed, when a responder is frozen, or when partial connectivity lets queries
arrive but metadata does not. It is not a substitute for B.

The wire format, policies, watermark sources and threat model are in
[`docs/RAM_DNS.md`](docs/RAM_DNS.md).

---

## 5. How B and C fit together

B and C address different failure modes and should not be presented as rival
“solutions”.

| Property | A: semantic majority | B: publication barrier | C: RAM-DNS |
|---|---|---|---|
| Acknowledged stale majority | **12/12** | **0/3 acked** | **0/12** |
| Stale answers after an acknowledged write | 12 | 0 | 0 |
| `SERVFAIL` / fail-closed | 0 | 9/9 held writes timed out ambiguously | 12/12 |
| Write ack p50 | 7.87 ms | 14.80 ms (control) | n/a (read side) |
| Lookup p50 | 11.25 ms | 11.46 ms (control) | 117.84 ms |
| Post-ack convergence p50 | 251.88 ms | 22.54 ms (control) | n/a |
| Repairs the write path | no | **yes** | no |
| Covers a frozen responder | no | no | **yes, if a newer revision is visible** |
| Byzantine-safe | no | no | no |

The intended deployment posture is therefore:

1. **B is the primary correctness mechanism.** A successful write should mean
   that a majority has published the revision to DNS.
2. **C is optional defence in depth.** Use it in front of resolvers that cannot
   assume B, or where responder-level freeze and partial connectivity are in the
   threat model.
3. **Neither is Byzantine fault tolerance.** B trusts self-reported peer
   revisions; C's signature proves which node made a claim, not that the claim is
   true. Two colluding nodes defeat both.

---

## 6. Consistency properties: what is and is not guaranteed

The project states its guarantees narrowly.

| Property | Status |
|---|---|
| Total order of committed operations | Guaranteed by the single-writer replicated log |
| Majority durability | A committed entry survives the loss of any one node |
| Convergence after restart | A lagging follower catches up to the committed log |
| Read-your-writes after an acknowledged write | **Violated by baseline A**; holds on B's normal path when a majority applies; C may return `SERVFAIL` instead of a stale answer |
| Monotonic reads | Not generally guaranteed; C detects some violations when a newer revision is visible |
| Bounded staleness | B bounds publication at acknowledgement; this is not a linearizability proof under failures |
| Byzantine safety | Not claimed |
| Watermark completeness | C cannot detect a newer commit that no responder has seen |
| DNSSEC authenticity | Not implemented; the EDNS token is an application-layer attestation |

The academic review is explicit that B is a publication barrier, not a
linearizable read protocol, and that C is a detector, not a consensus protocol.

---

## 7. Evidence: A/B/C methodology and results

### 7.1 Method

The harness starts three real registry processes on isolated ports
(`9201–9203` APIs, `5454–5456` DNS), seeds a namespace and
`techfest.cs.test`, waits for convergence, and alternates updates between two
addresses. After each write it records the acknowledgement time, queries every
node directly, asks the semantic resolver and the RAM-DNS resolver, and reads
each node's status and serving zone.

Three conditions are compared:

* **A — baseline:** semantic majority; acknowledge after majority storage.
* **B — barrier:** same cluster with `--publication-barrier`; acknowledge after a
  majority reports applying the revision.
* **C — RAM-DNS:** baseline answers evaluated with F1 freshness, two retries,
  `servfail` policy.

Two fault modes are used: **control** (no injection; snapshot immediately after
the acknowledgement) and **commit hold** (followers store but do not advance
`commit_index` or apply; released after observation). The hold endpoint is
chaos-gated and is not part of the normal write path.

### 7.2 Results

Baseline A and detector C, final run of 12 acknowledged writes:

| Mode | Trials | Acked | A stale | C stale | C `SERVFAIL` | Ack p50 | A lookup p50 | C lookup p50 | Convergence p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| control | 3 | 3 | 3 | 0 | 3 | 7.84 ms | 11.11 ms | 118.45 ms | 252.23 ms |
| hold-0 ms | 3 | 3 | 3 | 0 | 3 | 8.17 ms | 10.17 ms | 116.15 ms | 246.42 ms |
| hold-100 ms | 3 | 3 | 3 | 0 | 3 | 7.44 ms | 11.40 ms | 116.09 ms | 231.45 ms |
| hold-300 ms | 3 | 3 | 3 | 0 | 3 | 7.01 ms | 14.19 ms | 125.90 ms | 442.19 ms |
| **all** | **12** | **12** | **12** | **0** | **12** | **7.87 ms** | **11.25 ms** | **117.84 ms** | **251.88 ms** |

Barrier B, same schedule:

| Mode | Trials | Acked | Timeouts | A stale (acked) | C stale (acked) | C `SERVFAIL` | Ack p50 | Convergence p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| control | 3 | 3 | 0 | 0 | 0 | 0 | 14.80 ms | 22.54 ms |
| hold-0 ms | 3 | 0 | 3 | — | — | 3 | — | 134.87 ms |
| hold-100 ms | 3 | 0 | 3 | — | — | 3 | — | 236.17 ms |
| hold-300 ms | 3 | 0 | 3 | — | — | 3 | — | 434.99 ms |

All nine held writes returned `NO_QUORUM` with `"ambiguous": true` after the
configured 2.5 s timeout. All nine converged after the hold was released. No
acknowledged write was followed by a stale semantic majority.

### 7.3 Interpretation

* **A** is correct about agreement and wrong about freshness. Its low latency is
  bought by silently returning an old committed prefix.
* **B** is the standard consistency fix. It makes the acknowledgement match the
  publication state and removes the normal-path window. It fails closed rather
  than falsely succeeding when the majority cannot apply.
* **C** prevents the stale answer from being returned, but it does so by failing
  the lookup. It leaves the write path unchanged. On the baseline cluster it
  turns every stale-majority window into `SERVFAIL`.

The raw records are under `data/compare-baseline-final/results/` and
`data/compare-barrier-final/results/`; the harness is
`scripts/commit_lag_repro.py`.

---

## 8. Prior art and positioning

The stale-quorum-read problem is not new, and this project does not claim to have
invented it.

* **Charapko, Ailijiang and Demirbas, “Linearizable Quorum Reads in Paxos”**
  (HotStorage 2019) state that “a bare quorum read is insufficient and it needs
  to be amended with a rinse phase to account for pending update operations.”
  That is the same structural gap: a quorum can agree on an old value while a
  newer write is pending.
* **Ongaro and Ousterhout, “In Search of an Understandable Consensus Algorithm”**
  (Raft, USENIX ATC 2014) separate majority replication/commit from state-machine
  apply and warn that read-only requests can return stale data without additional
  precautions.
* **RFC 1034** (1987) explicitly accepts propagation delay: DNS prefers
  availability over “instantaneous updates or guarantees of consistency.”
* **RFC 1996** (NOTIFY) exists because zone transfers can leave “long intervals
  of incoherence among authority servers.”
* **Gao and Venkataramani** (IEEE INFOCOM 2019) measured eight top-tier managed
  DNS providers and found propagation delays commonly in the tens of seconds,
  monotonic-read violations in six of eight providers, and at least one apparent
  eventual-consistency violation.
* **Schomp et al., “Akamai DNS”** (ACM SIGCOMM 2020) document stale metadata and
  partial connectivity as production failure modes; nameservers self-suspend
  when critical state is stale.
* **DNSSEC**, primary/secondary DNS, anycast, DNScup, ECO-DNS and Aeacus are
  adjacent mechanisms. They address authenticity, redundancy, cache consistency,
  or TTL policy, not per-answer committed-revision freshness across replicated
  authoritative nodes.

What might remain as a narrow engineering contribution is the combination of a
signed per-answer committed revision plus zone digest, semantic majority over DNS
answers, and an explicit freshness condition with bounded retries and a
fail-closed policy. The academic review found no exact prior art for the name or
the full combination, but it also found **no evidence of novelty**. Absence of an
exact term is not proof of novelty. A professional prior-art search is required
before any patent filing or public novelty claim.

The full source-verified review, including quotations, evidence grading and
threats to validity, is in [`docs/ACADEMIC_REVIEW.md`](docs/ACADEMIC_REVIEW.md).

---

## 9. Limitations and threats to validity

* **Small, local sample.** Three nodes, one host, loopback, Windows, `.test`.
  Twelve comparison trials per variant plus 20 natural trials. Percentiles from
  small samples are indicative, not stable.
* **Synthetic fault injection.** The commit hold is a controlled fault, not a
  real network partition or slow disk.
* **The 100% baseline rate is harness-specific.** The ordering bug is general,
  but a production stale-answer rate depends on timing, batching, heartbeat and
  client behaviour. No production prevalence is claimed.
* **Non-Byzantine.** B trusts self-reported peer revisions. C's signature proves
  authorship, not truth. Two colluding nodes defeat both.
* **B does not cover responder freeze.** It checks `dns_revision`, not the
  responder's `serving_revision`.
* **C's watermark is incomplete.** If every responder is still at revision `R`,
  C cannot know that `R + 1` exists. F2/F3 with delta 0 can fail closed on
  unrelated updates; F1 is less sensitive when the up-to-date node remains in the
  semantic majority.
* **No production DNS.** No DNSSEC, anycast, global root, real recursive
  resolvers, or WAN study.
* **Ambiguous timeouts require idempotency.** B can time out after commit. A
  retry of a non-idempotent operation must not apply twice; operation
  de-duplication is a next step, not an implemented guarantee.
* **Key custody is demo-grade.** The portal holds private keys; node DNS signing
  keys live under `data/live/node-keys/`.

These are stated as limitations rather than hidden. A prototype that claims more
than it demonstrates is worth less than one that is precise about its boundaries.

---

## 10. Quick start

```powershell
pip install -r requirements.txt
python run_demo.py --fresh
```

Open **http://127.0.0.1:8000**. The console is the demo: query a name, watch each
node answer, inject a DNS fault, and recover without touching the registry.

That command creates the demo identities, starts three registry nodes, seeds a
small campus, starts each node's DNS responder, starts the quorum resolver, and
starts the portal. It also enables the console's loopback-only DNS fault controls;
`python run_demo.py --fresh --no-demo-controls` hides them.

To stop: `Ctrl+C`.

Verify DNS independently of the portal:

```powershell
python -m dcdns.dig techfest.cs.test --all
python -m dcdns.dig catalog.library.test
```

Windows `nslookup` does not support a custom port, which is why the project ships
`dcdns.dig`. On Linux or macOS, `dig @127.0.0.1 -p 5353 techfest.cs.test A`
works too.

### Enabling the publication barrier

The launcher does not yet expose B as a flag. To run a node with the barrier:

```powershell
python -m dcdns.node --id n1 --port 9101 `
  --peers n2=http://127.0.0.1:9102,n3=http://127.0.0.1:9103 `
  --data data/live/n1 --root identities/root.json `
  --dns-port 5354 --chaos --publication-barrier
```

Repeat for `n2` and `n3` with the corresponding ports and peer lists, then start
the resolver and portal as `run_demo.py` does. The audit's first recommendation is
to make this behaviour the default and add a regression test that queries a
majority of DNS responders immediately after a successful write.

---

## 11. Reproducing the evidence

```powershell
# Unit, wire, majority, freshness, commit-hold and console-control tests
python -m pytest tests/ -q

# Real three-process failure and recovery checks (stop the live demo first)
python scripts/cluster_smoke.py

# End-to-end portal forms (requires the live demo)
python scripts/portal_flow.py

# Live security experiments (requires the live demo)
python scripts/evaluate.py

# Final baseline A/C comparison
python scripts/commit_lag_repro.py --trials 3 --hold-delays 0,100,300 `
  --ram --data data/compare-baseline-final

# Final barrier B comparison, same schedule
python scripts/commit_lag_repro.py --trials 3 --hold-delays 0,100,300 `
  --ram --publication-barrier --data data/compare-barrier-final

# Larger natural run: 10 controls and 10 zero-delay holds
python scripts/commit_lag_repro.py --trials 10 --hold-delays 0 `
  --data data/commit-lag-natural
```

Latest verification:

```text
python -m pytest                 108 passed
python -m compileall -q dcdns scripts tests   OK
cluster smoke                    9/9 checks passed
portal flow                      14/14 checks passed
live experiments                 12/12 passed
baseline A/C                     12/12 acknowledged writes stale; C 12/12 SERVFAIL
barrier B                        3/3 control acked, 0 stale; 9/9 held timeouts ambiguous
```

The cluster check starts three real processes and verifies majority commit,
forged-write rejection, follower loss and catch-up, coordinator failover, old
coordinator catch-up, and write refusal without a majority.

---

## 12. What the system enforces

| Claim | How it is enforced | Where to see it |
|---|---|---|
| Only authorized participants can register a name | Every operation carries a signature; the state machine checks it against the namespace's delegated controller | Experiments → *Cross-namespace write* |
| Names are unique across the registry | Duplicate registration is rejected deterministically (`NAME_TAKEN`) | Experiments → *Duplicate registration* |
| One department cannot modify another's names | Authority is a namespace tree; the longest enclosing namespace decides who may act | Experiments → *Forged update* |
| Operations cannot be replayed | The signed payload includes a nonce that the state machine records | Experiments → *Replay* |
| Accepted changes are durable across node loss | A write is committed only after a majority has stored it; with B it is acknowledged only after a majority applies it | `scripts/cluster_smoke.py` |
| A successful write is publishable to DNS | With `--publication-barrier`, a majority must report applying the revision | `docs/CONSISTENCY_AUDIT.md` |
| Every change is auditable | Hash-chained audit log; editing one record breaks every later hash | Audit page |
| Revoked names stop resolving | A node's DNS snapshot excludes revoked domains and namespaces; pending transfers keep their frozen record live | Experiments → *Revocation* |
| One lying DNS node cannot change the client answer | The resolver requires two of three nodes to return semantically identical answers | Experiments → *Majority DNS resists a lying node* |
| A stale majority is not served as current | Every answer can carry its serving revision; the resolver checks F1/F2/F3 against a watermark and fails closed after bounded retries | Experiments → *Stale majority is detected, not served* |
| No DNS majority means no answer | With two nodes down the resolver returns `SERVFAIL` rather than trusting one node | `python -m dcdns.dig name --all` |

---

## 13. The console in three minutes

Full click-by-click script: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md).

1. **Baseline** — open the console and query `techfest.cs.test`. Three direct
   UDP rows show what each node answers and the revision carried by its EDNS
   token; a separate resolver row shows the resolver's own decision, vote map,
   watermark and per-node revision evidence.
2. **One node lies** — click **Make n3 lie**. n3's direct answer becomes
   `10.20.5.66`; the resolver still returns `10.20.5.42` because n1 and n2
   outvote it. A persistent **FAULT ACTIVE** banner names the fault.
3. **Lose DNS quorum** — click **Pause n2 + n3**. n1 still answers, n2 and n3
   time out, and the resolver returns `SERVFAIL`. The registry APIs stay up.
4. **Stale majority** — click **Freeze n1 + n2 DNS**, then update
   `techfest.cs.test` through the console. n1 and n2 keep serving their real
   frozen snapshot at the old revision, n3 serves the new commit, and the
   semantic majority is stale. The resolver reports `STALE_MAJORITY`, retries,
   and returns `SERVFAIL` instead of the old address. **Thaw DNS snapshots**
   restores the new answer.
5. **Registry quorum is different** — while DNS is paused or frozen, register or
   update a name. The write still commits because registry quorum and DNS quorum
   are separate, and the console's revision counters advance. The resolver still
   returns `SERVFAIL` if only n1 is answering.
6. **Recover** — click **Reset DNS faults**. All three nodes answer the current
   committed value, the resolver returns a fresh majority answer, and the banner
   clears.
7. **Authority and audit** — switch to *Mallory* and try to update Alice's
   domain: rejected with `UNAUTHORIZED`. The audit chain still verifies.

The fault controls are loopback-only and disabled unless `run_demo.py` starts the
portal with `--demo-controls` (the default). They change only the DNS responder;
they never sign, submit, or mutate a registry operation.

---

## 14. Project layout

```text
dcdns/
  crypto.py            Ed25519 identities, canonical signing bytes
  names.py             domain syntax and record policy
  state.py             deterministic registry state machine (the core)
  cluster.py           replicated log, leader takeover, catch-up, commit hold,
                       publication barrier, DNS snapshots
  node.py              HTTP API and DNS lifecycle for one registry node
  client.py            cluster-aware client
  dns_server.py        DNS wire format, query engine, EDNS revision token
  dns_node.py          per-node UDP authoritative responder, signing, freeze
  quorum_resolver.py   majority resolver + RAM-DNS freshness, retries, metrics
  probe.py             direct node UDP probes + resolver decision for the console
  dig.py               small DNS query client with revision/stale display
  experiments.py       live security experiments (shared by portal and CLI)
  portal.py            demonstration console and signed-operation UI
  bootstrap.py         demo identities
  templates/           Jinja2 pages
  static/              CSS, vendored IBM Plex Mono (SIL OFL), small JS
tests/                 108 tests: state machine, authorization, DNS wire format,
                       per-node responder, quorum resolver, RAM-DNS freshness,
                       commit hold, publication barrier, console controls
scripts/
  cluster_smoke.py     three-node failure and recovery checks
  portal_flow.py       end-to-end portal form checks
  evaluate.py          live experiment suite -> markdown report
  commit_lag_repro.py  deterministic A/B/C acknowledged-write harness
docs/
  SPECIFICATION.md     protocol, data model, error codes, guarantees
  ARCHITECTURE.md      decisions and rejected alternatives
  THREAT_MODEL.md      assets, adversaries, residual risk
  RAM_DNS.md           revision-aware majority DNS: mechanism, wire format, limits
  CONSISTENCY_AUDIT.md acknowledged-write stale-majority audit and A/B/C results
  ACADEMIC_REVIEW.md   source-verified literature review and novelty assessment
  EVALUATION.md        method and results
  DEMO_SCRIPT.md       the three-minute console walkthrough
run_demo.py            one-command launcher
DCDNS_PROJECT_GUIDE.txt        comprehensive plain-language guide and Q&A
DCDNS_PATENT_IDEA.txt          candidate invention disclosure (not filed)
DCDNS_PATENT_IDEA_COMPACT.txt  compact submission version
```

---

## 15. Documentation index

| Document | Contents |
|---|---|
| [docs/CONSISTENCY_AUDIT.md](docs/CONSISTENCY_AUDIT.md) | The central audit: bug trace, barrier design, A/B/C methodology, results, recommendation, limitations |
| [docs/ACADEMIC_REVIEW.md](docs/ACADEMIC_REVIEW.md) | Source-verified literature review, evidence table, novelty analysis, threats to validity, search log |
| [docs/RAM_DNS.md](docs/RAM_DNS.md) | RAM-DNS mechanism, EDNS wire format, watermark sources, policies, experiment design, limits |
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Participants, data model, operations, authorization, error codes, and the optional publication barrier |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Why this design; etcd, CoreDNS, central DNS, and the publication barrier evaluated |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What we protect, from whom, and what remains exposed, including the acknowledged-write publication gap |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Method, measurements, A/B/C evidence, and how to reproduce |
| [docs/EVALUATION_RESULTS.md](docs/EVALUATION_RESULTS.md) | Generated results from the last live security-experiment run (historical; see the audit for A/B/C) |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Presentation script with timings and the B/C distinction |
| [DCDNS_PROJECT_GUIDE.txt](DCDNS_PROJECT_GUIDE.txt) | Plain-language guide, architecture, evidence, Q&A and pitches |
| [DCDNS_PATENT_IDEA_COMPACT.txt](DCDNS_PATENT_IDEA_COMPACT.txt) | Compact candidate disclosure: RAM-DNS claims, audit update, validation, limitations |
| [DCDNS_PATENT_IDEA.txt](DCDNS_PATENT_IDEA.txt) | Full candidate disclosure: extended prior art, claims, evidence, limitations |

---

## 16. Patent / invention disclosure status

The project includes a separate, narrow candidate disclosure for a college
submission:

* [`DCDNS_PATENT_IDEA_COMPACT.txt`](DCDNS_PATENT_IDEA_COMPACT.txt) — the compact
  submission version.
* [`DCDNS_PATENT_IDEA.txt`](DCDNS_PATENT_IDEA.txt) — the full discussion with
  extended prior art and claim notes.

**Candidate mechanism:** *Freshness-Coherent Quorum Resolution for DNS Answers
from Replicated Authoritative Nodes* — short name **RAM-DNS**. This is variant C,
the read-side detector. It is **not** the primary write-path fix, and it is not
claimed to be novel.

The disclosure now incorporates the audit and the academic review:

* B, the publication barrier, is the validated correctness fix. It is a standard
  commit/apply acknowledgement discipline and is not claimed as an invention.
* C is an optional defence-in-depth detector. Its measured benefit over B is not
  demonstrated, and its local availability cost is high.
* The only plausible narrow contribution is the DNS-specific encoding and policy
  combination: signed per-answer committed revision, semantic majority, and a
  freshness condition with bounded retries and a fail-closed mode.
* This is a **candidate invention and technical disclosure**, not legal advice
  and not a filed patent. Check the college's student IP policy and
  public-disclosure rules, and obtain a professional prior-art search before
  filing. Do not publish or push the specific mechanism until that clearance is
  complete.

---

## 17. Status

* Branch: `dashboard-console`. The working tree contains the audit, barrier,
  harness and documentation changes described here.
* Tests: **108 passed**.
* Compilation: `python -m compileall -q dcdns scripts tests` succeeds.
* Cluster smoke: **9/9**. Portal flow: **14/14**. Live experiments: **12/12**.
* B is implemented and validated but **opt-in**; C is implemented and enabled by
  default in the demo resolver.
* No commit or push has been performed for this documentation update.

The honest summary is: **the stale-publication problem is real and impactful in
this prototype; B is the standard and effective fix; C is a useful detector with
unproven novelty and unproven incremental benefit over B.**
