# RAM-DNS: Revision-Aware Majority DNS

**Working name:** RAM-DNS
**Long name:** *Freshness-Coherent Quorum Resolution for DNS Answers from Replicated Authoritative Nodes*

RAM-DNS is the read-side freshness rule implemented in this prototype. It is
not a new consensus protocol and it does not replace DNSSEC. It adds one
question to the existing quorum resolver:

> The majority agreed on an answer, but is that majority answering from the
> current committed revision?

The implementation is in:

| File | Role |
|---|---|
| `dcdns/dns_server.py` | EDNS(0) revision token, zone digest, signature, stale marker |
| `dcdns/dns_node.py` | per-node responder, signed token publication, snapshot freeze |
| `dcdns/quorum_resolver.py` | semantic majority + freshness conditions, retries, fail-closed policy |
| `dcdns/experiments.py` | live stale-majority experiment |
| `tests/test_ram_dns.py` | wire, policy, retry and real-freeze tests |

---

## 1. The problem

The baseline resolver accepts an answer when a majority of authoritative nodes
return the same RCODE, type and RDATA. That rule is correct for *agreement* and
insufficient for *freshness*.

Consider three nodes and a committed update from `10.20.5.42` to
`10.20.5.99`:

| Node | Serving revision | Answer |
|---|---|---|
| n1 | 10 | `10.20.5.42` (old) |
| n2 | 10 | `10.20.5.42` (old) |
| n3 | 11 | `10.20.5.99` (new) |

n1 and n2 form a semantic majority, so the baseline returns the old address.
The majority is not lying: both nodes are serving a real committed snapshot.
They are simply behind. A client cannot tell that from the DNS answer, because
the wire format has no field for "which registry revision produced this".

The same failure appears when a node is paused, slow to apply committed entries,
or deliberately pinned to an older snapshot. It is a *stale majority*, not a
split-brain or a Byzantine fork: the registry still has one committed order,
but the read path can select an old prefix of it.

### 1.1 Relationship to the write-path fix

The audit in [`CONSISTENCY_AUDIT.md`](CONSISTENCY_AUDIT.md) found that this
window is deterministic in the baseline DCDNS write path: the API acknowledges
after a majority has *stored* an entry, while followers learn the new commit
index on a later push. Variant B, a commit/apply-aware publication barrier,
closes that window. RAM-DNS is therefore a read-side detector and
defence-in-depth, not a substitute for a correct write acknowledgement. It
remains useful when a DNS responder is frozen or when the resolver cannot trust
that the write path was fixed.

---

## 2. The mechanism

RAM-DNS keeps the semantic majority as the first condition and adds a second
condition over revision evidence.

```text
query
  |
  v
ask every configured node (UDP)
  |
  v
semantic majority? ---- no ---> SERVFAIL (existing behaviour)
  |
 yes
  |
  v
extract revision evidence from each response
  |  (EDNS option 65001, or status fallback)
  v
compute watermark W (best-known committed revision)
  |
  v
evaluate freshness condition F1/F2/F3 over the majority group
  |
  +-- fresh ----> return the majority answer
  |
  +-- stale ----> bounded retry (default 2)
                    |
                    +-- converged ----> return the new majority answer
                    |
                    +-- still stale --> stale policy:
                                          servfail      -> SERVFAIL (default)
                                          marked-stale  -> old answer + EDNS 65002 + reduced TTL
```

Two revisions matter:

* **committed revision** — the registry revision the node has applied and
  committed. This is what the node's `/status` reports as `revision`.
* **serving revision** — the revision attached to the DNS snapshot the
  responder is actually using. Normally it equals the committed revision; while
  a snapshot is frozen it stays at the pinned value and the difference is the
  `revision_lag`.

A node publishes the *serving* revision, not its latest committed revision.
Publishing the committed revision while serving an older zone would let a
frozen node claim freshness it does not have.

### 2.1 Freshness conditions

Let `W` be the watermark and `Δ` the allowed lag (`--lag-delta`, default `0`).
Let `M` be the revisions of the nodes in the winning semantic majority.

| Condition | Rule | Meaning | Typical use |
|---|---|---|---|
| **F1** (default) | `max(M) >= W` | At least one node in the majority is at the watermark. | Lowest latency; catches a majority that is uniformly behind. |
| **F2** | `count(r in M where r >= W - Δ) >= required` | At least a quorum of the majority is within `Δ` of the watermark. | Tolerates bounded lag without accepting an arbitrarily old majority. |
| **F3** | `min(M) >= W - Δ` | Every node in the majority is within `Δ` of the watermark. | Strictest; highest availability cost. |

The condition is evaluated only after a semantic majority exists. A semantic
split is still a semantic split; it is not relabelled as a freshness failure.

### 2.2 Watermark sources

| Source | Definition | Property |
|---|---|---|
| `responses` (default) | Maximum revision among the DNS responses. | Smallest evidence set; matches the patent's worked example. A single node claiming a fake high revision can force fail-closed behaviour. |
| `status` | Maximum `serving_revision` from the node status API. | Sees nodes whose DNS did not answer; depends on unauthenticated HTTP. |
| `combined` | Maximum of both. | Fail-closed but can reduce availability when a DNS-silent node has a current status. |
| `quorum` | Highest revision attested by at least `required` responses. | Resists one fake-high node, but cannot detect the stale-majority case because the stale majority is the quorum. |

`responses` is the default because it uses only evidence carried by the DNS
answer itself and does not require a second protocol. `quorum` is useful when a
single node's false revision claim is a greater concern than detecting a stale
majority; the two goals conflict, and the policy makes the trade-off explicit.

### 2.3 Retry and stale policy

A stale majority is often transient: the lagging nodes are about to apply the
committed entry. The resolver therefore retries the *entire* query up to
`retry_budget` times (default `2`, interval `0.1 s`). Each retry re-queries all
nodes and re-evaluates both the semantic majority and the freshness condition.
It does not reuse the old vote map.

If the majority is still stale:

* `--stale-policy servfail` (default) returns `SERVFAIL`. The client gets no
  data rather than old data presented as current.
* `--stale-policy marked-stale` returns the stale majority answer with EDNS
  option `65002`, a reduced TTL (`--marked-stale-ttl`, default `5 s`), and the
  watermark and majority revision in the marker. This is an explicit
  "known-stale" answer for clients that understand the private option; a
  client that ignores EDNS sees an ordinary answer with a short TTL.

The default is fail-closed because a normal DNS client cannot interpret the
private marker. `marked-stale` is a deliberate compatibility mode, not the
secure default.

### 2.4 Missing and invalid metadata

* If a response has no EDNS revision token, the resolver may fall back to the
  node's `/status` (`--no-status-fallback` disables this).
* `--require-revision` makes missing metadata a hard failure.
* A token whose signature does not verify, or whose node id does not match the
  queried node, fails closed with `invalid-revision-metadata`. A token that
  cannot be decoded at all is treated as missing metadata, and therefore also
  fails closed under `--require-revision`.
* If no node in the winning majority supplies revision evidence, the default
  lenient policy preserves semantic-only behaviour (`ok-no-watermark`). This
  keeps the resolver compatible with nodes that predate the token, but it means
  detection requires at least one majority node to attach a valid token. The
  demo nodes always attach signed tokens; deployments that cannot assume that
  should enable `--require-revision`.
* NXDOMAIN is checked by default. `apply_to_negative=False` exists for
  experiments that want to isolate positive answers; the default protects
  against a stale majority that still believes a name exists or does not exist.

---

## 3. Wire format

Both options are in the EDNS(0) local/experimental range reserved by RFC 6891
for private use. They are **not** standard DNS options and are not DNSSEC.

### 3.1 Revision token: option `65001`

```text
u8   version                 (1)
u8   node_id_len
..   node_id                 (UTF-8, at most 255 bytes)
u64  revision                (big endian)
16   zone_digest             (BLAKE2b-128 over the exact zone snapshot)
u8   signature_len           (0 or 64)
..   signature               (Ed25519, optional)
```

The signature covers:

```text
"DCDNS-DNS-REV-V1\n" + canonical_json({
    "v": version,
    "node": node_id,
    "revision": revision,
    "digest": zone_digest.hex()
})
```

The digest binds the token to the exact zone the node signed. Because the digest
is covered by the signature, it cannot be altered without invalidating the
token, and the resolver records it alongside the revision evidence. The resolver
does not recompute the full zone, so the digest is an attestation by the node,
not independent proof of the zone contents. The domain-separation prefix
prevents a revision token from being confused with a registry operation
signature.

The token is attached to every response that carries an EDNS OPT record,
including positive answers, NXDOMAIN and error responses. It is omitted when the
responder has no node id (for example, a bare `DNSEngine` used in a unit test).

### 3.2 Stale marker: option `65002`

```text
u8   version                 (1)
u64  watermark               (big endian)
u64  majority_revision       (big endian)
u16  retries                 (big endian)
```

The marker is emitted only under `--stale-policy marked-stale`. It tells a
cooperating client exactly why the answer is stale and how far behind the
majority was.

### 3.3 Transport notes

* The resolver sends EDNS on every query (`build_query(..., edns=True)`); a
  node that does not understand the private option simply ignores it.
* The response keeps a normal OPT record even when it has no revision option,
  so `has_edns` and `parse_edns_options` can distinguish "EDNS but no revision"
  from "no EDNS at all".
* The token is an application-layer attestation. It is not a DNSSEC signature,
  it does not protect clients that do not speak the option, and it does not
  make the DNS answer globally verifiable.

---

## 4. Threat model and honest limits

### 4.1 What RAM-DNS improves

* **Stale majority:** a majority that agrees on an old answer is detected when
  at least one response carries a newer revision. The resolver retries, then
  fails closed or marks the answer stale.
* **Wrong-node token reuse:** the token binds `node_id`, revision and zone
  digest, so one node cannot copy another node's token into its own answer.
* **Accidental staleness:** a frozen or lagging responder is visible in
  `/status` (`serving_revision`, `revision_lag`, `frozen`) and in the resolver
  decision stream.
* **Silent regression:** the stale-majority experiment demonstrates that the
  semantic-only baseline returns the old address while RAM-DNS returns
  `SERVFAIL`.

### 4.2 What it does not solve

* **Two colluding nodes.** A 2-of-3 semantic majority is still a majority. Two
  malicious nodes can return a false answer at a high revision and defeat both
  the semantic and freshness checks. RAM-DNS is not BFT.
* **A single node with a false high revision.** Under
  `watermark_source=responses`, one node can raise the watermark and force
  `SERVFAIL` (a denial-of-service). `watermark_source=quorum` resists this but
  cannot detect a stale majority. Signed tokens do not make a node's claim
  true; they only prove which node made it.
* **A commit no responder has seen.** If every responder is still at revision
  `R`, the watermark is `R` and the resolver cannot know that `R+1` exists.
  Watermark sources based only on responses are necessarily limited to evidence
  the responders can supply. The live experiment waits for the unfrozen node to
  serve the new revision before evaluating, which is the honest condition for
  the claim.
* **Compromised node keys.** The demo stores node signing keys on disk. A
  attacker who has a node's key can sign arbitrary revision claims for that
  node. Key custody and rotation are deployment problems, not solved here.
* **Status fallback trust.** `/status` is unauthenticated HTTP. It is a
  compatibility fallback, not a security boundary. Configure node keys and
  prefer the signed EDNS token where the threat model includes a lying node.
* **DNSSEC.** Not implemented. The private EDNS options do not provide
  transitive trust, zone signing, or validation by ordinary resolvers.
* **Global DNS.** This is a lab authoritative layer for `.test`; it is not a
  replacement for the global DNS root or for DNSSEC.

### 4.3 Why fail-closed is the default

Returning old data as if it were current is the failure the mechanism exists to
prevent. `SERVFAIL` is visible to the client and to monitoring; a stale answer
is not. The cost is availability during a transient lag, which is why the
resolver retries first and why `marked-stale` exists for deployments that
prefer a marked answer to no answer.

---

## 5. Experiment design

### 5.1 Unit and wire tests

`tests/test_ram_dns.py` covers:

* revision-token round-trip, signature verification, wrong-key rejection,
  node-id mismatch, malformed lengths, and zone-digest binding;
* positive and NXDOMAIN token attachment;
* EDNS option round-trip and stale-marker encoding;
* F1/F2/F3, the `Δ` bound, and the `quorum` watermark;
* missing metadata with and without status fallback;
* invalid signatures failing closed;
* retry-then-`SERVFAIL`, retry-then-converge, and `marked-stale`;
* the semantic-only default for library callers;
* a real `NodeDNSResponder` freeze/unfreeze cycle, including a pinned
  NXDOMAIN.

The tests do not fabricate DNS answers. Stale-majority cases are built from
`DNSEngine` instances that really hold older revisions, and the freeze test pins
a real provider snapshot.

### 5.2 Live stale-majority experiment

`ExperimentRunner._run_stale_majority` performs the following against the
running cluster:

1. Ensure `techfest.cs.test` exists and read its current address.
2. Freeze the DNS snapshots of `n1` and `n2` through
   `POST /internal/dns/freeze`. The responders keep serving the exact zone and
   revision they had at freeze time.
3. Commit a real signed `update_records` to a new address.
4. Wait until `n3` (the unfrozen node) serves the new answer.
5. Run a semantic-only resolver and a RAM-DNS resolver against the same live
   responders.
6. Record both decisions, then thaw `n1` and `n2` and wait for convergence.
7. Verify that the live resolver serves the new answer after thaw.

No answer is invented. The stale majority is a real majority serving a real
older committed snapshot, and the registry keeps replicating while it is frozen.

### 5.3 What is measured

| Measurement | Why it matters |
|---|---|
| Baseline answer | Shows the semantic-only resolver accepts the stale majority. |
| RAM-DNS decision | Shows the freshness rule rejects it. |
| Watermark and per-node revisions | Shows the evidence behind the decision. |
| Retry count | Shows the bounded retry path. |
| Convergence time after thaw | Shows the system recovers without operator intervention. |
| `stale_majority_queries`, `freshness_failures`, `retries`, `stale_answers` | Resolver metrics for monitoring and paper tables. |

---

## 6. Results

The generated report is [`EVALUATION_RESULTS.md`](EVALUATION_RESULTS.md). The
last recorded run reports:

* **12/12** live experiments pass, including `stale_majority`.
* **108/108** tests pass (the count now includes the commit-hold,
  publication-barrier and unrelated-update tests).
* Node DNS revision keys loaded: **3/3**.
* Freshness policy: **F1**, delta `0`, watermark `responses`, stale policy
  `servfail`.

The stale-majority row from one generated report (revision numbers vary by run):

```text
baseline returned stale '10.20.5.123' (majority rev [30, 30]);
RAM-DNS watermark 31 -> SERVFAIL (stale-majority);
live resolver SERVFAIL; fresh answer after 0.00s
```

A manual walkthrough against the same live demo produced:

```text
resolver stale     rcode=SERVFAIL  answer=SERVFAIL  stale=False wm=20
                   revs={'n1': 19, 'n2': 19, 'n3': 20}
                   reason=stale-majority retries=2
  n1 direct: 10.20.5.42 rev=19 signed=True
  n2 direct: 10.20.5.42 rev=19 signed=True
  n3 direct: 10.20.5.78 rev=20 signed=True
resolver thawed    rcode=NOERROR   answer=10.20.5.78  wm=20
                   revs={'n1': 20, 'n2': 20, 'n3': 20} reason=ok retries=0
```

The first line is the core evidence: the majority (`n1`, `n2`) agreed on the
old address, the watermark was `20`, and the resolver returned `SERVFAIL`
instead of the stale answer. After thaw, all three responders reached revision
`20` and the new answer was served.

`convergence_seconds` in the generated experiment can be `0.00` or a few
hundredths of a second because the unfrozen node already has the new revision
and the frozen nodes publish their new snapshot as soon as they are thawed. It
is a measurement of the thaw path, not a claim about WAN propagation.

---

## 7. Running it

The demo enables F1 by default:

```powershell
python run_demo.py --fresh
python -m dcdns.dig techfest.cs.test --all
```

The `dig` output shows each node's revision and whether its token is signed:

```text
quorum  127.0.0.1:5353  NOERROR  10.20.5.42  rev 8  signed
n1      127.0.0.1:5354  NOERROR  10.20.5.42  rev 8  signed
n2      127.0.0.1:5355  NOERROR  10.20.5.42  rev 8  signed
n3      127.0.0.1:5356  NOERROR  10.20.5.42  rev 8  signed
```

Other policies:

```powershell
python run_demo.py --fresh --freshness f2
python run_demo.py --fresh --freshness off
python run_demo.py --fresh --stale-policy marked-stale
```

Standalone resolver:

```powershell
python -m dcdns.quorum_resolver --port 5353 --metrics-port 5380 `
  --nodes n1=127.0.0.1:5354,n2=127.0.0.1:5355,n3=127.0.0.1:5356 `
  --api-nodes n1=http://127.0.0.1:9101,n2=http://127.0.0.1:9102,n3=http://127.0.0.1:9103 `
  --freshness f1 --watermark responses --stale-policy servfail --retries 2
```

Useful endpoints:

| Endpoint | Contents |
|---|---|
| `http://127.0.0.1:5380/metrics` | resolver counters, per-node revisions, freshness config and recent decisions |
| `http://127.0.0.1:5380/query?name=techfest.cs.test` | one decision with votes, revisions, watermark, reason and retries |
| `http://127.0.0.1:9101/status` | node committed revision, serving revision, lag, frozen state, token signing |
| `http://127.0.0.1:8000/` | console: direct probes, resolver decision, freeze/thaw controls |

Manual stale-majority demonstration:

1. Open the console and query `techfest.cs.test`.
2. Click **Freeze n1 + n2 DNS**.
3. Update the domain through the console (or commit an `update_records`).
4. Query again: the resolver reports `STALE_MAJORITY`, watermark and
   per-node revisions, and returns `SERVFAIL`.
5. Click **Thaw DNS snapshots**. The resolver returns the new address and the
   decision stream shows `UNANIMOUS` again.

---

## 8. Claims and non-claims

**Claimed and demonstrated:**

* A replicated authoritative DNS layer can carry a per-answer committed
  revision token and use it to reject a semantically agreeing but stale
  majority.
* The freshness decision can be expressed as explicit conditions over a
  watermark, with a bounded retry and a fail-closed or marked-stale outcome.
* The mechanism composes with the existing semantic majority, delegated
  authority, Ed25519 operations and leader-based replication without changing
  the write path.
* The live stale-majority experiment is real: real frozen snapshots, a real
  signed commit, and a real resolver decision.

**Not claimed:**

* Byzantine fault tolerance, trustlessness, or resistance to two colluding
  nodes.
* A replacement for DNSSEC or for the global DNS.
* A solution to watermark completeness when no responder has seen a commit.
* Production key custody, key rotation, or a secure status channel.
* That this is a filed patent or that the mechanism is novel until a
  professional prior-art search says so.

A source-verified literature review and novelty assessment is in
[`ACADEMIC_REVIEW.md`](ACADEMIC_REVIEW.md). It concludes that the underlying
stale-DNS phenomenon is real and impactful, while RAM-DNS itself is an
engineering combination with no demonstrated novelty.

---

## 9. IP note

This document describes a **candidate invention and technical disclosure**, not
legal advice. The college's student IP policy and public-disclosure rules should
be checked before publishing or filing. The specific mechanism should not be
pushed to a public repository or otherwise disclosed until the college's IP
clearance process is complete. Prior art around quorum reads, DNSSEC,
primary/secondary DNS, anycast and blockchain DNS is crowded; the narrow
combination argued here is semantic majority + per-answer committed revision +
a freshness condition that fails closed on a stale majority.
