# Academic review: stale DNS reads, DNS update consistency, and RAM-DNS

**Status:** local literature review and evidence assessment, 31 October 2026.
This is not a peer-reviewed paper, a systematic review, or a legal prior-art
search. Nothing was committed or pushed.

## 0. Bottom line

Two questions have to be kept separate.

1. **Is the stale-read / DNS-inconsistency phenomenon real and impactful?**
   **Yes.** Independent measurements of eight top-tier managed DNS providers
   found inter-nameserver propagation delays commonly in the tens of seconds,
   6 of 8 providers violating monotonic read consistency under frequent updates,
   roughly one third of end users vulnerable to TTL abuse, and at least one
   provider apparently violating even eventual consistency (Gao &
   Venkataramani, INFOCOM 2019). Akamai documents stale metadata and partial
   connectivity as production failure modes in one of the world's largest
   authoritative DNS infrastructures (SIGCOMM 2020). DNS itself was designed to
   tolerate propagation delay (RFC 1034), and the IETF has added mechanisms for
   asynchronous notification, serve-stale, and update leases (RFC 1996, RFC
   8767, RFC 9664). The problem class is real, measured, and operationally
   significant.

2. **Is RAM-DNS a novel or demonstrated-improvement mechanism?**
   **Not established.** The local DCDNS failure is real: the write path
   acknowledges after a majority stores an entry, while followers apply on a
   later push, so 12/12 acknowledged writes in the final baseline run left a
   stale semantic majority. But this is an instance of a known
   commit-versus-apply / quorum-read freshness gap. PQR states that "a bare
   quorum read is insufficient" and needs a rinse phase (HotStorage 2019); Raft
   requires extra precautions for read-only requests and warns that a leader may
   return stale data (ATC 2014); session guarantees define read-your-writes and
   monotonic reads (PDIS 1994). RAM-DNS is a DNS-specific engineering
   combination of semantic majority, per-answer revision evidence, and a
   freshness policy. It is not a new consistency primitive, and its incremental
   benefit over the publication barrier B has not been demonstrated.

**Impact verdict.** The problem is impactful. The publication barrier B is the
high-leverage fix. RAM-DNS is a plausible defense-in-depth detector, but its
measured cost in the baseline experiment was high (12/12 `SERVFAIL`, p50 lookup
about 118 ms), and its novelty is unproven. Do not present RAM-DNS as a novel or
generally superior solution without a WAN/production evaluation and a
professional prior-art search.

---

## 1. Scope and method

### 1.1 Questions

This review asks:

* **Q1:** Is post-update stale DNS service a real, documented, and consequential
  phenomenon?
* **Q2:** Is the DCDNS stale-majority failure a real instance of a known problem?
* **Q3:** Is RAM-DNS novel, or a demonstrated improvement over simpler fixes?
* **Q4:** What evidence would be needed before claiming academic or patent
  impact?

It does not attempt a full systematic review of all DNS consistency work, nor a
patent clearance search.

### 1.2 Sources and search strategy

The review used a structured but non-systematic search:

| Source | Use |
|---|---|
| OpenAlex API | Title/abstract searches, DOI/work lookups, citation-count snapshots |
| USENIX, ACM DL, IEEE Xplore | Primary papers and abstracts |
| RFC Editor | Standards text for DNS propagation, NOTIFY, serve-stale, update leases, EDNS(0) |
| Author pages and university repositories | Paywalled-paper abstracts and PDFs |
| General web search | Exact-term checks and abstract completion |
| Semantic Scholar API | Attempted, but rate-limited (HTTP 429); not used as a primary source |

Representative queries:

* `"Linearizable Quorum Reads in Paxos" HotStorage 2019`
* `"Session Guarantees for Weakly Consistent Replicated Data" Terry 1994`
* `"Measuring Update Performance and Consistency Anomalies in Managed DNS Services"`
* `"Akamai DNS" "Providing Authoritative Answers" SIGCOMM 2020`
* `Raft read-only queries stale reads leader lease ReadIndex`
* `DNS consistency` (OpenAlex title/abstract: 402 works)
* `DNS propagation` (OpenAlex: 926 works)
* `authoritative DNS stale` (OpenAlex: 7 works)
* `anycast DNS consistency` (OpenAlex: 3 works)
* `"RAM-DNS" revision-aware majority DNS`
* `"revision-aware majority DNS"`, `"freshness-coherent quorum resolution"`
* RFC 1034, RFC 1996, RFC 8767, RFC 9664, RFC 6891 lookups

Screening prioritized peer-reviewed papers and standards that (a) measure DNS
update inconsistency, (b) describe stale quorum reads or commit/apply gaps, or
(c) implement DNS consistency mechanisms. Citations from those works were
followed where accessible.

### 1.3 Verification legend

| Mark | Meaning |
|---|---|
| **P** | Primary PDF/text read directly (or extracted with a PDF-to-text service). |
| **A** | Author or publisher abstract read directly; full text not read. |
| **S** | Claim verified only through a search snippet or secondary summary; treated as weaker. |
| **L** | Local DCDNS artifact (code, test, experiment log), not external literature. |

The INFOCOM 2019 paper is paywalled. Its abstract was read on the author's page;
the final clause about eventual consistency was completed from a search snippet.
The full text was not available, so detailed methodology and numbers beyond the
abstract are not independently checked here.

### 1.4 What this review is not

* Not a systematic review with a registered protocol.
* Not a patent search (no USPTO, WIPO, or Google Patents database search).
* Not a claim that the exact DCDNS failure rate generalizes.
* Not a substitute for reading the paywalled papers in full.

---

## 2. What the literature establishes

### 2.1 DNS deliberately accepts incoherence

RFC 1034 is explicit:

> Access to information is more critical than instantaneous updates or
> guarantees of consistency. Hence the update process allows updates to
> percolate out through the users of the domain system rather than guaranteeing
> that all copies are simultaneously updated. [8]

RFC 1996 introduces NOTIFY precisely because zone transfers can leave "long
intervals of incoherence among authority servers whenever the zone is updated."
[9]

RFC 8767 extends TTL so recursive resolvers can serve stale data when
authorities are unreachable; it is a resiliency mechanism, not a freshness
guarantee. [10]

RFC 9664 (June 2025) adds an EDNS(0) option to negotiate leases on DNS updates
so servers can garbage-collect stale records. It addresses record lifetime, not
replica freshness. [11]

**Implication for DCDNS.** Plain DNS never promised immediate consistency.
DCDNS's HTTP API does something stronger: it returns `committed: true` and
clients then query DNS immediately. The mismatch between the API's contract and
DNS's normal propagation model is the space in which the stale-majority bug
lives. This is not an argument that DNS is broken; it is an argument that the
API and the DNS publication layer must agree on what "committed" means.

### 2.2 The inconsistency is measurable in production

Gao and Venkataramani measured eight top-tier managed DNS providers. Their
abstract reports:

* inter-nameserver update propagation delays commonly take tens of seconds, with
  little improvement over several years;
* roughly one third of end users are vulnerable to TTL abuse by local DNS
  resolvers;
* 6 of 8 providers violate monotonic read consistency under frequent updates;
* at least one large provider appears to violate even eventual consistency.

This is the strongest single piece of evidence that post-update stale DNS
service is not a lab artifact. It is a production measurement across major
providers. It supports the phenomenon class, not the exact DCDNS
ack-before-apply bug.

Akamai DNS describes the operational version:

* "The consequence of serving DNS answers based on stale metadata can be poor
  performance or an outage for end-users."
* "A particularly insidious case is a partial connectivity failure, causing the
  nameservers to be unable to receive metadata from the Akamai network, yet
  still able to receive DNS queries from some subset of the Internet."
* nameservers "check for staleness in critical state and, if determined to be
  stale, self-suspend."

This is important because it shows a large operator treating stale authoritative
state as a real availability/security risk and building a fail-closed response.
It also shows that the problem is not only "the write has not replicated yet";
it can be partial connectivity where queries arrive but metadata does not.

DNScup, ECO-DNS, and Aeacus show sustained academic interest in DNS consistency:

* DNScup proposes a proactive cache-update protocol with dynamic leases to
  provide strong cache consistency for DNS.
* ECO-DNS defines Expected Aggregate Inconsistency (EAI) and optimizes TTLs to
  trade consistency against bandwidth.
* Aeacus (2025) uses QUIC handshake inference for low-latency,
  strong-consistency name resolution in 5G, reporting 8.9–71.8% lower
  connection setup delay at 5.9% overhead.

These are adjacent, not identical, to RAM-DNS: DNScup and Aeacus target cache
consistency, ECO-DNS targets TTL policy, and none combines semantic majority
with per-answer committed-revision freshness across replicated authoritative
nodes. But they establish that DNS consistency is a real research area with
practical deployment concerns.

### 2.3 The distributed-systems pattern is known

**PQR (HotStorage 2019).** The abstract states: "For guaranteeing
linearizability, a bare quorum read is insufficient and it needs to be amended
with a rinse phase to account for pending update operations." PQR's setting is
Paxos, not DNS, but the structural insight is the same: a quorum can agree on an
old value while a newer operation is pending. DCDNS's semantic majority is
exactly a bare quorum read over DNS answers. [1]

**Raft (ATC 2014), §8.** Raft separates majority replication/commit from
state-machine apply. Its read-only discussion says:

> Read-only operations can be handled without writing anything into the log.
> However, with no additional measures, this would run the risk of returning
> stale data, since the leader responding to the request might have been
> superseded by a newer leader of which it is unaware.

It then requires two precautions: the leader must know which entries are
committed (a no-op at term start), and it must check that it has not been
deposed before serving a read-only request (heartbeat exchange with a majority,
or a time-based lease). [2]

DCDNS has the same commit/apply distinction. Its original `submit()` returns
when `commit_index >= index` (majority stored), while followers apply on the next
push. That is a commit-before-apply acknowledgement. Raft's client interaction
section also notes that a client retry after a commit-but-before-response can
execute a command twice, which is why Raft uses unique serial numbers. That maps
directly to the audit's idempotency recommendation for ambiguous timeouts. [2]

**Session guarantees (PDIS 1994).** Terry et al. define read-your-writes,
monotonic reads, writes-follow-reads, and monotonic writes for weakly consistent
replicated data. [3] DCDNS's API creates a read-your-writes expectation: a client
writes, receives success, then queries DNS. The baseline violates that
expectation in 12/12 local trials. The same window can produce a monotonic-read
violation if a client sees a newer answer and then the resolver returns an older
semantic majority, although the audit did not run a dedicated monotonic-read
experiment.

**Why this matters for novelty.** The core problem is not new, and the standard
fixes are known: make the write acknowledgement wait for publication/apply (B),
use a read protocol that accounts for pending updates (PQR-style rinse or Raft
ReadIndex), or attach version evidence and validate it (C). RAM-DNS is a
DNS-specific version of the third approach, combined with semantic majority.

### 2.4 Evidence table

| Source | Venue / year | What it establishes | Bearing on DCDNS / RAM-DNS | Verification |
|---|---|---|---|---|
| RFC 1034 | IETF, 1987 | DNS accepts propagation delay; availability over instantaneous consistency | Explains why plain DNS tolerates stale replicas; DCDNS's API creates a stronger contract | P |
| RFC 1996 | IETF, 1996 | NOTIFY reduces "long intervals of incoherence" between authority servers | Asynchronous publication is normal; a commit ack can precede DNS visibility | P |
| RFC 8767 | IETF, 2020 | Serve-stale for recursive resolvers when authorities are unreachable | Resiliency, not freshness; do not confuse with RAM-DNS | P |
| RFC 9664 | IETF, 2025 | EDNS(0) update leases for garbage-collecting stale records | Record lifetime, not replica freshness; shows continued standards interest | P |
| Gao & Venkataramani | INFOCOM 2019 | 8 top-tier providers; tens-of-seconds propagation; 6/8 monotonic-read violations; ~1/3 TTL abuse; at least one eventual-consistency violation | Strong evidence the phenomenon is real and impactful in production | A/S (paywalled) |
| Schomp et al., Akamai DNS | SIGCOMM 2020 | Stale metadata and partial connectivity are production failure modes; nameservers self-suspend on staleness | Operators already treat stale authoritative state as an outage/security risk | P |
| Chen et al., DNScup | ICDCS 2006 / TKDE 2007 | Proactive DNS cache update with dynamic leases for strong cache consistency | Adjacent prior art: strong DNS consistency via leases, not majority freshness | P |
| Chen et al., ECO-DNS | ICDCS 2015 | EAI metric; TTL optimization for consistency/bandwidth trade-off | Adjacent prior art: quantitative DNS inconsistency and TTL policy | P |
| Li et al., Aeacus | IEEE TMC 2025 | QUIC-based low-latency, strong-consistency name resolution; 8.9–71.8% lower setup delay, 5.9% overhead | Adjacent prior art: DNS consistency remains an active systems problem | A/S |
| Charapko et al., PQR | HotStorage 2019 | "A bare quorum read is insufficient"; rinse phase for pending updates | Direct conceptual prior art for the stale-majority gap | P |
| Ongaro & Ousterhout, Raft | ATC 2014 | Commit vs apply; read-only requests need freshness/deposed-leader checks; idempotent client serials | Direct systems prior art for the commit/apply bug and ambiguous retries | P |
| Terry et al. | PDIS 1994 | Read-your-writes, monotonic reads, and other session guarantees | Defines the client-visible properties DCDNS's API implies | A |

### 2.5 Reach snapshot

OpenAlex citation counts on 31 October 2026, included only to show that the
relevant literature is established, not as a quality score:

| Work | OpenAlex citations |
|---|---:|
| Raft (2014) | 1,908 |
| Terry et al. (1994) | 413 |
| Akamai DNS (2020) | 38 |
| DNScup (2006/2007) | 14 |
| PQR (2019) | 12 |
| Gao & Venkataramani (2019) | 11 |
| ECO-DNS (2015) | 8 |
| Aeacus (2025) | 0 (recent) |

The pattern is what one would expect: the underlying distributed-systems results
are heavily cited; the DNS-specific consistency papers are smaller, specialized
literatures. RAM-DNS would enter the latter, not create a new field.

---

## 3. How the local DCDNS results fit

### 3.1 Local evidence

From `docs/CONSISTENCY_AUDIT.md` and the raw runs [14]:

| Variant | What it does | Key result | Cost |
|---|---|---|---|
| A: semantic majority | Returns the majority DNS answer; no freshness check | 12/12 acknowledged writes left a stale semantic majority; natural run 20/20 | Lookup p50 11.25 ms; convergence p50 251.88 ms |
| B: publication barrier | Acknowledges only after a majority reports applying the committed revision | 3/3 control writes acked with 0 stale; 9/9 held writes timed out `NO_QUORUM` with `ambiguous: true`; all 9 converged after release | Control ack p50 14.80 ms (vs 7.87 ms baseline) |
| C: RAM-DNS | Semantic majority + F1 freshness; retries, then `SERVFAIL` | 0/12 stale answers; 12/12 `SERVFAIL`; 24 retries | Lookup p50 117.84 ms |

The natural run reproduced the baseline in 20/20 trials (10 controls, 10
zero-delay holds), with control ack p50 14.05 ms. The final baseline run's
control p50 was 7.84 ms. These are local, loopback, three-node measurements; the
exact numbers are not production estimates.

### 3.2 What the local results prove

1. **The DCDNS bug is real in this codebase.** The acknowledgement condition is
   `commit_index >= index` (majority stored), and `_replicate()` snapshots the
   commit index before `_advance_commit()`. Followers therefore store the entry
   but do not apply it until the next push. The client is told "committed" while
   a majority still serves the old DNS state.
2. **The failure is deterministic under the harness's timing.** The ordering bug
   plus immediate querying produces 12/12 and 20/20 reproduction. This is
   stronger than a rare race in this environment.
3. **B closes the normal-path window.** A majority must report applying the
   revision before success. Held writes fail closed with an explicit ambiguous
   timeout instead of falsely succeeding.
4. **C detects the stale majority when a newer revision is visible.** It prevents
   the stale answer from being returned, but it does so by failing the lookup
   (12/12 `SERVFAIL` in the baseline run), not by repairing the write path.

### 3.3 What the local results do not prove

* **Production prevalence.** The 100% rate is a property of this loopback,
  immediate-query, ack-before-apply harness. A production system with different
  timing, batching, or client behavior could see a much lower rate.
* **WAN behavior.** No multi-host, emulated-WAN, packet-loss, or clock-skew study
  was run.
* **Byzantine tolerance.** B trusts self-reported peer revisions; C's signed
  token proves who made a claim, not that the claim is true. Two colluding nodes
  defeat both.
* **Responder-freeze coverage for B.** B checks the registry's `dns_revision`,
  not the responder's `serving_revision`. A frozen responder can still let B
  acknowledge.
* **Watermark completeness for C.** If every responder is still at revision `R`,
  C cannot know `R+1` exists. F1 tolerates unrelated updates when the up-to-date
  node is in the semantic majority; F2/F3 with delta 0 can fail closed on
  unrelated updates.
* **Novelty or general superiority.** The local comparison shows B is the primary
  fix and C is a detector with an availability cost; it does not show C is
  better than B or than a PQR-style read protocol.

### 3.4 Mapping to client-visible properties

| Property | A baseline | B barrier | C RAM-DNS |
|---|---|---|---|
| Read-your-writes after an acknowledged write | Violated in 12/12 local trials | Holds on the normal path when a majority has applied | No stale answer, but may return `SERVFAIL` |
| Monotonic reads | Not guaranteed | Improved for the normal path; not a general proof | Detects some violations when a newer revision is visible |
| Bounded staleness | No bound on DNS publication | Majority-applied at ack; not a linearizability proof under failures | Detection depends on watermark evidence |
| Availability under lag | High (serves stale) | Lower (may time out ambiguously) | Lower (may `SERVFAIL`) |
| Byzantine safety | No | No | No |

This table is deliberately modest. B is a publication barrier, not a
linearizable read protocol. C is a detector, not a consensus protocol.

---

## 4. Is the phenomenon impactful?

### 4.1 Impact pathways

Stale DNS answers are not cosmetic. They can:

* route clients to a decommissioned or wrong server, causing connection failures
  or data exposure;
* keep a revoked or transferred name resolving after the registry says it is
  gone;
* undermine incident response, where an operator updates a record to fail over
  and some clients keep hitting the old target;
* create misleading monitoring and audit evidence: the registry says revision
  `R+1`, but the resolver serves `R`;
* violate a client's read-your-writes expectation immediately after a successful
  API call.

The Akamai paper's stale-metadata discussion and the Gao/Venkataramani
measurement both show operators treating these as real outage risks, not
theoretical anomalies.

### 4.2 Strength of evidence

| Claim | Evidence strength | Why |
|---|---|---|
| DNS update inconsistency occurs in production | **Strong** | Independent measurement of 8 top-tier providers; Akamai operational paper; RFCs and deployed mechanisms |
| DCDNS's ack-before-apply bug is real | **Strong locally** | Code path, deterministic 12/12 and 20/20 reproduction, raw logs |
| The exact DCDNS failure rate generalizes | **Unknown** | No production deployment or WAN study; 100% is harness-specific |
| RAM-DNS improves outcomes over B | **Not demonstrated** | No head-to-head WAN/production evaluation; C's local cost is high |
| RAM-DNS is novel | **Not established** | No exact prior art found, but the ingredients are known and no patent search was done |

### 4.3 Impact verdict

* **As a problem:** real and impactful. The literature is clear enough to justify
  fixing the write path and measuring DNS publication freshness.
* **As a local bug:** real and worth fixing. The deterministic reproduction is
  credible evidence of a design flaw, not merely a flaky test.
* **As a research contribution:** RAM-DNS is not yet shown to be impactful. The
  local experiment demonstrates a detector, but not that the detector is better
  than the simpler barrier or that it generalizes. A paper would need a
  WAN/production evaluation and a careful comparison with PQR/ReadIndex, DNScup,
  and B.

---

## 5. Is RAM-DNS novel?

### 5.1 Decompose the claim

RAM-DNS combines four elements:

1. A replicated authoritative DNS layer where each node serves from its own
   committed registry revision.
2. A client-side semantic majority over DNS answers.
3. Per-answer revision evidence (EDNS option 65001, with optional signature and
   zone digest).
4. A freshness condition relative to a watermark, with bounded retries and a
   fail-closed or marked-stale policy.

### 5.2 Prior-art mapping

| Element | Closest prior art | What is shared | What differs |
|---|---|---|---|
| Quorum read can be stale | PQR (2019); Raft §8 (2014) | A quorum/leader can return an old committed prefix; need extra freshness step | PQR is Paxos reads; Raft is leader reads; neither is DNS |
| Per-answer version metadata | DNSSEC zone signatures, SOA serial, EDNS(0) options [12], RFC 9664 leases | DNS answers can carry metadata; zone serial identifies a zone version | Signed per-answer committed revision + zone digest + node id is a specific encoding |
| Semantic majority over DNS | DCDNS baseline; generic quorum systems | Majority agreement resists a minority liar | Applying it to DNS answers across replicated authoritative nodes is a system design |
| Strong DNS consistency | DNScup (2006/2007), Aeacus (2025) | DNS consistency is a real problem; leases/QUIC handshakes can improve it | DNScup targets caches; Aeacus targets 5G resolution; neither uses semantic majority + revision watermark |
| Freshness watermark + fail-closed | Session guarantees; bounded staleness; Akamai self-suspension | Clients can require freshness and fail closed when evidence is insufficient | DNS-specific watermark sources and EDNS policy are an engineering combination |

### 5.3 Exact-term search

Searches for `"RAM-DNS"`, `"revision-aware majority DNS"`, and
`"freshness-coherent quorum resolution"` returned no relevant academic results.
General searches for the acronym were dominated by unrelated hardware/DNS pages.
OpenAlex title/abstract searches for `DNS consistency` (402 works), `DNS
propagation` (926), `authoritative DNS stale` (7), and `anycast DNS consistency`
(3) returned adjacent work, not an exact match.

**This is not proof of novelty.** Exact-term absence can mean the idea is new, or
that it is described with different vocabulary, or that it is an obvious
combination not worth a separate paper, or that it exists in patents or industry
documentation not indexed by these searches. A professional patent search is
still required.

### 5.4 What might be narrowly new

The defensible narrow description is:

* carrying a signed per-answer committed revision plus a zone digest and node id
  in an EDNS(0) option;
* combining that evidence with a semantic majority over DNS answers;
* applying an explicit freshness condition (F1/F2/F3) against a watermark, with
  bounded retries and a fail-closed or marked-stale policy;
* doing this in a replicated authoritative registry where every node serves DNS
  from its own committed state.

Each ingredient is known. The combination is specific to this system. That is an
engineering contribution, not a new consistency primitive. It may be enough for a
narrow patent claim or a systems demo; it is not enough for a strong novelty
claim without a professional search and a broader evaluation.

### 5.5 Novelty verdict

**No demonstrated novelty.** The honest position is:

* the problem is real and known;
* the standard fix (B) is known;
* the read-side detector (C) is a reasonable combination of known ideas;
* the DNS-specific encoding/policy is the only plausible narrow contribution;
* patentability and academic novelty remain unproven.

---

## 6. Threats to validity

### 6.1 Local experiment

* Three nodes, one host, loopback, Windows, `.test`; no WAN, anycast, DNSSEC,
  real recursive resolvers, or production traffic.
* Synthetic commit hold; deterministic by design, but not a real network
  partition or slow disk.
* Small sample: 12 comparison trials per variant plus 20 natural trials; p99
  values from 3–12 samples are indicative only.
* `marked-stale` was unit-tested but not exercised in the live comparison; the
  live comparison used `servfail`.
* The baseline's 100% rate is harness-specific; production prevalence is unknown.

### 6.2 Mechanism limits

* Non-Byzantine: B trusts self-reported peer revisions; C's signature proves
  authorship, not truth; two colluding nodes defeat both.
* B does not cover a frozen responder because it checks `dns_revision`, not
  `serving_revision`.
* C's watermark is incomplete if every responder is stale.
* F1 tolerates unrelated updates when the up-to-date node is in the semantic
  majority; F2/F3 with delta 0 can fail closed on unrelated updates.
* A single node with a false high revision can raise the `responses` watermark
  and force `SERVFAIL`; `quorum` resists one liar but cannot detect a stale
  majority.

### 6.3 Literature review

* Not a systematic review; no registered protocol, no dual screening, no
  meta-analysis.
* Semantic Scholar API was rate-limited; OpenAlex and publisher pages were the
  main index.
* The INFOCOM 2019 full text was paywalled; the abstract and a search snippet
  were used. Detailed methodology and all numbers were not independently
  checked.
* Citation counts are date-stamped snapshots and are not a measure of quality.
* No patent database search; no industry standards beyond the RFCs cited.
* Exact-term search absence is weak evidence of novelty.

### 6.4 What would change the conclusion

* A production/WAN measurement showing no stale reads after acknowledged writes
  would weaken the DCDNS-specific impact claim.
* A prior patent or paper disclosing signed per-answer revision + semantic
  majority + freshness watermark would defeat the narrow novelty claim.
* A head-to-head evaluation showing C is cheaper or more available than B in a
  realistic deployment would strengthen C's case.
* A proof that B alone satisfies the intended consistency property under the
  deployment's failure model would make C optional in more settings.
* A high false-`SERVFAIL` rate under unrelated updates would make F1/F2/F3
  unattractive for general DNS workloads.

---

## 7. Recommendation and research agenda

### 7.1 Product recommendation

1. **Make B the default.** A successful write should mean "committed and a
   majority has applied/published the revision to DNS." Keep the unsafe path
   only as an explicit experiment.
2. **Add an end-to-end majority-visibility regression test.** After a successful
   write, query a majority of DNS responders directly and assert they serve the
   new revision. This is the test that would have caught the original bug.
3. **Add idempotency / operation deduplication.** B can time out after commit; a
   retry of a non-idempotent operation must not apply twice. Raft's client
   serial numbers are the standard analogy.
4. **Close B's responder gap.** Have followers report the responder's
   `serving_revision`, not only the registry's `dns_revision`, or keep C in front
   of the resolver.
5. **Keep C optional.** Use it for responder freeze, partial connectivity, or
   deployments that cannot enforce B. Choose `servfail` when silent staleness is
   unacceptable; use `marked-stale` only when availability dominates and the
   client understands the marker.
6. **Do not claim novelty.** Present RAM-DNS as a well-engineered DNS-specific
   detector and a teaching/demo artifact. If a patent or paper is still desired,
   narrow the claim and run a professional prior-art search first.

### 7.2 Research agenda

If this is to become an academic contribution, the minimum credible study would:

* deploy 5+ nodes across hosts or an emulated WAN with realistic latency, loss,
  and partitions;
* replay or generate realistic update/query workloads, including bursts,
  revocations, transfers, and unrelated updates;
* compare A, B, C, PQR-style/ReadIndex-style reads, and a DNScup/Aeacus-like
  baseline;
* measure stale-answer rate, read-your-writes violations, monotonic-read
  violations, false-`SERVFAIL` rate, p50/p99 latency, convergence, and
  availability;
* formalize the target consistency property and prove what B and C actually
  guarantee under stated assumptions;
* include a security analysis of self-reported revisions and colluding nodes;
* run a professional patent prior-art search before any public novelty claim.

Until then, the honest claim is: **the problem is real and impactful; the local
bug is real; the fix B is standard and effective; RAM-DNS is a plausible detector
with unproven novelty and unproven incremental impact.**

---

## 8. References

[1] A. Charapko, A. Ailijiang, and M. Demirbas, "Linearizable Quorum Reads in
Paxos," in *Proceedings of the 11th USENIX Workshop on Hot Topics in Storage and
File Systems (HotStorage '19)*, 2019. [Online]. Available:
https://www.usenix.org/conference/hotstorage19/presentation/charapko
(accessed 31 Oct. 2026). Verification: P.

[2] D. Ongaro and J. Ousterhout, "In Search of an Understandable Consensus
Algorithm," in *Proceedings of the 2014 USENIX Annual Technical Conference (ATC
'14)*, 2014. [Online]. Available: https://raft.github.io/raft.pdf (accessed 31
Oct. 2026). Verification: P, including §8 "Client interaction."

[3] D. B. Terry, A. J. Demers, K. Petersen, M. J. Spreitzer, M. M. Theimer, and
B. B. Welch, "Session Guarantees for Weakly Consistent Replicated Data," in
*Proceedings of the Third IEEE Workshop on the Management of Replicated Data
(PDIS '94)*, 1994, pp. 140–149. doi: 10.1109/PDIS.1994.331722. Verification: A.

[4] Z. Gao and A. Venkataramani, "Measuring Update Performance and Consistency
Anomalies in Managed DNS Services," in *IEEE INFOCOM 2019*, 2019, pp. 2206–2214.
doi: 10.1109/INFOCOM.2019.8737568. Verification: A/S (full text paywalled).

[5] K. Schomp, O. Bhardwaj, E. Kurdoglu, M. Muhaimen, and R. K. Sitaraman,
"Akamai DNS: Providing Authoritative Answers to the World's Queries," in
*Proceedings of the ACM SIGCOMM 2020 Conference*, 2020. doi:
10.1145/3387514.3405881. [Online]. Available:
https://www.akamai.com/site/en/documents/research-paper/akamai-dns-providing-authoritative-answers-to-the-worlds-queries.pdf
(accessed 31 Oct. 2026). Verification: P.

[6] X. Chen, H. Wang, S. Ren, and X. Zhang, "DNScup: Strong Cache Consistency
Protocol for DNS," in *Proceedings of the 26th IEEE International Conference on
Distributed Computing Systems (ICDCS 2006)*, 2006. doi: 10.1109/ICDCS.2006.31.
Extended version: "Maintaining Strong Cache Consistency for the Domain Name
System," *IEEE Transactions on Knowledge and Data Engineering*, 2007. [Online].
Available: https://www.eecis.udel.edu/~hnw/paper/tkde.pdf (accessed 31 Oct.
2026). Verification: P (extended version).

[7] C. Chen, S. Matsumoto, and A. Perrig, "ECO-DNS: Expected Consistency
Optimization for DNS," in *Proceedings of the 35th IEEE International Conference
on Distributed Computing Systems (ICDCS 2015)*, 2015, pp. 256–267. doi:
10.1109/ICDCS.2015.34. [Online]. Available:
https://netsec.ethz.ch/publications/papers/icdcs15_ecodns.pdf (accessed 31 Oct.
2026). Verification: P.

[8] P. Mockapetris, "Domain Names — Concepts and Facilities," RFC 1034, Nov.
1987. doi: 10.17487/RFC1034. [Online]. Available:
https://www.rfc-editor.org/rfc/rfc1034.txt (accessed 31 Oct. 2026).
Verification: P.

[9] P. Vixie, "A Mechanism for Prompt Notification of Zone Changes (DNS
NOTIFY)," RFC 1996, Aug. 1996. doi: 10.17487/RFC1996. [Online]. Available:
https://www.rfc-editor.org/rfc/rfc1996.txt (accessed 31 Oct. 2026).
Verification: P.

[10] D. Lawrence, W. Kumari, and P. Sood, "Serving Stale Data to Improve DNS
Resiliency," RFC 8767, Mar. 2020. doi: 10.17487/RFC8767. [Online]. Available:
https://www.rfc-editor.org/rfc/rfc8767.txt (accessed 31 Oct. 2026).
Verification: P.

[11] S. Cheshire and T. Lemon, "An EDNS(0) Option to Negotiate Leases on DNS
Updates," RFC 9664, Jun. 2025. doi: 10.17487/RFC9664. [Online]. Available:
https://www.rfc-editor.org/rfc/rfc9664.html (accessed 31 Oct. 2026).
Verification: P.

[12] J. Damas, M. Graff, and P. Vixie, "Extension Mechanisms for DNS
(EDNS(0))," RFC 6891, Apr. 2013. doi: 10.17487/RFC6891. [Online]. Available:
https://www.rfc-editor.org/rfc/rfc6891.txt (accessed 31 Oct. 2026).
Verification: standard reference; not separately analyzed here.

[13] X. Li, B. Cho, S. Katta, J. Costa-Requena, and Y. Xiao, "Aeacus:
QUIC-Powered Low-Latency and Strong-Consistency Name Resolution in 5G," *IEEE
Transactions on Mobile Computing*, 2025. doi: 10.1109/TMC.2025.3539590.
Verification: A/S.

[14] DCDNS project, "Acknowledged-write stale majority in DCDNS," local audit,
30 Oct. 2026. `docs/CONSISTENCY_AUDIT.md`. Verification: L.

[15] DCDNS project, "Freshness-Coherent Quorum Resolution for DNS Answers from
Replicated Authoritative Nodes," compact invention disclosure, 25 Oct. 2026.
`DCDNS_PATENT_IDEA_COMPACT.txt`. Verification: L (candidate disclosure, not a
filed patent).

---

## Appendix A. Verified quotations

The following quotations were checked against the cited source text.

**PQR (HotStorage 2019)** [1]:

> For guaranteeing linearizability, a bare quorum read is insufficient and it
> needs to be amended with a rinse phase to account for pending update
> operations.

**Raft (ATC 2014), §8** [2]:

> Read-only operations can be handled without writing anything into the log.
> However, with no additional measures, this would run the risk of returning
> stale data, since the leader responding to the request might have been
> superseded by a newer leader of which it is unaware.

> Second, a leader must check whether it has been deposed before processing a
> read-only request (its information may be stale if a more recent leader has
> been elected).

**RFC 1034 (1987)** [8]:

> Access to information is more critical than instantaneous updates or
> guarantees of consistency. Hence the update process allows updates to
> percolate out through the users of the domain system rather than guaranteeing
> that all copies are simultaneously updated.

**RFC 1996 (1996)** [9]:

> Long intervals of incoherence among authority servers whenever the zone is
> updated.

**Akamai DNS (SIGCOMM 2020)** [5]:

> The consequence of serving DNS answers based on stale metadata can be poor
> performance or an outage for end-users.

> A particularly insidious case is a partial connectivity failure, causing the
> nameservers to be unable to receive metadata from the Akamai network, yet
> still able to receive DNS queries from some subset of the Internet.

**Gao & Venkataramani (INFOCOM 2019)** [4], author abstract:

> [I]nter-nameserver update propagation delays commonly take tens of seconds
> with little improvement over the last several years. Client-perceived
> inconsistency is rampant with roughly a third of end-users being vulnerable
> to TTL abuse by local DNS resolvers. Furthermore, we find that 6 of the 8
> MDNS providers violate monotonic read consistency under frequent updates and
> at least one large MDNS provider appears to violate even eventual
> consistency.

The final clause was completed from a search snippet because the full text is
paywalled; see §1.3.

---

## Appendix B. Search log

| Query / action | Source | Result used |
|---|---|---|
| `"Linearizable Quorum Reads in Paxos" HotStorage 2019` | Web search, USENIX, OpenAlex | PQR paper and abstract |
| `"Session Guarantees for Weakly Consistent Replicated Data" Terry 1994` | Web search, Cornell course page, OpenAlex | Session-guarantees abstract and definitions |
| `"Measuring Update Performance and Consistency Anomalies in Managed DNS Services"` | Web search, UMass author page, OpenAlex | INFOCOM abstract and bibliographic data |
| `"Akamai DNS" "Providing Authoritative Answers" SIGCOMM 2020` | Web search, Akamai PDF, ACM DL | Akamai DNS paper |
| `Raft read-only queries stale reads leader lease ReadIndex` | Web search, Raft PDF | Raft §8 text |
| `DNS consistency` | OpenAlex title/abstract | 402 works; screened top results |
| `DNS propagation` | OpenAlex title/abstract | 926 works; screened top results |
| `authoritative DNS stale` | OpenAlex title/abstract | 7 works; identified RFC 8767 and related |
| `anycast DNS consistency` | OpenAlex title/abstract | 3 works; no exact match |
| `"RAM-DNS" revision-aware majority DNS` | Web search | No relevant academic result |
| `"revision-aware majority DNS"` | Web search | No relevant academic result |
| `"freshness-coherent quorum resolution"` | Web search | No relevant academic result |
| RFC 1034, 1996, 8767, 9664, 6891 | RFC Editor | Standards text and exact quotations |
| DNScup / ECO-DNS PDFs | University and ETH pages | Full-text abstracts and mechanism descriptions |
| Aeacus | IEEE Xplore, Aalto research portal | Abstract and reported performance numbers |

**Search limitations.** OpenAlex and web search are not exhaustive; Semantic
Scholar was rate-limited; the INFOCOM full text was paywalled; no patent database
was searched. The absence of an exact "RAM-DNS" result is not evidence of
novelty.
