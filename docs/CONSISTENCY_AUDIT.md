# Acknowledged-write stale majority in DCDNS

**Status:** local audit and experiment report, 2026-10-30. Nothing was committed
or pushed.

## 0. Bottom line

The suspected failure is real, and in this prototype it is deterministic rather
than a rare race.

* In the final baseline run, **12 of 12 acknowledged writes** left two of the
  three nodes serving the old address. The semantic-majority resolver returned
  that old address in **12 of 12** cases.
* In a larger natural run with no artificial delay, **10 of 10 control trials**
  reproduced it, as did 10 of 10 commit-hold trials.
* The cause is in the write path: `ClusterNode.submit()` returns success when a
  majority has **stored** the log entry, while followers learn the new commit
  index only on a later replication push. The leader therefore acknowledges
  before a majority has applied the entry to the state used for DNS answers.
* Variant B, a commit/apply-aware publication barrier, closes the window. In the
  final comparison it acknowledged all 3 control writes with **zero** stale
  majorities, and failed closed with an explicit ambiguous timeout on all 9
  held writes. After release, all 9 converged.
* Variant C, RAM-DNS, detects the stale majority and returns `SERVFAIL`: **0
  stale answers out of 12 acknowledged writes**, but **12 of 12 SERVFAIL** and a
  p50 lookup latency of about 118 ms. It is a detection layer, not a repair of
  the write path.
* **Recommendation:** make the publication barrier the default write-path
  behaviour. Keep RAM-DNS as optional defence-in-depth for responder-level
  staleness and partial connectivity, not as the primary fix. Do not claim
  novelty for RAM-DNS without a professional prior-art search; the core idea is
  very close to known quorum-read work.

The hypothesis "this is only a DCDNS-specific artifact" is partly right. The
*underlying* stale-quorum-read pattern is general and well known. The
*deterministic 100% reproduction here* is caused by DCDNS's acknowledgement
design: the API promises "committed" but the DNS publication state can still be
one revision behind. Nothing here establishes that the exact DCDNS failure rate
is common in production; the general pattern is known, while the 100% rate is a
property of this local write path and immediate-query harness.

---

## 1. What was tested

Three real registry processes were started on isolated ports:

| Component | Ports |
|---|---|
| Node HTTP APIs | `9201`, `9202`, `9203` |
| Per-node DNS responders | UDP `5454`, `5455`, `5456` |
| Client-facing semantic resolver | in-process, quorum 2 of 3 |
| Client-facing RAM-DNS resolver | in-process, F1, delta 0, `servfail`, 2 retries |

The harness seeds a namespace and `techfest.cs.test`, waits for full
convergence, then alternates updates between two addresses. After each write it
records the acknowledgement time, queries every node directly, asks the
semantic resolver and the RAM-DNS resolver, and reads each node's status and
serving zone.

Three conditions were compared:

| Variant | Behaviour |
|---|---|
| **A** | Baseline semantic majority. A write is acknowledged after majority storage; DNS answers are whatever each node has applied. |
| **B** | Same cluster with `--publication-barrier`. A write is acknowledged only after a majority reports that it has applied the committed revision to its DNS state. |
| **C** | Same answers as A, evaluated by RAM-DNS: semantic majority plus F1 freshness against the highest observed revision, bounded retries, then `SERVFAIL`. |

Two fault modes were used:

* **Control:** no injection. The snapshot is taken immediately after the write
  acknowledgement, so it measures the natural window.
* **Commit hold:** the two followers keep storing and acknowledging entries but
  do not advance `commit_index` or apply them to `state`/`dns_snapshot`. The
  hold is released after the observation. Delays of 0, 100 and 300 ms were
  used; the hold itself is the deterministic part, the delay only changes when
  the observation is taken.

The hold endpoint is chaos-gated (the node's default bind is loopback) and is
not part of the normal write path.

---

## 2. Code-level explanation

The relevant code is in `dcdns/cluster.py`.

### 2.1 The write path

`ClusterNode.submit()` appends the entry locally, then loops:

```python
while time.monotonic() < deadline:
    await self._replicate()
    if self.commit_index >= index:
        return self._write_result(index, preview)
    await asyncio.sleep(0.02)
```

In the baseline path (and as the first condition in the current code), the
success condition is `commit_index >= index`, i.e. a majority has stored the
entry. It is **not** "a majority has applied the entry to the DNS snapshot".

### 2.2 Why followers are one step behind

`_replicate()` snapshots the commit index before pushing:

```python
async def _replicate(self) -> None:
    commit = self.commit_index          # line 315
    ...
    payload = {
        ...
        "commit_index": commit,         # line 326
    }
    ...
    self._advance_commit()              # line 344
```

`_advance_commit()` runs *after* the push. It counts how many nodes have stored
the new entry, advances the leader's `commit_index`, persists it, and applies it
locally. The first push for a new entry therefore advertises the **previous**
commit index. Followers store the entry but do not apply it yet. The leader then
acknowledges.

The next heartbeat (default 0.25 s) pushes the new commit index. Only then does
`handle_append()` on each follower advance its commit and apply the entry:

```python
incoming_commit = min(int(payload.get("commit_index", 0)), len(self.log))
if incoming_commit > self.commit_index:
    self.commit_index = incoming_commit
    self._persist_meta()
    self._apply_committed()
```

### 2.3 The observable sequence

For an update at log index `i`:

1. Leader appends entry `i` and pushes it with `commit_index = i-1`.
2. Followers store `i` and reply `last_index = i`, `commit_index = i-1`.
3. Leader's `_advance_commit()` sees a majority stored, sets
   `commit_index = i`, applies locally, and `submit()` returns success.
4. An immediate client query sees:
   * leader: revision `i`, new answer;
   * both followers: revision `i-1`, old answer.
5. The semantic resolver sees two votes for the old answer and one for the new
   answer, so it returns the old answer.
6. The next heartbeat pushes `commit_index = i`; followers apply and the window
   closes.

This is not a Byzantine or split-brain scenario. All nodes serve a real
committed prefix. The bug is that the API calls the write "committed" while the
read path can still select the previous prefix.

### 2.4 Why the control trials reproduce so reliably

`_replicate()` always takes the commit snapshot *before* `_advance_commit()`.
Every new entry therefore gets at least one push with the old commit index, and
the acknowledgement is sent immediately after the local commit advance. On
loopback the next heartbeat is about 200–300 ms away, which is long enough for
the harness to query all nodes and both resolvers. The ordering bug is general;
the 100% rate is a property of this timing and this acknowledgement design.

---

## 3. Reproduction and measurements

### 3.1 Commands

```powershell
# Final baseline comparison (A and C, 3 trials per condition)
python scripts/commit_lag_repro.py --trials 3 --hold-delays 0,100,300 `
  --ram --data data/compare-baseline-final

# Final barrier comparison (B, A and C, same schedule)
python scripts/commit_lag_repro.py --trials 3 --hold-delays 0,100,300 `
  --ram --publication-barrier --data data/compare-barrier-final

# Larger natural run: 10 controls and 10 zero-delay holds
python scripts/commit_lag_repro.py --trials 10 --hold-delays 0 `
  --data data/commit-lag-natural
```

Raw records are in each run's `results/trials.jsonl`; aggregates are in
`results/summary.json` and `results/summary.md`.

### 3.2 Baseline (A and C)

Final run: `data/compare-baseline-final`, 12 trials, all acknowledged.

| Mode | Trials | Acked | A stale | C stale | C SERVFAIL | Ack p50/p95/p99 (ms) | A p50/p95/p99 (ms) | C p50/p95/p99 (ms) | Convergence p50/p95/p99 (ms) |
|---|---:|---:|---:|---:|---:|---|---|---|---|
| control | 3 | 3 | 3 | 0 | 3 | 7.84 / — / — | 11.11 / — / — | 118.45 / — / — | 252.23 / — / — |
| hold-0 ms | 3 | 3 | 3 | 0 | 3 | 8.17 / — / — | 10.17 / — / — | 116.15 / — / — | 246.42 / — / — |
| hold-100 ms | 3 | 3 | 3 | 0 | 3 | 7.44 / — / — | 11.40 / — / — | 116.09 / — / — | 231.45 / — / — |
| hold-300 ms | 3 | 3 | 3 | 0 | 3 | 7.01 / — / — | 14.19 / — / — | 125.90 / — / — | 442.19 / — / — |
| **all** | **12** | **12** | **12** | **0** | **12** | **7.87 / 9.25 / 9.31** | **11.25 / 15.39 / 16.16** | **117.84 / 126.74 / 127.56** | **251.88 / 444.60 / 446.96** |

Per-mode p95/p99 are omitted in the first four rows only because each cell has
three samples; the aggregate row gives the full percentiles.

C used 2 retries per query (24 retries total) and returned `SERVFAIL` with
reason `stale-majority` in every case. It never returned the stale answer.

The larger natural run (`data/commit-lag-natural`) reproduced the failure in
**20 of 20** trials: 10 of 10 controls and 10 of 10 zero-delay holds. For the
controls, ack p50 was 14.05 ms, semantic-resolver p50 was 7.90 ms, and
convergence p50 was 258.73 ms.

### 3.3 What the raw evidence looks like

Trial 1 of the final baseline run, a no-injection control:

```text
acknowledged: true, write_ack_ms: 7.84
old address: 10.20.5.42    new address: 10.20.5.123
n1: revision 4, commit 4, DNS answer 10.20.5.123
n2: revision 3, commit 3, DNS answer 10.20.5.42
n3: revision 3, commit 3, DNS answer 10.20.5.42
semantic resolver: answer 10.20.5.42
  votes: n1=10.20.5.123, n2=10.20.5.42, n3=10.20.5.42
  winner: n2, n3
  majority revisions: [3, 3]
observed 115.48 ms after the acknowledgement
```

The old answer was still being served more than 100 ms after the client was told
the write had committed. Convergence took 181.16 ms.

### 3.4 Barrier (B)

Final run: `data/compare-barrier-final`, same schedule.

| Mode | Trials | Acked | Timeouts | A stale (acked) | C stale (acked) | C SERVFAIL (all) | Ack p50 (ms) | Convergence p50/p95/p99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| control | 3 | 3 | 0 | 0 | 0 | 0 | 14.80 | 22.54 / 26.18 / 26.50 |
| hold-0 ms | 3 | 0 | 3 | — | — | 3 | — | 134.87 / 138.42 / 138.73 |
| hold-100 ms | 3 | 0 | 3 | — | — | 3 | — | 236.17 / 239.28 / 239.55 |
| hold-300 ms | 3 | 0 | 3 | — | — | 3 | — | 434.99 / 436.80 / 436.96 |

The control convergence values are measured from the write acknowledgement. The
hold values are measured from the release of the hold (after the observation
and timeout), so they include the fault duration; they are not directly
comparable to the control row.

All 9 held writes returned `NO_QUORUM` with `"ambiguous": true`, after about
2.5 s (the configured write timeout). No acknowledged write was followed by a
stale semantic majority. All 9 held writes converged after the hold was
released. The control writes acknowledged in 12.63–14.80 ms; in those three
trials all three nodes were already at the new revision when the snapshot was
taken, so post-ack convergence was 16–27 ms.

The barrier adds one replication round trip to the write acknowledgement. In
this run its control p50 was 14.8 ms versus 7.9 ms for baseline A. That is the
intended trade: a slightly later success, but success means the DNS state is
actually published.

### 3.5 A/B/C comparison

A and C are read-side variants evaluated on the same 12 acknowledged baseline
writes. B is a write-path variant, so its row counts acknowledged writes and
timeouts rather than read outcomes.

| Property | A: semantic majority | B: publication barrier | C: RAM-DNS |
|---|---|---|---|
| Acknowledged stale majority | **12/12** | **0/3 acked** | **0/12** |
| Stale answers after an acknowledged write | 12 | 0 | 0 |
| `SERVFAIL` / fail-closed | 0 | 9/9 held writes timed out ambiguously | 12/12 |
| Write ack p50 | 7.87 ms | 14.80 ms (control) | n/a (read side) |
| Lookup p50 | 11.25 ms | 11.46 ms (control) | 117.84 ms |
| Post-ack convergence p50 | 251.88 ms | 22.54 ms (control) | n/a |
| Retries | 0 | 0 | 24 total, 2 per query |
| Fixes the write path? | no | **yes** | no |
| Covers responder freeze? | no | no (checks state revision) | **yes, if a newer revision is visible** |
| Byzantine-safe? | no | no | no |

Interpretation:

* **A** is correct about agreement and wrong about freshness. Its low latency is
  bought by silently returning an old committed prefix.
* **B** is the standard consistency fix. It makes the acknowledgement match the
  publication state and removes the normal-path window. It fails closed rather
  than falsely succeeding when the majority cannot apply.
* **C** is a detector. It prevents the stale answer from being returned, but it
  does so by failing the lookup, and it leaves the write path unchanged. On the
  baseline cluster it therefore turns every stale-majority window into
  `SERVFAIL`. It is useful where the resolver cannot trust that the write path
  was fixed, or where the DNS responder itself can be frozen.

B and C are complementary, not alternatives. B fixes the ordinary replication
window. C covers a different fault: a responder that is pinned to an old
snapshot even though the registry has applied a newer revision. B's current
check uses `node.dns_revision` (state revision), not the responder's
`serving_revision`, so a frozen responder can still let B acknowledge.

---

## 4. Behaviour matrix

| Scenario | Result | Evidence |
|---|---|---|
| Registration and first update | Seeded and converged before every trial | Harness setup; `cluster_smoke.py` 9/9 |
| Consecutive updates while held | Both entries stored; release applies the latest; final DNS answer is the latest | `test_consecutive_held_updates_apply_latest_on_release` |
| Delayed replication | A stale; B times out ambiguously; C `SERVFAIL`; all converge after release | 0/100/300 ms runs |
| Unavailable follower | Leader plus one live follower is still a majority; if the only available follower is behind, B refuses | `test_applied_majority_ignores_unavailable_nodes`; smoke test 9/9 |
| Leader failure / restart | New leader elected, former leader catches up | `cluster_smoke.py` 9/9 |
| Transient hold across restart | Hold and pending commit are not persisted; node reloads the last durable commit | `test_restart_clears_transient_hold_and_pending_commit` |
| Revocation | Held follower applies revocation on release and removes the name from the DNS snapshot | `test_revocation_removes_name_from_dns_snapshot_on_release`; portal flow 14/14 |
| NXDOMAIN | Revision token attached to negative answers; stale NXDOMAIN majority rejected by default | `tests/test_ram_dns.py` |
| False revision claim, one node | `watermark=responses` can be forced to `SERVFAIL`; `watermark=quorum` resists one liar but cannot detect a stale majority | `test_quorum_watermark_resists_a_single_fake_high_revision` |
| False revision claim, barrier | B trusts a peer's self-reported `dns_revision`; a lying peer can defeat it | `test_barrier_trusts_self_reported_peer_revision` |
| Unrelated update | F1 passes when the up-to-date node is in the semantic majority; F2/F3 with delta 0 can fail closed on the lagging members | `test_f1_tolerates_unrelated_update_when_answer_is_unchanged`; no live unrelated-update trial |
| Two colluding nodes | Both A and C can be defeated | Documented limitation; not BFT |

Two behaviours deserve emphasis:

1. **F2/F3, not F1, are sensitive to unrelated updates.** F1 only needs one
   member of the semantic majority at the watermark. If an unrelated name
   advances the log while the queried name is unchanged, the up-to-date node is
   still in that majority and F1 passes. F2/F3 require a quorum or the minimum
   of the majority at the watermark, so the same unrelated update can make them
   fail closed. The comparison used F1, so this did not affect the numbers. A
   per-name revision would make all three conditions precise.
2. **B does not cover a frozen responder.** `handle_append()` returns the
   registry's `dns_revision`, while the DNS responder can be frozen at an older
   `serving_revision`. A future B should report the responder's serving
   revision, or C should remain in front of the resolver.

---

## 5. Prior art

A separate, source-verified review is in
[`ACADEMIC_REVIEW.md`](ACADEMIC_REVIEW.md). It distinguishes the documented
DNS-inconsistency phenomenon from the unproven novelty of RAM-DNS, and it records
the search method, evidence strength, and remaining threats to validity. The
summary below is consistent with that review.

The core observation is not new. The closest work:

* **Charapko, Ailijiang and Demirbas, "Linearizable Quorum Reads in Paxos",
  HotStorage 2019.** The abstract states that "a bare quorum read is
  insufficient and it needs to be amended with a rinse phase to account for
  pending update operations." This is the same gap as DCDNS: a quorum of
  replicas can agree on an old value while a newer write is pending. PQR adds a
  rinse phase to account for pending updates; B is the write-path analogue
  (acknowledge only after apply), while C is a read-side detector.
* **Ongaro and Ousterhout, "In Search of an Understandable Consensus Algorithm"
  (Raft), USENIX ATC 2014.** Raft separates majority replication/commit from
  state-machine apply. Its read-only discussion notes that reading without
  additional measures risks stale data and that a leader must check it has not
  been deposed. DCDNS has the same commit/apply distinction but originally
  acknowledged at commit.
* **RFC 1034 (1987).** DNS explicitly chooses availability over instantaneous
  consistency: "Access to information is more critical than instantaneous
  updates or guarantees of consistency. Hence the update process allows updates
  to percolate out through the users of the domain system rather than
  guaranteeing that all copies are simultaneously updated." This is why plain
  DNS accepts propagation delay. DCDNS's problem is that its HTTP API creates a
  stronger expectation than plain DNS: it says "committed" and clients then
  query DNS immediately.
* **RFC 1995 (IXFR) and RFC 1996 (NOTIFY).** Zone changes propagate
  asynchronously. NOTIFY is a best-effort interrupt intended to reduce
  propagation delay; RFC 1996 explicitly notes "long intervals of incoherence
  among authority servers whenever the zone is updated."
* **RFC 8767 (serve-stale, 2020).** Serve-stale is a recursive-resolver
  resiliency mechanism for when authoritative servers cannot be reached. It is
  not a guarantee that authoritative replicas are fresh after a write.
* **Schomp et al., "Akamai DNS: Providing Authoritative Answers to the World's
  Queries", SIGCOMM 2020.** The paper describes operational failure modes in
  which nameservers cannot receive metadata but can still receive DNS queries,
  so they keep answering from older metadata. Stale answers at the edge are a
  real operational concern, not only a lab artifact.

What might remain as a narrow contribution:

* carrying a signed committed revision (plus zone digest and node id) in an
  EDNS(0) option, so answer and revision travel in one packet;
* a resolver policy that combines semantic majority with F1/F2/F3 freshness and
  an explicit `servfail`/`marked-stale` choice;
* the operational measurement of the stale-majority rate after acknowledged
  writes in this registry.

Those are engineering combinations, not a new consistency primitive. The
review's structured search found no exact prior art for the name or the full
combination, but it also found no evidence of novelty; absence of an exact term
is not proof of novelty. The patent-style disclosure's own differentiation
section says distributed databases "do not operate on DNS wire responses or
group DNS answers semantically" — that is a DNS-encoding difference, not a new
quorum algorithm. A professional prior-art search is still required before any
filing or public claim.

---

## 6. Recommendation

1. **Adopt B as the default write-path behaviour.** The barrier is the
   standard, minimal fix: acknowledge only after a majority has applied the
   committed revision. Keep the flag for experiments, but do not leave the
   unsafe path as the default in a system that advertises `committed: true`.
2. **Make the acknowledgement contract explicit.** A success should mean "the
   write is committed and a majority has published it to DNS." A timeout after
   commit should keep returning `ambiguous: true`; clients must not assume the
   write failed.
3. **Add idempotency or operation de-duplication.** With B, a timeout can occur
   after commit. A client retry of a non-idempotent operation (transfer, revoke)
   must not apply twice.
4. **Keep C as optional defence-in-depth.** It is valuable for responder-level
   freeze, partial connectivity, and deployments that cannot enforce B. It is
   not a substitute for B. Choose `servfail` when silent staleness is
   unacceptable; choose `marked-stale` only when availability dominates and the
   client can understand the marker.
5. **Close B's responder gap.** Either have followers report their responder's
   `serving_revision` in the append response, or keep C in front of the
   resolver. Do not claim B covers a frozen DNS responder until this is done.
6. **Do not claim novelty.** Treat RAM-DNS as a well-engineered detection layer
   and a useful teaching/demo artifact. If a patent or paper is still desired,
   narrow the claim to the DNS-specific encoding/policy combination and run a
   professional prior-art search first.

---

## 7. Limitations

* **Small, local sample.** Three nodes, one host, loopback, Windows. 12
  comparison trials per variant plus 20 natural trials. p99 values from 3–12
  samples are indicative, not stable.
* **Synthetic fault injection.** The commit hold is a controlled fault, not a
  real network partition or a real slow disk. It is deterministic by design.
* **Non-Byzantine.** B trusts self-reported peer revisions. C's signed token
  proves which node made a claim, not that the claim is true. Two colluding
  nodes defeat both. Neither is BFT.
* **B does not cover responder freeze.** The barrier checks registry state, not
  the responder's serving snapshot.
* **C's watermark is incomplete.** If every responder is still at revision `R`,
  C cannot know that `R+1` exists. F2/F3 with delta 0 also treat unrelated
  global revisions as staleness; F1 is less sensitive because the up-to-date
  node remains in the semantic majority when the answer is unchanged.
* **No production DNS.** `.test` only; no DNSSEC, anycast, global root, or
  resolver ecosystem. The experiment measures the authoritative layer.
* **No WAN or clock-skew study.** The 0.25 s heartbeat is local. A WAN
  deployment would need a different timing and failure model.
* **`marked-stale` was not exercised in the live comparison.** Unit tests cover
  it; the comparison used `servfail`.
* **The baseline's production rate is unknown.** The 100% rate is specific to
  this immediate-query, loopback, ack-before-apply path. The ordering bug is
  general, but a real deployment's stale-answer rate depends on query timing,
  heartbeat, and client behaviour.

---

## 8. Changed files and test results

New or modified for this audit:

| File | Change |
|---|---|
| `dcdns/cluster.py` | Commit-hold fault injection; `_applied_majority`; publication barrier; peer commit/DNS revision tracking; status fields; ambiguous `NoQuorum` timeouts |
| `dcdns/node.py` | `--publication-barrier`; chaos-gated `POST /internal/replication/hold`; serving-zone snapshot in `/internal/zone`; ambiguous flag from `NoQuorum`; status fields |
| `dcdns/errors.py` | `NoQuorum.ambiguous` |
| `scripts/commit_lag_repro.py` | Deterministic A/B/C harness with real processes, hold injection, raw JSONL and reports |
| `tests/test_commit_hold.py` | 10 tests: hold/release, clamping, applied-majority counting, unavailable nodes, false-claim boundary, restart, consecutive updates, revocation, chaos gating, ambiguous timeouts |
| `tests/test_ram_dns.py` | Added an unrelated-update test showing F1 passes while F2/F3 with delta 0 fail closed |
| `docs/CONSISTENCY_AUDIT.md` | This report |
| `docs/ACADEMIC_REVIEW.md` | Source-verified literature review: real/impactful DNS inconsistency, novelty assessment, threats to validity |
| `docs/RAM_DNS.md` | Pre-existing uncommitted token wording; this audit added §1.1 (relationship to the write-path fix) and updated the test count to 108 |
| `README.md` | Linked this report, the academic review and the reproduction harness; updated the test count to 108 |

Verification run on 2026-10-30:

```text
python -m pytest                 108 passed in 8.67s
python -m compileall -q dcdns scripts tests   OK
python scripts/portal_flow.py    14/14 checks passed
cluster smoke (isolated ports)   9/9 checks passed
commit_lag_repro baseline final  12/12 reproduced
commit_lag_repro barrier final   3/3 control acked, 0 stale; 9/9 held timeouts, 0 acked stale
```

Re-run on 2026-10-31 after adding the academic review:

```text
python -m pytest                 108 passed in 8.73s
python -m compileall -q dcdns scripts tests   OK
```

The smoke test was run from a temporary copy of `scripts/cluster_smoke.py` on
ports `9301–9303` and `data/smoke-isolated`, because the live demo occupies
`9101–9103`. The temporary copy was removed. The original demo was not
disturbed.

Not rerun in this audit: `scripts/evaluate.py`. Its last recorded result was
12/12, and rerunning it would overwrite the generated
`docs/EVALUATION_RESULTS.md` and run fault experiments against the live demo.
The unit, portal-flow and isolated smoke results above cover the changed code.

No commit or push was performed.

---

## 9. Next steps

1. Make the publication barrier the default and add a regression test that
   asserts a successful write is immediately visible from a majority of DNS
   responders.
2. Add idempotency keys / operation deduplication so ambiguous timeouts are safe
   to retry.
3. Make B report the responder's `serving_revision`, not only the registry
   `dns_revision`, or explicitly document that C is required in front of B.
4. Add live integration coverage for NXDOMAIN, revocation, restart and
   consecutive updates under the hold fault. The unit tests now cover the state
   transitions; the HTTP/DNS path should be exercised end to end.
5. Run a multi-host or emulated-WAN study. Measure stale-answer rate, p99
   latency, false-`SERVFAIL` rate under unrelated updates, and convergence under
   real partitions.
6. Run a professional prior-art search before any patent filing or public
   disclosure. Narrow any claim to the DNS-specific encoding and policy, and do
   not claim a new quorum-read primitive.
