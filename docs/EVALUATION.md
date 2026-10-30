# Evaluation Method and Results

The project's claim is not "the software runs". It is that specific properties
hold under specific conditions, and that failures are handled as designed. This
document states how each property is measured and what the measurements mean.

---

## 1. Method

Five independent layers of evidence, each reproducible with one command:

| Layer | Command | What it establishes |
|---|---|---|
| Unit and wire tests | `python -m pytest tests/ -q` | The state machine, DNS encoding, per-node responder, quorum resolver, RAM-DNS freshness policy and publication barrier are correct in isolation |
| Cluster integration | `python scripts/cluster_smoke.py` | Real processes, real kills, real recovery |
| Portal flow | `python scripts/portal_flow.py` | The actual HTTP forms drive the intended end-to-end behaviour |
| Live experiments | `python scripts/evaluate.py` | Security properties against a running system |
| Consistency comparison | `python scripts/commit_lag_repro.py` | Controlled A/B/C comparison of acknowledged-write staleness, barrier timeouts and read-side detection |

The experiments are not reimplemented for the report: `dcdns/experiments.py` is
imported by both the portal and the CLI, so a button press and a report row
execute identical code.

## 2. Metrics

| Metric | Definition | Source |
|---|---|---|
| Commit latency | Time from `POST /op` to majority acknowledgement | experiment output |
| Acknowledged-write staleness | Whether an acknowledged write is followed by a semantic DNS majority still serving the old revision | `commit_lag_repro.py` |
| Publication-barrier latency | Time from `POST /op` to an acknowledgement that also satisfies the applied-majority condition | `commit_lag_repro.py` |
| DNS propagation | Time from the client's commit response until the quorum resolver returns the new address | experiment output |
| Revocation withdrawal | Time from revocation commit until `NXDOMAIN` | experiment output |
| Majority DNS correctness | Whether the quorum answer is the honest answer while one node returns a forgery | experiment output |
| Stale-majority detection | Whether a semantically agreeing but revision-lagging majority is refused rather than served | `stale_majority` experiment |
| Freshness evidence coverage | How many responses carry a revision token, and how many tokens verify against configured node keys | resolver metrics + `/query` |
| Freshness failures | Queries where the semantic majority failed F1/F2/F3 | resolver metrics |
| Bounded retries | Retries performed after a stale majority | resolver metrics |
| Marked stale answers | Answers returned under `marked-stale` with EDNS option `65002` | resolver metrics |
| Post-thaw convergence | Time from thaw to the resolver serving the new answer | experiment output |
| Per-node votes | Each node's RCODE and answer for a query | resolver metrics |
| Per-node revision evidence | Serving revision, source (`edns`/`status`) and token signature status | resolver metrics + `/query` |
| Convergence | Whether all reachable nodes report the same revision | cluster smoke |
| Catch-up time | Time for a restarted node to reach the coordinator's revision | cluster smoke |
| Rejection correctness | Whether the exact error code matches the expected policy | experiments |
| Audit integrity | Whether the hash chain verifies | tests + portal badge |

## 3. Current results

See [`EVALUATION_RESULTS.md`](EVALUATION_RESULTS.md) for the generated table from
the most recent run. Summary at the time of writing:

* **108/108** unit, wire, majority-resolver, RAM-DNS freshness, console-control,
  commit-hold and publication-barrier tests pass.
* **9/9** cluster checks pass: convergence, forged-write rejection, follower
  loss, follower catch-up, coordinator failover, old-coordinator catch-up,
  quorum loss.
* **14/14** portal flow checks pass: register, update, transfer, freeze, accept,
  revoke and DNS withdrawal.
* **12/12** security experiments pass, including majority DNS against a lying
  node and the stale-majority freshness experiment.
* **A/B/C comparison:** baseline A left a stale semantic majority after
  **12/12** acknowledged writes (natural run **20/20**). Barrier B acknowledged
  **3/3** control writes with **0** stale and failed closed on **9/9** held
  writes with `NO_QUORUM` / `ambiguous: true`; all nine converged after release.
  Detector C returned **0/12** stale answers but **12/12** `SERVFAIL`, with 24
  retries and a lookup p50 of **117.84 ms**.
* DNS propagation measured at **0.31 s** after the client response in the latest
  run (commit took 16 ms).
* Revocation withdrawal measured at **0.20 s**.
* Commit latency varied from under 1 ms to ~0.4 s across runs; the slower cases
  are dominated by the 0.25 s replication tick rather than by consensus itself.
* Majority-DNS experiment: n3 returned the forged `10.20.5.66`; the quorum
  resolver returned the honest `10.20.5.123`.
* Stale-majority experiment: the semantic-only resolver returned the old
  address from a frozen majority; RAM-DNS saw a watermark one revision ahead,
  reported `stale-majority`, and returned `SERVFAIL` after its bounded retries.
  After thaw, the new answer was served. Exact revisions and timings vary by run
  and are recorded in the generated report.
* Node DNS revision keys loaded: **3/3**; the generated report records the
  freshness policy (`F1`, delta `0`, watermark `responses`, stale policy
  `servfail`).

## 4. Interpretation

**What the numbers show.** The baseline write path acknowledged after majority
storage, before the followers had applied the entry, so an immediate DNS query
could see a stale semantic majority. The publication barrier B closes that
normal-path window by requiring a majority to report applying the committed
revision before the write is acknowledged. Its control ack p50 was 14.80 ms
versus 7.87 ms for the baseline: one extra replication round trip buys an
acknowledgement that matches the DNS publication state. DNS propagation is
therefore a property of the write-path contract, not of a separate publisher
polling loop.

**What the majority-DNS experiment shows.** One node is deliberately made to
return a forged address. The resolver still returns the honest answer because
two nodes agree, and it records the disagreement. This is a read-time majority
check, not Byzantine consensus: it tolerates one lying node, not two.

**What the stale-majority experiment shows.** The two frozen responders are not
lying and are not partitioned; they are serving the exact committed zone and
revision they had when the snapshot was frozen. The third responder has applied
the new commit. Semantic agreement alone therefore selects the old address.
RAM-DNS reads the serving revision attached to each answer, computes the
watermark from the responses, sees that the winning majority is behind it, and
fails closed after its bounded retry budget. This is the specific read-side
failure the detector exists to expose, and the experiment exercises it with real
DNS packets and a real signed commit rather than a mocked vote map.

C is a detector, not a repair. The primary fix for the ordinary
acknowledged-write window is B. C remains useful when the resolver cannot assume
B, when a responder is frozen at an older snapshot, or when partial connectivity
delivers queries but not metadata.

**What the freshness numbers do not show.** The watermark is computed from
evidence the responders supply. If every responder is still at revision `R`,
the resolver cannot know that `R+1` was committed. The live experiment waits
for the unfrozen node to serve the new revision before evaluating, which is the
honest precondition for the claim. The `responses` watermark is also vulnerable
to a single node claiming a false high revision; `quorum` resists that but
cannot detect a stale majority. Signed tokens prove which node made a claim, not
that the claim is true.

**What the numbers do not show.** Throughput and latency under load are not
measured; the cluster is three processes on one host, so network partitions are
simulated by process death rather than by real link failure. Absolute latency
numbers therefore say more about the prototype's replication constants than
about the protocol's scalability.

**Why the failure tests matter more than the happy path.** A registry that
works when everyone is honest demonstrates nothing. The evidence that carries
weight is that the same forged operation is rejected whether it is sent to the
coordinator or a follower, that a write is refused when a majority is
unavailable, that a node which missed entries converges to exactly the committed
revision on rejoin, and that a lying DNS node cannot change the client answer.

## 5. Threats to validity

| Threat | Effect | Mitigation |
|---|---|---|
| Single host | No true network partition | Process termination used instead; documented |
| Three nodes only | Cannot distinguish 2-of-3 from larger quorums | Quorum computed from configuration, not hard-coded |
| Demo keys on disk | Portal signing is not realistic | Labelled in UI and README |
| Experiments mutate state | Repeated runs add domains | Unique name suffixes; results unaffected |
| Timing on a laptop | Latency varies with load | Metrics reported as observations, not benchmarks |
| No DNSSEC | DNS answers rely on majority trust, not cryptographic proof | Documented; one liar is outvoted, two can collude |
| One host for all DNS nodes | No real independent failure domains | Process death approximates node loss; stated as a limitation |
| Response-only watermark | A commit no responder has seen cannot raise the watermark | Stated as a limit; the experiment waits for one responder to converge before evaluating |
| Single fake-high revision | One node can force fail-closed behaviour under `watermark=responses` | Signed tokens identify the claimant; `watermark=quorum` is available but cannot detect a stale majority |
| Status fallback is unauthenticated | A lying node's `/status` can supply revision evidence when EDNS is absent | Prefer signed EDNS tokens and configure node keys; `--no-status-fallback` and `--require-revision` fail closed |
| Private EDNS options | Ordinary clients ignore options `65001`/`65002`; the mechanism is not DNSSEC | Documented; marked-stale is a compatibility mode, not the secure default |

## 6. Reproducing

```powershell
python run_demo.py --fresh          # terminal 1
python scripts/portal_flow.py       # terminal 2
python scripts/evaluate.py          # terminal 2
python scripts/cluster_smoke.py     # terminal 2, after stopping the demo
```

The demo enables RAM-DNS F1 by default. To compare policies:

```powershell
python run_demo.py --fresh --freshness off          # semantic majority only
python run_demo.py --fresh --freshness f2
python run_demo.py --fresh --stale-policy marked-stale
```

The mechanism, wire format and manual freeze/thaw walkthrough are documented in
[`RAM_DNS.md`](RAM_DNS.md). The cluster smoke test uses ports 9101–9103 and its
own data directory, so it must not run while the demo is using those ports.

## 7. Conclusion

Every success criterion listed in §12 of the specification is covered by an
automated check, and all of them pass on the current implementation. The
central result is the acknowledged-write publication gap: baseline A exposed it
in 12/12 controlled trials and 20/20 natural trials, B closed the normal-path
window, and C detected the remaining read-side staleness at the cost of
availability. The limitations — Byzantine faults, two colluding nodes, root-key
compromise, key recovery, response-only watermark completeness, a frozen
responder that B does not cover, ambiguous barrier timeouts without
de-duplication, and real network partitions — are stated in the threat model and
are not claimed as solved. For a prototype whose research question is
*delegated authority over campus namespaces plus the boundary between a
committed write and a publishable DNS answer*, that is the correct boundary: B is
the write-path fix, C is the optional detector, and the trust anchor, key
custody and watermark completeness remain documented future work.
