# Evaluation Method and Results

The project's claim is not "the software runs". It is that specific properties
hold under specific conditions, and that failures are handled as designed. This
document states how each property is measured and what the measurements mean.

---

## 1. Method

Three independent layers of evidence, each reproducible with one command:

| Layer | Command | What it establishes |
|---|---|---|
| Unit and wire tests | `python -m pytest tests/ -q` | The state machine and DNS encoding are correct in isolation |
| Cluster integration | `python scripts/cluster_smoke.py` | Real processes, real kills, real recovery |
| Live experiments | `python scripts/evaluate.py` | Security properties against a running system |

The experiments are not reimplemented for the report: `dcdns/experiments.py` is
imported by both the portal and the CLI, so a button press and a report row
execute identical code.

## 2. Metrics

| Metric | Definition | Source |
|---|---|---|
| Commit latency | Time from `POST /op` to majority acknowledgement | experiment output |
| DNS propagation | Time from the client's commit response until the authoritative server returns the new address | experiment output |
| Revocation withdrawal | Time from revocation commit until `NXDOMAIN` | experiment output |
| Convergence | Whether all reachable nodes report the same revision | cluster smoke |
| Catch-up time | Time for a restarted node to reach the leader's revision | cluster smoke |
| Rejection correctness | Whether the exact error code matches the expected policy | experiments |
| Audit integrity | Whether the hash chain verifies | tests + portal badge |

## 3. Current results

See [`EVALUATION_RESULTS.md`](EVALUATION_RESULTS.md) for the generated table from
the most recent run. Summary at the time of writing:

* **43/43** unit and wire tests pass.
* **9/9** cluster checks pass: convergence, forged-write rejection, follower
  loss, follower catch-up, leader failover, old-leader catch-up, quorum loss.
* **10/10** security experiments pass.
* DNS propagation measured at **0.41 s** after the client response (publisher
  polls every 0.4 s).
* Revocation withdrawal measured at **1.02 s**.
* Commit latency observed at **~0.4 s**, dominated by the 0.25 s replication
  tick rather than by consensus itself.

## 4. Interpretation

**What the numbers show.** The publication delay is dominated by the polling
interval, not by the registry. That is a design property: the publisher is a
separate consumer of committed state, so DNS lag is tunable independently of
consensus. If sub-100 ms propagation were required, the publisher would be
replaced by a push subscription on commit; the measurement would then reflect
network and process scheduling rather than polling.

**What the numbers do not show.** Throughput and latency under load are not
measured; the cluster is three processes on one host, so network partitions are
simulated by process death rather than by real link failure. Absolute latency
numbers therefore say more about the prototype's polling constants than about
the protocol's scalability.

**Why the failure tests matter more than the happy path.** A registry that
works when everyone is honest demonstrates nothing. The evidence that carries
weight is that the same forged operation is rejected whether it is sent to the
leader or a follower, that a write is refused when a majority is unavailable,
and that a node which missed entries converges to exactly the committed
revision on rejoin.

## 5. Threats to validity

| Threat | Effect | Mitigation |
|---|---|---|
| Single host | No true network partition | Process termination used instead; documented |
| Three nodes only | Cannot distinguish 2-of-3 from larger quorums | Quorum computed from configuration, not hard-coded |
| Demo keys on disk | Portal signing is not realistic | Labelled in UI and README |
| Experiments mutate state | Repeated runs add domains | Unique name suffixes; results unaffected |
| Timing on a laptop | Latency varies with load | Metrics reported as observations, not benchmarks |

## 6. Reproducing

```powershell
python run_demo.py --fresh          # terminal 1
python scripts/evaluate.py          # terminal 2
python scripts/cluster_smoke.py     # terminal 2, after stopping the demo
```

The cluster smoke test uses ports 9101–9103 and its own data directory, so it
must not run while the demo is using those ports.

## 7. Conclusion

Every success criterion listed in §12 of the specification is covered by an
automated check, and all of them pass on the current implementation. The
limitations — Byzantine faults, root-key compromise, key recovery, real network
partitions — are stated in the threat model and are not claimed as solved. For a
prototype whose research question is *delegated authority over campus
namespaces*, that is the correct boundary: the delegation model is implemented
and tested, while the trust anchor and its recovery policy are documented as
future work.
