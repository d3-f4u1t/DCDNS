# Demo Script

A three-minute console walkthrough, plus optional depth if you have longer.

The console is not a mock: every query is sent to the running nodes and the
resolver, and every fault control changes a live process. The point of the
script is to show the mechanism, not to narrate a screenshot.

---

## Before you start (2 minutes)

```powershell
cd C:\Users\hkpan\DCDNS
pip install -r requirements.txt
python run_demo.py --fresh
```

Wait for the `READY` banner, then open **http://127.0.0.1:8000**.

Optional baseline checks in a second terminal:

```powershell
python -m pytest tests/ -q
python -m dcdns.dig techfest.cs.test --all
```

`run_demo.py` enables the console's DNS fault controls by default. They are
bound to loopback and can be hidden with `--no-demo-controls`. Leave the demo
terminal running.

**Opening line:** *"This is a permissioned registry for campus DNS names. Three
nodes replicate it, signatures decide who may change what, every node serves DNS
from its own committed state, and the client-facing resolver accepts an answer
only when a majority agrees."*

---

## The three-minute path

### 0:00–0:25 — Baseline

Point at the console:

* three registry nodes, one leader, all at the same registry revision;
* three per-node DNS responders on UDP 5354–5356;
* the quorum resolver on UDP 5353, requiring 2 of 3;
* audit chain **verified**, registry quorum **available**.

Query `techfest.cs.test` in the DNS panel. Read the table carefully:

* the three `n1`/`n2`/`n3` rows are **direct UDP queries** to each node;
* the `resolver` row is a **separate decision** with its own vote map;
* the revision column comes from each node's `/status`, not from the DNS packet.

> "The resolver is not reading a cached dashboard value. `/query` uses the same
> decision path as UDP 5353. The direct rows show what each node would say; the
> resolver row shows what a client would actually receive."

### 0:25–0:55 — One node lies

Click **Make n3 lie**.

* n3's direct row changes to the forged address `10.20.5.66`;
* n1 and n2 still answer `10.20.5.42`;
* the resolver still returns `10.20.5.42`, with a 2-of-3 vote map;
* the console shows **FAULT ACTIVE** and names n3's forged record.

> "n3 is lying at the DNS layer. It is outvoted. This tolerates one liar, not
> two colluding nodes, and it is majority trust rather than DNSSEC."

### 0:55–1:25 — Lose DNS quorum

Click **Pause n2 + n3**.

* n1 still answers directly;
* n2 and n3 time out because their DNS responders drop datagrams;
* the resolver returns `SERVFAIL` — one vote is not a majority;
* the registry APIs remain reachable, and the audit chain is unchanged.

> "This is a DNS-layer pause, not a process kill. The registry processes are
> still running and still replicating. We isolate DNS quorum from registry
> quorum so the distinction is visible."

### 1:25–1:55 — Registry quorum still commits

While n2 and n3 are paused at the DNS layer, go to **Domains** and register a
name as Alice, or update an existing record.

* the write commits and the revision increments;
* every registry node applies it, so the revision counters advance even on the
  paused nodes;
* the resolver still returns `SERVFAIL`, because n2 and n3 are not answering;
* the console shows the new registry revision without pretending DNS quorum is
  healthy.

> "A registry write needs a majority of registry nodes. That majority is
> intact, so the write commits even though DNS reads currently fail. Registry
> quorum and DNS quorum are different decisions."

Reset the pause when you want the resolver to return the new value. The console
also exposes registry → DNS lag when a node is genuinely behind; here the pause,
not a revision gap, is what keeps the resolver at `SERVFAIL`.

### 1:55–2:20 — Recover

Click **Reset DNS faults** (or **Clear all DNS faults** in the banner).

* n2 and n3 answer again;
* all three nodes converge on the committed revision;
* the resolver returns the new value with a majority;
* the fault banner and the **FAULT ACTIVE** pill disappear.

> "Recovery is a flag clear, not a restart or a state rollback. The registry log
> was never touched by the fault."

### 2:20–2:45 — Authority and audit

Switch **Acting as** to *Mallory (unaffiliated attacker)*. Open Alice's domain
and try to update the record.

* the portal submits a real signed operation;
* the state machine rejects it with `UNAUTHORIZED`;
* the record is unchanged;
* the audit page still verifies the hash chain.

> "Mallory has a valid key and can reach any node. A valid signature is not
> enough: the operation must also be authorized by the namespace tree."

### 2:45–3:00 — Close

> "Authority is delegated top-down, ownership is proven cryptographically, state
> is majority-replicated, every node serves DNS, and the client answer is decided
> by majority agreement. The boundaries — a root trust anchor, no Byzantine
> tolerance, two colluding DNS nodes can lie, no DNSSEC, no key recovery, and no
> revision-aware freshness — are documented rather than hidden."

---

## If you have more time

### Experiments page

Run three or four live experiments:

* *Duplicate registration* — `NAME_TAKEN`;
* *Forged record update* — `UNAUTHORIZED`;
* *Replay of a valid operation* — `REPLAY_DETECTED`;
* *Revocation removes the name from DNS* — the name disappears from the zone.

Each result is produced by a real signed operation against the running cluster,
not by a canned string.

### CLI evidence

```powershell
python -m dcdns.dig techfest.cs.test --all
python -m dcdns.dig techfest.cs.test --port 5354
```

The first shows the quorum decision and each node's answer; the second queries
n1 directly.

### Real process failure and recovery

Stop the demo first, then run:

```powershell
python scripts/cluster_smoke.py
```

It starts three real processes and demonstrates:

1. three nodes converge on one revision;
2. a forged update is rejected;
3. a follower is killed — writes still commit (2 of 3);
4. the follower rejoins — it catches up;
5. the leader is killed — a new leader takes over and commits;
6. the old leader rejoins — it catches up;
7. two nodes are killed — writes are refused.

The console's pause control is deliberately different: it fails only the DNS
responder, so the registry process stays alive and the supervisor does not
restart it. Use `cluster_smoke.py` when you want real process death.

---

## Questions you should expect

**"Isn't this just a replicated database?"**
> "The replication is the easy part. The research question is authority: who may
> create a namespace, who may delegate it, what a department can do without
> asking the centre, and how that is verified by every node. That logic is in
> one deterministic state machine and is tested independently of replication."

**"Why not etcd or Raft?"**
> "etcd was the original plan and remains the production path. For this
> prototype I needed zero external dependencies, and the workload allows a
> simpler protocol: one writer at a time, followers never originate entries, so
> logs are always prefixes and no truncation is needed. The trade-off is no
> Byzantine tolerance, which I state explicitly."

**"Why is there still a leader? Isn't that centralization?"**
> "It is a temporary write coordinator, elected as the lowest-id node among the
> reachable majority. It has no extra signing key and cannot change a record
> without a valid signature. It can be killed and replaced. A single writer is
> needed to order unique-name and ownership operations. DNS has no leader at
> all: every node answers and the client compares."

**"What if the root key is compromised?"**
> "Then delegation is compromised — that is the trust anchor. It cannot forge an
> owner's signature, so record-level forgery would still appear in the audit log
> as a root-signed operation. Mitigation is 2-of-3 root signatures, specified in
> the threat model but not implemented."

**"What if one DNS node lies?"**
> "The other two outvote it. The resolver compares RCODE plus answer records and
> requires two matching answers. If two nodes collude, they can lie; DNSSEC is
> the future work that would give cryptographic proof instead of majority trust."

**"Isn't pausing DNS just cheating?"**
> "It is failure injection at the DNS layer, and the console labels it as such.
> The process is still running, so it also proves that DNS quorum loss does not
> stop registry commits. Real process death is exercised separately by
> `cluster_smoke.py`."

**"Why did the resolver briefly return the old address after a write?"**
> "The resolver requires semantic agreement, not revision agreement. A lagging
> majority can therefore return the previous answer for a moment. The console
> shows per-node revisions and registry → DNS lag. Revision-aware freshness is
> the patent candidate, not implemented here."

**"What do the resolver votes mean?"**
> "Each vote is the semantic answer from one node. `no-answer` means the node
> did not reply at all; it is not a vote for `SERVFAIL`. The resolver requires a
> majority of configured responders, so two absent votes cannot form a majority."

**"How do you know it works?"**
> "60 tests, 9 cluster failure checks, 14 portal flow checks and 11 live
> experiments. All reproducible with the commands in the README, and the results
> file is generated by the same code the demo buttons call."

---

## If something breaks

| Symptom | Fix |
|---|---|
| Port already in use | `Get-Process python \| Stop-Process -Force`, then rerun |
| Portal shows "no quorum" | Wait 3 s; if it persists, `run_demo.py --fresh` |
| DNS returns nothing | Check `http://127.0.0.1:5380/metrics`; the node responders or resolver may still be starting |
| Fault banner will not clear | Click **Reset DNS faults**; portal startup also clears DNS faults |
| Stale data | `--fresh` wipes `data/live` and reseeds |
| `nslookup` ignores `-port` | Windows `nslookup` has no port option; use `python -m dcdns.dig name --all` |
| Fault controls are missing | The portal was started with `--no-demo-controls`; restart without it |
| Quorum experiment says chaos disabled | Start the demo without `--no-dns`; `run_demo.py` enables `--chaos` by default |

Logs are in `data/live/logs/` (`n1.log`, `n2.log`, `n3.log`, `quorum.log`,
`portal.log`).
