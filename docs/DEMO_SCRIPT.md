# Demo Script

A five-minute walkthrough, plus a longer version if you have ten.

---

## Before you start (2 minutes)

```powershell
cd C:\Users\hkpan\DCDNS
pip install -r requirements.txt
python run_demo.py --fresh
```

Wait for the `READY` banner. Then, in a second terminal:

```powershell
python -m pytest tests/ -q
python -m dcdns.dig techfest.cs.test --all
```

If both work, you are ready. Leave the demo terminal running.

**Opening line:** *"This is a registry for campus DNS names. Three nodes
replicate it, signatures decide who may change what, every node serves DNS from
its own committed state, and a client accepts an answer only when a majority
agrees."*

---

## The five-minute path

### 1. Dashboard — 45 s

Open **http://127.0.0.1:8000**.

Point at:

* three nodes, all at the **same revision**;
* one **coordinator** (called the leader in the code), two followers;
* **quorum available**;
* **audit chain verified**;
* three **per-node DNS authorities** on ports 5354–5356;
* the **quorum resolver** on 5353, with its required votes and recent queries.

> "The nodes agree on the state, and each node answers DNS from the state it has
> committed. The dashboard polls live — this is not a screenshot."

### 2. Register a name — 60 s

Go to **Domains**. Acting as *Alice Rivera*.

* Name: `myproject.cs.test`
* Address: `10.20.5.50`
* Click **Sign and submit**.

Then in the terminal:

```powershell
python -m dcdns.dig myproject.cs.test --all
```

Expected: the quorum answer and all three nodes return `10.20.5.50`.

> "Alice is a member of the CS namespace, so the registry accepts her
> signature. Each node applies the committed operation and refreshes its DNS
> snapshot; the resolver sees a majority within a fraction of a second."

### 3. Update and observe propagation — 45 s

Open the domain, change the address to `10.20.5.51`, submit, then query again.

```powershell
python -m dcdns.dig myproject.cs.test --all
```

> "The registry committed the change. There is no publisher polling loop: each
> node refreshes its snapshot on commit. The quorum resolver now returns the new
> address, and the dashboard shows the revision and recent votes."

### 4. Attack it — 60 s

Switch **Acting as** to *Mallory (unaffiliated attacker)*. Open
`myproject.cs.test` and try to update the record.

> "Mallory has a valid key and can reach any node. She is rejected with
> `UNAUTHORIZED`, and the record is unchanged."

Optional: try to register `x.cs.test` as *Library Administration* → also
`UNAUTHORIZED`.

### 5. Lying DNS node — 60 s

Go to **Experiments** and run *Majority DNS resists a lying node*. It makes n3
return a forged address, queries n3 directly and through the quorum resolver,
then clears the override.

> "n3 is lying: it returns the forged address. The resolver still returns the
> honest answer because n1 and n2 agree. One liar is outvoted. Two colluding
> nodes could lie — that is the honest majority boundary, because we do not have
> DNSSEC."

Manual version:

```powershell
python -c "import httpx; print(httpx.post('http://127.0.0.1:9103/internal/chaos', json={'name':'techfest.cs.test','address':'10.20.5.66'}, timeout=3).json())"
python -m dcdns.dig techfest.cs.test --all
python -c "import httpx; print(httpx.post('http://127.0.0.1:9103/internal/chaos', json={'clear':True}, timeout=3).json())"
```

### 6. Run the experiments — 60 s

Go to **Experiments** and run three or four, ideally:

* *Duplicate registration*
* *Forged record update*
* *Replay of a valid operation*
* *Revocation removes the name from DNS*

Each shows PASS and the observed behaviour.

> "These are real signed operations against the running cluster, not canned
> results. The same code generates the report."

### 7. Audit — 30 s

Go to **Audit**.

> "Every accepted operation is hash-chained. Changing any historical record
> breaks every later hash — that is what the verification badge checks."

### 8. Closing — 30 s

> "So: authority is delegated top-down, ownership is proven cryptographically,
> state is majority-replicated, every node serves DNS, and the client answer is
> decided by majority agreement. The limitations — a root trust anchor, no
> Byzantine tolerance, two colluding DNS nodes can lie, no DNSSEC, no key
> recovery — are documented rather than hidden."

---

## If you have ten minutes: show failure handling

In a third terminal, stop the coordinator. Easier than hunting for the PID: use
the smoke test, which does this properly and prints a pass/fail table.

```powershell
# stop the demo first, then:
python scripts/cluster_smoke.py
```

It demonstrates, in order:

1. three nodes converge on one revision;
2. a forged update is rejected;
3. a follower is killed — writes still commit (2 of 3);
4. the follower rejoins — it catches up;
5. the coordinator is killed — a new coordinator takes over and commits;
6. the old coordinator rejoins — it catches up;
7. two nodes are killed — writes are refused.

For the DNS half of the failure story, start the demo with `--no-supervisor`, then
kill two node processes. Query the name:

```powershell
python -m dcdns.dig techfest.cs.test --all
```

> "The surviving node still answers if you query it directly, but the resolver
> returns SERVFAIL because it requires 2 of 3 configured nodes. We prefer no
> answer to trusting one node."

> "Losing one node costs nothing. Losing the majority stops writes and stops
> majority DNS rather than risking divergence."

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

**"How do you know it works?"**
> "54 tests, 9 cluster failure checks, 14 portal flow checks and 11 live
> experiments. All reproducible with four commands, and the results file is
> generated by the same code the demo buttons call."

---

## If something breaks

| Symptom | Fix |
|---|---|
| Port already in use | `Get-Process python \| Stop-Process -Force`, then rerun |
| Portal shows "no quorum" | Wait 3 s; if it persists, `run_demo.py --fresh` |
| DNS returns nothing | Check `http://127.0.0.1:5380/metrics`; the node responders or resolver may still be starting |
| Stale data | `--fresh` wipes `data/live` and reseeds |
| `nslookup` ignores `-port` | Windows `nslookup` has no port option; use `python -m dcdns.dig name --all` |
| Quorum experiment says chaos disabled | Start the demo without `--no-dns`; `run_demo.py` enables `--chaos` by default |

Logs are in `data/live/logs/` (`n1.log`, `n2.log`, `n3.log`, `quorum.log`,
`portal.log`).
