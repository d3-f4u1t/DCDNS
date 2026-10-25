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
nslookup -port=5353 techfest.cs.test 127.0.0.1
```

If both work, you are ready. Leave the demo terminal running.

**Opening line:** *"This is a registry for campus DNS names. Three nodes
replicate it, signatures decide who may change what, and committed records are
published into a real DNS server."*

---

## The five-minute path

### 1. Dashboard — 45 s

Open **http://127.0.0.1:8000**.

Point at:

* three nodes, all at the **same revision**;
* one **leader**, two followers;
* **quorum available**;
* **audit chain verified**;
* DNS **in sync**, published revision equal to committed revision.

> "The nodes agree on the state. The dashboard polls live — this is not a
> screenshot."

### 2. Register a name — 60 s

Go to **Domains**. Acting as *Alice Rivera*.

* Name: `myproject.cs.test`
* Address: `10.20.5.50`
* Click **Sign and submit**.

Then in the terminal:

```powershell
nslookup -port=5353 myproject.cs.test 127.0.0.1
```

> "Alice is a member of the CS namespace, so the registry accepts her
> signature. Within about half a second the name is live in DNS."

### 3. Update and observe propagation — 45 s

Open the domain, change the address to `10.20.5.51`, submit, then query again.

```powershell
nslookup -port=5353 myproject.cs.test 127.0.0.1
```

> "The registry committed the change; the publisher picked it up; DNS now
> answers the new address. The measured delay is around 0.4 seconds and it is
> shown on the dashboard."

### 4. Attack it — 60 s

Switch **Acting as** to *Mallory (unaffiliated attacker)*. Open
`myproject.cs.test` and try to update the record.

> "Mallory has a valid key and can reach any node. She is rejected with
> `UNAUTHORIZED`, and the record is unchanged."

Optional: try to register `x.cs.test` as *Library Administration* → also
`UNAUTHORIZED`.

### 5. Run the experiments — 60 s

Go to **Experiments** and run three or four, ideally:

* *Duplicate registration*
* *Forged record update*
* *Replay of a valid operation*
* *Revocation removes the name from DNS*

Each shows PASS and the observed behaviour.

> "These are real signed operations against the running cluster, not canned
> results. The same code generates the report."

### 6. Audit — 30 s

Go to **Audit**.

> "Every accepted operation is hash-chained. Changing any historical record
> breaks every later hash — that is what the verification badge checks."

### 7. Closing — 30 s

> "So: authority is delegated top-down, ownership is proven cryptographically,
> state is majority-replicated, and the DNS layer only ever publishes committed
> records. The limitations — a root trust anchor, no Byzantine tolerance, no key
> recovery — are documented rather than hidden."

---

## If you have ten minutes: show failure handling

In a third terminal, stop the leader:

```powershell
# find the leader URL on the dashboard, e.g. n1 = 9101
Get-Process python | Where-Object { $_.Id -eq <PID> } | Stop-Process
```

Easier: press `Ctrl+C` is not granular, so use the smoke test instead, which
does this properly and prints a pass/fail table:

```powershell
# stop the demo first, then:
python scripts/cluster_smoke.py
```

It demonstrates, in order:

1. three nodes converge on one revision;
2. a forged update is rejected;
3. a follower is killed — writes still commit (2 of 3);
4. the follower rejoins — it catches up;
5. the leader is killed — a new leader takes over and commits;
6. the old leader rejoins — it catches up;
7. two nodes are killed — writes are refused.

> "Losing one node costs nothing. Losing the majority stops writes rather than
> risking divergence."

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

**"What if the root key is compromised?"**
> "Then delegation is compromised — that is the trust anchor. It cannot forge an
> owner's signature, so record-level forgery would still appear in the audit log
> as a root-signed operation. Mitigation is 2-of-3 root signatures, specified in
> the threat model but not implemented."

**"How do you know it works?"**
> "43 tests, 9 cluster failure checks, 10 live experiments. All reproducible with
> three commands, and the results file is generated by the same code the demo
> buttons call."

---

## If something breaks

| Symptom | Fix |
|---|---|
| Port already in use | `Get-Process python \| Stop-Process -Force`, then rerun |
| Portal shows "no quorum" | Wait 3 s; if it persists, `run_demo.py --fresh` |
| DNS returns nothing | Check `http://127.0.0.1:5380/metrics`; the front-end may still be starting |
| Stale data | `--fresh` wipes `data/live` and reseeds |
| `nslookup` ignores `-port` | Use `nslookup -port=5353 name 127.0.0.1` exactly, or run `python -c "from dcdns.experiments import Resolver; print(Resolver('127.0.0.1',5353).query('techfest.cs.test'))"` |

Logs are in `data/live/logs/` (`n1.log`, `n2.log`, `n3.log`, `dns.log`,
`portal.log`).
