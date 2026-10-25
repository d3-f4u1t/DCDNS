<<<<<<< HEAD
# DCDNS — Decentralized Campus Domain Registry

A permissioned registry for campus DNS namespaces. Authorized participants
register and manage names like `techfest.cs.test`, ownership is proven with
Ed25519 signatures, every accepted change is committed by a majority of registry
nodes, and committed records are published into a live authoritative DNS server
that ordinary resolvers can query.

```text
$ nslookup -port=5353 techfest.cs.test 127.0.0.1
Name:    techfest.cs.test
Address: 10.20.5.42
```

That answer is not read from a static zone file. It is served from a registry
revision that a majority of nodes agreed on.

---

## Quick start

```powershell
pip install -r requirements.txt
python run_demo.py --fresh
```

Then open **http://127.0.0.1:8000**.

That single command creates the demo identities, starts three registry nodes,
seeds a small campus, starts the DNS front-end and starts the portal.

To stop: `Ctrl+C`.

Verify DNS independently of the portal:

```powershell
nslookup -port=5353 techfest.cs.test 127.0.0.1
nslookup -port=5353 catalog.library.test 127.0.0.1
```

---

## What the system actually enforces

| Claim | How it is enforced | Where to see it |
|---|---|---|
| Only authorized participants can register a name | Every operation carries a signature; the state machine checks it against the namespace's delegated controller | Experiments → *Cross-namespace write* |
| Names are unique across the whole registry | Duplicate registration is rejected deterministically (`NAME_TAKEN`) | Experiments → *Duplicate registration* |
| One department cannot modify another's names | Authority is a namespace tree; the longest enclosing namespace decides who may act | Experiments → *Forged update* |
| Operations cannot be replayed | Signed payload includes a nonce that the state machine records | Experiments → *Replay* |
| Accepted changes are durable across node loss | A write is acknowledged only after a majority of nodes stores it | `scripts/cluster_smoke.py` |
| Every change is auditable | Hash-chained audit log; editing one record breaks every later hash | Audit page |
| Revoked names stop resolving | The DNS front-end publishes only `active` domains in `active` namespaces | Experiments → *Revocation* |

---

## Architecture

```text
                        Portal (FastAPI + Jinja2)
                                   |
                                   | signed operations (Ed25519)
                                   v
                 +-----------------+-----------------+
                 |                 |                 |
            Registry n1       Registry n2       Registry n3
            (leader)          (follower)        (follower)
                 |                 |                 |
                 +-------- quorum-replicated log -----+
                                   |
                        committed registry state
                                   |
                        publisher (polls committed state)
                                   |
                     authoritative DNS front-end :5353
                                   |
                          nslookup / dig / resolver
```

* **Registry nodes** run the same deterministic state machine. They agree on the
  *order* of operations; the state machine decides whether each operation is
  legal.
* **Writes** may be sent to any node; followers forward to the leader. A write
  returns success only after a majority stores it.
* **Reads** are served from local committed state. Every node converges to the
  same revision.
* **The DNS front-end** never reads the registry database directly. It polls
  committed state and republishes the zone, which makes propagation measurable.

---

## Three ways to run the evidence

```powershell
python -m pytest tests/ -q          # 43 unit + wire-protocol tests
python scripts/cluster_smoke.py     # 9 real failure/recovery checks
python scripts/evaluate.py          # 10 live security experiments -> docs/EVALUATION_RESULTS.md
```

The cluster check starts three real processes, then:

1. commits a registration and verifies all three nodes converge;
2. rejects a forged update;
3. kills a follower and commits anyway (2 of 3);
4. restarts the follower and watches it catch up;
5. kills the leader and watches a new leader take over;
6. restarts the old leader and watches it catch up;
7. kills two nodes and verifies writes are refused.

Latest run: **9/9 cluster checks, 10/10 security experiments, 43/43 tests.**

---

## The demo in five minutes

Full click-by-click script: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md).

1. **Dashboard** — three nodes, one leader, all at the same revision; DNS in sync.
2. **Domains** — register `myproject.cs.test` as Alice; watch it appear at all
   three nodes.
3. **DNS** — `nslookup -port=5353 myproject.cs.test 127.0.0.1` returns the address.
4. **Update** — change the address in the portal, query again within a second.
5. **Attack** — switch to *Mallory* and try to update Alice's domain: rejected
   with `UNAUTHORIZED`, record unchanged.
6. **Experiments** — run all ten live; they are real signed operations.
7. **Audit** — show the hash chain and its verification badge.

---

## Project layout

```text
dcdns/
  crypto.py        Ed25519 identities, canonical signing bytes
  names.py         domain syntax and record policy
  state.py         deterministic registry state machine (the core)
  cluster.py       quorum-replicated log, leader takeover, catch-up
  node.py          HTTP API for one registry node
  client.py        cluster-aware client
  dns_server.py    authoritative DNS wire-protocol server + publisher
  experiments.py   live security experiments (shared by portal and CLI)
  portal.py        demonstration UI
  bootstrap.py     demo identities
  templates/       Jinja2 pages
  static/          CSS + small progressive-enhancement JS
tests/             43 tests: state machine, authorization, DNS wire format
scripts/
  cluster_smoke.py   3-node failure and recovery checks
  evaluate.py        live experiment suite -> markdown report
docs/
  SPECIFICATION.md   protocol, data model, error codes, guarantees
  ARCHITECTURE.md    decisions and rejected alternatives
  THREAT_MODEL.md    assets, adversaries, residual risk
  EVALUATION.md      method and results
  DEMO_SCRIPT.md     the five-minute walkthrough
run_demo.py         one-command launcher
```

---

## What this is, precisely

This is a **permissioned registry with delegated namespace authority**. It
distributes day-to-day namespace administration among departments, and it
replicates state across independent nodes with majority commit.

It is **not** a trustless or peer-to-peer system:

* a root authority still bootstraps trust by certifying departmental keys;
* the root can revoke an entire namespace — a documented residual power;
* the replication protocol tolerates crash and network faults, **not** malicious
  nodes (no Byzantine fault tolerance);
* the demo portal holds private keys on disk for convenience — production
  signing belongs on the client;
* the DNS front-end is authoritative for `.test` only inside this lab.

These are stated as limitations rather than hidden, because a prototype that
claims more than it demonstrates is worth less than one that is precise about
its boundaries.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Participants, data model, every operation, authorization rules, error codes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Why this design; etcd, CoreDNS and Raft evaluated |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What we protect, from whom, and what remains exposed |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Method, measurements, and how to reproduce |
| [docs/EVALUATION_RESULTS.md](docs/EVALUATION_RESULTS.md) | Generated results from the last live run |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Presentation script with timings |
=======
# DCDNS
>>>>>>> f0201177fb56e1dfd501a21ca22f24c14eb50b2c
