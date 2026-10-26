# DCDNS — Decentralized Campus Domain Registry

A permissioned registry for campus DNS namespaces. Authorized participants
register and manage names like `techfest.cs.test`, ownership is proven with
Ed25519 signatures, and every accepted change is committed by a majority of
registry nodes.

Every registry node is also an authoritative DNS server. A client-facing
resolver asks all nodes and returns an answer only when a majority agrees. There
is no separate DNS publisher and no single DNS server that owns the zone.

```text
$ python -m dcdns.dig techfest.cs.test --all
quorum   NOERROR   10.20.5.42   (2 of 3 nodes agree)
n1       NOERROR   10.20.5.42
n2       NOERROR   10.20.5.42
n3       NOERROR   10.20.5.42
```

Those answers are not read from a static zone file. They are served from the
registry revision each node has committed, and the client accepts them only
after a majority check.

---

## Quick start

```powershell
pip install -r requirements.txt
python run_demo.py --fresh
```

Open **http://127.0.0.1:8000**. The console is the demo: query a name, watch
each node answer, inject a DNS fault, and recover without touching the registry.

That single command creates the demo identities, starts three registry nodes,
seeds a small campus, starts each node's DNS responder, starts the quorum
resolver and starts the portal. It also enables the console's loopback-only DNS
fault controls; `python run_demo.py --fresh --no-demo-controls` hides them.

To stop: `Ctrl+C`.

Verify DNS independently of the portal:

```powershell
python -m dcdns.dig techfest.cs.test --all
python -m dcdns.dig catalog.library.test
```

Windows `nslookup` does not support a custom port, which is why the project ships
`dcdns.dig`. On Linux or macOS, `dig @127.0.0.1 -p 5353 techfest.cs.test A`
works too.

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
| Revoked names stop resolving | A node's DNS snapshot excludes revoked domains and namespaces; pending transfers keep their frozen record live | Experiments → *Revocation* |
| One lying DNS node cannot change the client answer | The quorum resolver requires 2 of 3 nodes to return semantically identical answers | Experiments → *Majority DNS resists a lying node* |
| No DNS majority means no answer | With two nodes down the resolver returns `SERVFAIL` rather than trusting one node | `python -m dcdns.dig name --all` |

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
            API 9101          API 9102          API 9103
            DNS 5354          DNS 5355          DNS 5356
                 |                 |                 |
                 +-------- quorum-replicated log -----+
                                   |
                        committed registry state
                                   |
                 +-----------------+-----------------+
                 |                 |                 |
            DNS responder     DNS responder     DNS responder
                 |                 |                 |
                 +------- client quorum resolver ----+
                              UDP 5353
                                   |
                          dig / DNS client
                    (answer only if 2 of 3 agree)
```

* **Registry nodes** run the same deterministic state machine. They agree on the
  *order* of operations; the state machine decides whether each operation is
  legal.
* **Writes** may be sent to any node; followers forward to the coordinator
  (called the leader in the code). A write returns success only after a majority
  stores it.
* **Reads** are served from local committed state. Every node converges to the
  same revision.
* **Each node serves DNS** from its own committed snapshot. There is no central
  publisher process and no single DNS front-end.
* **The quorum resolver** fans a query out to all configured nodes, compares the
  semantic answers, and returns one only if a majority agrees. Otherwise it
  returns `SERVFAIL`.

---

## Five ways to run the evidence

```powershell
python -m pytest tests/ -q          # 59 unit + wire + majority + console-control tests
python scripts/cluster_smoke.py     # 9 real failure/recovery checks
python scripts/portal_flow.py       # 14 end-to-end portal checks (live demo)
python scripts/evaluate.py          # 11 live security experiments -> docs/EVALUATION_RESULTS.md
```

The fifth is the console itself at **http://127.0.0.1:8000**: every query and
fault control exercises the running processes, not a canned animation.

The cluster check starts three real processes, then:

1. commits a registration and verifies all three nodes converge;
2. rejects a forged update;
3. kills a follower and commits anyway (2 of 3);
4. restarts the follower and watches it catch up;
5. kills the leader and watches a new leader take over;
6. restarts the old leader and watches it catch up;
7. kills two nodes and verifies writes are refused.

Latest run: **59/59 tests, 9/9 cluster checks, 14/14 portal checks, 11/11 live
experiments.**

---

## The console in three minutes

Full click-by-click script: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md).

1. **Baseline** — open the console and query `techfest.cs.test`. Three direct
   UDP rows show what each node answers; a separate resolver row shows the
   resolver's own decision and vote map. Revisions come from each node's
   `/status`, not from the DNS packet.
2. **One node lies** — click **Make n3 lie**. n3's direct answer becomes
   `10.20.5.66`; the resolver still returns `10.20.5.42` because n1 and n2
   outvote it. A persistent **FAULT ACTIVE** banner names the fault.
3. **Lose DNS quorum** — click **Pause n2 + n3**. n1 still answers, n2 and n3
   time out, and the resolver returns `SERVFAIL`. The registry APIs stay up.
4. **Registry quorum is different** — while DNS is paused, register or update a
   name. The write still commits because registry quorum and DNS quorum are
   separate, and the console's revision counters advance. The resolver still
   returns `SERVFAIL` because only n1 is answering. Reset the pause when you
   want the resolver to see a majority again.
5. **Recover** — click **Reset DNS faults**. All three nodes answer the current
   committed value, the resolver returns a majority answer, and the banner
   clears.
6. **Authority and audit** — switch to *Mallory* and try to update Alice's
   domain: rejected with `UNAUTHORIZED`. The audit chain still verifies.

The fault controls are loopback-only and disabled unless `run_demo.py` starts
the portal with `--demo-controls` (the default). They change only the DNS
responder; they never sign, submit, or mutate a registry operation.

---

## Project layout

```text
dcdns/
  crypto.py          Ed25519 identities, canonical signing bytes
  names.py           domain syntax and record policy
  state.py           deterministic registry state machine (the core)
  cluster.py         quorum-replicated log, leader takeover, catch-up, DNS snapshots
  node.py            HTTP API and DNS lifecycle for one registry node
  client.py          cluster-aware client
  dns_server.py      DNS wire format and query engine
  dns_node.py        per-node UDP authoritative responder + chaos overrides
  quorum_resolver.py client-facing majority resolver, metrics, /query, CLI
  probe.py           direct node UDP probes + resolver decision for the console
  dig.py             small DNS query client for the demo
  experiments.py     live security experiments (shared by portal and CLI)
  portal.py          demonstration console and signed-operation UI
  bootstrap.py       demo identities
  templates/         Jinja2 pages
  static/            CSS + small progressive-enhancement JS
tests/               59 tests: state machine, authorization, DNS wire format,
                     per-node responder, quorum resolver, console controls
scripts/
  cluster_smoke.py   3-node failure and recovery checks
  portal_flow.py     end-to-end portal form checks
  evaluate.py        live experiment suite -> markdown report
docs/
  SPECIFICATION.md   protocol, data model, error codes, guarantees
  ARCHITECTURE.md    decisions and rejected alternatives
  THREAT_MODEL.md    assets, adversaries, residual risk
  EVALUATION.md      method and results
  DEMO_SCRIPT.md     the three-minute console walkthrough
run_demo.py          one-command launcher
DCDNS_PROJECT_GUIDE.txt  comprehensive plain-language guide and presentation Q&A
DCDNS_PATENT_IDEA.txt          patent-style invention disclosure (candidate, not filed)
DCDNS_PATENT_IDEA_COMPACT.txt  compact submission version of the disclosure
```

---

## What this is, precisely

This is a **permissioned registry with delegated namespace authority**. It
distributes day-to-day namespace administration among departments, replicates
state across independent nodes with majority commit, and serves DNS from every
node with client-side majority agreement.

It is **not** a trustless or peer-to-peer system:

* a root authority still bootstraps trust by certifying departmental keys;
* the root can revoke an entire namespace — a documented residual power;
* the replication protocol tolerates crash and network faults, **not** malicious
  nodes (no Byzantine fault tolerance);
* the DNS layer tolerates **one** lying node, not two colluding nodes;
* the resolver compares semantic answers, not revisions: immediately after a
  write, a majority of lagging nodes can briefly return the previous answer.
  The console exposes per-node revisions and registry → DNS lag; revision-aware
  freshness is the patent candidate, **not** implemented in this prototype;
* the demo portal holds private keys on disk for convenience — production
  signing belongs on the client;
* the DNS layer is authoritative for `.test` only inside this lab, and DNSSEC is
  not implemented.

These are stated as limitations rather than hidden, because a prototype that
claims more than it demonstrates is worth less than one that is precise about
its boundaries.

---

## Patent / invention disclosure

The project includes a separate, narrow invention disclosure for a college
submission. Two versions are provided:

* [`DCDNS_PATENT_IDEA_COMPACT.txt`](DCDNS_PATENT_IDEA_COMPACT.txt) — the
  submission-ready version: 11 sections, 15 draft claims, ~380 lines.
* [`DCDNS_PATENT_IDEA.txt`](DCDNS_PATENT_IDEA.txt) — the full disclosure with
  extended prior-art and claim discussion.

**Candidate invention:** *Freshness-Coherent Quorum Resolution for DNS Answers
from Replicated Authoritative Nodes* — short name **revision-aware majority
DNS**.

The current resolver requires 2-of-3 semantic agreement, but agreement alone
does not prove freshness. Suppose n1 and n2 are at revision 10 and return
`10.20.5.42`, while n3 is at revision 11 and returns `10.20.5.99`. The majority
is stale, and the current resolver would return the old address. The proposed
mechanism attaches each node's committed revision to its DNS answer and requires
both a semantic majority and a freshness condition relative to the highest
revision observed. A stale majority triggers a bounded retry, then `SERVFAIL`
(or an explicitly marked stale answer) instead of silently serving old data.

Status and honest framing:

* This is a **candidate invention and a technical disclosure**, not legal advice
  and not a filed patent.
* The DCDNS prototype currently implements semantic majority voting, **not** the
  revision-aware freshness mechanism described in the disclosure.
* The idea is incremental over quorum reads, DNSSEC, primary/secondary DNS,
  anycast, and blockchain DNS. Prior art is crowded; the disclosure argues only
  for the narrow freshness-coherence combination.
* Check the college's student IP policy and public-disclosure rules, and obtain a
  professional prior-art search before filing or publishing the specific
  mechanism.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Participants, data model, every operation, authorization rules, error codes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Why this design; etcd, CoreDNS and central DNS evaluated |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What we protect, from whom, and what remains exposed |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Method, measurements, and how to reproduce |
| [docs/EVALUATION_RESULTS.md](docs/EVALUATION_RESULTS.md) | Generated results from the last live run |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Presentation script with timings |
| [DCDNS_PROJECT_GUIDE.txt](DCDNS_PROJECT_GUIDE.txt) | Everything explained in plain language, with presentation Q&A |
| [DCDNS_PATENT_IDEA_COMPACT.txt](DCDNS_PATENT_IDEA_COMPACT.txt) | Compact submission version: 11 sections, 15 draft claims, validation plan, limitations |
| [DCDNS_PATENT_IDEA.txt](DCDNS_PATENT_IDEA.txt) | Candidate invention disclosure: revision-aware majority DNS, draft claims, prior art, limitations |
