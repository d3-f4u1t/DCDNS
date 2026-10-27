# Evaluation results

Generated: 2026-10-27 10:27:17

Produced by `python scripts/evaluate.py` against a live three-node
cluster, its per-node DNS responders and the client-facing quorum
resolver. Every row is the result of a real signed operation, not a
simulation.

- Nodes reachable: **3/3**
- Current leader: `http://127.0.0.1:9101`
- Committed revision at start: **22**
- Node DNS revision keys loaded: **3/3**
- Freshness policy: **F1** (delta 0, watermark `responses`, stale policy `servfail`)
- Experiments passed: **12/12**

| # | Experiment | Expected | Observed | Result |
|---|---|---|---|---|
| 1 | Duplicate registration | exactly one registration succeeds; the second is rejected with NAME_TAKEN | first registration committed at revision 23; second rejected with NAME_TAKEN | PASS |
| 2 | Forged record update | rejected with UNAUTHORIZED; the stored record is unchanged | rejected with UNAUTHORIZED; record unchanged (10.20.5.124) | PASS |
| 3 | Cross-namespace write | rejected with UNAUTHORIZED | rejected with UNAUTHORIZED | PASS |
| 4 | Unauthorized delegation | rejected with UNAUTHORIZED | rejected with UNAUTHORIZED | PASS |
| 5 | Tampered signature | rejected with INVALID_SIGNATURE | rejected with INVALID_SIGNATURE | PASS |
| 6 | Replay of a valid operation | rejected with REPLAY_DETECTED | first submission committed at revision 24; replay rejected with REPLAY_DETECTED | PASS |
| 7 | Prohibited destination | rejected with RECORD_NOT_ALLOWED by the record policy | rejected with RECORD_NOT_ALLOWED | PASS |
| 8 | Two-party ownership transfer | ownership moves only after acceptance | status after initiate: pending_transfer; owner after accept: bob | PASS |
| 9 | Revocation removes the name from DNS | the name stops resolving within the propagation window | withdrawn from DNS 0.20s after revocation | PASS |
| 10 | DNS propagation latency | the new answer is served within a few seconds | new answer 10.20.5.123 live 0.31s after the client response (commit took 16ms) | PASS |
| 11 | Majority DNS resists a lying node | the resolver returns the honest address even though the lying node answers directly with the forgery | quorum returned '10.20.5.123'; n3 answered directly with '10.20.5.66' (forged '10.20.5.66', honest '10.20.5.123') | PASS |
| 12 | Stale majority is detected, not served | baseline returns the stale address; RAM-DNS retries and returns SERVFAIL (or a marked stale answer), then serves the new address after the lagging nodes catch up | baseline returned stale '10.20.5.123' (majority rev [30, 30]); RAM-DNS watermark 31 -> SERVFAIL (stale-majority); live resolver SERVFAIL; fresh answer after 0.00s | PASS |

## Machine-readable results

```json
{
  "duplicate_registration": {
    "passed": true,
    "observed": "first registration committed at revision 23; second rejected with NAME_TAKEN",
    "detail": {}
  },
  "forged_update": {
    "passed": true,
    "observed": "rejected with UNAUTHORIZED; record unchanged (10.20.5.124)",
    "detail": {}
  },
  "cross_namespace": {
    "passed": true,
    "observed": "rejected with UNAUTHORIZED",
    "detail": {
      "code": "UNAUTHORIZED"
    }
  },
  "unauthorized_delegation": {
    "passed": true,
    "observed": "rejected with UNAUTHORIZED",
    "detail": {
      "code": "UNAUTHORIZED"
    }
  },
  "invalid_signature": {
    "passed": true,
    "observed": "rejected with INVALID_SIGNATURE",
    "detail": {
      "code": "INVALID_SIGNATURE"
    }
  },
  "replay": {
    "passed": true,
    "observed": "first submission committed at revision 24; replay rejected with REPLAY_DETECTED",
    "detail": {
      "code": "REPLAY_DETECTED"
    }
  },
  "malicious_record": {
    "passed": true,
    "observed": "rejected with RECORD_NOT_ALLOWED",
    "detail": {
      "code": "RECORD_NOT_ALLOWED"
    }
  },
  "ownership_transfer": {
    "passed": true,
    "observed": "status after initiate: pending_transfer; owner after accept: bob",
    "detail": {}
  },
  "revocation": {
    "passed": true,
    "observed": "withdrawn from DNS 0.20s after revocation",
    "detail": {}
  },
  "dns_propagation": {
    "passed": true,
    "observed": "new answer 10.20.5.123 live 0.31s after the client response (commit took 16ms)",
    "detail": {
      "propagation_seconds": 0.312,
      "commit_ms": 16.0
    }
  },
  "quorum_dns": {
    "passed": true,
    "observed": "quorum returned '10.20.5.123'; n3 answered directly with '10.20.5.66' (forged '10.20.5.66', honest '10.20.5.123')",
    "detail": {
      "liar": "n3",
      "honest": "10.20.5.123",
      "forged": "10.20.5.66",
      "quorum_answer": "10.20.5.123",
      "liar_answer": "10.20.5.66"
    }
  },
  "stale_majority": {
    "passed": true,
    "observed": "baseline returned stale '10.20.5.123' (majority rev [30, 30]); RAM-DNS watermark 31 -> SERVFAIL (stale-majority); live resolver SERVFAIL; fresh answer after 0.00s",
    "detail": {
      "stale_address": "10.20.5.123",
      "target": "10.20.5.124",
      "lagging_nodes": [
        "n1",
        "n2"
      ],
      "current_node": "n3",
      "commit_revision": 31,
      "baseline": {
        "ok": true,
        "name": "techfest.cs.test",
        "qtype": 1,
        "qtype_name": "A",
        "answer": "10.20.5.123",
        "rcode": "NOERROR",
        "votes": {
          "n1": "10.20.5.123",
          "n2": "10.20.5.123",
          "n3": "10.20.5.124"
        },
        "winner": [
          "n1",
          "n2"
        ],
        "disagreement": true,
        "required": 2,
        "responders": 3,
        "latency_ms": 3.33,
        "at": 1793077036.2869842,
        "source": "resolver /query (same decision path as udp/5353)",
        "watermark": null,
        "fresh": true,
        "stale": false,
        "stale_majority": false,
        "retries": 0,
        "reason": "ok",
        "freshness": {
          "enabled": false,
          "condition": "off",
          "delta": 0,
          "watermark": null,
          "watermark_source": "off",
          "fresh": true,
          "stale": false,
          "stale_majority": false,
          "retries": 0,
          "reason": "ok",
          "majority_revisions": [
            30,
            30
          ],
          "revisions": {
            "n1": 30,
            "n2": 30,
            "n3": 31
          },
          "revision_sources": {
            "n1": "edns",
            "n2": "edns",
            "n3": "edns"
          },
          "revision_errors": {},
          "metadata_missing": false,
          "metadata_invalid": false
        }
      },
      "ram_dns": {
        "ok": false,
        "name": "techfest.cs.test",
        "qtype": 1,
        "qtype_name": "A",
        "answer": "SERVFAIL",
        "rcode": "SERVFAIL",
        "votes": {
          "n1": "10.20.5.123",
          "n2": "10.20.5.123",
          "n3": "10.20.5.124"
        },
        "winner": [
          "n1",
          "n2"
        ],
        "disagreement": true,
        "required": 2,
        "responders": 3,
        "latency_ms": 107.95,
        "at": 1793077036.3961957,
        "source": "resolver /query (same decision path as udp/5353)",
        "watermark": 31,
        "fresh": false,
        "stale": false,
        "stale_majority": true,
        "retries": 2,
        "reason": "stale-majority",
        "freshness": {
          "enabled": true,
          "condition": "F1",
          "delta": 0,
          "watermark": 31,
          "watermark_source": "responses",
          "fresh": false,
          "stale": false,
          "stale_majority": true,
          "retries": 2,
          "reason": "stale-majority",
          "majority_revisions": [
            30,
            30
          ],
          "revisions": {
            "n1": 30,
            "n2": 30,
            "n3": 31
          },
          "revision_sources": {
            "n1": "edns",
            "n2": "edns",
            "n3": "edns"
          },
          "revision_errors": {},
          "metadata_missing": false,
          "metadata_invalid": false
        }
      },
      "live": {
        "rcode": 2,
        "rcode_name": "SERVFAIL",
        "answer": null,
        "revision": null,
        "node_id": null,
        "signed": false,
        "stale": null
      },
      "convergence_seconds": 0.0
    }
  }
}
```

## What is not covered here

- **Node failure and quorum loss** are exercised by
  `python scripts/cluster_smoke.py`, which starts and kills real node
  processes. They are kept separate because they require process control
  rather than registry operations.
- **Byzantine behaviour** is out of scope. The replication protocol tolerates
  crash and omission failures only; a compromised node is assumed not to
  exist. RAM-DNS raises the cost of serving stale data, but two colluding
  nodes can still form a stale or false majority. This is a documented
  limitation, not a claim of BFT protection.
- **DNSSEC** is not implemented. The revision token is an application-layer
  attestation inside EDNS(0); it is not a DNSSEC signature and does not
  protect clients that do not speak this private option.
- **Clock skew** is checked only as an ingress sanity bound; the state
  machine itself is time-independent.
