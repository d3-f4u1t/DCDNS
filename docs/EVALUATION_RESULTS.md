# Evaluation results

Generated: 2026-10-26 15:46:16

Produced by `python scripts/evaluate.py` against a live three-node
cluster, its per-node DNS responders and the client-facing quorum
resolver. Every row is the result of a real signed operation, not a
simulation.

- Nodes reachable: **3/3**
- Current leader: `http://127.0.0.1:9101`
- Committed revision at start: **13**
- Experiments passed: **11/11**

| # | Experiment | Expected | Observed | Result |
|---|---|---|---|---|
| 1 | Duplicate registration | exactly one registration succeeds; the second is rejected with NAME_TAKEN | first registration committed at revision 14; second rejected with NAME_TAKEN | PASS |
| 2 | Forged record update | rejected with UNAUTHORIZED; the stored record is unchanged | rejected with UNAUTHORIZED; record unchanged (10.20.5.42) | PASS |
| 3 | Cross-namespace write | rejected with UNAUTHORIZED | rejected with UNAUTHORIZED | PASS |
| 4 | Unauthorized delegation | rejected with UNAUTHORIZED | rejected with UNAUTHORIZED | PASS |
| 5 | Tampered signature | rejected with INVALID_SIGNATURE | rejected with INVALID_SIGNATURE | PASS |
| 6 | Replay of a valid operation | rejected with REPLAY_DETECTED | first submission committed at revision 15; replay rejected with REPLAY_DETECTED | PASS |
| 7 | Prohibited destination | rejected with RECORD_NOT_ALLOWED by the record policy | rejected with RECORD_NOT_ALLOWED | PASS |
| 8 | Two-party ownership transfer | ownership moves only after acceptance | status after initiate: pending_transfer; owner after accept: bob | PASS |
| 9 | Revocation removes the name from DNS | the name stops resolving within the propagation window | withdrawn from DNS 0.31s after revocation | PASS |
| 10 | DNS propagation latency | the new answer is served within a few seconds | new answer 10.20.5.123 live 0.22s after the client response (commit took 0ms) | PASS |
| 11 | Majority DNS resists a lying node | the resolver returns the honest address even though the lying node answers directly with the forgery | quorum returned '10.20.5.123'; n3 answered directly with '10.20.5.66' (forged '10.20.5.66', honest '10.20.5.123') | PASS |

## Machine-readable results

```json
{
  "duplicate_registration": {
    "passed": true,
    "observed": "first registration committed at revision 14; second rejected with NAME_TAKEN",
    "detail": {}
  },
  "forged_update": {
    "passed": true,
    "observed": "rejected with UNAUTHORIZED; record unchanged (10.20.5.42)",
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
    "observed": "first submission committed at revision 15; replay rejected with REPLAY_DETECTED",
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
    "observed": "withdrawn from DNS 0.31s after revocation",
    "detail": {}
  },
  "dns_propagation": {
    "passed": true,
    "observed": "new answer 10.20.5.123 live 0.22s after the client response (commit took 0ms)",
    "detail": {
      "propagation_seconds": 0.218,
      "commit_ms": 0.0
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
  exist. This is a documented limitation, not a claim of protection.
- **Clock skew** is checked only as an ingress sanity bound; the state
  machine itself is time-independent.
