"""Run the full experiment suite against a live cluster and write a report.

    python scripts/evaluate.py

Writes docs/EVALUATION_RESULTS.md with a timestamped table of what the running
system actually did. The portal's Experiments page calls the same runner, so the
report and the live demo cannot disagree.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dcdns import crypto  # noqa: E402
from dcdns.bootstrap import load_identities  # noqa: E402
from dcdns.client import ClusterClient  # noqa: E402
from dcdns.experiments import EXPERIMENTS, ExperimentRunner, Resolver  # noqa: E402

NODES = [
    "http://127.0.0.1:9101",
    "http://127.0.0.1:9102",
    "http://127.0.0.1:9103",
]


def main() -> int:
    identities = load_identities(str(ROOT / "identities"))
    keys = {
        item["name"]: crypto.load_keypair(str(ROOT / "identities" / item["file"]))
        for item in identities
    }

    client = ClusterClient(NODES, timeout=6.0)
    resolver = Resolver("127.0.0.1", 5353)
    runner = ExperimentRunner(client, keys, resolver)

    print("\n=== DCDNS evaluation ===\n")
    statuses = client.statuses()
    live = [s for s in statuses if s.get("ok")]
    leader = next((s["url"] for s in live if s.get("role") == "leader"), None)
    revision = max((s.get("revision", 0) for s in live), default=0)
    print(f"nodes reachable : {len(live)}/{len(statuses)}")
    print(f"leader          : {leader}")
    print(f"committed rev   : {revision}\n")

    results: dict[str, dict] = {}
    for experiment in EXPERIMENTS:
        print(f"  running {experiment['id']} ...", end=" ", flush=True)
        result = runner.run(experiment["id"]).as_dict()
        results[experiment["id"]] = result
        print("PASS" if result["passed"] else "FAIL")
        print(f"    {result['observed']}")

    passed = sum(1 for r in results.values() if r["passed"])
    total = len(results)
    print(f"\n{passed}/{total} experiments passed\n")

    lines = [
        "# Evaluation results",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Produced by `python scripts/evaluate.py` against a live three-node",
        "cluster and the authoritative DNS front-end. Every row is the result of",
        "a real signed operation, not a simulation.",
        "",
        f"- Nodes reachable: **{len(live)}/{len(statuses)}**",
        f"- Current leader: `{leader}`",
        f"- Committed revision at start: **{revision}**",
        f"- Experiments passed: **{passed}/{total}**",
        "",
        "| # | Experiment | Expected | Observed | Result |",
        "|---|---|---|---|---|",
    ]
    for index, experiment in enumerate(EXPERIMENTS, start=1):
        result = results[experiment["id"]]
        observed = result["observed"].replace("|", "\\|")
        lines.append(
            f"| {index} | {experiment['title']} | {experiment['expectation']} | "
            f"{observed} | {'PASS' if result['passed'] else 'FAIL'} |"
        )

    lines += [
        "",
        "## Machine-readable results",
        "",
        "```json",
        json.dumps(results, indent=2),
        "```",
        "",
        "## What is not covered here",
        "",
        "- **Node failure and quorum loss** are exercised by",
        "  `python scripts/cluster_smoke.py`, which starts and kills real node",
        "  processes. They are kept separate because they require process control",
        "  rather than registry operations.",
        "- **Byzantine behaviour** is out of scope. The replication protocol tolerates",
        "  crash and omission failures only; a compromised node is assumed not to",
        "  exist. This is a documented limitation, not a claim of protection.",
        "- **Clock skew** is checked only as an ingress sanity bound; the state",
        "  machine itself is time-independent.",
        "",
    ]

    out = ROOT / "docs" / "EVALUATION_RESULTS.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), "utf-8")
    print(f"report written to {out}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
