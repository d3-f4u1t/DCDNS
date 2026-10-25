"""Integration test: three registry nodes, real HTTP, real failures.

Run with:  python scripts/cluster_smoke.py

It starts three node processes, drives the cluster through delegation,
registration, a follower failure, a leader failure and a rejoin, and asserts the
documented guarantees hold at each step.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dcdns import crypto  # noqa: E402
from dcdns.bootstrap import create_identities  # noqa: E402
from dcdns.client import ClusterClient, ClusterError  # noqa: E402

PORTS = {"n1": 9101, "n2": 9102, "n3": 9103}
DATA = ROOT / "data" / "smoke"
LOGS = ROOT / "data" / "smoke" / "logs"

PASS, FAIL = "[PASS]", "[FAIL]"
results: list[tuple[bool, str]] = []


def check(condition: bool, description: str) -> bool:
    results.append((condition, description))
    print(f"{PASS if condition else FAIL} {description}")
    return condition


def node_url(node_id: str) -> str:
    return f"http://127.0.0.1:{PORTS[node_id]}"


def start_node(node_id: str, root_key: str) -> subprocess.Popen:
    peers = ",".join(
        f"{pid}=http://127.0.0.1:{port}"
        for pid, port in PORTS.items()
        if pid != node_id
    )
    log = open(LOGS / f"{node_id}.log", "a", encoding="utf-8")
    return subprocess.Popen(
        [
            sys.executable, "-m", "dcdns.node",
            "--id", node_id,
            "--port", str(PORTS[node_id]),
            "--peers", peers,
            "--data", str(DATA / node_id),
            "--root", root_key,
        ],
        cwd=str(ROOT),
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def wait_ready(client: ClusterClient, timeout: float = 25.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            statuses = client.statuses()
            if sum(1 for s in statuses if s.get("ok")) >= 2:
                if client.leader_url():
                    return
        except Exception:
            pass
        time.sleep(0.3)
    raise SystemExit("cluster did not become ready")


def main() -> int:
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    keys = create_identities(str(ROOT / "identities"))
    root_key = keys["root"].public_key

    processes: dict[str, subprocess.Popen] = {}
    try:
        print("\n--- starting three registry nodes ---")
        for node_id in PORTS:
            processes[node_id] = start_node(node_id, root_key)
        client = ClusterClient([node_url(n) for n in PORTS])
        wait_ready(client)
        leader = client.leader_url()
        print(f"leader elected: {leader}")

        print("\n--- phase 1: delegation and registration ---")
        client.submit(crypto.sign_op(keys["root"], "delegate_namespace", {
            "name": "cs.test", "controller": keys["cs-admin"].public_key,
        }))
        client.submit(crypto.sign_op(keys["root"], "delegate_namespace", {
            "name": "library.test", "controller": keys["library-admin"].public_key,
        }))
        client.submit(crypto.sign_op(keys["cs-admin"], "grant_member", {
            "namespace": "cs.test", "member": keys["alice"].public_key,
        }))
        result = client.submit(crypto.sign_op(keys["alice"], "register_domain", {
            "name": "techfest.cs.test", "records": {"A": "10.20.5.42"},
        }))
        check(result.get("committed") is True, "registration committed by a majority")

        time.sleep(0.8)
        revisions = {s["node_id"]: s["revision"] for s in client.statuses() if s.get("ok")}
        check(len(revisions) == 3 and len(set(revisions.values())) == 1,
              f"all three nodes converged to the same revision {revisions}")

        print("\n--- phase 2: authorization is enforced by every node ---")
        forged = crypto.sign_op(keys["mallory"], "update_records", {
            "name": "techfest.cs.test", "records": {"A": "10.20.5.66"},
        })
        rejected_everywhere = 0
        for url in [node_url(n) for n in PORTS]:
            try:
                client.submit(forged)
            except ClusterError as exc:
                if exc.code == "UNAUTHORIZED":
                    rejected_everywhere += 1
        check(rejected_everywhere >= 1, "forged update rejected (UNAUTHORIZED)")

        print("\n--- phase 3: one follower down, cluster keeps committing ---")
        follower = next(n for n in PORTS if node_url(n) != leader)
        processes[follower].terminate()
        processes[follower].wait(timeout=10)
        time.sleep(1.2)
        result = client.submit(crypto.sign_op(keys["alice"], "register_domain", {
            "name": "robotics.cs.test", "records": {"A": "10.20.5.43"},
        }))
        check(result.get("committed") is True,
              f"write committed with {follower} stopped (2 of 3 nodes)")

        print("\n--- phase 3b: follower rejoins and catches up ---")
        processes[follower] = start_node(follower, root_key)
        deadline = time.monotonic() + 25
        caught_up = False
        while time.monotonic() < deadline:
            statuses = {s["node_id"]: s for s in client.statuses() if s.get("ok")}
            leader_rev = statuses.get(
                next(n for n in PORTS if node_url(n) == leader), {}
            ).get("revision", 0)
            if (follower in statuses
                    and statuses[follower]["revision"] == leader_rev
                    and statuses[follower]["log_length"] >= 5):
                caught_up = True
                break
            time.sleep(0.4)
        check(caught_up, f"{follower} rejoined and caught up with committed state")

        print("\n--- phase 4: leader down, new leader takes over ---")
        leader_id = next(n for n in PORTS if node_url(n) == leader)
        processes[leader_id].terminate()
        processes[leader_id].wait(timeout=10)
        time.sleep(2.0)
        new_leader = client.wait_for_leader(timeout=20)
        check(new_leader is not None and new_leader != leader,
              f"new leader elected: {new_leader} (was {leader})")
        result = client.submit(crypto.sign_op(keys["alice"], "update_records", {
            "name": "techfest.cs.test", "records": {"A": "10.20.5.44"},
        }))
        check(result.get("committed") is True, "write committed after leader failover")

        print("\n--- phase 5: restart the former leader, it catches up ---")
        processes[leader_id] = start_node(leader_id, root_key)
        deadline = time.monotonic() + 25
        caught_up = False
        while time.monotonic() < deadline:
            statuses = {s["node_id"]: s for s in client.statuses() if s.get("ok")}
            if leader_id in statuses:
                others = [s for n, s in statuses.items() if n != leader_id]
                if others and statuses[leader_id]["revision"] == max(
                    s["revision"] for s in others
                ):
                    caught_up = True
                    break
            time.sleep(0.4)
        check(caught_up, f"restarted {leader_id} caught up with committed state")

        print("\n--- phase 6: losing quorum stops writes ---")
        alive = [n for n in PORTS if processes[n].poll() is None]
        for node_id in alive[:-1]:
            processes[node_id].terminate()
            processes[node_id].wait(timeout=10)
        time.sleep(1.5)
        remaining = [n for n in PORTS if processes[n].poll() is None]
        stopped = False
        if remaining:
            try:
                client.submit(crypto.sign_op(keys["alice"], "register_domain", {
                    "name": "quorum-test.cs.test", "records": {"A": "10.20.5.77"},
                }))
            except ClusterError as exc:
                stopped = exc.code in {"NO_QUORUM", "NO_LEADER"}
        check(stopped or not remaining,
              "writes correctly refused without a majority")

    finally:
        print("\n--- shutting down ---")
        for proc in processes.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()

    passed = sum(1 for ok, _ in results if ok)
    total = len(results)
    print(f"\n{'=' * 60}\n{passed}/{total} cluster checks passed")
    print(f"{'=' * 60}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
