"""Reproduce the acknowledged-write / stale-majority window deterministically.

What this measures
------------------
The registry acknowledges a write when a majority has *stored* the log entry.
Followers learn the new commit index on a later replication push, so for a
short window they still answer DNS from the previous committed snapshot. If two
of three nodes are in that window, the semantic-majority resolver returns the
old answer even though the write was acknowledged.

This script starts three real node processes on ports that do not collide with
``run_demo.py``, seeds one record, and then runs two kinds of trials:

``control``
    No fault injection. The snapshot is taken immediately after the write
    acknowledgement, so it measures the natural window.

``hold-<N>ms``
    Commit application is held on the two followers. They still store and
    acknowledge entries, so the leader can commit, but their ``commit_index``,
    state revision and DNS snapshot stay at the previous commit. The snapshot
    is taken N milliseconds after the acknowledgement, while the hold is still
    active, then the hold is released and convergence is timed.

Run:
    python scripts/commit_lag_repro.py
    python scripts/commit_lag_repro.py --trials 5 --hold-delays 0,100,300
    python scripts/commit_lag_repro.py --keep

Outputs (under ``data/commit-lag/results`` by default):
    trials.jsonl    one raw record per trial
    summary.json    aggregate measurements
    summary.md      human-readable report
    commands.txt    exact command and environment
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dcdns import crypto  # noqa: E402
from dcdns.bootstrap import create_identities  # noqa: E402
from dcdns.client import ClusterClient, ClusterError  # noqa: E402
from dcdns.dns_server import build_query  # noqa: E402
from dcdns.experiments import Resolver  # noqa: E402
from dcdns.quorum_resolver import FreshnessPolicy, QuorumResolver  # noqa: E402

HTTP_PORTS = {"n1": 9201, "n2": 9202, "n3": 9203}
DNS_PORTS = {"n1": 5454, "n2": 5455, "n3": 5456}
NAME = "techfest.cs.test"
OLD = "10.20.5.42"
NEW = "10.20.5.123"
POLL_INTERVAL = 0.05


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def node_url(node_id: str) -> str:
    return f"http://127.0.0.1:{HTTP_PORTS[node_id]}"


def dns_nodes() -> dict[str, tuple[str, int]]:
    return {nid: ("127.0.0.1", port) for nid, port in DNS_PORTS.items()}


def node_apis() -> dict[str, str]:
    return {nid: node_url(nid) for nid in HTTP_PORTS}


def check_ports() -> None:
    busy: list[str] = []
    for node_id, port in HTTP_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                busy.append(f"tcp/{port} ({node_id} HTTP)")
    for node_id, port in DNS_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                busy.append(f"udp/{port} ({node_id} DNS)")
    if busy:
        raise SystemExit(
            "Cannot start: experiment ports are already in use:\n  "
            + "\n  ".join(busy)
            + "\nStop the process using them (the demo uses 9101-9103 / 5354-5356)."
        )


def start_node(
    node_id: str,
    root_key: str,
    data_dir: Path,
    log_dir: Path,
    dns_key: Path,
    publication_barrier: bool = False,
) -> tuple[subprocess.Popen, object]:
    peers = ",".join(
        f"{pid}=http://127.0.0.1:{port}"
        for pid, port in HTTP_PORTS.items()
        if pid != node_id
    )
    log = open(log_dir / f"{node_id}.log", "a", encoding="utf-8", buffering=1)
    command = [
        sys.executable, "-u", "-m", "dcdns.node",
        "--id", node_id,
        "--port", str(HTTP_PORTS[node_id]),
        "--peers", peers,
        "--data", str(data_dir / node_id),
        "--root", root_key,
        "--dns-port", str(DNS_PORTS[node_id]),
        "--dns-key", str(dns_key),
        "--chaos",
    ]
    if publication_barrier:
        command.append("--publication-barrier")
    process = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return process, log


def wait_ready(client: ClusterClient, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        statuses = client.statuses()
        good = [s for s in statuses if s.get("ok")]
        if len(good) == len(HTTP_PORTS):
            leaders = [s for s in good if s.get("role") == "leader"]
            if len(leaders) == 1:
                return
        time.sleep(0.2)
    raise SystemExit("cluster did not become ready with three reachable nodes")


def fetch_statuses(http: httpx.Client, apis: dict[str, str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for node_id, api in apis.items():
        try:
            response = http.get(f"{api}/status")
            result[node_id] = (
                response.json()
                if response.status_code == 200
                else {"ok": False, "http_status": response.status_code}
            )
        except Exception as exc:
            result[node_id] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return result


def fetch_zones(http: httpx.Client, apis: dict[str, str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for node_id, api in apis.items():
        try:
            response = http.get(f"{api}/internal/zone")
            result[node_id] = (
                response.json()
                if response.status_code == 200
                else {"ok": False, "http_status": response.status_code}
            )
        except Exception as exc:
            result[node_id] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return result


def set_hold(
    http: httpx.Client, apis: dict[str, str], node_ids: list[str], held: bool
) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for node_id in node_ids:
        try:
            response = http.post(
                f"{apis[node_id]}/internal/replication/hold",
                json={"held": held},
            )
            result[node_id] = (
                response.json()
                if response.status_code == 200
                else {"ok": False, "http_status": response.status_code}
            )
        except Exception as exc:
            result[node_id] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return result


def direct_details(
    resolvers: dict[str, Resolver], name: str
) -> dict[str, dict]:
    details: dict[str, dict] = {}
    for node_id, resolver in resolvers.items():
        detail = resolver.query_detail(name)
        details[node_id] = {key: value for key, value in detail.items() if key != "raw"}
    return details


def snapshot(
    baseline: QuorumResolver,
    resolvers: dict[str, Resolver],
    http: httpx.Client,
    apis: dict[str, str],
    name: str,
    ack_time: float,
    ram: QuorumResolver | None = None,
) -> dict:
    """Take node and resolver observations as close together as possible."""
    packet = build_query(name)
    with ThreadPoolExecutor(max_workers=9) as pool:
        resolver_future = pool.submit(baseline.resolve_detail, packet)
        ram_future = pool.submit(ram.resolve_detail, packet) if ram else None
        direct_futures = {
            node_id: pool.submit(resolver.query_detail, name)
            for node_id, resolver in resolvers.items()
        }
        status_future = pool.submit(fetch_statuses, http, apis)
        zone_future = pool.submit(fetch_zones, http, apis)

        baseline_detail = resolver_future.result()
        ram_detail = ram_future.result() if ram_future else None
        direct = {
            node_id: {
                key: value
                for key, value in future.result().items()
                if key != "raw"
            }
            for node_id, future in direct_futures.items()
        }
        statuses = status_future.result()
        zones = zone_future.result()

    return {
        "observed_at_ms": round((time.perf_counter() - ack_time) * 1000.0, 2),
        "resolver": baseline_detail,
        "ram_dns": ram_detail,
        "nodes": {
            node_id: {
                "dns": direct[node_id],
                "status": statuses.get(node_id, {}),
                "zone": zones.get(node_id, {}),
            }
            for node_id in sorted(HTTP_PORTS)
        },
    }


def ensure_converged(
    http: httpx.Client,
    apis: dict[str, str],
    resolvers: dict[str, Resolver],
    baseline: QuorumResolver,
    address: str,
    timeout: float = 12.0,
) -> tuple[bool, dict]:
    deadline = time.monotonic() + timeout
    last: dict = {}
    packet = build_query(NAME)
    while time.monotonic() < deadline:
        statuses = fetch_statuses(http, apis)
        leader = next(
            (s for s in statuses.values() if s.get("ok") and s.get("role") == "leader"),
            None,
        )
        if leader is None:
            time.sleep(POLL_INTERVAL)
            continue
        target = int(leader.get("commit_index", 0))
        direct = direct_details(resolvers, NAME)
        resolver_detail = baseline.resolve_detail(packet)
        last = {
            "leader_commit_index": target,
            "statuses": statuses,
            "direct": direct,
            "resolver": resolver_detail,
        }
        all_committed = all(
            s.get("ok")
            and int(s.get("revision", -1)) == target
            and int(s.get("dns_revision", -1)) == target
            and not s.get("commit_hold", False)
            for s in statuses.values()
        )
        all_answers = all(
            item.get("rcode") == 0 and item.get("answer") == address
            for item in direct.values()
        )
        resolver_ok = (
            resolver_detail.get("ok") is True
            and resolver_detail.get("answer") == address
        )
        if all_committed and all_answers and resolver_ok:
            return True, last
        time.sleep(POLL_INTERVAL)
    return False, last


def choose_leader(statuses: dict[str, dict]) -> str | None:
    leaders = [
        node_id
        for node_id, status in statuses.items()
        if status.get("ok") and status.get("role") == "leader"
    ]
    return leaders[0] if len(leaders) == 1 else None


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 2)
    value = ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    return round(value, 2)


def latency_summary(values: list[float]) -> dict:
    clean = [float(value) for value in values if value is not None]
    return {
        "count": len(clean),
        "p50": percentile(clean, 0.50),
        "p95": percentile(clean, 0.95),
        "p99": percentile(clean, 0.99),
        "min": round(min(clean), 2) if clean else None,
        "max": round(max(clean), 2) if clean else None,
    }


def aggregate(records: list[dict]) -> dict:
    modes: dict[str, list[dict]] = {}
    for record in records:
        modes.setdefault(record["mode"], []).append(record)

    summary: dict[str, dict] = {}
    for mode, items in modes.items():
        acknowledged = [r for r in items if r.get("acknowledged")]
        failures = [r for r in acknowledged if r.get("failure_reproduced")]
        stale_counts = [
            len(r.get("stale_nodes") or []) for r in acknowledged
        ]
        summary[mode] = {
            "trials": len(items),
            "acknowledged": len(acknowledged),
            "not_acknowledged": len(items) - len(acknowledged),
            "failures_reproduced": len(failures),
            "stale_answer_rate": (
                round(len(failures) / len(acknowledged), 3) if acknowledged else None
            ),
            "stale_node_counts": {
                str(count): stale_counts.count(count)
                for count in sorted(set(stale_counts))
            },
            "baseline_servfail": sum(
                1
                for r in acknowledged
                if (r.get("snapshot", {}).get("resolver") or {}).get("rcode")
                == "SERVFAIL"
            ),
            "ram_stale_answers": sum(
                1 for r in acknowledged if r.get("ram_stale")
            ),
            "ram_servfail": sum(
                1 for r in acknowledged if r.get("ram_servfail")
            ),
            "ram_stale_rate": (
                round(
                    sum(1 for r in acknowledged if r.get("ram_stale"))
                    / len(acknowledged),
                    3,
                )
                if acknowledged else None
            ),
            "ram_servfail_rate": (
                round(
                    sum(1 for r in acknowledged if r.get("ram_servfail"))
                    / len(acknowledged),
                    3,
                )
                if acknowledged else None
            ),
            "write_ack_ms": latency_summary(
                [r.get("write_ack_ms") for r in acknowledged]
            ),
            "resolver_latency_ms": latency_summary(
                [
                    (r.get("snapshot", {}).get("resolver") or {}).get("latency_ms")
                    for r in acknowledged
                ]
            ),
            "ram_latency_ms": latency_summary(
                [
                    (r.get("snapshot", {}).get("ram_dns") or {}).get("latency_ms")
                    for r in acknowledged
                ]
            ),
            "convergence_ms": latency_summary(
                [r.get("convergence_ms") for r in items if r.get("converged")]
            ),
            "retries": sum(
                int((r.get("snapshot", {}).get("resolver") or {}).get("retries") or 0)
                for r in acknowledged
            ),
            "ram_retries": sum(
                int((r.get("snapshot", {}).get("ram_dns") or {}).get("retries") or 0)
                for r in acknowledged
            ),
        }
    return summary


def write_report(
    output_dir: Path,
    records: list[dict],
    summary: dict,
    metadata: dict,
    config: dict,
) -> None:
    lines = [
        "# Commit-lag / stale-majority reproduction",
        "",
        f"- Git HEAD: `{metadata.get('git_head', 'unknown')}`",
        f"- Command: `{metadata.get('command', '')}`",
        f"- Trials: {len(records)}",
        f"- Hold delays: {config.get('hold_delays_ms')} ms",
        "",
        "## Aggregate",
        "",
        "| mode | trials | acked | timeouts | A stale | A rate | C stale | C SERVFAIL | ack p50/p95 (ms) | A p50/p95 (ms) | C p50/p95 (ms) | converge p50/p95 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|",
    ]
    for mode, item in summary.items():
        ack = item["write_ack_ms"]
        res = item["resolver_latency_ms"]
        ram = item["ram_latency_ms"]
        conv = item["convergence_ms"]
        lines.append(
            f"| {mode} | {item['trials']} | {item['acknowledged']} | "
            f"{item['not_acknowledged']} | {item['failures_reproduced']} | "
            f"{item['stale_answer_rate']} | {item['ram_stale_answers']} | "
            f"{item['ram_servfail']} | "
            f"{ack['p50']}/{ack['p95']} | {res['p50']}/{res['p95']} | "
            f"{ram['p50']}/{ram['p95']} | {conv['p50']}/{conv['p95']} |"
        )

    lines += [
        "",
        "## Per-trial outcome",
        "",
        "| # | mode | delay ms | acked | old answers | A answer | C answer | ack ms | convergence ms |",
        "|---:|---|---:|---|---:|---|---|---:|---:|",
    ]
    for record in records:
        old = record.get("stale_nodes") or []
        resolver = (record.get("snapshot", {}).get("resolver") or {})
        ram = (record.get("snapshot", {}).get("ram_dns") or {})
        lines.append(
            f"| {record['trial']} | {record['mode']} | {record['hold_delay_ms']} | "
            f"{record.get('acknowledged')} | {', '.join(old) or '-'} | "
            f"{resolver.get('answer', '-')} ({resolver.get('rcode', '-')}) | "
            f"{ram.get('answer', '-')} ({ram.get('reason', '-')}) | "
            f"{record.get('write_ack_ms', '-')} | {record.get('convergence_ms', '-')} |"
        )

    reproduced = any(r.get("failure_reproduced") for r in records)
    control_reproduced = any(
        r.get("failure_reproduced") for r in records if r["mode"] == "control"
    )
    lines += ["", "## Conclusion", ""]
    if metadata.get("publication_barrier"):
        acked = sum(item["acknowledged"] for item in summary.values())
        timeouts = sum(item["not_acknowledged"] for item in summary.values())
        lines.append(
            f"Variant B (publication barrier) acknowledged {acked} write(s) and "
            f"timed out on {timeouts}. A timeout is the intended fail-closed "
            "outcome while a majority cannot apply the commit: the client is told "
            "the write is ambiguous rather than receiving a false success."
        )
        if reproduced:
            lines.append(
                "A stale majority still followed an acknowledged write, so the "
                "barrier did not cover every trial; inspect the raw records."
            )
        else:
            lines.append(
                "No acknowledged write was followed by a stale semantic majority."
            )
    elif reproduced:
        lines.append(
            "The baseline failure was reproduced: at least one acknowledged write "
            "left two nodes serving the old answer and the semantic-majority "
            "resolver returned that old answer."
        )
        if control_reproduced:
            lines.append(
                "It also occurred in at least one no-injection control trial, which "
                "means the natural commit-propagation window is wide enough to hit "
                "without artificial delay."
            )
        else:
            lines.append(
                "It did not occur in the no-injection control trials, so the "
                "commit-hold fault is what made the window observable."
            )
    else:
        lines.append(
            "The baseline failure was not reproduced under these conditions. "
            "Inspect the raw records before drawing a conclusion."
        )

    if metadata.get("ram_dns"):
        acknowledged = sum(item["acknowledged"] for item in summary.values())
        a_stale = sum(item["failures_reproduced"] for item in summary.values())
        c_stale = sum(item["ram_stale_answers"] for item in summary.values())
        c_servfail = sum(item["ram_servfail"] for item in summary.values())
        lines.append(
            f"Across {acknowledged} acknowledged writes, variant A served the old "
            f"answer in {a_stale} case(s); variant C served it in {c_stale} and "
            f"returned SERVFAIL in {c_servfail}. RAM-DNS trades availability for "
            "not silently serving a stale majority."
        )
    lines.append("")

    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    (output_dir / "summary.json").write_text(
        json.dumps(
            {"metadata": metadata, "config": config, "summary": summary},
            indent=2,
        ),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trials", type=int, default=3,
        help="control trials per run; each hold delay also gets this many trials",
    )
    parser.add_argument(
        "--hold-delays", default="0,100,300",
        help="comma-separated hold durations before the snapshot, in ms",
    )
    parser.add_argument(
        "--data", default=str(ROOT / "data" / "commit-lag"),
        help="data directory for this experiment",
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="reuse existing data/logs instead of wiping them",
    )
    parser.add_argument(
        "--timeout", type=float, default=12.0,
        help="convergence timeout per trial, in seconds",
    )
    parser.add_argument(
        "--publication-barrier", action="store_true",
        help="start the cluster in variant-B mode (ack after a majority applied)",
    )
    parser.add_argument(
        "--ram", action="store_true",
        help="also evaluate the RAM-DNS resolver (variant C) on the same answers",
    )
    parser.add_argument(
        "--ram-stale-policy", choices=["servfail", "marked-stale"],
        default="servfail", help="RAM-DNS behaviour when freshness fails",
    )
    args = parser.parse_args()

    if args.trials < 1:
        raise SystemExit("--trials must be at least 1")
    hold_delays = sorted(
        {int(part) for part in args.hold_delays.split(",") if part.strip()}
    )
    if not hold_delays or any(delay < 0 for delay in hold_delays):
        raise SystemExit("--hold-delays must be non-negative milliseconds")

    data_dir = Path(args.data).resolve()
    logs_dir = data_dir / "logs"
    results_dir = data_dir / "results"
    node_keys_dir = data_dir / "node-keys"
    identities_dir = data_dir / "identities"

    check_ports()
    if data_dir.exists() and not args.keep:
        shutil.rmtree(data_dir)
    for directory in (data_dir, logs_dir, results_dir, node_keys_dir, identities_dir):
        directory.mkdir(parents=True, exist_ok=True)

    keys = create_identities(str(identities_dir))
    root_key = keys["root"].public_key
    node_keys: dict[str, crypto.KeyPair] = {}
    node_key_files: dict[str, Path] = {}
    for node_id in HTTP_PORTS:
        path = node_keys_dir / f"{node_id}.json"
        if path.exists():
            node_keys[node_id] = crypto.load_keypair(str(path))
        else:
            node_keys[node_id] = crypto.KeyPair.generate(
                label=f"registry node {node_id}", role="registry"
            )
            crypto.save_keypair(node_keys[node_id], str(path))
        node_key_files[node_id] = path

    command = " ".join([sys.executable, *sys.argv])
    metadata = {
        "command": command,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": sys.version,
        "platform": sys.platform,
        "http_ports": HTTP_PORTS,
        "dns_ports": DNS_PORTS,
        "name": NAME,
        "publication_barrier": args.publication_barrier,
        "ram_dns": args.ram,
        "ram_stale_policy": args.ram_stale_policy if args.ram else None,
    }
    try:
        metadata["git_head"] = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        metadata["git_head"] = "unknown"
    (results_dir / "commands.txt").write_text(
        command + "\n" + json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    processes: dict[str, subprocess.Popen] = {}
    log_handles: list[object] = []
    client = ClusterClient([node_url(n) for n in HTTP_PORTS])
    http = httpx.Client(timeout=3.0)
    resolvers = {
        node_id: Resolver(host, port, timeout=0.75)
        for node_id, (host, port) in dns_nodes().items()
    }
    baseline = QuorumResolver(
        dns_nodes(),
        required=2,
        freshness=False,
        node_keys={nid: key.public_key for nid, key in node_keys.items()},
        timeout=0.75,
    )
    ram: QuorumResolver | None = None
    if args.ram:
        ram = QuorumResolver(
            dns_nodes(),
            required=2,
            freshness=FreshnessPolicy(
                enabled=True,
                condition="F1",
                delta=0,
                watermark_source="responses",
                stale_policy=args.ram_stale_policy,
                retry_budget=2,
                retry_interval=0.05,
            ),
            node_keys={nid: key.public_key for nid, key in node_keys.items()},
            timeout=0.75,
        )
    records: list[dict] = []
    trials_path = results_dir / "trials.jsonl"

    try:
        print(f"data: {data_dir}")
        print("starting three registry nodes with DNS responders...")
        for node_id in HTTP_PORTS:
            process, handle = start_node(
                node_id, root_key, data_dir, logs_dir, node_key_files[node_id],
                publication_barrier=args.publication_barrier,
            )
            processes[node_id] = process
            log_handles.append(handle)
        wait_ready(client)
        leader_url = client.wait_for_leader(timeout=20.0)
        print(f"leader: {leader_url}")

        print("seeding namespace and record...")
        client.submit(crypto.sign_op(keys["root"], "delegate_namespace", {
            "name": "cs.test", "controller": keys["cs-admin"].public_key,
        }))
        client.submit(crypto.sign_op(keys["cs-admin"], "grant_member", {
            "namespace": "cs.test", "member": keys["alice"].public_key,
        }))
        client.submit(crypto.sign_op(keys["alice"], "register_domain", {
            "name": NAME, "records": {"A": OLD},
        }))

        converged, state = ensure_converged(
            http, node_apis(), resolvers, baseline, OLD, timeout=20.0
        )
        if not converged:
            raise SystemExit(
                "cluster did not converge after seeding; last state: "
                + json.dumps(state, indent=2)[:4000]
            )

        schedule: list[tuple[str, int, bool]] = []
        for _ in range(args.trials):
            schedule.append(("control", 0, False))
            for delay in hold_delays:
                schedule.append((f"hold-{delay}ms", delay, True))

        current = OLD
        print(f"running {len(schedule)} trials...")
        with open(trials_path, "w", encoding="utf-8", buffering=1) as trials_file:
            for index, (mode, delay_ms, use_hold) in enumerate(schedule, start=1):
                statuses = fetch_statuses(http, node_apis())
                leader = choose_leader(statuses)
                if leader is None:
                    raise SystemExit(f"no unique leader before trial {index}")
                followers = [nid for nid in HTTP_PORTS if nid != leader]

                converged, state = ensure_converged(
                    http, node_apis(), resolvers, baseline, current,
                    timeout=args.timeout,
                )
                if not converged:
                    raise SystemExit(
                        f"trial {index}: cluster did not converge to {current}; "
                        + json.dumps(state, indent=2)[:4000]
                    )

                target = NEW if current == OLD else OLD
                held: dict[str, dict] = {}
                if use_hold:
                    held = set_hold(http, node_apis(), followers, True)
                    if not all(item.get("ok") and item.get("commit_hold") for item in held.values()):
                        raise SystemExit(
                            f"trial {index}: could not hold {followers}: {held}"
                        )

                op = crypto.sign_op(keys["alice"], "update_records", {
                    "name": NAME, "records": {"A": target},
                })
                started = time.perf_counter()
                response = http.post(f"{node_url(leader)}/op", json=op)
                ack_time = time.perf_counter()
                try:
                    payload = response.json()
                except Exception:
                    payload = {"ok": False, "raw": response.text}
                acknowledged = (
                    response.status_code == 200 and payload.get("committed") is True
                )
                write_ack_ms = round((ack_time - started) * 1000.0, 2)

                if delay_ms:
                    time.sleep(delay_ms / 1000.0)
                observed = snapshot(
                    baseline, resolvers, http, node_apis(), NAME, ack_time, ram=ram
                )
                stale_nodes = [
                    node_id
                    for node_id, node in observed["nodes"].items()
                    if node["dns"].get("rcode") == 0
                    and node["dns"].get("answer") == current
                ]
                resolver_detail = observed["resolver"]
                baseline_stale = (
                    resolver_detail.get("ok") is True
                    and resolver_detail.get("answer") == current
                )
                ram_detail = observed.get("ram_dns") or {}
                ram_stale = (
                    ram_detail.get("ok") is True
                    and ram_detail.get("answer") == current
                )
                ram_servfail = ram_detail.get("rcode") == "SERVFAIL"
                failure = (
                    acknowledged and len(stale_nodes) >= 2 and baseline_stale
                )

                release: dict[str, dict] = {}
                release_ms = None
                if use_hold:
                    release_started = time.perf_counter()
                    release = set_hold(http, node_apis(), followers, False)
                    release_ms = round((time.perf_counter() - release_started) * 1000.0, 2)

                converged_after, after_state = ensure_converged(
                    http, node_apis(), resolvers, baseline, target,
                    timeout=args.timeout,
                )
                convergence_ms = (
                    round((time.perf_counter() - ack_time) * 1000.0, 2)
                    if converged_after else None
                )

                record = {
                    "trial": index,
                    "mode": mode,
                    "hold_delay_ms": delay_ms,
                    "use_hold": use_hold,
                    "leader": leader,
                    "held_nodes": followers if use_hold else [],
                    "name": NAME,
                    "old_address": current,
                    "new_address": target,
                    "acknowledged": acknowledged,
                    "write_ack_ms": write_ack_ms,
                    "submit_response": payload,
                    "snapshot": observed,
                    "stale_nodes": stale_nodes,
                    "baseline_stale": baseline_stale,
                    "ram_stale": ram_stale,
                    "ram_servfail": ram_servfail,
                    "failure_reproduced": failure,
                    "hold_release": release,
                    "hold_release_ms": release_ms,
                    "converged": converged_after,
                    "convergence_ms": convergence_ms,
                    "post_convergence": {
                        "leader_commit_index": after_state.get("leader_commit_index"),
                        "answers": {
                            nid: item.get("answer")
                            for nid, item in (after_state.get("direct") or {}).items()
                        },
                    },
                }
                records.append(record)
                trials_file.write(json.dumps(record, separators=(",", ":")) + "\n")

                node_bits = ", ".join(
                    f"{nid}=r{node['status'].get('revision')}/"
                    f"c{node['status'].get('commit_index')}/"
                    f"{node['dns'].get('answer')}"
                    for nid, node in observed["nodes"].items()
                )
                print(
                    f"  [{index:02d}] {mode:<11} ack={acknowledged} "
                    f"{write_ack_ms:6.1f}ms stale={','.join(stale_nodes) or '-':<7} "
                    f"A={resolver_detail.get('answer')} "
                    f"C={ram_detail.get('answer', '-')}/{ram_detail.get('reason', '-')} "
                    f"converged={'yes' if converged_after else 'NO'}"
                    f" ({convergence_ms if convergence_ms is not None else '-'}ms)"
                )
                print(f"       {node_bits}")

                if not acknowledged:
                    print(f"       submit failed: {payload}")
                current = target

        summary = aggregate(records)
        config = {
            "trials_per_condition": args.trials,
            "hold_delays_ms": hold_delays,
            "timeout_seconds": args.timeout,
            "name": NAME,
        }
        write_report(results_dir, records, summary, metadata, config)
        print("\n" + "=" * 78)
        for mode, item in summary.items():
            print(
                f"{mode:<12} trials={item['trials']:2d} "
                f"acked={item['acknowledged']:2d} "
                f"timeouts={item['not_acknowledged']:2d} "
                f"A_stale={item['failures_reproduced']:2d} "
                f"C_stale={item['ram_stale_answers']:2d} "
                f"C_servfail={item['ram_servfail']:2d} "
                f"ack_p50={item['write_ack_ms']['p50']}ms "
                f"A_p50={item['resolver_latency_ms']['p50']}ms "
                f"C_p50={item['ram_latency_ms']['p50']}ms "
                f"converge_p50={item['convergence_ms']['p50']}ms"
            )
        reproduced = any(r["failure_reproduced"] for r in records)
        if args.publication_barrier:
            print(
                "RESULT: "
                + (
                    "publication barrier FAILED (acknowledged write still stale)"
                    if reproduced
                    else "publication barrier held (no acknowledged stale majority)"
                )
            )
            exit_code = 2 if reproduced else 0
        else:
            print(
                "RESULT: "
                + (
                    "baseline stale-majority failure REPRODUCED"
                    if reproduced
                    else "baseline stale-majority failure NOT reproduced"
                )
            )
            exit_code = 0 if reproduced else 2
        print(f"raw trials: {trials_path}")
        print(f"report:     {results_dir / 'summary.md'}")
        print("=" * 78)
        return exit_code

    finally:
        baseline.stop()
        if ram is not None:
            ram.stop()
        http.close()
        client.close()
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
        for process in processes.values():
            try:
                process.wait(timeout=10)
            except Exception:
                process.kill()
        for handle in log_handles:
            try:
                handle.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
