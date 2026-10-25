"""Start the whole DCDNS prototype with one command.

    python run_demo.py            # start (or reuse existing identities)
    python run_demo.py --fresh    # wipe data/ and start from a clean registry
    python run_demo.py --no-portal

Starts:
  * three registry nodes on 9101-9103
  * an authoritative DNS responder inside every registry node
    (UDP 5354-5356)
  * a client-facing quorum resolver on UDP 5353 that requires a majority of
    the nodes to agree before answering
  * the demonstration portal on http://127.0.0.1:8000

A supervisor restarts any child that dies, and restarts the portal if it stops
answering, so a live demonstration survives an unexpected crash.

Press Ctrl+C to stop everything.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dcdns import crypto  # noqa: E402
from dcdns.bootstrap import create_identities  # noqa: E402
from dcdns.client import ClusterClient, ClusterError  # noqa: E402

NODE_PORTS = {"n1": 9101, "n2": 9102, "n3": 9103}
DNS_PORTS = {"n1": 5354, "n2": 5355, "n3": 5356}
DATA = ROOT / "data" / "live"
LOGS = DATA / "logs"
IDENTITIES = ROOT / "identities"

DNS_PORT = 5353
DNS_METRICS_PORT = 5380
PORTAL_PORT = 8000


def node_url(node_id: str) -> str:
    return f"http://127.0.0.1:{NODE_PORTS[node_id]}"


def start_node(
    node_id: str,
    root_key: str,
    log_dir: Path,
    dns_port: int | None = None,
    chaos: bool = False,
) -> subprocess.Popen:
    peers = ",".join(
        f"{pid}=http://127.0.0.1:{port}"
        for pid, port in NODE_PORTS.items()
        if pid != node_id
    )
    log = open(log_dir / f"{node_id}.log", "a", encoding="utf-8")
    command = [
        sys.executable, "-m", "dcdns.node",
        "--id", node_id,
        "--port", str(NODE_PORTS[node_id]),
        "--peers", peers,
        "--data", str(DATA / node_id),
        "--root", root_key,
    ]
    if dns_port:
        command += ["--dns-port", str(dns_port)]
    if chaos:
        command.append("--chaos")
    return subprocess.Popen(
        command,
        cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
    )


def wait_until(description: str, predicate, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    sys.stdout.write(f"  waiting for {description} ")
    sys.stdout.flush()
    while time.monotonic() < deadline:
        try:
            if predicate():
                print("ok")
                return
        except Exception:
            pass
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.3)
    print("TIMEOUT")
    raise SystemExit(f"timed out waiting for {description}")


def seed(client: ClusterClient, keys: dict[str, crypto.KeyPair]) -> None:
    """Idempotently create the demo campus. Safe to run on every start."""
    existing = {ns["name"] for ns in client.get("/namespaces").get("namespaces", [])}

    def op(signer: str, operation: str, body: dict) -> None:
        try:
            client.submit(crypto.sign_op(keys[signer], operation, body))
            print(f"  + {operation:<20} {body.get('name', body.get('namespace', ''))}")
        except ClusterError as exc:
            if exc.code in {"NAMESPACE_TAKEN", "NAME_TAKEN"}:
                return
            raise

    if "cs.test" not in existing:
        op("root", "delegate_namespace",
           {"name": "cs.test", "controller": keys["cs-admin"].public_key})
    if "library.test" not in existing:
        op("root", "delegate_namespace",
           {"name": "library.test", "controller": keys["library-admin"].public_key})

    op("cs-admin", "grant_member",
       {"namespace": "cs.test", "member": keys["alice"].public_key})

    if "team.cs.test" not in existing:
        op("cs-admin", "delegate_namespace",
           {"name": "team.cs.test", "controller": keys["bob"].public_key})

    domains = {
        "techfest.cs.test": ("alice", "10.20.5.42"),
        "robotics.cs.test": ("alice", "10.20.5.43"),
        "project.team.cs.test": ("bob", "10.20.5.77"),
        "catalog.library.test": ("library-admin", "10.20.6.10"),
    }
    for name, (signer, address) in domains.items():
        try:
            client.get(f"/domains/{name}")
            continue
        except ClusterError:
            pass
        op(signer, "register_domain", {"name": name, "records": {"A": address}})


def _http_ok(url: str) -> bool:
    import httpx

    try:
        with httpx.Client(timeout=1.5) as http:
            return http.get(url).status_code == 200
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fresh", action="store_true", help="delete data/live and start clean")
    parser.add_argument("--no-portal", action="store_true")
    parser.add_argument("--no-dns", action="store_true")
    parser.add_argument("--no-supervisor", action="store_true",
                        help="do not restart crashed children (useful for failure demos)")
    args = parser.parse_args()

    if args.fresh and DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    print("\n=== DCDNS :: decentralized campus domain registry ===\n")
    keys = create_identities(str(IDENTITIES))
    root_key = keys["root"].public_key

    node_urls = ",".join(node_url(n) for n in NODE_PORTS)

    def launch_quorum_dns() -> subprocess.Popen:
        log = open(LOGS / "quorum.log", "a", encoding="utf-8")
        dns_nodes = ",".join(
            f"{node_id}=127.0.0.1:{DNS_PORTS[node_id]}" for node_id in NODE_PORTS
        )
        api_nodes = ",".join(
            f"{node_id}={node_url(node_id)}" for node_id in NODE_PORTS
        )
        return subprocess.Popen(
            [
                sys.executable, "-m", "dcdns.quorum_resolver",
                "--port", str(DNS_PORT),
                "--metrics-port", str(DNS_METRICS_PORT),
                "--nodes", dns_nodes,
                "--api-nodes", api_nodes,
            ],
            cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
        )

    def launch_portal() -> subprocess.Popen:
        log = open(LOGS / "portal.log", "a", encoding="utf-8")
        return subprocess.Popen(
            [
                sys.executable, "-m", "dcdns.portal",
                "--port", str(PORTAL_PORT),
                "--nodes", node_urls,
                "--dns-port", str(DNS_PORT),
                "--dns-metrics", f"http://127.0.0.1:{DNS_METRICS_PORT}",
                "--identities", str(IDENTITIES),
            ],
            cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
        )

    launchers = {
        node_id: (
            lambda nid=node_id: start_node(
                nid,
                root_key,
                LOGS,
                dns_port=None if args.no_dns else DNS_PORTS[nid],
                chaos=not args.no_dns,
            )
        )
        for node_id in NODE_PORTS
    }
    if not args.no_dns:
        launchers["quorum"] = launch_quorum_dns
    if not args.no_portal:
        launchers["portal"] = launch_portal

    processes: dict[str, subprocess.Popen] = {}
    client = ClusterClient([node_url(n) for n in NODE_PORTS])

    try:
        print("starting registry nodes (each one is also an authoritative DNS server)")
        for node_id in NODE_PORTS:
            processes[node_id] = start_node(
                node_id,
                root_key,
                LOGS,
                dns_port=None if args.no_dns else DNS_PORTS[node_id],
                chaos=not args.no_dns,
            )
            dns_note = (
                f"  dns udp/{DNS_PORTS[node_id]}" if not args.no_dns else ""
            )
            print(f"  {node_id} -> {node_url(node_id)}{dns_note}")

        wait_until("a leader to be elected", lambda: client.leader_url() is not None, 40)

        print("\nseeding campus registry")
        seed(client, keys)

        if not args.no_dns:
            print("\nstarting quorum DNS resolver")
            processes["quorum"] = launch_quorum_dns()
            print(f"  client-facing udp://127.0.0.1:{DNS_PORT} "
                  f"(majority of {len(NODE_PORTS)} nodes must agree)")
            print(f"  metrics http://127.0.0.1:{DNS_METRICS_PORT}/metrics")

        if not args.no_portal:
            print("\nstarting portal")
            processes["portal"] = launch_portal()
            wait_until("the portal",
                       lambda: _http_ok(f"http://127.0.0.1:{PORTAL_PORT}/health"), 40)

        print("\n" + "=" * 66)
        print("  READY")
        print("=" * 66)
        print(f"  Portal      http://127.0.0.1:{PORTAL_PORT}")
        print(f"  DNS         udp://127.0.0.1:{DNS_PORT}  (quorum resolver)")
        print(f"  Node DNS    " + "  ".join(
            f"{n}=udp/{DNS_PORTS[n]}" for n in NODE_PORTS
        ))
        print(f"  Metrics     http://127.0.0.1:{DNS_METRICS_PORT}/metrics")
        print(f"  Node APIs   {', '.join(node_url(n) for n in NODE_PORTS)}")
        print("")
        print("  Try:  python -m dcdns.dig techfest.cs.test --all")
        print("        python -m dcdns.dig techfest.cs.test --port 5354   (node n1 only)")
        print("        python -m dcdns.dig catalog.library.test")
        print("")
        print("  Press Ctrl+C to stop.")
        print("=" * 66 + "\n")

        portal_down_since: float | None = None
        while True:
            time.sleep(2)
            for name, launcher in launchers.items():
                proc = processes.get(name)
                if proc is not None and proc.poll() is None:
                    continue
                if args.no_supervisor:
                    continue
                print(f"!! {name} is not running (exit {proc.returncode if proc else '?'}); restarting")
                time.sleep(0.5)
                processes[name] = launcher()

            # Restart the portal if it is alive but has stopped answering.
            if "portal" in processes and not args.no_supervisor:
                healthy = _http_ok(f"http://127.0.0.1:{PORTAL_PORT}/health")
                if healthy:
                    portal_down_since = None
                else:
                    portal_down_since = portal_down_since or time.monotonic()
                    if time.monotonic() - portal_down_since > 8:
                        print("!! portal stopped answering; restarting")
                        try:
                            processes["portal"].terminate()
                            processes["portal"].wait(timeout=5)
                        except Exception:
                            processes["portal"].kill()
                        processes["portal"] = launch_portal()
                        portal_down_since = None

    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        for proc in processes.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
        print("stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
