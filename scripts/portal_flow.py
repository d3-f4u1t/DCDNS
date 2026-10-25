"""End-to-end check of the portal's write paths.

Drives the same HTTP forms a user clicks, then verifies the registry and DNS
state. Run against a live demo:

    python scripts/portal_flow.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dcdns.client import ClusterClient  # noqa: E402
from dcdns.experiments import Resolver  # noqa: E402

PORTAL = "http://127.0.0.1:8000"
NODES = ["http://127.0.0.1:9101", "http://127.0.0.1:9102", "http://127.0.0.1:9103"]

checks: list[tuple[bool, str]] = []


def check(condition: bool, description: str) -> None:
    checks.append((bool(condition), description))
    print(f"{'[PASS]' if condition else '[FAIL]'} {description}")


def main() -> int:
    index = json.loads((ROOT / "identities" / "index.json").read_text("utf-8"))
    bob = next(item for item in index if item["name"] == "bob")
    alice = next(item for item in index if item["name"] == "alice")

    client = ClusterClient(NODES)
    resolver = Resolver("127.0.0.1", 5353)
    name = f"flowtest-{int(time.time()) % 100000}.cs.test"

    with httpx.Client(base_url=PORTAL, follow_redirects=False, timeout=10.0) as http:
        http.cookies.set("dcdns_identity", "alice")

        response = http.get("/")
        check(response.status_code == 200, "dashboard renders")

        response = http.post(
            "/domains/register",
            data={"name": name, "address": "10.20.5.60"},
        )
        check(response.status_code == 303 and "err=" not in response.headers.get("location", ""),
              f"portal registered {name}")

        response = http.get(f"/domains/{name}")
        check(response.status_code == 200 and name in response.text,
              "domain page renders the new name")

        deadline = time.monotonic() + 8
        answer = None
        while time.monotonic() < deadline:
            rcode, candidate = resolver.query(name)
            if rcode == 0 and candidate == "10.20.5.60":
                answer = candidate
                break
            time.sleep(0.1)
        check(answer == "10.20.5.60", "new name resolves in DNS")

        response = http.post(f"/domains/{name}/records", data={"address": "10.20.5.61"})
        check(response.status_code == 303, "record update accepted")

        elapsed = resolver.wait_for(name, "10.20.5.61", timeout=8)
        check(elapsed is not None, f"updated address propagated in {elapsed:.2f}s"
              if elapsed is not None else "updated address did not propagate")

        response = http.post(f"/domains/{name}/transfer",
                             data={"new_owner": bob["public_key"]})
        check(response.status_code == 303, "transfer initiated")

        detail = client.get(f"/domains/{name}")["domain"]
        check(detail["status"] == "pending_transfer", "domain is pending transfer")

        response = http.post(f"/domains/{name}/records", data={"address": "10.20.5.99"})
        location = response.headers.get("location", "")
        check("TRANSFER_PENDING" in location or "err=" in location,
              "records are frozen during transfer")

        http.cookies.set("dcdns_identity", "bob")
        response = http.post(f"/domains/{name}/transfer/accept")
        check(response.status_code == 303, "recipient accepted transfer")

        detail = client.get(f"/domains/{name}")["domain"]
        check(detail["owner"] == bob["public_key"], "ownership moved to Bob")

        http.cookies.set("dcdns_identity", "alice")
        response = http.post(f"/domains/{name}/revoke", data={"reason": "flow test"})
        location = response.headers.get("location", "")
        check("UNAUTHORIZED" in location,
              "previous owner can no longer revoke after transferring")

        http.cookies.set("dcdns_identity", "bob")
        response = http.post(f"/domains/{name}/revoke", data={"reason": "flow test"})
        location = response.headers.get("location", "")
        check(response.status_code == 303 and "err=" not in location,
              "new owner revokes successfully")

        elapsed = resolver.wait_for_nxdomain(name, timeout=8)
        check(elapsed is not None,
              f"revoked name withdrawn from DNS in {elapsed:.2f}s"
              if elapsed is not None else "revoked name still resolves")

    passed = sum(1 for ok, _ in checks if ok)
    print(f"\n{passed}/{len(checks)} portal flow checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
