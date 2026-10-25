"""Small HTTP client used by tests, the demo script and the portal."""

from __future__ import annotations

import time
from typing import Any, Iterable

import httpx


class ClusterError(RuntimeError):
    def __init__(self, message: str, code: str = "CLUSTER_ERROR"):
        super().__init__(message)
        self.code = code


class ClusterClient:
    def __init__(self, urls: Iterable[str], timeout: float = 5.0) -> None:
        self.urls = list(urls)
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    def statuses(self) -> list[dict]:
        results = []
        for url in self.urls:
            try:
                with httpx.Client(timeout=1.0) as client:
                    resp = client.get(f"{url}/status")
                if resp.status_code == 200:
                    results.append(resp.json())
                else:
                    results.append({"ok": False, "url": url, "error": f"HTTP {resp.status_code}"})
            except Exception as exc:
                results.append({"ok": False, "url": url, "error": str(exc)})
        return results

    def leader_url(self) -> str | None:
        for status in self.statuses():
            if status.get("ok") and status.get("role") == "leader":
                return status.get("url")
        return None

    def wait_for_leader(self, timeout: float = 15.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            url = self.leader_url()
            if url:
                return url
            time.sleep(0.2)
        raise ClusterError("no leader was elected within the timeout", "NO_LEADER")

    # ------------------------------------------------------------------ #
    def submit(self, op: dict) -> dict:
        """Submit a signed operation, tolerating leader changes."""
        last_error: dict | None = None
        for _ in range(3):
            for url in self.urls:
                try:
                    with httpx.Client(timeout=self.timeout) as client:
                        resp = client.post(f"{url}/op", json=op)
                    payload = resp.json()
                    if resp.status_code == 200:
                        return payload
                    last_error = payload
                    code = payload.get("error", {}).get("code", "")
                    if code in {"NOT_LEADER", "NO_QUORUM"}:
                        time.sleep(0.15)
                        continue
                    raise ClusterError(
                        f"{code}: {payload.get('error', {}).get('message', '')}", code
                    )
                except httpx.HTTPError as exc:
                    last_error = {"error": {"code": "TRANSPORT", "message": str(exc)}}
                    continue
            time.sleep(0.2)
        code = (last_error or {}).get("error", {}).get("code", "NO_QUORUM")
        message = (last_error or {}).get("error", {}).get("message", "request failed")
        raise ClusterError(message, code)

    def get(self, path: str, **params: Any) -> dict:
        last: Exception | None = None
        for url in self.urls:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(f"{url}{path}", params=params)
                if resp.status_code == 200:
                    return resp.json()
                last = ClusterError(f"HTTP {resp.status_code}", f"HTTP_{resp.status_code}")
            except httpx.HTTPError as exc:
                last = exc
        raise ClusterError(str(last or "no node reachable"))

    def consistent_state(self) -> dict:
        """Return the most advanced committed snapshot across all reachable nodes."""
        best: dict | None = None
        for url in self.urls:
            try:
                with httpx.Client(timeout=2.0) as client:
                    resp = client.get(f"{url}/internal/state")
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if best is None or data.get("revision", 0) > best.get("revision", 0):
                    best = data
                    best["_source"] = url
            except httpx.HTTPError:
                continue
        if best is None:
            raise ClusterError("no registry node is reachable", "NO_NODES")
        return best
