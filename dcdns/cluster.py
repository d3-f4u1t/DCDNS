"""Quorum-replicated registry state.

What this is
------------
A leader-based replicated log with majority commit, automatic leader takeover
and follower catch-up. It is *not* Raft: there is no vote protocol and no log
truncation, because the design removes the need for both.

Why the simplification is safe
------------------------------
1. Only the node with the lowest id among the *reachable majority* may act as
   leader. Any two majorities of a 3-node cluster intersect, and "lowest id" is
   a deterministic function of the live set, so two nodes cannot both satisfy
   the rule while both hold a majority.  -> single writer per term.
2. Followers never originate log entries. With a single writer, every node's
   log is always a *prefix* of the leader's log. -> no conflicting entries, so
   no truncation is ever required.
3. A write is acknowledged only after a majority has durably stored it.
   -> committed entries survive the loss of any single node.

Known limitations (documented, not hidden)
------------------------------------------
* No vote protocol: a node that is partitioned away and later returns adopts
  the longer log rather than negotiating. Safe under (1) and (2), but not
  Byzantine-fault tolerant.
* A write that times out after partial replication may still commit later; the
  API reports ``ambiguous: true`` in that case instead of pretending it failed.
* Membership is static: the peer set comes from configuration.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import httpx

from .errors import NoQuorum, NotLeader, RegistryError
from .state import RegistryState


class ClusterNode:
    def __init__(
        self,
        node_id: str,
        url: str,
        peers: dict[str, str],
        data_dir: str | Path,
        root_public: str,
        heartbeat_interval: float = 0.25,
        write_timeout: float = 2.5,
        request_timeout: float = 0.6,
        publication_barrier: bool = False,
    ) -> None:
        self.id = node_id
        self.url = url
        self.peers = dict(peers)  # excludes self
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.heartbeat_interval = heartbeat_interval
        self.write_timeout = write_timeout
        self.request_timeout = request_timeout

        # Variant B: acknowledge a write only after a majority has applied the
        # committed entry to the state used for DNS answers. Off by default so
        # the original baseline remains available for comparison.
        self.publication_barrier = publication_barrier
        self.peer_commit: dict[str, int] = {peer: 0 for peer in self.peers}
        self.peer_dns_revision: dict[str, int] = {peer: 0 for peer in self.peers}

        self.state = RegistryState(root_public=root_public)
        self.log: list[dict] = []
        self.term: int = 0
        self.commit_index: int = 0
        self.leader_id: str | None = None

        # Every node is also a DNS authority. This is a flattened, immutable
        # snapshot of the *committed* state; the DNS responder thread reads it
        # without taking the event loop's locks. ``dns_snapshot`` binds the zone
        # and revision in one atomic tuple so a responder can never publish a
        # zone and a revision from different commits.
        self.dns_zone: dict[str, str] = {}
        self.dns_revision: int = 0
        self.dns_snapshot: tuple[dict[str, str], int] = ({}, 0)
        self.dns_port: int | None = None

        self.live_peers: set[str] = set()
        self.peer_last: dict[str, int] = {p: 0 for p in self.peers}
        self.last_leader_contact: float = 0.0

        self._lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._running = False
        self._client: httpx.AsyncClient | None = None

        self.accepted: int = 0
        self.rejected: int = 0
        self.last_error: str | None = None

        # Deterministic fault injection for the commit-lag experiment. While
        # held, a follower still stores replicated entries and reports their
        # presence, but refuses to advance ``commit_index`` or apply them to
        # ``state``/``dns_snapshot``. Releasing applies the highest commit
        # index the leader has announced in the meantime.
        self.commit_hold: bool = False
        self.pending_commit_index: int = 0

        self._load()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    @property
    def _log_path(self) -> Path:
        return self.data_dir / "log.jsonl"

    @property
    def _meta_path(self) -> Path:
        return self.data_dir / "meta.json"

    def _load(self) -> None:
        if self._meta_path.exists():
            try:
                meta = json.loads(self._meta_path.read_text("utf-8"))
                self.term = meta.get("term", 0)
                self.commit_index = meta.get("commit_index", 0)
            except Exception:
                self.term, self.commit_index = 0, 0

        if self._log_path.exists():
            for line in self._log_path.read_text("utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.log.append(json.loads(line))
                except Exception:
                    continue

        # Rebuild the state machine from the committed prefix of the log.
        for entry in self.log[: self.commit_index]:
            try:
                self.state.apply(entry["op"])
            except RegistryError as exc:  # pragma: no cover - corruption guard
                self.last_error = f"replay failed at index {entry['index']}: {exc.code}"

        self._refresh_dns_zone()

    def _refresh_dns_zone(self) -> None:
        """Rebuild the per-node DNS view from committed state.

        The responder thread only ever reads ``dns_snapshot``. Replacing the
        tuple atomically (rather than mutating it) means a query can never
        observe a zone and a revision from different commits. The separate
        ``dns_zone`` / ``dns_revision`` attributes are kept for status output.
        """
        zone: dict[str, str] = {}
        for name, records in self.state.snapshot_for_dns().items():
            address = records.get("A")
            if address:
                zone[name] = address
        revision = self.state.revision
        self.dns_snapshot = (zone, revision)
        self.dns_zone = zone
        self.dns_revision = revision

    def _persist_meta(self) -> None:
        tmp = self._meta_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {"term": self.term, "commit_index": self.commit_index},
                indent=2,
            ),
            "utf-8",
        )
        os.replace(tmp, self._meta_path)

    def _persist_entry(self, entry: dict) -> None:
        with open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    # ------------------------------------------------------------------ #
    # topology helpers
    # ------------------------------------------------------------------ #
    @property
    def total_nodes(self) -> int:
        return len(self.peers) + 1

    @property
    def quorum(self) -> int:
        return self.total_nodes // 2 + 1

    def _reachable(self) -> set[str]:
        return set(self.live_peers) | {self.id}

    def has_quorum(self) -> bool:
        return len(self._reachable()) >= self.quorum

    def expected_leader(self) -> str | None:
        """Deterministic: lowest id in the reachable set, if a majority is up."""
        if not self.has_quorum():
            return None
        return min(self._reachable())

    def role(self) -> str:
        if not self.has_quorum():
            return "isolated"
        return "leader" if self.expected_leader() == self.id else "follower"

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        self._running = True
        self._client = httpx.AsyncClient(timeout=self.request_timeout)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._client:
            await self._client.aclose()

    async def _run(self) -> None:
        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the loop alive
                self.last_error = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(self.heartbeat_interval)

    async def _tick(self) -> None:
        await self._probe_peers()
        expected = self.expected_leader()

        if expected is None:
            self.leader_id = None
            return

        if expected == self.id:
            if self.leader_id != self.id:
                await self._assume_leadership()
            await self._replicate()
        else:
            self.leader_id = expected

    async def _probe_peers(self) -> None:
        if not self._client:
            return
        async def ping(peer_id: str, url: str) -> None:
            try:
                resp = await self._client.get(f"{url}/internal/ping")
                if resp.status_code == 200:
                    self.live_peers.add(peer_id)
                else:
                    self.live_peers.discard(peer_id)
            except Exception:
                self.live_peers.discard(peer_id)

        await asyncio.gather(
            *(ping(pid, url) for pid, url in self.peers.items())
        )

    async def _assume_leadership(self) -> None:
        self.term += 1
        self.leader_id = self.id
        self.last_leader_contact = time.monotonic()
        self._persist_meta()
        await self._adopt_longest_log()

    async def _adopt_longest_log(self) -> None:
        """Pull entries from any peer whose log is longer.

        Safe because logs are always prefixes of one another: appending the
        missing tail can never overwrite committed history.
        """
        if not self._client:
            return
        for peer_id, url in self.peers.items():
            if peer_id not in self.live_peers:
                continue
            try:
                info = (await self._client.get(f"{url}/internal/log_info")).json()
                peer_last = int(info.get("last_index", 0))
                if peer_last > len(self.log):
                    resp = await self._client.get(
                        f"{url}/internal/log", params={"from": len(self.log) + 1}
                    )
                    for entry in resp.json().get("entries", []):
                        if entry["index"] == len(self.log) + 1:
                            self.log.append(entry)
                            self._persist_entry(entry)
            except Exception:
                continue
        self._apply_committed()

    # ------------------------------------------------------------------ #
    # replication
    # ------------------------------------------------------------------ #
    async def _replicate(self) -> None:
        if not self._client:
            return
        commit = self.commit_index
        async def push(peer_id: str, url: str) -> None:
            if peer_id not in self.live_peers:
                return
            start = self.peer_last.get(peer_id, 0) + 1
            entries = self.log[start - 1:][:64]
            payload = {
                "term": self.term,
                "leader_id": self.id,
                "leader_url": self.url,
                "entries": entries,
                "commit_index": commit,
            }
            try:
                resp = await self._client.post(f"{url}/internal/append", json=payload)
                data = resp.json()
                if data.get("ok"):
                    self.peer_last[peer_id] = int(data.get("last_index", start - 1))
                    self.peer_commit[peer_id] = int(data.get("commit_index", 0))
                    self.peer_dns_revision[peer_id] = int(
                        data.get("dns_revision", 0)
                    )
                elif data.get("term", 0) > self.term:
                    self.term = int(data["term"])
                    self.leader_id = None
            except Exception:
                pass

        await asyncio.gather(*(push(pid, url) for pid, url in self.peers.items()))
        self._advance_commit()

    def _advance_commit(self) -> None:
        if self.expected_leader() != self.id:
            return
        advanced = False
        while self.commit_index < len(self.log):
            candidate = self.commit_index + 1
            stored = 1 + sum(
                1 for peer, last in self.peer_last.items()
                if peer in self.live_peers and last >= candidate
            )
            if stored < self.quorum:
                break
            self.commit_index = candidate
            advanced = True
        if advanced:
            self._persist_meta()
            self._apply_committed()

    def _apply_committed(self) -> None:
        changed = False
        while self.state.revision < self.commit_index:
            entry = self.log[self.state.revision]
            result = self.state.apply(entry["op"])
            self.accepted += 1
            changed = True
            _ = result
        if changed or self.dns_revision != self.state.revision:
            self._refresh_dns_zone()

    def _applied_majority(self, index: int) -> bool:
        """True when a majority has applied ``index`` to its DNS snapshot.

        The leader counts itself only after ``_refresh_dns_zone`` has exposed
        the applied revision. Followers report their own ``dns_revision`` in
        the append response, which is sent after they have applied the commit.
        This is a non-Byzantine check: a lying follower could claim a revision
        it does not have. The point is to close the ordinary acknowledgement
        window, not to tolerate arbitrary faulty nodes.
        """
        if self.dns_revision < index:
            return False
        applied = 1
        for peer in self.live_peers:
            if self.peer_dns_revision.get(peer, 0) >= index:
                applied += 1
        return applied >= self.quorum

    # ------------------------------------------------------------------ #
    # write path
    # ------------------------------------------------------------------ #
    async def submit(self, op: dict) -> dict:
        async with self._write_lock:
            if not self.has_quorum():
                self.rejected += 1
                raise NoQuorum("no majority of registry nodes is reachable")

            if self.expected_leader() != self.id:
                self.rejected += 1
                raise NotLeader(self.leader_id, self.peers.get(self.leader_id or ""))

            # Validate deterministically before touching the log. This means an
            # invalid operation never consumes a log slot on any node.
            try:
                preview = self.state.probe(op)
            except RegistryError:
                self.rejected += 1
                raise

            async with self._lock:
                index = len(self.log) + 1
                entry = {"index": index, "term": self.term, "op": op}
                self.log.append(entry)
                self._persist_entry(entry)

            deadline = time.monotonic() + self.write_timeout
            while time.monotonic() < deadline:
                await self._replicate()
                if self.commit_index >= index:
                    if (
                        not self.publication_barrier
                        or self._applied_majority(index)
                    ):
                        return self._write_result(index, preview)
                    # The entry is committed, but followers learned the previous
                    # commit index in the push above. Push the new commit index
                    # and require a majority of applied DNS snapshots before
                    # acknowledging.
                    await self._replicate()
                    if self._applied_majority(index):
                        return self._write_result(index, preview)
                await asyncio.sleep(0.02)

            if self.commit_index >= index:
                raise NoQuorum(
                    "operation committed, but a majority did not apply it to "
                    "the DNS state before the deadline; it may become visible "
                    "later (ambiguous write)",
                    ambiguous=True,
                )
            raise NoQuorum(
                "operation was appended to the leader log but did not reach a "
                "majority in time; it may still commit later (ambiguous write)",
                ambiguous=True,
            )

    def _write_result(self, index: int, preview: dict) -> dict:
        return {
            "ok": True,
            "committed": True,
            "index": index,
            "revision": preview["revision"],
            "op": preview["op"],
            "target": preview["target"],
            "detail": preview["detail"],
            "term": self.term,
        }

    # ------------------------------------------------------------------ #
    # follower RPC handlers
    # ------------------------------------------------------------------ #
    async def handle_append(self, payload: dict) -> dict:
        term = int(payload.get("term", 0))
        if term < self.term:
            return {"ok": False, "term": self.term, "last_index": len(self.log)}

        self.term = term
        self.leader_id = payload.get("leader_id")
        self.last_leader_contact = time.monotonic()

        async with self._lock:
            for entry in payload.get("entries", []):
                if entry["index"] == len(self.log) + 1:
                    self.log.append(entry)
                    self._persist_entry(entry)

            incoming_commit = min(int(payload.get("commit_index", 0)), len(self.log))
            if incoming_commit > self.commit_index:
                if self.commit_hold:
                    # Store the fact that the leader has committed further, but
                    # do not expose it to readers or the DNS responder yet.
                    self.pending_commit_index = max(
                        self.pending_commit_index, incoming_commit
                    )
                else:
                    self.commit_index = incoming_commit
                    self._persist_meta()
                    self._apply_committed()

        return {
            "ok": True,
            "term": self.term,
            "last_index": len(self.log),
            "commit_index": self.commit_index,
            "pending_commit_index": self.pending_commit_index,
            "commit_hold": self.commit_hold,
            "revision": self.state.revision,
            "dns_revision": self.dns_revision,
        }

    async def set_commit_hold(self, held: bool) -> dict:
        """Enable or release deterministic commit-application lag.

        This is fault injection, not part of normal replication. A held node
        keeps receiving and durably storing entries, so the leader can still
        count it toward a majority; it simply does not advance its committed
        state or DNS snapshot. Releasing applies every commit the leader
        announced while the hold was active.
        """
        async with self._lock:
            if held:
                self.commit_hold = True
                self.pending_commit_index = max(
                    self.pending_commit_index, self.commit_index
                )
            else:
                self.commit_hold = False
                pending = min(self.pending_commit_index, len(self.log))
                if pending > self.commit_index:
                    self.commit_index = pending
                    self._persist_meta()
                    self._apply_committed()
                self.pending_commit_index = self.commit_index
        return self.replication_status()

    def replication_status(self) -> dict:
        return {
            "commit_index": self.commit_index,
            "pending_commit_index": self.pending_commit_index,
            "commit_hold": self.commit_hold,
            "applied_revision": self.state.revision,
            "dns_revision": self.dns_revision,
            "log_length": len(self.log),
        }

    # ------------------------------------------------------------------ #
    # introspection
    # ------------------------------------------------------------------ #
    def status(self) -> dict:
        return {
            "node_id": self.id,
            "url": self.url,
            "role": self.role(),
            "term": self.term,
            "leader_id": self.leader_id,
            "commit_index": self.commit_index,
            "pending_commit_index": self.pending_commit_index,
            "commit_hold": self.commit_hold,
            "publication_barrier": self.publication_barrier,
            "peer_commit": dict(self.peer_commit),
            "peer_dns_revision": dict(self.peer_dns_revision),
            "revision": self.state.revision,
            "log_length": len(self.log),
            "peers": sorted(self.peers),
            "reachable": sorted(self._reachable()),
            "live_peers": sorted(self.live_peers),
            "quorum": self.quorum,
            "has_quorum": self.has_quorum(),
            "accepted": self.accepted,
            "rejected": self.rejected,
            "last_error": self.last_error,
            "domain_count": len(self.state.domains),
            "namespace_count": len(self.state.namespaces),
            "dns_port": self.dns_port,
            "dns_revision": self.dns_revision,
            "zone_size": len(self.dns_zone),
        }
