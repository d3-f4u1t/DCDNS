"""Regression tests for the write-acknowledgement contract.

The original DCDNS bug: the leader acknowledged after a majority had *stored*
an entry, while followers applied it only on the next replication push. A
client that queried DNS immediately after a successful write could therefore
receive the old answer from a semantic majority.

These tests drive the real leader path (``_replicate`` -> ``_advance_commit``
-> ``_applied_majority``) against in-process followers, so they exercise the
ordering bug itself rather than a simplified stub. The barrier test is the
regression test the consistency audit asked for. The baseline test proves the
test is sensitive: with the barrier disabled, the acknowledgement really does
arrive while only the leader serves the new revision.
"""

from __future__ import annotations

import asyncio

from dcdns import crypto
from dcdns.cluster import ClusterNode

NAME = "techfest.cs.test"
OLD = "10.20.5.42"
NEW = "10.20.5.99"

NODE_IDS = ("n1", "n2", "n3")


class _Response:
    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.status_code = 200

    def json(self) -> dict:
        return self._payload


class InProcessPeers:
    """Minimal httpx-client stand-in that routes appends in-process.

    Only the methods used by ``ClusterNode._replicate`` are implemented. This
    keeps the test deterministic and socket-free while still going through the
    leader's real commit, apply and applied-majority logic.
    """

    def __init__(self, nodes: dict[str, ClusterNode], by_url: dict[str, str]) -> None:
        self._nodes = nodes
        self._by_url = by_url

    async def post(self, url: str, json: dict | None = None) -> _Response:
        base = url.split("/internal/", 1)[0]
        node = self._nodes[self._by_url[base]]
        return _Response(await node.handle_append(json or {}))

    async def get(self, url: str) -> _Response:  # pragma: no cover - not used here
        return _Response({"ok": True})


def _keys() -> dict[str, crypto.KeyPair]:
    return {
        "root": crypto.KeyPair.generate("Root", "root"),
        "cs": crypto.KeyPair.generate("CS", "department"),
        "alice": crypto.KeyPair.generate("Alice", "student"),
    }


def _seed_entries(keys: dict[str, crypto.KeyPair]) -> list[dict]:
    operations = [
        crypto.sign_op(keys["root"], "delegate_namespace", {
            "name": "cs.test", "controller": keys["cs"].public_key,
        }),
        crypto.sign_op(keys["cs"], "grant_member", {
            "namespace": "cs.test", "member": keys["alice"].public_key,
        }),
        crypto.sign_op(keys["alice"], "register_domain", {
            "name": NAME, "records": {"A": OLD},
        }),
    ]
    return [
        {"index": index, "term": 1, "op": op}
        for index, op in enumerate(operations, start=1)
    ]


async def _acknowledge_update(
    tmp_path,
    *,
    publication_barrier: bool | None,
) -> tuple[dict, dict[str, ClusterNode], dict]:
    keys = _keys()
    nodes: dict[str, ClusterNode] = {}
    by_url: dict[str, str] = {}

    for node_id in NODE_IDS:
        url = f"http://127.0.0.1/{node_id}"
        by_url[url] = node_id
        peers = {
            pid: f"http://127.0.0.1/{pid}"
            for pid in NODE_IDS
            if pid != node_id
        }
        kwargs = {} if publication_barrier is None else {
            "publication_barrier": publication_barrier
        }
        nodes[node_id] = ClusterNode(
            node_id=node_id,
            url=url,
            peers=peers,
            data_dir=tmp_path / node_id,
            root_public=keys["root"].public_key,
            **kwargs,
        )

    seed = _seed_entries(keys)
    for node in nodes.values():
        await node.handle_append({
            "term": 1,
            "leader_id": "n1",
            "leader_url": nodes["n1"].url,
            "entries": seed,
            "commit_index": 3,
        })
        assert node.dns_zone == {NAME: OLD}

    leader = nodes["n1"]
    leader.live_peers = {"n2", "n3"}
    leader._client = InProcessPeers(nodes, by_url)

    update = crypto.sign_op(keys["alice"], "update_records", {
        "name": NAME, "records": {"A": NEW},
    })
    result = await leader.submit(update)
    return result, nodes, {"n1": leader}


def test_acknowledgement_implies_a_majority_serves_the_new_revision(tmp_path):
    """The audit's regression test: success must mean publishable to a majority.

    The barrier is the default, so this test omits the argument deliberately.
    """
    result, nodes, _ = asyncio.run(_acknowledge_update(
        tmp_path, publication_barrier=None,
    ))

    assert result["ok"] is True
    assert result["committed"] is True
    assert result["publication"] == "barrier"

    serving_new = [
        node_id
        for node_id, node in nodes.items()
        if node.dns_zone.get(NAME) == NEW
    ]
    assert len(serving_new) >= 2, (
        "acknowledged write was not visible at a majority of DNS responders: "
        f"{serving_new!r}"
    )

    revision = int(result["revision"])
    assert sum(1 for node in nodes.values() if node.dns_revision >= revision) >= 2


def test_baseline_acknowledges_before_a_majority_publishes(tmp_path):
    """Documents the bug and proves the regression test can detect it.

    With B disabled, the leader returns success after the entry is stored by a
    majority but applied only by the leader. Only one of three responders
    serves the new answer at acknowledgement time.
    """
    result, nodes, _ = asyncio.run(_acknowledge_update(
        tmp_path, publication_barrier=False,
    ))

    assert result["ok"] is True
    assert result["publication"] == "commit"

    serving_new = [
        node_id
        for node_id, node in nodes.items()
        if node.dns_zone.get(NAME) == NEW
    ]
    assert serving_new == ["n1"], (
        "the A baseline must acknowledge before followers apply the entry; "
        f"got {serving_new!r}"
    )
