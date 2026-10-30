"""Tests for deterministic commit-application lag.

The commit-hold fault is what turns the real replication window (the leader
acknowledges after a majority has *stored* an entry, while followers learn the
new commit index on a later push) into a repeatable experiment. These tests
verify that a held follower keeps storing entries and acknowledging them, but
does not expose them through ``state`` or the DNS snapshot until released.
"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from dcdns import crypto
from dcdns.cluster import ClusterNode
from dcdns.errors import NoQuorum
from dcdns.node import create_app

NAME = "techfest.cs.test"
OLD = "10.20.5.42"
NEW = "10.20.5.99"


def _keys() -> dict[str, crypto.KeyPair]:
    return {
        "root": crypto.KeyPair.generate("Root", "root"),
        "cs": crypto.KeyPair.generate("CS", "department"),
        "alice": crypto.KeyPair.generate("Alice", "student"),
    }


def _entries(keys: dict[str, crypto.KeyPair]) -> list[dict]:
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
        crypto.sign_op(keys["alice"], "update_records", {
            "name": NAME, "records": {"A": NEW},
        }),
    ]
    return [
        {"index": index, "term": 1, "op": op}
        for index, op in enumerate(operations, start=1)
    ]


def _append(node: ClusterNode, entries: list[dict], commit_index: int) -> dict:
    return asyncio.run(
        node.handle_append(
            {
                "term": 1,
                "leader_id": "n1",
                "leader_url": "http://127.0.0.1:1",
                "entries": entries,
                "commit_index": commit_index,
            }
        )
    )


def test_commit_hold_defers_state_and_dns_then_release_applies(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n2",
        url="http://127.0.0.1:2",
        peers={},
        data_dir=tmp_path / "n2",
        root_public=keys["root"].public_key,
    )
    entries = _entries(keys)

    _append(node, entries[:3], commit_index=3)
    assert node.commit_index == 3
    assert node.state.revision == 3
    assert node.dns_zone == {NAME: OLD}

    asyncio.run(node.set_commit_hold(True))

    # The leader sends the new entry but still advertises the previous commit.
    # A held follower stores it without applying it.
    _append(node, [entries[3]], commit_index=3)
    assert node.log[-1]["index"] == 4
    assert node.commit_index == 3
    assert node.state.revision == 3
    assert node.dns_zone == {NAME: OLD}

    # A later push announces the new commit. The held follower records the
    # pending index but still serves the old committed snapshot.
    _append(node, [], commit_index=4)
    assert node.commit_index == 3
    assert node.pending_commit_index == 4
    assert node.state.revision == 3
    assert node.dns_revision == 3
    assert node.dns_zone == {NAME: OLD}

    status = asyncio.run(node.set_commit_hold(False))
    assert status["commit_hold"] is False
    assert status["commit_index"] == 4
    assert status["applied_revision"] == 4
    assert node.state.revision == 4
    assert node.dns_revision == 4
    assert node.dns_zone == {NAME: NEW}


def test_applied_majority_counts_dns_snapshots(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n1",
        url="http://127.0.0.1:1",
        peers={"n2": "http://127.0.0.1:2", "n3": "http://127.0.0.1:3"},
        data_dir=tmp_path / "n1",
        root_public=keys["root"].public_key,
    )
    node.live_peers = {"n2", "n3"}

    node.dns_revision = 5
    node.peer_dns_revision = {"n2": 5, "n3": 4}
    assert node._applied_majority(5) is True

    node.peer_dns_revision = {"n2": 4, "n3": 5}
    assert node._applied_majority(5) is True

    node.peer_dns_revision = {"n2": 4, "n3": 4}
    assert node._applied_majority(5) is False

    # The leader itself must have published the revision too.
    node.dns_revision = 4
    node.peer_dns_revision = {"n2": 5, "n3": 5}
    assert node._applied_majority(5) is False


def test_consecutive_held_updates_apply_latest_on_release(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n2",
        url="http://127.0.0.1:2",
        peers={},
        data_dir=tmp_path / "n2",
        root_public=keys["root"].public_key,
    )
    entries = _entries(keys)
    _append(node, entries[:3], commit_index=3)
    asyncio.run(node.set_commit_hold(True))

    latest = "10.20.5.77"
    entries.append({
        "index": 5,
        "term": 1,
        "op": crypto.sign_op(keys["alice"], "update_records", {
            "name": NAME, "records": {"A": latest},
        }),
    })
    _append(node, entries[3:], commit_index=3)
    _append(node, [], commit_index=5)

    assert node.commit_index == 3
    assert node.pending_commit_index == 5
    assert node.dns_zone == {NAME: OLD}

    asyncio.run(node.set_commit_hold(False))
    assert node.commit_index == 5
    assert node.state.revision == 5
    assert node.dns_revision == 5
    assert node.dns_zone == {NAME: latest}


def test_revocation_removes_name_from_dns_snapshot_on_release(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n2",
        url="http://127.0.0.1:2",
        peers={},
        data_dir=tmp_path / "n2",
        root_public=keys["root"].public_key,
    )
    entries = _entries(keys)
    _append(node, entries[:3], commit_index=3)
    asyncio.run(node.set_commit_hold(True))

    revoke = {
        "index": 4,
        "term": 1,
        "op": crypto.sign_op(keys["alice"], "revoke_domain", {
            "name": NAME, "reason": "test revocation",
        }),
    }
    _append(node, [revoke], commit_index=3)
    _append(node, [], commit_index=4)

    assert node.dns_zone == {NAME: OLD}
    asyncio.run(node.set_commit_hold(False))
    assert node.state.revision == 4
    assert node.dns_revision == 4
    assert NAME not in node.dns_zone


def test_applied_majority_ignores_unavailable_nodes(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n1",
        url="http://127.0.0.1:1",
        peers={"n2": "http://127.0.0.1:2", "n3": "http://127.0.0.1:3"},
        data_dir=tmp_path / "n1",
        root_public=keys["root"].public_key,
    )

    # With n3 unavailable, the leader plus n2 is still a majority.
    node.live_peers = {"n2"}
    node.dns_revision = 5
    node.peer_dns_revision = {"n2": 5, "n3": 0}
    assert node._applied_majority(5) is True

    # If the only available follower is behind, the barrier must not pass.
    node.peer_dns_revision = {"n2": 4, "n3": 0}
    assert node._applied_majority(5) is False


def test_barrier_trusts_self_reported_peer_revision(tmp_path):
    """Variant B is non-Byzantine: it counts a peer's own revision claim.

    A follower that reports a revision it has not actually applied defeats the
    barrier. Closing that requires authenticated evidence or an external
    verifier, which is outside B's scope and is recorded as a limitation.
    """
    keys = _keys()
    node = ClusterNode(
        node_id="n1",
        url="http://127.0.0.1:1",
        peers={"n2": "http://127.0.0.1:2", "n3": "http://127.0.0.1:3"},
        data_dir=tmp_path / "n1",
        root_public=keys["root"].public_key,
    )
    node.live_peers = {"n2", "n3"}
    node.dns_revision = 5
    node.peer_dns_revision = {"n2": 5, "n3": 5}
    assert node._applied_majority(5) is True


def test_restart_clears_transient_hold_and_pending_commit(tmp_path):
    keys = _keys()
    directory = tmp_path / "n2"
    node = ClusterNode(
        node_id="n2",
        url="http://127.0.0.1:2",
        peers={},
        data_dir=directory,
        root_public=keys["root"].public_key,
    )
    entries = _entries(keys)
    _append(node, entries[:4], commit_index=4)
    asyncio.run(node.set_commit_hold(True))
    _append(node, [], commit_index=4)
    node.pending_commit_index = 5

    restarted = ClusterNode(
        node_id="n2",
        url="http://127.0.0.1:2",
        peers={},
        data_dir=directory,
        root_public=keys["root"].public_key,
    )
    assert restarted.commit_hold is False
    assert restarted.pending_commit_index == 0
    assert restarted.commit_index == 4
    assert restarted.state.revision == 4
    assert restarted.dns_zone == {NAME: NEW}


def test_hold_does_not_advance_past_stored_log(tmp_path):
    keys = _keys()
    node = ClusterNode(
        node_id="n3",
        url="http://127.0.0.1:3",
        peers={},
        data_dir=tmp_path / "n3",
        root_public=keys["root"].public_key,
    )
    entries = _entries(keys)
    _append(node, entries[:2], commit_index=2)
    asyncio.run(node.set_commit_hold(True))

    # A bogus commit index beyond the local log must be clamped, exactly as in
    # the normal (unheld) path.
    _append(node, [], commit_index=99)
    assert node.pending_commit_index == 2
    asyncio.run(node.set_commit_hold(False))
    assert node.commit_index == 2


def test_no_quorum_distinguishes_ambiguous_timeouts():
    assert NoQuorum("not reachable").ambiguous is False
    assert NoQuorum("may still commit", ambiguous=True).ambiguous is True


def test_hold_endpoint_is_chaos_gated_and_round_trips(tmp_path):
    keys = _keys()
    root = keys["root"].public_key

    closed = create_app(
        "n2", "http://127.0.0.1:2", {}, str(tmp_path / "closed"), root,
        chaos=False,
    )
    with TestClient(closed) as client:
        response = client.post("/internal/replication/hold", json={"held": True})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "CHAOS_DISABLED"

    opened = create_app(
        "n2", "http://127.0.0.1:2", {}, str(tmp_path / "opened"), root,
        chaos=True,
    )
    with TestClient(opened) as client:
        response = client.post("/internal/replication/hold", json={"held": True})
        assert response.status_code == 200
        held = response.json()
        assert held["commit_hold"] is True

        status = client.get("/status").json()
        assert status["commit_hold"] is True

        response = client.post("/internal/replication/hold", json={"held": False})
        assert response.status_code == 200
        assert response.json()["commit_hold"] is False
