"""HTTP service for a single registry node.

Every node exposes the same API. Writes are accepted by any node but are
executed by the current leader; a follower transparently forwards them. Reads
are served from the local committed state, which may lag the leader slightly
(``consistent=true`` forces a leader read).
"""

from __future__ import annotations

import argparse
import ipaddress
import time

import httpx
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import crypto
from .cluster import ClusterNode
from .dns_node import NodeDNSResponder
from .errors import NoQuorum, NotLeader, RegistryError
from .names import normalise

MAX_CLOCK_SKEW_SECONDS = 900


def create_app(
    node_id: str,
    url: str,
    peers: dict[str, str],
    data_dir: str,
    root_public: str,
    dns_port: int | None = None,
    chaos: bool = False,
    dns_key: str | None = None,
    publication_barrier: bool = False,
) -> FastAPI:
    node = ClusterNode(
        node_id=node_id,
        url=url,
        peers=peers,
        data_dir=data_dir,
        root_public=root_public,
        publication_barrier=publication_barrier,
    )
    node.dns_port = dns_port
    signer = None
    if dns_key:
        try:
            signer = crypto.load_keypair(dns_key)
        except Exception:
            signer = None
    responder: NodeDNSResponder | None = None
    if dns_port:
        responder = NodeDNSResponder(
            node_id=node_id,
            host="127.0.0.1",
            port=dns_port,
            zone_provider=lambda: node.dns_zone,
            revision_provider=lambda: node.dns_revision,
            snapshot_provider=lambda: node.dns_snapshot,
            chaos_enabled=chaos,
            signer=signer,
        )

    app = FastAPI(
        title=f"DCDNS registry node {node_id}",
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.state.cluster = node
    app.state.node_id = node_id

    @app.on_event("startup")
    async def _startup() -> None:
        await node.start()
        if responder is not None:
            responder.start()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if responder is not None:
            responder.stop()
        await node.stop()

    # ------------------------------------------------------------------ #
    # error handling
    # ------------------------------------------------------------------ #
    @app.exception_handler(RegistryError)
    async def _registry_error(_: Request, exc: RegistryError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.as_dict())

    @app.exception_handler(NoQuorum)
    async def _no_quorum(_: Request, exc: NoQuorum) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": {"code": "NO_QUORUM", "message": str(exc)},
                "ambiguous": bool(getattr(exc, "ambiguous", False)),
            },
        )

    @app.exception_handler(NotLeader)
    async def _not_leader(_: Request, exc: NotLeader) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": {
                    "code": "NOT_LEADER",
                    "message": "this node is not the current leader",
                },
                "leader_id": exc.leader_id,
                "leader_url": exc.leader_url,
            },
        )

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    @app.get("/")
    async def root() -> dict:
        return {
            "service": "DCDNS registry node",
            "node_id": node_id,
            "role": node.role(),
            "docs": "/docs",
        }

    @app.post("/op")
    async def submit(
        request: Request,
        x_dcdns_forwarded: str | None = Header(default=None),
    ) -> JSONResponse:
        try:
            op = await request.json()
        except Exception:
            raise RegistryError("MALFORMED_OPERATION", "request body must be JSON")

        if not isinstance(op, dict):
            raise RegistryError("MALFORMED_OPERATION", "request body must be a JSON object")

        ts = op.get("ts")
        if isinstance(ts, int) and abs(time.time() - ts) > MAX_CLOCK_SKEW_SECONDS:
            raise RegistryError(
                "STALE_OPERATION",
                "operation timestamp is too far from the node clock; re-sign the operation",
            )

        try:
            result = await node.submit(op)
            return JSONResponse(status_code=200, content=result)
        except NotLeader as exc:
            # Forward once. A forwarded request that still finds no leader is
            # returned to the caller rather than bouncing around the cluster.
            if x_dcdns_forwarded or not exc.leader_url:
                raise
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(
                        f"{exc.leader_url}/op",
                        json=op,
                        headers={"X-DCDNS-Forwarded": "1"},
                    )
                return JSONResponse(status_code=resp.status_code, content=resp.json())
            except httpx.HTTPError:
                raise NoQuorum("could not reach the leader to forward the operation")

    @app.get("/domains")
    async def list_domains() -> dict:
        state = node.state
        items = []
        for name, domain in sorted(state.domains.items()):
            items.append(
                {
                    "name": name,
                    "owner": domain["owner"],
                    "namespace": domain["namespace"],
                    "status": domain["status"],
                    "records": domain["records"],
                    "created_revision": domain["created_revision"],
                    "updated_revision": domain["updated_revision"],
                }
            )
        return {"ok": True, "revision": state.revision, "domains": items}

    @app.get("/domains/{name}")
    async def get_domain(name: str, consistent: bool = False) -> dict:
        key = normalise(name)

        if consistent and node.role() != "leader":
            leader = node.expected_leader()
            target = node.peers.get(leader or "")
            if target:
                try:
                    async with httpx.AsyncClient(timeout=3.0) as client:
                        resp = await client.get(f"{target}/domains/{key}")
                    return resp.json()
                except httpx.HTTPError:
                    pass

        domain = node.state.domains.get(key)
        if domain is None:
            raise RegistryError("NAME_NOT_FOUND", f"{key} is not registered", 404)
        return {
            "ok": True,
            "revision": node.state.revision,
            "node": node.id,
            "domain": domain,
        }

    @app.get("/domains/{name}/history")
    async def domain_history(name: str) -> dict:
        key = normalise(name)
        entries = [h for h in node.state.history if h["target"] == key]
        return {
            "ok": True,
            "name": key,
            "revision": node.state.revision,
            "history": entries,
        }

    @app.get("/namespaces")
    async def list_namespaces() -> dict:
        return {
            "ok": True,
            "revision": node.state.revision,
            "root_zone": node.state.root_public,
            "namespaces": [
                dict(ns) for _, ns in sorted(node.state.namespaces.items())
            ],
        }

    @app.get("/audit")
    async def audit(limit: int = 100) -> dict:
        records = node.state.audit[-limit:]
        return {
            "ok": True,
            "revision": node.state.revision,
            "verify": node.state.verify_audit_chain(),
            "audit": records,
        }

    @app.get("/status")
    async def status() -> dict:
        data = node.status()
        if responder is not None:
            data["dns"] = responder.summary()
        else:
            data["dns"] = {"enabled": False}
        data["ok"] = True
        return data

    # ------------------------------------------------------------------ #
    # internal cluster API
    # ------------------------------------------------------------------ #
    @app.get("/internal/ping")
    async def ping() -> dict:
        return {"ok": True, "node_id": node_id, "term": node.term}

    @app.post("/internal/append")
    async def append(payload: dict) -> dict:
        return await node.handle_append(payload)

    @app.get("/internal/log_info")
    async def log_info() -> dict:
        return {
            "ok": True,
            "node_id": node_id,
            "last_index": len(node.log),
            "term": node.term,
            "commit_index": node.commit_index,
            "pending_commit_index": node.pending_commit_index,
            "commit_hold": node.commit_hold,
        }

    @app.get("/internal/log")
    async def log_from(from_: int = 1) -> dict:
        entries = node.log[max(0, from_ - 1):]
        return {"ok": True, "entries": entries}

    @app.get("/internal/state")
    async def internal_state() -> dict:
        payload = node.state.to_dict()
        payload["ok"] = True
        payload["node"] = node_id
        payload["commit_index"] = node.commit_index
        payload["role"] = node.role()
        return payload

    @app.get("/internal/health")
    async def health() -> JSONResponse:
        ok = node.has_quorum()
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"ok": ok, "role": node.role(), "quorum": node.has_quorum()},
        )

    @app.get("/internal/zone")
    async def internal_zone() -> dict:
        """The exact zone and revision this node is currently answering from."""
        summary = responder.summary() if responder else {}
        if responder is not None:
            serving_zone, serving_revision = responder.serving_snapshot()
        else:
            serving_zone, serving_revision = dict(node.dns_zone), node.dns_revision
        return {
            "ok": True,
            "node_id": node_id,
            "revision": node.dns_revision,
            "serving_revision": serving_revision,
            "zone": dict(serving_zone),
            "zone_size": len(serving_zone),
            "dns_port": dns_port,
            "chaos": bool(responder and responder.overrides),
            "overrides": dict(responder.overrides) if responder else {},
            "paused": bool(responder and responder.paused),
            "frozen": bool(responder and responder.frozen),
            "frozen_revision": responder.frozen_revision if responder else None,
            "signed": bool(summary.get("signed")),
        }

    @app.post("/internal/chaos")
    async def internal_chaos(payload: dict) -> dict:
        """Make this node lie about one name (demo/failure-injection only).

        Disabled unless the node was started with ``--chaos``. The endpoint is
        bound to loopback like the rest of the internal API, and exists so the
        quorum resolver's majority rule can be demonstrated against a node that
        returns a wrong answer.
        """
        if responder is None or not chaos:
            return JSONResponse(
                status_code=404,
                content={
                    "ok": False,
                    "error": {
                        "code": "CHAOS_DISABLED",
                        "message": "this node was not started with --chaos",
                    },
                },
            )

        if payload.get("clear"):
            responder.overrides.clear()
            return {"ok": True, "node_id": node_id, "overrides": {}}

        updates: dict[str, str] = {}
        if isinstance(payload.get("overrides"), dict):
            updates = dict(payload["overrides"])
        else:
            updates = {
                str(payload.get("name", "")): str(payload.get("address", ""))
            }

        for raw_name, raw_address in updates.items():
            name = normalise(raw_name)
            if not name:
                raise RegistryError("INVALID_NAME", "chaos override needs a name")
            try:
                address = ipaddress.ip_address(str(raw_address).strip())
            except ValueError:
                raise RegistryError(
                    "INVALID_RECORDS",
                    f"{raw_address!r} is not a valid IP address",
                ) from None
            if address.version != 4:
                raise RegistryError("INVALID_RECORDS", "only IPv4 overrides are supported")
            responder.overrides[name] = str(address)

        return {
            "ok": True,
            "node_id": node_id,
            "overrides": dict(responder.overrides),
        }

    @app.post("/internal/dns/pause")
    async def internal_dns_pause(payload: dict) -> dict:
        """Temporarily stop this node's DNS responder (demo/failure-injection).

        The registry process keeps running and keeps replicating. Only DNS
        datagrams are dropped, which is what a resolver sees when a node is
        unreachable at the DNS layer. Disabled unless the node was started with
        ``--chaos``, like the lying-node endpoint.
        """
        if responder is None or not chaos:
            return JSONResponse(
                status_code=404,
                content={
                    "ok": False,
                    "error": {
                        "code": "CHAOS_DISABLED",
                        "message": "this node was not started with --chaos",
                    },
                },
            )

        paused = bool(payload.get("paused", payload.get("pause", True)))
        responder.set_paused(paused)
        return {
            "ok": True,
            "node_id": node_id,
            "paused": responder.paused,
        }

    @app.post("/internal/dns/freeze")
    async def internal_dns_freeze(payload: dict) -> dict:
        """Pin this node's DNS responder to its current committed snapshot.

        This is the controlled replication-lag fault used by the stale-majority
        experiment. The registry keeps committing and replicating; the DNS
        responder keeps answering from the real zone snapshot and revision it
        had when the freeze was applied. It never fabricates an answer and it
        does not alter the committed log. Disabled unless the node was started
        with ``--chaos``.
        """
        if responder is None or not chaos:
            return JSONResponse(
                status_code=404,
                content={
                    "ok": False,
                    "error": {
                        "code": "CHAOS_DISABLED",
                        "message": "this node was not started with --chaos",
                    },
                },
            )

        frozen = bool(payload.get("frozen", payload.get("freeze", True)))
        responder.set_frozen(frozen)
        summary = responder.summary()
        return {
            "ok": True,
            "node_id": node_id,
            "frozen": responder.frozen,
            "frozen_revision": responder.frozen_revision,
            "serving_revision": summary.get("serving_revision"),
            "registry_revision": summary.get("revision"),
            "revision_lag": summary.get("revision_lag"),
        }

    @app.post("/internal/replication/hold")
    async def internal_replication_hold(payload: dict) -> dict:
        """Delay applying committed entries on this node (fault injection).

        This does not stop replication or alter the log: the node still stores
        entries and acknowledges them, so the leader can commit through it.
        Only the local ``commit_index`` and the DNS snapshot are held back.
        Disabled unless the node was started with ``--chaos``.
        """
        if not chaos:
            return JSONResponse(
                status_code=404,
                content={
                    "ok": False,
                    "error": {
                        "code": "CHAOS_DISABLED",
                        "message": "this node was not started with --chaos",
                    },
                },
            )

        held = bool(payload.get("held", payload.get("hold", True)))
        state = await node.set_commit_hold(held)
        return {"ok": True, "node_id": node_id, **state}

    return app


def main() -> None:
    from .runtime import configure_event_loop

    configure_event_loop()

    parser = argparse.ArgumentParser(description="Run one DCDNS registry node")
    parser.add_argument("--id", required=True, help="node id, e.g. n1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--peers",
        default="",
        help="comma separated id=url pairs, excluding this node",
    )
    parser.add_argument("--data", required=True, help="data directory")
    parser.add_argument("--root", required=True, help="root authority public key (base64)")
    parser.add_argument(
        "--dns-port",
        type=int,
        default=None,
        help="also answer DNS on this UDP port (one per node)",
    )
    parser.add_argument(
        "--chaos",
        action="store_true",
        help="enable loopback-only fault injection (lying node, DNS pause/freeze, "
        "commit hold) for experiments",
    )
    parser.add_argument(
        "--dns-key",
        default=None,
        help="path to this node's Ed25519 key for signing DNS revision tokens",
    )
    parser.add_argument(
        "--publication-barrier",
        action="store_true",
        help="variant B: acknowledge writes only after a majority has applied "
        "them to the state used for DNS answers",
    )
    parser.add_argument("--log-level", default="warning")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    peers: dict[str, str] = {}
    for chunk in args.peers.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        pid, purl = chunk.split("=", 1)
        peers[pid.strip()] = purl.strip()

    app = create_app(
        args.id,
        url,
        peers,
        args.data,
        args.root,
        dns_port=args.dns_port,
        chaos=args.chaos,
        dns_key=args.dns_key,
        publication_barrier=args.publication_barrier,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
