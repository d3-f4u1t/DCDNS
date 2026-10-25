"""Demonstration portal for the DCDNS registry.

Server-rendered Jinja2 pages with a small amount of progressive-enhancement
JavaScript. Every action is a real signed registry operation; there is no mock
data anywhere in this file.

Signing note: for demo convenience the portal holds the participant key files
and signs on the selected identity's behalf. In a production system signing
happens client-side and the server never sees a private key.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import crypto
from .client import ClusterClient, ClusterError
from .experiments import EXPERIMENTS, ExperimentRunner, Resolver

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
TEMPLATES.env.auto_reload = True

DEFAULT_NODES = "http://127.0.0.1:9101,http://127.0.0.1:9102,http://127.0.0.1:9103"
DEFAULT_DNS_METRICS = "http://127.0.0.1:5380"

EXPERIMENT_RESULTS: dict[str, dict] = {}


def create_app(
    node_urls: list[str] | None = None,
    dns_host: str = "127.0.0.1",
    dns_port: int = 5353,
    dns_metrics_url: str = DEFAULT_DNS_METRICS,
    identities_dir: str = "identities",
) -> FastAPI:
    urls = node_urls or [u.strip() for u in os.environ.get("DCDNS_NODES", DEFAULT_NODES).split(",")]
    client = ClusterClient(urls, timeout=6.0)
    resolver = Resolver(dns_host, dns_port)

    identity_dir = Path(identities_dir)
    index_path = identity_dir / "index.json"
    identities: list[dict] = []
    if index_path.exists():
        import json

        identities = json.loads(index_path.read_text("utf-8"))

    keys: dict[str, crypto.KeyPair] = {}
    for item in identities:
        try:
            keys[item["name"]] = crypto.load_keypair(str(identity_dir / item["file"]))
        except Exception:
            continue

    labels = {item["public_key"]: item["label"] for item in identities}
    fingerprints = {item["public_key"]: item["fingerprint"] for item in identities}

    app = FastAPI(title="DCDNS portal", version="1.0.0")
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def current_identity(request: Request) -> dict:
        name = request.cookies.get("dcdns_identity", "alice")
        for item in identities:
            if item["name"] == name:
                return item
        if identities:
            return identities[0]
        return {"name": "anonymous", "label": "Anonymous", "role": "none",
                "public_key": "", "fingerprint": "-", "member_of": None}

    def context(request: Request, active: str, **extra) -> dict:
        ok = request.query_params.get("ok")
        err = request.query_params.get("err")
        code = request.query_params.get("code")
        flash = None
        if ok:
            flash = {"ok": True, "message": ok}
        elif err:
            flash = {"ok": False, "message": err, "code": code}
        base = {
            "request": request,
            "active": active,
            "identity": current_identity(request),
            "identities": identities,
            "labels": labels,
            "fingerprints": fingerprints,
            "flash": flash,
            "now": time.time(),
        }
        base.update(extra)
        return base

    def redirect(path: str, ok: str | None = None, err: str | None = None,
                 code: str | None = None) -> RedirectResponse:
        from urllib.parse import quote

        query = []
        if ok:
            query.append("ok=" + quote(ok))
        if err:
            query.append("err=" + quote(err))
        if code:
            query.append("code=" + quote(code))
        sep = "&" if "?" in path else "?"
        return RedirectResponse(
            path + (sep + "&".join(query) if query else ""), status_code=303
        )

    def submit(signer: str, op: str, body: dict) -> tuple[bool, str, str | None]:
        key = keys.get(signer)
        if key is None:
            return False, f"no key available for {signer}", "NO_KEY"
        try:
            result = client.submit(crypto.sign_op(key, op, body))
            return True, f"{op} committed at revision {result['revision']}", None
        except ClusterError as exc:
            return False, str(exc), exc.code
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}", "ERROR"

    def dns_metrics() -> dict | None:
        try:
            with httpx.Client(timeout=1.0) as http:
                resp = http.get(f"{dns_metrics_url}/metrics")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            return None
        return None

    def snapshot() -> dict:
        statuses = client.statuses()
        live = [s for s in statuses if s.get("ok")]
        revision = max([s.get("revision", 0) for s in live], default=0)
        leader = next((s.get("url") for s in live if s.get("role") == "leader"), None)

        domains_count = 0
        namespaces_count = 0
        audit: list[dict] = []
        audit_verify = {"ok": False, "length": 0, "broken_at": 0, "head": ""}
        try:
            state = client.consistent_state()
            domains_count = len(state.get("domains", {}))
            namespaces_count = len(state.get("namespaces", {}))
            revision = max(revision, int(state.get("revision", 0)))
        except Exception:
            pass
        try:
            payload = client.get("/audit", limit=10)
            audit = list(reversed(payload.get("audit", [])))
            audit_verify = payload.get("verify", audit_verify)
        except Exception:
            pass

        return {
            "nodes": statuses,
            "live": live,
            "revision": revision,
            "leader": leader,
            "dns": dns_metrics(),
            "audit": audit,
            "audit_verify": audit_verify,
            "domains_count": domains_count,
            "namespaces_count": namespaces_count,
        }

    def build_tree(namespaces: dict) -> list[dict]:
        ordered = sorted(namespaces.values(), key=lambda ns: (ns["name"].count("."), ns["name"]))
        return [
            {
                "name": ns["name"],
                "depth": ns["name"].count(".") - 1,
                "status": ns["status"],
                "controller": ns["controller"],
                "members": ns.get("members", {}),
                "created_revision": ns["created_revision"],
            }
            for ns in ordered
        ]

    # ------------------------------------------------------------------ #
    # dashboard
    # ------------------------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        data = snapshot()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="dashboard.html",
            context=context(request, "dashboard", **data),
        )

    @app.get("/partials/status", response_class=HTMLResponse)
    async def status_partial(request: Request) -> HTMLResponse:
        data = snapshot()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="partials/status.html",
            context=context(request, "dashboard", **data),
        )

    @app.get("/health")
    async def health() -> JSONResponse:
        try:
            state = client.consistent_state()
            return JSONResponse({"ok": True, "revision": state.get("revision", 0)})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)

    # ------------------------------------------------------------------ #
    # domains
    # ------------------------------------------------------------------ #
    @app.get("/domains", response_class=HTMLResponse)
    async def domain_list(request: Request, q: str = "") -> HTMLResponse:
        try:
            payload = client.get("/domains")
            domains = payload.get("domains", [])
            revision = payload.get("revision", 0)
        except Exception:
            domains, revision = [], 0
        if q:
            needle = q.strip().lower()
            domains = [d for d in domains if needle in d["name"].lower()]
        return TEMPLATES.TemplateResponse(
            request=request,
            name="domains.html",
            context=context(request, "domains", domains=domains, revision=revision, q=q),
        )

    @app.post("/domains/register")
    async def register_domain(
        request: Request,
        name: str = Form(...),
        address: str = Form(...),
    ) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "register_domain", {"name": name.strip(), "records": {"A": address.strip()}}
        )
        target = f"/domains/{name.strip().lower().rstrip('.')}"
        return redirect(target, ok=message) if ok else redirect("/domains", err=message, code=code)

    @app.get("/domains/{name}", response_class=HTMLResponse)
    async def domain_detail(request: Request, name: str) -> HTMLResponse:
        try:
            payload = client.get(f"/domains/{name}")
        except Exception:
            return redirect("/domains", err=f"{name} is not registered", code="NAME_NOT_FOUND")

        domain = payload["domain"]
        try:
            history = client.get(f"/domains/{name}/history").get("history", [])
        except Exception:
            history = []

        actor = current_identity(request)
        is_owner = actor["public_key"] == domain["owner"]
        try:
            namespaces = client.get("/namespaces").get("namespaces", [])
        except Exception:
            namespaces = []
        ns = next((n for n in namespaces if n["name"] == domain["namespace"]), None)
        is_controller = bool(ns and ns["controller"] == actor["public_key"])

        return TEMPLATES.TemplateResponse(
            request=request,
            name="domain_detail.html",
            context=context(
                request, "domains",
                domain=domain,
                history=history,
                is_owner=is_owner,
                is_controller=is_controller,
                can_edit=is_owner or is_controller,
            ),
        )

    @app.post("/domains/{name}/records")
    async def update_records(
        request: Request, name: str, address: str = Form(...)
    ) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "update_records", {"name": name, "records": {"A": address.strip()}}
        )
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/transfer")
    async def transfer(request: Request, name: str, new_owner: str = Form(...)) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "transfer_initiate", {"name": name, "new_owner": new_owner}
        )
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/transfer/accept")
    async def transfer_accept(request: Request, name: str) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "transfer_accept", {"name": name})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/transfer/cancel")
    async def transfer_cancel(request: Request, name: str) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "transfer_cancel", {"name": name})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/revoke")
    async def revoke(request: Request, name: str, reason: str = Form("")) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "revoke_domain", {"name": name, "reason": reason})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    # ------------------------------------------------------------------ #
    # namespaces
    # ------------------------------------------------------------------ #
    @app.get("/namespaces", response_class=HTMLResponse)
    async def namespace_list(request: Request) -> HTMLResponse:
        try:
            namespaces = client.get("/namespaces").get("namespaces", [])
        except Exception:
            namespaces = []
        tree = build_tree({ns["name"]: ns for ns in namespaces})
        return TEMPLATES.TemplateResponse(
            request=request,
            name="namespaces.html",
            context=context(request, "namespaces", tree=tree),
        )

    @app.post("/namespaces/delegate")
    async def delegate(request: Request, name: str = Form(...),
                       controller: str = Form(...)) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "delegate_namespace", {"name": name.strip(), "controller": controller}
        )
        return redirect("/namespaces", ok=message) if ok else redirect(
            "/namespaces", err=message, code=code
        )

    @app.post("/namespaces/grant")
    async def grant(request: Request, namespace: str = Form(...),
                    member: str = Form(...)) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "grant_member", {"namespace": namespace, "member": member}
        )
        return redirect("/namespaces", ok=message) if ok else redirect(
            "/namespaces", err=message, code=code
        )

    # ------------------------------------------------------------------ #
    # audit
    # ------------------------------------------------------------------ #
    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request) -> HTMLResponse:
        try:
            payload = client.get("/audit", limit=200)
            records = payload.get("audit", [])
            verify = payload.get("verify", {})
            revision = payload.get("revision", 0)
        except Exception:
            records, verify, revision = [], {"ok": False, "length": 0, "broken_at": 0}, 0
        return TEMPLATES.TemplateResponse(
            request=request,
            name="audit.html",
            context=context(request, "audit", records=records, verify=verify, revision=revision),
        )

    # ------------------------------------------------------------------ #
    # experiments
    # ------------------------------------------------------------------ #
    @app.get("/experiments", response_class=HTMLResponse)
    async def experiments_page(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="experiments.html",
            context=context(request, "experiments", experiments=EXPERIMENTS,
                            results=EXPERIMENT_RESULTS),
        )

    @app.post("/experiments/{experiment_id}")
    async def run_experiment(request: Request, experiment_id: str) -> RedirectResponse:
        runner = ExperimentRunner(client, keys, resolver)
        result = runner.run(experiment_id).as_dict()
        EXPERIMENT_RESULTS[experiment_id] = result
        if result["passed"]:
            return redirect("/experiments", ok=f"{experiment_id}: PASS — {result['observed']}")
        return redirect("/experiments", err=f"{experiment_id}: FAIL — {result['observed']}",
                        code="EXPERIMENT_FAILED")

    # ------------------------------------------------------------------ #
    # identities
    # ------------------------------------------------------------------ #
    @app.get("/identities", response_class=HTMLResponse)
    async def identities_page(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="identities.html",
            context=context(request, "identities"),
        )

    @app.post("/identity")
    async def select_identity(request: Request, identity: str = Form(...)) -> RedirectResponse:
        response = redirect(request.headers.get("referer", "/"))
        response.set_cookie("dcdns_identity", identity, httponly=True, samesite="lax")
        return response

    return app


def main() -> None:
    import argparse

    from .runtime import configure_event_loop

    configure_event_loop()

    parser = argparse.ArgumentParser(description="Run the DCDNS portal")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--nodes", default=os.environ.get("DCDNS_NODES", DEFAULT_NODES))
    parser.add_argument("--dns-host", default="127.0.0.1")
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--dns-metrics", default=DEFAULT_DNS_METRICS)
    parser.add_argument("--identities", default="identities")
    args = parser.parse_args()

    app = create_app(
        node_urls=[u.strip() for u in args.nodes.split(",")],
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        dns_metrics_url=args.dns_metrics,
        identities_dir=args.identities,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
