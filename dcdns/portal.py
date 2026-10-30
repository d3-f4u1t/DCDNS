"""Demonstration portal for the DCDNS registry.

Server-rendered Jinja2 pages with a small amount of progressive-enhancement
JavaScript. Every action is a real signed registry operation; there is no mock
data anywhere in this file.

Signing note: for demo convenience the portal holds the participant key files
and signs on the selected identity's behalf. In a production system signing
happens client-side and the server never sees a private key.
"""

from __future__ import annotations

import ipaddress
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import httpx
import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import crypto
from .client import ClusterClient, ClusterError
from .experiments import (
    DEFAULT_DNS_NODES,
    EXPERIMENTS,
    ExperimentRunner,
    Resolver,
)
from .names import normalise
from .probe import probe_nodes, probe_resolver

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
    demo_controls: bool = False,
    dns_nodes: dict[str, tuple[str, int]] | None = None,
    node_apis: dict[str, str] | None = None,
    http_client: httpx.Client | None = None,
    node_keys: dict[str, str] | None = None,
) -> FastAPI:
    urls = node_urls or [u.strip() for u in os.environ.get("DCDNS_NODES", DEFAULT_NODES).split(",")]
    client = ClusterClient(urls, timeout=6.0)
    resolver = Resolver(dns_host, dns_port)
    # One loopback HTTP client for status, metrics and demo controls. Creating a
    # fresh httpx.Client per request is very slow on Windows (certificate-store
    # scan) and made the dashboard take ten seconds to render.
    http = http_client or httpx.Client(timeout=3.0)
    dns_nodes = dict(dns_nodes or DEFAULT_DNS_NODES)
    node_keys = dict(node_keys or {})
    node_apis = dict(
        node_apis
        or {f"n{index + 1}": url for index, url in enumerate(urls)}
    )

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

    @app.on_event("startup")
    async def _clear_demo_faults_on_startup() -> None:
        # A portal restart must not leave a previous presentation's forged
        # answer or paused responder active. This only clears DNS demo faults.
        clear_faults(ignore_unreachable=True)

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
            "demo_controls": demo_controls,
            "node_apis": node_apis,
            "dns_nodes": dns_nodes,
        }
        base.update(extra)
        return base

    def node_statuses(timeout: float = 0.8) -> list[dict]:
        """Fetch every node's status in parallel.

        ``ClusterClient.statuses`` is deliberately sequential for the CLI. The
        console polls every two seconds, so one dead node must not delay the
        other two.
        """
        def one(item: tuple[str, str]) -> dict:
            node_id, url = item
            try:
                response = http.get(f"{url}/status", timeout=timeout)
                if response.status_code == 200:
                    data = response.json()
                    data.setdefault("url", url)
                    data["node_id"] = data.get("node_id") or node_id
                    data["ok"] = True
                    return data
                return {
                    "ok": False,
                    "node_id": node_id,
                    "url": url,
                    "error": f"HTTP {response.status_code}",
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "node_id": node_id,
                    "url": url,
                    "error": f"{type(exc).__name__}: {exc}",
                }

        with ThreadPoolExecutor(max_workers=max(1, len(node_apis))) as pool:
            return list(pool.map(one, node_apis.items()))

    def faults_from_statuses(statuses: list[dict]) -> list[dict]:
        faults: list[dict] = []
        for status in statuses:
            if not status.get("ok"):
                continue
            dns = status.get("dns") or {}
            if dns.get("paused"):
                faults.append(
                    {
                        "node_id": status.get("node_id", "?"),
                        "kind": "dns_paused",
                        "detail": "DNS responder paused; registry replication continues",
                    }
                )
            for name, address in (dns.get("overrides") or {}).items():
                faults.append(
                    {
                        "node_id": status.get("node_id", "?"),
                        "kind": "dns_override",
                        "detail": f"{name} → {address}",
                    }
                )
            if dns.get("frozen"):
                faults.append(
                    {
                        "node_id": status.get("node_id", "?"),
                        "kind": "dns_frozen",
                        "detail": (
                            f"serving revision {dns.get('frozen_revision')} "
                            f"(registry {dns.get('revision')})"
                        ),
                    }
                )
        return faults

    def run_probe(raw_name: str) -> dict | None:
        name = normalise(raw_name)
        if not name:
            return None
        started = time.time()
        with ThreadPoolExecutor(max_workers=3) as pool:
            nodes_future = pool.submit(probe_nodes, name, dns_nodes, 0.75)
            resolver_future = pool.submit(
                probe_resolver, dns_metrics_url, name, 2.0, http
            )
            status_future = pool.submit(node_statuses)
            nodes = nodes_future.result()
            resolver_result = resolver_future.result()
            statuses = status_future.result()

        status_by_id = {item.get("node_id"): item for item in statuses}
        for row in nodes:
            status = status_by_id.get(row["node_id"]) or {}
            dns = status.get("dns") or {}
            row["registry_revision"] = status.get("revision")
            row["dns_revision"] = dns.get("serving_revision", dns.get("revision"))
            row["dns_registry_revision"] = dns.get("revision")
            row["packet_revision"] = row.get("revision")
            row["packet_signed"] = bool(row.get("revision_signed"))
            row["dns_frozen"] = bool(dns.get("frozen"))
            row["dns_revision_lag"] = int(dns.get("revision_lag", 0) or 0)
            row["paused"] = bool(dns.get("paused"))
            row["overrides"] = dict(dns.get("overrides") or {})
            row["api_reachable"] = bool(status.get("ok"))
            row["revision_source"] = (
                "DNS EDNS token" if row.get("packet_revision") is not None
                else ("node /status" if status.get("ok") else "unavailable")
            )

        # If the resolver process predates the /query endpoint, still show the
        # client-visible UDP answer. The UI labels the fallback source.
        if resolver_result.get("error") and not resolver_result.get("votes"):
            fallback = probe_nodes(name, {dns_host: (dns_host, dns_port)}, 0.9)[0]
            resolver_result = {
                "ok": fallback["rcode"] == 0,
                "name": name,
                "rcode": fallback["rcode_name"],
                "answer": fallback["answer"],
                "votes": {},
                "winner": [],
                "disagreement": False,
                "required": None,
                "responders": None,
                "latency_ms": fallback["latency_ms"],
                "error": resolver_result.get("error"),
                "source": f"resolver UDP {dns_host}:{dns_port} (fallback; no vote map)",
            }

        finished = time.time()
        return {
            "name": name,
            "qtype": "A",
            "at": finished,
            "at_display": time.strftime("%H:%M:%S", time.localtime(finished))
            + f".{int(finished * 1000) % 1000:03d}",
            "elapsed_ms": round((finished - started) * 1000.0, 2),
            "nodes": nodes,
            "resolver": resolver_result,
            "source": "direct node UDP queries + resolver /query",
        }

    def require_demo() -> None:
        if not demo_controls:
            raise HTTPException(status_code=404, detail="demo controls are disabled")

    def post_node(node_id: str, path: str, payload: dict) -> dict:
        url = node_apis.get(node_id)
        if not url:
            raise HTTPException(status_code=404, detail=f"unknown node {node_id}")
        try:
            response = http.post(f"{url}{path}", json=payload, timeout=2.0)
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"{node_id} did not accept the control: {type(exc).__name__}: {exc}",
            ) from exc
        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"{node_id} returned HTTP {response.status_code}: {response.text[:200]}",
            )
        return response.json()

    def clear_faults(ignore_unreachable: bool = False) -> list[str]:
        """Clear DNS overrides and pause flags on every node.

        Called at portal startup and by the reset control. It never touches
        registry state or the committed log. Startup tolerates nodes that are
        not up yet; an explicit reset reports every node it could not reach so
        the UI never claims a fault was cleared when it was not.
        """
        errors: list[str] = []
        for node_id, url in node_apis.items():
            for path, payload in (
                ("/internal/chaos", {"clear": True}),
                ("/internal/dns/pause", {"paused": False}),
                ("/internal/dns/freeze", {"frozen": False}),
            ):
                try:
                    response = http.post(f"{url}{path}", json=payload, timeout=1.0)
                    if response.status_code not in (200, 404):
                        errors.append(f"{node_id} {path}: HTTP {response.status_code}")
                except Exception as exc:
                    if not ignore_unreachable:
                        errors.append(
                            f"{node_id} {path}: {type(exc).__name__}: {exc}"
                        )
        return errors

    def redirect(path: str, ok: str | None = None, err: str | None = None,
                 code: str | None = None) -> RedirectResponse:
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
            resp = http.get(f"{dns_metrics_url}/metrics", timeout=1.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            return None
        return None

    def snapshot() -> dict:
        statuses = node_statuses()
        live = [s for s in statuses if s.get("ok")]
        revision = max([s.get("revision", 0) for s in live], default=0)
        leader = next((s.get("url") for s in live if s.get("role") == "leader"), None)
        faults = faults_from_statuses(statuses)
        dns = dns_metrics()
        if dns:
            for item in dns.get("recent", []):
                try:
                    item["at_display"] = time.strftime(
                        "%H:%M:%S", time.localtime(float(item["at"]))
                    )
                except (KeyError, TypeError, ValueError, OverflowError, OSError):
                    item["at_display"] = "--:--:--"

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
            payload = client.get("/audit", limit=8)
            audit = list(reversed(payload.get("audit", [])))
            audit_verify = payload.get("verify", audit_verify)
        except Exception:
            pass

        return {
            "nodes": statuses,
            "live": live,
            "revision": revision,
            "leader": leader,
            "dns": dns,
            "audit": audit,
            "audit_verify": audit_verify,
            "domains_count": domains_count,
            "namespaces_count": namespaces_count,
            "faults": faults,
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
    def dashboard(request: Request) -> HTMLResponse:
        q = (request.query_params.get("q") or "techfest.cs.test").strip()
        probe = run_probe(q)
        data = snapshot()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="dashboard.html",
            context=context(request, "dashboard", q=q, probe=probe, probe_embed=True, **data),
        )

    @app.get("/partials/status", response_class=HTMLResponse)
    def status_partial(request: Request) -> HTMLResponse:
        q = (request.query_params.get("q") or "techfest.cs.test").strip()
        data = snapshot()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="partials/status.html",
            context=context(request, "dashboard", q=q, **data),
        )

    @app.get("/partials/activity", response_class=HTMLResponse)
    def activity_partial(request: Request) -> HTMLResponse:
        q = (request.query_params.get("q") or "techfest.cs.test").strip()
        data = snapshot()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="partials/activity.html",
            context=context(request, "dashboard", q=q, **data),
        )

    @app.get("/partials/live")
    def live_partial(request: Request) -> JSONResponse:
        """Both live fragments from one snapshot, for the 2s console poll."""
        q = (request.query_params.get("q") or "techfest.cs.test").strip()
        data = snapshot()
        ctx = context(request, "dashboard", q=q, **data)
        status_html = TEMPLATES.get_template("partials/status.html").render(ctx)
        activity_html = TEMPLATES.get_template("partials/activity.html").render(ctx)
        return JSONResponse({"status": status_html, "activity": activity_html})

    @app.get("/partials/probe", response_class=HTMLResponse)
    def probe_partial(request: Request, name: str = "") -> HTMLResponse:
        q = name.strip()
        probe = run_probe(q) if q else None
        embed = request.query_params.get("embed") == "1"
        return TEMPLATES.TemplateResponse(
            request=request,
            name="partials/probe.html",
            context=context(request, "dashboard", q=q, probe=probe, probe_embed=embed),
        )

    @app.get("/api/probe")
    def api_probe(name: str = "") -> JSONResponse:
        """JSON form of the console probe, useful for scripted checks."""
        probe = run_probe(name.strip()) if name.strip() else None
        return JSONResponse({"ok": probe is not None, "probe": probe})

    @app.get("/health")
    def health() -> JSONResponse:
        """Liveness probe: the portal process is accepting requests.

        This deliberately does not call the cluster. A busy dashboard request
        must not make the supervisor believe the portal has died.
        """
        return JSONResponse({"ok": True, "service": "portal"})

    @app.get("/ready")
    def ready() -> JSONResponse:
        """Readiness probe: the portal can read committed cluster state."""
        try:
            state = client.consistent_state()
            return JSONResponse({"ok": True, "revision": state.get("revision", 0)})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)

    # ------------------------------------------------------------------ #
    # domains
    # ------------------------------------------------------------------ #
    @app.get("/domains", response_class=HTMLResponse)
    def domain_list(request: Request, q: str = "") -> HTMLResponse:
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
    def register_domain(
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
    def domain_detail(request: Request, name: str) -> HTMLResponse:
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

        q = (request.query_params.get("q") or name).strip()
        probe = run_probe(q)
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
                q=q,
                probe=probe,
            ),
        )

    @app.post("/domains/{name}/records")
    def update_records(
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
    def transfer(request: Request, name: str, new_owner: str = Form(...)) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "transfer_initiate", {"name": name, "new_owner": new_owner}
        )
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/transfer/accept")
    def transfer_accept(request: Request, name: str) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "transfer_accept", {"name": name})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/transfer/cancel")
    def transfer_cancel(request: Request, name: str) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "transfer_cancel", {"name": name})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    @app.post("/domains/{name}/revoke")
    def revoke(request: Request, name: str, reason: str = Form("")) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(actor, "revoke_domain", {"name": name, "reason": reason})
        return redirect(f"/domains/{name}", ok=message) if ok else redirect(
            f"/domains/{name}", err=message, code=code
        )

    # ------------------------------------------------------------------ #
    # namespaces
    # ------------------------------------------------------------------ #
    @app.get("/namespaces", response_class=HTMLResponse)
    def namespace_list(request: Request) -> HTMLResponse:
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
    def delegate(request: Request, name: str = Form(...),
                       controller: str = Form(...)) -> RedirectResponse:
        actor = current_identity(request)["name"]
        ok, message, code = submit(
            actor, "delegate_namespace", {"name": name.strip(), "controller": controller}
        )
        return redirect("/namespaces", ok=message) if ok else redirect(
            "/namespaces", err=message, code=code
        )

    @app.post("/namespaces/grant")
    def grant(request: Request, namespace: str = Form(...),
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
    def audit_page(request: Request) -> HTMLResponse:
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
    def experiments_page(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="experiments.html",
            context=context(request, "experiments", experiments=EXPERIMENTS,
                            results=EXPERIMENT_RESULTS),
        )

    @app.post("/experiments/{experiment_id}")
    def run_experiment(request: Request, experiment_id: str) -> RedirectResponse:
        runner = ExperimentRunner(
            client,
            keys,
            resolver,
            dns_nodes=dns_nodes,
            node_apis=node_apis,
            node_keys=node_keys,
        )
        result = runner.run(experiment_id).as_dict()
        EXPERIMENT_RESULTS[experiment_id] = result
        if result["passed"]:
            return redirect("/experiments", ok=f"{experiment_id}: PASS — {result['observed']}")
        return redirect("/experiments", err=f"{experiment_id}: FAIL — {result['observed']}",
                        code="EXPERIMENT_FAILED")

    # ------------------------------------------------------------------ #
    # demo fault controls (loopback-only, gated by --demo-controls)
    # ------------------------------------------------------------------ #
    @app.post("/demo/fault/lie")
    def demo_lie(
        request: Request,
        node: str = Form("n3"),
        name: str = Form("techfest.cs.test"),
        address: str = Form("10.20.5.66"),
        clear: str = Form(""),
        q: str = Form(""),
    ) -> RedirectResponse:
        require_demo()
        target = "/?q=" + quote(q or name or "techfest.cs.test")
        try:
            if clear:
                post_node(node, "/internal/chaos", {"clear": True})
                return redirect(target, ok=f"{node}: forged DNS answer cleared")
            dns_name = normalise(name)
            if not dns_name:
                raise ValueError("a domain name is required")
            try:
                parsed = ipaddress.ip_address(address.strip())
            except ValueError:
                raise ValueError(f"{address!r} is not an IP address") from None
            if parsed.version != 4:
                raise ValueError("only IPv4 forged answers are supported")
            post_node(
                node,
                "/internal/chaos",
                {"name": dns_name, "address": str(parsed)},
            )
            return redirect(
                target,
                ok=f"{node} will answer {dns_name} with {parsed} (DNS only; registry unchanged)",
            )
        except HTTPException as exc:
            return redirect(target, err=str(exc.detail), code="DEMO_CONTROL_FAILED")
        except Exception as exc:
            return redirect(
                target,
                err=f"{type(exc).__name__}: {exc}",
                code="DEMO_CONTROL_FAILED",
            )

    @app.post("/demo/fault/pause")
    def demo_pause(
        request: Request,
        node: str = Form(...),
        paused: str = Form("1"),
        q: str = Form(""),
    ) -> RedirectResponse:
        require_demo()
        target = "/?q=" + quote(q or "techfest.cs.test")
        want_paused = paused.strip().lower() in {"1", "true", "yes", "on"}
        try:
            node_ids = [item.strip() for item in node.split(",") if item.strip()]
            if not node_ids:
                raise ValueError("at least one node is required")
            results = []
            for node_id in node_ids:
                result = post_node(
                    node_id, "/internal/dns/pause", {"paused": want_paused}
                )
                results.append(
                    f"{node_id}={'paused' if result.get('paused') else 'resumed'}"
                )
            return redirect(
                target,
                ok=", ".join(results) + " (registry nodes still running)",
            )
        except HTTPException as exc:
            return redirect(target, err=str(exc.detail), code="DEMO_CONTROL_FAILED")
        except Exception as exc:
            return redirect(
                target,
                err=f"{type(exc).__name__}: {exc}",
                code="DEMO_CONTROL_FAILED",
            )

    @app.post("/demo/fault/reset")
    def demo_reset(request: Request, q: str = Form("")) -> RedirectResponse:
        require_demo()
        target = "/?q=" + quote(q or "techfest.cs.test")
        errors = clear_faults()
        if errors:
            return redirect(
                target,
                err="reset incomplete: " + "; ".join(errors),
                code="DEMO_RESET_PARTIAL",
            )
        return redirect(target, ok="all DNS demo faults cleared")

    @app.post("/demo/fault/freeze")
    def demo_freeze(
        request: Request,
        node: str = Form("n1,n2"),
        frozen: str = Form("1"),
        q: str = Form(""),
    ) -> RedirectResponse:
        """Pin one or more DNS responders to their current committed snapshot.

        This is the manual version of the stale-majority experiment: freeze two
        nodes, commit an address change, and the semantic-only answer is stale
        while RAM-DNS fails closed. The registry keeps committing throughout.
        """
        require_demo()
        target = "/?q=" + quote(q or "techfest.cs.test")
        want_frozen = frozen.strip().lower() in {"1", "true", "yes", "on"}
        try:
            node_ids = [item.strip() for item in node.split(",") if item.strip()]
            if not node_ids:
                raise ValueError("at least one node is required")
            results = []
            for node_id in node_ids:
                result = post_node(
                    node_id, "/internal/dns/freeze", {"frozen": want_frozen}
                )
                state = (
                    f"frozen at rev {result.get('frozen_revision')}"
                    if result.get("frozen")
                    else "live"
                )
                results.append(f"{node_id}={state}")
            return redirect(
                target,
                ok=", ".join(results)
                + " (DNS snapshot only; registry replication continues)",
            )
        except HTTPException as exc:
            return redirect(target, err=str(exc.detail), code="DEMO_CONTROL_FAILED")
        except Exception as exc:
            return redirect(
                target,
                err=f"{type(exc).__name__}: {exc}",
                code="DEMO_CONTROL_FAILED",
            )

    # ------------------------------------------------------------------ #
    # identities
    # ------------------------------------------------------------------ #
    @app.get("/identities", response_class=HTMLResponse)
    def identities_page(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="identities.html",
            context=context(request, "identities"),
        )

    @app.post("/identity")
    def select_identity(request: Request, identity: str = Form(...)) -> RedirectResponse:
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
    parser.add_argument(
        "--demo-controls",
        action="store_true",
        help="enable loopback-only DNS fault-injection controls",
    )
    parser.add_argument(
        "--node-apis",
        default="n1=http://127.0.0.1:9101,n2=http://127.0.0.1:9102,n3=http://127.0.0.1:9103",
        help="comma separated id=url entries for node control/status",
    )
    parser.add_argument(
        "--dns-nodes",
        default="n1=127.0.0.1:5354,n2=127.0.0.1:5355,n3=127.0.0.1:5356",
        help="comma separated id=host:udp-port entries for direct DNS probes",
    )
    parser.add_argument(
        "--node-keys",
        default="",
        help="comma separated id=public-key entries for verifying signed revision tokens",
    )
    args = parser.parse_args()

    def parse_pairs(spec: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            key, value = chunk.split("=", 1)
            result[key.strip()] = value.strip()
        return result

    node_apis = parse_pairs(args.node_apis)
    dns_nodes = {
        node_id: (host, int(port))
        for node_id, address in parse_pairs(args.dns_nodes).items()
        for host, port in [address.rsplit(":", 1)]
    }

    app = create_app(
        node_urls=[u.strip() for u in args.nodes.split(",")],
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        dns_metrics_url=args.dns_metrics,
        identities_dir=args.identities,
        demo_controls=args.demo_controls,
        node_apis=node_apis,
        dns_nodes=dns_nodes,
        node_keys=parse_pairs(args.node_keys) if args.node_keys else {},
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
