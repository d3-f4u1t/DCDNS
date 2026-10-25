"""The deterministic registry state machine.

This module is the heart of the project. Given a sequence of signed operations,
every registry node applies the *same* pure function to the *same* starting
state and must arrive at the *same* result. Consensus is only responsible for
agreeing on the *order* of operations; it is this file that decides whether an
operation is legal at all.

Nothing here reads the clock, the network, or the local filesystem.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Any

from . import crypto
from .errors import RegistryError
from .names import (
    ROOT_ZONE,
    parent_of,
    validate_name,
    validate_namespace_name,
    validate_records,
)

PROTOCOL_VERSION = 1

KNOWN_OPERATIONS = {
    "delegate_namespace",
    "grant_member",
    "register_domain",
    "update_records",
    "transfer_initiate",
    "transfer_accept",
    "transfer_cancel",
    "revoke_domain",
    "revoke_namespace",
    "rotate_controller",
}

# Fields every signed operation must carry.
ENVELOPE_FIELDS = {"v", "op", "actor", "nonce", "ts", "body", "sig"}


class RegistryState:
    """Mutable registry state with a deterministic ``apply`` function."""

    def __init__(self, root_public: str | None = None) -> None:
        self.root_public: str | None = root_public
        self.revision: int = 0
        self.namespaces: dict[str, dict] = {}
        self.domains: dict[str, dict] = {}
        self.nonces: dict[str, int] = {}
        self.audit: list[dict] = []
        self.history: list[dict] = []

    # ------------------------------------------------------------------ #
    # serialisation
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        return {
            "root_public": self.root_public,
            "revision": self.revision,
            "namespaces": self.namespaces,
            "domains": self.domains,
            "nonces": self.nonces,
            "audit": self.audit,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RegistryState":
        state = cls(root_public=data.get("root_public"))
        state.revision = data.get("revision", 0)
        state.namespaces = data.get("namespaces", {})
        state.domains = data.get("domains", {})
        state.nonces = data.get("nonces", {})
        state.audit = data.get("audit", [])
        state.history = data.get("history", [])
        return state

    def clone(self) -> "RegistryState":
        return RegistryState.from_dict(copy.deepcopy(self.to_dict()))

    # ------------------------------------------------------------------ #
    # queries
    # ------------------------------------------------------------------ #
    def governing_namespace(self, name: str) -> dict | None:
        """Longest delegated namespace that encloses ``name``."""
        best: dict | None = None
        for ns_name, ns in self.namespaces.items():
            if name == ns_name or name.endswith("." + ns_name):
                if best is None or len(ns_name) > len(best["name"]):
                    best = ns
        return best

    def is_root(self, actor: str) -> bool:
        return self.root_public is not None and actor == self.root_public

    def snapshot_for_dns(self) -> dict[str, dict]:
        """Publishable names: not revoked, inside an active namespace.

        ``pending_transfer`` is deliberately included. Records are frozen while
        a transfer is pending, but the name is still owned and must keep
        resolving; a handover should not cause downtime. Revocation is the only
        domain state that withdraws a name.
        """
        published: dict[str, dict] = {}
        for name, domain in self.domains.items():
            if domain["status"] == "revoked":
                continue
            ns = self.governing_namespace(name)
            if ns is None or ns["status"] != "active":
                continue
            published[name] = dict(domain["records"])
        return published

    def verify_audit_chain(self) -> dict:
        prev = "0" * 64
        for index, record in enumerate(self.audit):
            body = {k: v for k, v in record.items() if k != "hash"}
            expected = crypto.sha256_hex(crypto.canonical_json(body))
            if record.get("prev_hash") != prev:
                return {"ok": False, "broken_at": index + 1,
                        "reason": "prev_hash mismatch"}
            if record.get("hash") != expected:
                return {"ok": False, "broken_at": index + 1,
                        "reason": "record hash mismatch"}
            prev = record["hash"]
        return {"ok": True, "length": len(self.audit),
                "head": prev}

    # ------------------------------------------------------------------ #
    # operation application
    # ------------------------------------------------------------------ #
    def apply(self, op: dict) -> dict:
        """Validate and commit one operation. Raises ``RegistryError``."""
        self._verify_envelope(op)
        nonce_key = f"{op['actor']}|{op['nonce']}"
        if nonce_key in self.nonces:
            raise RegistryError(
                "REPLAY_DETECTED",
                "this operation nonce has already been used "
                f"(first seen at revision {self.nonces[nonce_key]})",
            )

        handler = getattr(self, f"_op_{op['op']}", None)
        if handler is None:
            raise RegistryError("UNKNOWN_OPERATION", f"unsupported operation {op['op']!r}")

        # Handlers validate fully before they mutate, so a raise below leaves
        # the state untouched.
        detail, target = handler(op)

        self.revision += 1
        self.nonces[nonce_key] = self.revision

        entry = {
            "revision": self.revision,
            "op": op["op"],
            "target": target,
            "actor": op["actor"],
            "detail": detail,
            "ts": op.get("ts"),
        }
        self.history.append(entry)
        self._append_audit(entry)

        return {
            "revision": self.revision,
            "op": op["op"],
            "target": target,
            "detail": detail,
        }

    def probe(self, op: dict) -> dict:
        """Validate against a throwaway copy; used before replication."""
        return self.clone().apply(op)

    # ------------------------------------------------------------------ #
    # envelope validation
    # ------------------------------------------------------------------ #
    def _verify_envelope(self, op: Any) -> None:
        if not isinstance(op, dict):
            raise RegistryError("MALFORMED_OPERATION", "operation must be an object")
        missing = ENVELOPE_FIELDS - set(op)
        if missing:
            raise RegistryError(
                "MALFORMED_OPERATION",
                f"missing field(s): {', '.join(sorted(missing))}",
            )
        if op["v"] != PROTOCOL_VERSION:
            raise RegistryError(
                "UNSUPPORTED_VERSION",
                f"unsupported protocol version {op['v']!r}; expected {PROTOCOL_VERSION}",
            )
        if op["op"] not in KNOWN_OPERATIONS:
            raise RegistryError("UNKNOWN_OPERATION", f"unsupported operation {op['op']!r}")
        if not isinstance(op["body"], dict):
            raise RegistryError("MALFORMED_OPERATION", "body must be an object")
        if not isinstance(op["nonce"], str) or len(op["nonce"]) < 16:
            raise RegistryError("MALFORMED_OPERATION", "nonce must be a string of >=16 chars")
        if not isinstance(op["ts"], int):
            raise RegistryError("MALFORMED_OPERATION", "ts must be an integer")
        if not crypto.valid_public_key(op["actor"]):
            raise RegistryError("MALFORMED_OPERATION", "actor is not a valid Ed25519 public key")
        if not isinstance(op["sig"], str):
            raise RegistryError("MALFORMED_OPERATION", "sig must be a string")

        if not crypto.verify_signature(
            op["actor"], crypto.signing_bytes(op), op["sig"]
        ):
            raise RegistryError(
                "INVALID_SIGNATURE",
                "signature does not verify against the supplied actor key",
                401,
            )

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #
    def _append_audit(self, entry: dict) -> None:
        prev = self.audit[-1]["hash"] if self.audit else "0" * 64
        record = {
            "seq": len(self.audit) + 1,
            "revision": entry["revision"],
            "op": entry["op"],
            "target": entry["target"],
            "actor": entry["actor"],
            "detail": entry["detail"],
            "prev_hash": prev,
        }
        record["hash"] = crypto.sha256_hex(crypto.canonical_json(record))
        self.audit.append(record)

    def _require_active_namespace(self, ns: dict) -> None:
        if ns["status"] != "active":
            raise RegistryError(
                "NAMESPACE_REVOKED",
                f"namespace {ns['name']} has been revoked and cannot be used",
                409,
            )

    def _require_controller(self, ns: dict, actor: str, action: str) -> None:
        if not self.is_root(actor) and ns["controller"] != actor:
            raise RegistryError(
                "UNAUTHORIZED",
                f"only the controller of {ns['name']} (or the root authority) may {action}",
                403,
            )

    def _get_domain(self, name: str) -> dict:
        domain = self.domains.get(name)
        if domain is None:
            raise RegistryError("NAME_NOT_FOUND", f"{name} is not registered", 404)
        return domain

    # ------------------------------------------------------------------ #
    # operation handlers
    # ------------------------------------------------------------------ #
    def _op_delegate_namespace(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_namespace_name(body.get("name", ""))
        controller = body.get("controller")
        if not isinstance(controller, str) or not crypto.valid_public_key(controller):
            raise RegistryError("INVALID_KEY", "controller must be a valid Ed25519 public key")

        if name in self.namespaces:
            raise RegistryError("NAMESPACE_TAKEN", f"{name} is already delegated", 409)
        if name in self.domains:
            raise RegistryError("NAMESPACE_TAKEN", f"{name} is already registered as a domain", 409)

        parent_name = parent_of(name)
        if parent_name == ROOT_ZONE:
            if not self.is_root(op["actor"]):
                raise RegistryError(
                    "UNAUTHORIZED",
                    "only the root authority may delegate top-level campus namespaces",
                    403,
                )
        else:
            parent_ns = self.namespaces.get(parent_name or "")
            if parent_ns is None:
                raise RegistryError(
                    "PARENT_NAMESPACE_NOT_FOUND",
                    f"{parent_name} is not a delegated namespace; delegate the parent first",
                    404,
                )
            self._require_active_namespace(parent_ns)
            self._require_controller(parent_ns, op["actor"], "delegate sub-namespaces")

        record = {
            "name": name,
            "controller": controller,
            "parent": parent_name,
            "status": "active",
            "delegated_by": op["actor"],
            "created_revision": self.revision + 1,
            "members": {},
        }
        self.namespaces[name] = record
        return {"namespace": name, "controller": controller, "parent": parent_name}, name

    def _op_grant_member(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_namespace_name(body.get("namespace", ""))
        member = body.get("member")
        if not isinstance(member, str) or not crypto.valid_public_key(member):
            raise RegistryError("INVALID_KEY", "member must be a valid Ed25519 public key")

        ns = self.namespaces.get(name)
        if ns is None:
            raise RegistryError("NAMESPACE_NOT_FOUND", f"{name} is not a delegated namespace", 404)
        self._require_active_namespace(ns)
        self._require_controller(ns, op["actor"], "grant registrar rights")

        can_register = bool(body.get("can_register", True))
        ns["members"][member] = {"can_register": can_register}
        return {"namespace": name, "member": member, "can_register": can_register}, name

    def _op_register_domain(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        records = validate_records(body.get("records", {}))

        if name in self.domains:
            existing = self.domains[name]
            raise RegistryError(
                "NAME_TAKEN",
                f"{name} is already registered to {crypto.fingerprint(existing['owner'])}",
                409,
            )
        if name in self.namespaces:
            raise RegistryError("NAME_TAKEN", f"{name} is a delegated namespace", 409)

        ns = self.governing_namespace(name)
        if ns is None:
            raise RegistryError(
                "NO_NAMESPACE",
                f"{name} does not fall inside any delegated campus namespace",
                404,
            )
        self._require_active_namespace(ns)

        actor = op["actor"]
        allowed = (
            actor == ns["controller"]
            or self.is_root(actor)
            or ns["members"].get(actor, {}).get("can_register", False)
        )
        if not allowed:
            raise RegistryError(
                "UNAUTHORIZED",
                f"{crypto.fingerprint(actor)} is not authorized to register names under "
                f"{ns['name']}",
                403,
            )

        domain = {
            "name": name,
            "owner": actor,
            "namespace": ns["name"],
            "records": records,
            "status": "active",
            "created_revision": self.revision + 1,
            "updated_revision": self.revision + 1,
            "transfer": None,
        }
        self.domains[name] = domain
        return {"name": name, "owner": actor, "records": records, "namespace": ns["name"]}, name

    def _op_update_records(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        records = validate_records(body.get("records", {}))
        domain = self._get_domain(name)

        if domain["status"] == "revoked":
            raise RegistryError("NAME_REVOKED", f"{name} has been revoked", 409)
        if domain["status"] == "pending_transfer":
            raise RegistryError(
                "TRANSFER_PENDING",
                f"{name} has a pending ownership transfer; records are frozen until it "
                "completes or is cancelled",
                409,
            )

        ns = self.governing_namespace(name)
        actor = op["actor"]
        if actor != domain["owner"] and not (ns and actor == ns["controller"]):
            raise RegistryError(
                "UNAUTHORIZED",
                f"only the owner of {name} (or its namespace controller) may change records",
                403,
            )

        previous = dict(domain["records"])
        domain["records"] = records
        domain["updated_revision"] = self.revision + 1
        return {"name": name, "before": previous, "after": records}, name

    def _op_transfer_initiate(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        new_owner = body.get("new_owner")
        domain = self._get_domain(name)

        if not isinstance(new_owner, str) or not crypto.valid_public_key(new_owner):
            raise RegistryError("INVALID_KEY", "new_owner must be a valid Ed25519 public key")
        if domain["status"] == "revoked":
            raise RegistryError("NAME_REVOKED", f"{name} has been revoked", 409)
        if domain["status"] == "pending_transfer":
            raise RegistryError("TRANSFER_PENDING", f"{name} already has a pending transfer", 409)
        if op["actor"] != domain["owner"]:
            raise RegistryError(
                "UNAUTHORIZED", f"only the current owner may transfer {name}", 403
            )
        if new_owner == domain["owner"]:
            raise RegistryError(
                "INVALID_TRANSFER", "the proposed owner already owns this domain"
            )

        domain["status"] = "pending_transfer"
        domain["transfer"] = {
            "new_owner": new_owner,
            "initiated_by": op["actor"],
            "initiated_revision": self.revision + 1,
        }
        return {"name": name, "new_owner": new_owner, "state": "pending_transfer"}, name

    def _op_transfer_accept(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        domain = self._get_domain(name)

        if domain["status"] != "pending_transfer" or not domain["transfer"]:
            raise RegistryError("NO_PENDING_TRANSFER", f"{name} has no pending transfer", 409)
        if op["actor"] != domain["transfer"]["new_owner"]:
            raise RegistryError(
                "UNAUTHORIZED",
                "only the proposed new owner may accept this transfer",
                403,
            )

        previous_owner = domain["owner"]
        domain["owner"] = op["actor"]
        domain["status"] = "active"
        domain["transfer"] = None
        domain["updated_revision"] = self.revision + 1
        return {"name": name, "previous_owner": previous_owner, "new_owner": op["actor"]}, name

    def _op_transfer_cancel(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        domain = self._get_domain(name)

        if domain["status"] != "pending_transfer":
            raise RegistryError("NO_PENDING_TRANSFER", f"{name} has no pending transfer", 409)
        if op["actor"] != domain["owner"]:
            raise RegistryError(
                "UNAUTHORIZED", f"only the current owner may cancel the transfer of {name}", 403
            )

        domain["status"] = "active"
        domain["transfer"] = None
        domain["updated_revision"] = self.revision + 1
        return {"name": name, "state": "active"}, name

    def _op_revoke_domain(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_name(body.get("name", ""))
        domain = self._get_domain(name)

        if domain["status"] == "revoked":
            raise RegistryError("NAME_REVOKED", f"{name} is already revoked", 409)

        ns = self.governing_namespace(name)
        actor = op["actor"]
        if not (
            actor == domain["owner"]
            or self.is_root(actor)
            or (ns is not None and actor == ns["controller"])
        ):
            raise RegistryError(
                "UNAUTHORIZED",
                f"only the owner, the namespace controller or the root authority may "
                f"revoke {name}",
                403,
            )

        domain["status"] = "revoked"
        domain["revoked_revision"] = self.revision + 1
        domain["revoked_reason"] = str(body.get("reason", ""))[:280]
        return {"name": name, "state": "revoked",
                "reason": domain["revoked_reason"]}, name

    def _op_revoke_namespace(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_namespace_name(body.get("name", ""))
        ns = self.namespaces.get(name)
        if ns is None:
            raise RegistryError("NAMESPACE_NOT_FOUND", f"{name} is not delegated", 404)
        self._require_controller(ns, op["actor"], "revoke this namespace")

        ns["status"] = "revoked"
        ns["revoked_revision"] = self.revision + 1
        ns["revoked_reason"] = str(body.get("reason", ""))[:280]
        return {"namespace": name, "state": "revoked"}, name

    def _op_rotate_controller(self, op: dict) -> tuple[dict, str]:
        body = op["body"]
        name = validate_namespace_name(body.get("name", ""))
        new_controller = body.get("new_controller")
        ns = self.namespaces.get(name)
        if ns is None:
            raise RegistryError("NAMESPACE_NOT_FOUND", f"{name} is not delegated", 404)
        self._require_controller(ns, op["actor"], "rotate the controller key")
        if not isinstance(new_controller, str) or not crypto.valid_public_key(new_controller):
            raise RegistryError("INVALID_KEY", "new_controller must be a valid public key")

        previous = ns["controller"]
        ns["controller"] = new_controller
        return {"namespace": name, "previous": previous, "controller": new_controller}, name
