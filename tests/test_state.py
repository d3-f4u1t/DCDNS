"""Unit tests for the deterministic registry state machine."""

from __future__ import annotations

import copy

import pytest

from dcdns import crypto
from dcdns.errors import RegistryError
from dcdns.state import RegistryState


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def keys():
    return {
        "root": crypto.KeyPair.generate("Campus Root Authority", "root"),
        "cs": crypto.KeyPair.generate("Computer Science Dept", "department"),
        "library": crypto.KeyPair.generate("Library Administration", "department"),
        "alice": crypto.KeyPair.generate("Alice (student)", "student"),
        "bob": crypto.KeyPair.generate("Bob (student)", "student"),
        "mallory": crypto.KeyPair.generate("Mallory (attacker)", "student"),
    }


@pytest.fixture
def registry(keys):
    """A registry seeded with two department namespaces."""
    state = RegistryState(root_public=keys["root"].public_key)

    state.apply(crypto.sign_op(keys["root"], "delegate_namespace", {
        "name": "cs.test", "controller": keys["cs"].public_key,
    }))
    state.apply(crypto.sign_op(keys["root"], "delegate_namespace", {
        "name": "library.test", "controller": keys["library"].public_key,
    }))
    # CS allows nominated students to self-register under its namespace.
    state.apply(crypto.sign_op(keys["cs"], "grant_member", {
        "namespace": "cs.test", "member": keys["alice"].public_key,
    }))
    return state


def register(keys, state, name="robotics.cs.test", ip="10.20.5.42",
             signer="alice"):
    return state.apply(crypto.sign_op(keys[signer], "register_domain", {
        "name": name, "records": {"A": ip},
    }))


# --------------------------------------------------------------------------- #
# happy paths
# --------------------------------------------------------------------------- #
def test_register_domain_succeeds(keys, registry):
    result = registry.apply(crypto.sign_op(keys["alice"], "register_domain", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.42"},
    }))
    assert result["revision"] > 0
    domain = registry.domains["robotics.cs.test"]
    assert domain["owner"] == keys["alice"].public_key
    assert domain["status"] == "active"
    assert domain["namespace"] == "cs.test"


def test_names_are_case_insensitive_and_canonicalised(keys, registry):
    registry.apply(crypto.sign_op(keys["alice"], "register_domain", {
        "name": "ROBOTICS.CS.TEST.", "records": {"A": "10.20.5.42"},
    }))
    assert "robotics.cs.test" in registry.domains


def test_update_records_by_owner(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["alice"], "update_records", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.99"},
    }))
    assert registry.domains["robotics.cs.test"]["records"]["A"] == "10.20.5.99"


def test_sub_namespace_delegation_chain(keys, registry):
    """cs.test -> team.cs.test -> student registers project.team.cs.test."""
    registry.apply(crypto.sign_op(keys["cs"], "delegate_namespace", {
        "name": "team.cs.test", "controller": keys["alice"].public_key,
    }))
    registry.apply(crypto.sign_op(keys["alice"], "register_domain", {
        "name": "project.team.cs.test", "records": {"A": "10.20.5.7"},
    }))
    assert registry.domains["project.team.cs.test"]["namespace"] == "team.cs.test"


def test_full_transfer_flow(keys, registry):
    register(keys, registry)

    registry.apply(crypto.sign_op(keys["alice"], "transfer_initiate", {
        "name": "robotics.cs.test", "new_owner": keys["bob"].public_key,
    }))
    assert registry.domains["robotics.cs.test"]["status"] == "pending_transfer"
    # A handover freezes the record but must not take the name out of DNS.
    assert "robotics.cs.test" in registry.snapshot_for_dns()

    registry.apply(crypto.sign_op(keys["bob"], "transfer_accept", {
        "name": "robotics.cs.test",
    }))
    domain = registry.domains["robotics.cs.test"]
    assert domain["owner"] == keys["bob"].public_key
    assert domain["status"] == "active"


def test_revocation_removes_from_dns_snapshot(keys, registry):
    register(keys, registry)
    assert "robotics.cs.test" in registry.snapshot_for_dns()

    registry.apply(crypto.sign_op(keys["alice"], "revoke_domain", {
        "name": "robotics.cs.test", "reason": "end of semester",
    }))
    assert "robotics.cs.test" not in registry.snapshot_for_dns()
    assert registry.domains["robotics.cs.test"]["status"] == "revoked"


def test_namespace_revocation_withdraws_domains_from_dns(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["cs"], "revoke_namespace", {
        "name": "cs.test", "reason": "department dissolved",
    }))
    assert registry.snapshot_for_dns() == {}


# --------------------------------------------------------------------------- #
# authorization failures
# --------------------------------------------------------------------------- #
def test_duplicate_registration_rejected(keys, registry):
    register(keys, registry)
    with pytest.raises(RegistryError) as exc:
        register(keys, registry, ip="10.20.5.43", signer="cs")
    assert exc.value.code == "NAME_TAKEN"


def test_forged_update_by_another_student_rejected(keys, registry):
    register(keys, registry)
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["mallory"], "update_records", {
            "name": "robotics.cs.test", "records": {"A": "10.20.5.66"},
        }))
    assert exc.value.code == "UNAUTHORIZED"
    assert registry.domains["robotics.cs.test"]["records"]["A"] == "10.20.5.42"


def test_cross_department_registration_rejected(keys, registry):
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["library"], "register_domain", {
            "name": "robotics.cs.test", "records": {"A": "10.20.5.42"},
        }))
    assert exc.value.code == "UNAUTHORIZED"


def test_unauthorized_namespace_delegation_rejected(keys, registry):
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["library"], "delegate_namespace", {
            "name": "secret.cs.test", "controller": keys["library"].public_key,
        }))
    assert exc.value.code == "UNAUTHORIZED"


def test_non_root_cannot_create_top_level_namespace(keys, registry):
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["cs"], "delegate_namespace", {
            "name": "evil.test", "controller": keys["cs"].public_key,
        }))
    assert exc.value.code == "UNAUTHORIZED"


def test_registration_outside_any_namespace_rejected(keys, registry):
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["root"], "register_domain", {
            "name": "stray.test", "records": {"A": "10.20.5.42"},
        }))
    assert exc.value.code == "NO_NAMESPACE"


def test_transfer_requires_owner(keys, registry):
    register(keys, registry)
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["mallory"], "transfer_initiate", {
            "name": "robotics.cs.test", "new_owner": keys["mallory"].public_key,
        }))
    assert exc.value.code == "UNAUTHORIZED"


def test_transfer_accept_requires_new_owner(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["alice"], "transfer_initiate", {
        "name": "robotics.cs.test", "new_owner": keys["bob"].public_key,
    }))
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["mallory"], "transfer_accept", {
            "name": "robotics.cs.test",
        }))
    assert exc.value.code == "UNAUTHORIZED"


def test_records_frozen_during_pending_transfer(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["alice"], "transfer_initiate", {
        "name": "robotics.cs.test", "new_owner": keys["bob"].public_key,
    }))
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["alice"], "update_records", {
            "name": "robotics.cs.test", "records": {"A": "10.20.5.77"},
        }))
    assert exc.value.code == "TRANSFER_PENDING"


# --------------------------------------------------------------------------- #
# signature and replay protection
# --------------------------------------------------------------------------- #
def test_invalid_signature_rejected(keys, registry):
    op = crypto.sign_op(keys["alice"], "register_domain", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.42"},
    })
    op["body"]["records"]["A"] = "10.20.5.43"  # tamper after signing
    with pytest.raises(RegistryError) as exc:
        registry.apply(op)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_impersonation_rejected(keys, registry):
    """Sign with mallory's key but claim to be alice."""
    op = crypto.sign_op(keys["mallory"], "register_domain", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.42"},
    })
    op["actor"] = keys["alice"].public_key
    with pytest.raises(RegistryError) as exc:
        registry.apply(op)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_replayed_operation_rejected(keys, registry):
    op = crypto.sign_op(keys["alice"], "register_domain", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.42"},
    })
    registry.apply(op)
    with pytest.raises(RegistryError) as exc:
        registry.apply(copy.deepcopy(op))
    assert exc.value.code == "REPLAY_DETECTED"


def test_rejected_operations_do_not_mutate_state(keys, registry):
    """A rejection must be side-effect free, including nonce consumption.

    The same invalid operation therefore fails the same way every time, and an
    attacker gains nothing by resubmitting it.
    """
    before = registry.revision
    op = crypto.sign_op(keys["mallory"], "update_records", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.66"},
    })
    for _ in range(2):
        with pytest.raises(RegistryError) as exc:
            registry.apply(op)
        assert exc.value.code == "NAME_NOT_FOUND"
    assert registry.revision == before
    assert op["nonce"] not in {k.split("|")[1] for k in registry.nonces}


# --------------------------------------------------------------------------- #
# record policy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ip", [
    "8.8.8.8",
    "203.0.113.9",
    "1.1.1.1",
    "0.0.0.0",
    "224.0.0.1",
])
def test_public_or_reserved_addresses_rejected(keys, registry, ip):
    with pytest.raises(RegistryError) as exc:
        register(keys, registry, ip=ip)
    assert exc.value.code == "RECORD_NOT_ALLOWED"


def test_ipv6_and_unknown_record_types_rejected(keys, registry):
    with pytest.raises(RegistryError) as exc:
        registry.apply(crypto.sign_op(keys["alice"], "register_domain", {
            "name": "v6.cs.test", "records": {"AAAA": "2001:db8::1"},
        }))
    assert exc.value.code == "UNSUPPORTED_RECORD_TYPE"


def test_names_outside_root_zone_rejected(keys, registry):
    with pytest.raises(RegistryError) as exc:
        register(keys, registry, name="robotics.cs.example.com")
    assert exc.value.code == "OUTSIDE_ROOT_ZONE"


def test_malformed_domain_names_rejected(keys, registry):
    for bad in ["-x.cs.test", "a..cs.test", "cs.test", "x" * 64 + ".cs.test"]:
        with pytest.raises(RegistryError):
            register(keys, registry, name=bad)


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def test_audit_chain_is_valid(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["alice"], "update_records", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.50"},
    }))
    report = registry.verify_audit_chain()
    assert report["ok"] is True
    assert report["length"] == registry.revision


def test_audit_chain_detects_tampering(keys, registry):
    register(keys, registry)
    registry.audit[0]["detail"]["name"] = "evil.cs.test"  # tamper
    report = registry.verify_audit_chain()
    assert report["ok"] is False
    assert report["broken_at"] == 1


def test_audit_records_rejected_operations(keys, registry):
    with pytest.raises(RegistryError):
        register(keys, registry, ip="8.8.8.8")
    assert len(registry.audit) == 3  # seed ops only; rejected ops never mutate state
    assert registry.revision == 3


def test_history_is_per_domain(keys, registry):
    register(keys, registry)
    registry.apply(crypto.sign_op(keys["alice"], "update_records", {
        "name": "robotics.cs.test", "records": {"A": "10.20.5.50"},
    }))
    entries = [h for h in registry.history if h["target"] == "robotics.cs.test"]
    assert len(entries) == 2


def test_state_round_trips_through_serialisation(keys, registry):
    register(keys, registry)
    restored = RegistryState.from_dict(registry.to_dict())
    assert restored.domains == registry.domains
    assert restored.verify_audit_chain()["ok"] is True
