"""Domain-name and record validation.

These rules run inside the deterministic state machine, so every node reaches
the same verdict for the same operation. They are deliberately strict: the
registry is authoritative for a controlled campus namespace, not a general
purpose registrar.
"""

from __future__ import annotations

import ipaddress
import re

from .errors import RegistryError

ROOT_ZONE = "test"

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Campus policy: registrants may only point names at internal address space.
# This is the kind of rule a university registry would actually enforce.
ALLOWED_A_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",        # RFC1918
        "172.16.0.0/12",     # RFC1918
        "192.168.0.0/16",    # RFC1918
        "127.0.0.0/8",       # loopback (useful for lab demos)
    )
]

SUPPORTED_RECORD_TYPES = {"A"}


def normalise(name: str) -> str:
    """Lower-case and strip the trailing dot of an absolute name."""
    if not isinstance(name, str):
        raise RegistryError("INVALID_NAME", "domain name must be a string")
    return name.strip().rstrip(".").lower()


def validate_name(name: str) -> str:
    """Validate a fully-qualified name and return its normal form."""
    name = normalise(name)
    if not name:
        raise RegistryError("INVALID_NAME", "domain name is empty")
    if len(name) > 253:
        raise RegistryError("INVALID_NAME", "domain name exceeds 253 characters")
    if "*" in name or " " in name or "/" in name:
        raise RegistryError("INVALID_NAME", "domain name contains forbidden characters")

    labels = name.split(".")
    if len(labels) < 2:
        raise RegistryError("INVALID_NAME", "domain name needs at least two labels")
    for label in labels:
        if not LABEL_RE.match(label):
            raise RegistryError(
                "INVALID_NAME",
                f"invalid label {label!r}: labels must be 1-63 characters of "
                "a-z, 0-9 and '-', and may not start or end with '-'",
            )
    if labels[-1] != ROOT_ZONE:
        raise RegistryError(
            "OUTSIDE_ROOT_ZONE",
            f"name must live under the .{ROOT_ZONE} root zone managed by this registry",
        )
    return name


def validate_namespace_name(name: str) -> str:
    name = validate_name(name)
    if name == ROOT_ZONE:
        raise RegistryError("INVALID_NAME", "the root zone cannot be delegated")
    return name


def parent_of(name: str) -> str | None:
    parts = name.split(".", 1)
    if len(parts) < 2:
        return None
    parent = parts[1]
    return parent if parent else None


def validate_records(records: dict) -> dict:
    """Validate and normalise a record set. v1 supports IPv4 ``A`` only."""
    if not isinstance(records, dict) or not records:
        raise RegistryError("INVALID_RECORDS", "records must be a non-empty object")

    unknown = set(records) - SUPPORTED_RECORD_TYPES
    if unknown:
        raise RegistryError(
            "UNSUPPORTED_RECORD_TYPE",
            f"unsupported record type(s): {', '.join(sorted(unknown))}; "
            f"this registry supports {', '.join(sorted(SUPPORTED_RECORD_TYPES))}",
        )

    value = records.get("A")
    if not isinstance(value, str) or not value.strip():
        raise RegistryError("INVALID_RECORDS", "record 'A' must be a dotted IPv4 address")

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise RegistryError(
            "INVALID_RECORDS", f"{value!r} is not a valid IP address"
        ) from None

    if address.version != 4:
        raise RegistryError("INVALID_RECORDS", "only IPv4 A records are supported")

    if not any(address in net for net in ALLOWED_A_NETWORKS):
        raise RegistryError(
            "RECORD_NOT_ALLOWED",
            f"{address} is outside the permitted campus address space "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)",
        )

    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise RegistryError("RECORD_NOT_ALLOWED", f"{address} is not assignable")

    return {"A": str(address)}
