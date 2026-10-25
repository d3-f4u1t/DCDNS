"""Cryptographic primitives for the DCDNS registry.

Design notes
------------
* Identity == Ed25519 public key. There is no separate account database; a
  participant *is* the holder of a private key.
* Every operation is signed over a domain-separated canonical serialisation.
  Canonicalisation is strict (sorted keys, no whitespace, UTF-8) so that the
  exact bytes verified are the exact bytes committed to the log.
* Signatures cover a nonce, which the state machine records. Replaying a valid
  signed operation therefore fails even though the signature itself is valid.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Domain separation: a signature produced for DCDNS can never be replayed as a
# signature over some other protocol's payload, and vice versa.
SIGNING_CONTEXT = b"DCDNS-OP-V1\n"

PUBKEY_LEN = 32


# --------------------------------------------------------------------------- #
# encoding helpers
# --------------------------------------------------------------------------- #
def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for hashing and signing."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #
@dataclass
class KeyPair:
    """An Ed25519 identity.

    ``label`` and ``role`` are demo metadata only; they are never trusted by the
    registry, which knows identities solely as public keys.
    """

    private_key: Ed25519PrivateKey
    label: str = "anonymous"
    role: str = "participant"
    member_of: str | None = None
    _public_b64: str = field(default="", init=False)

    def __post_init__(self) -> None:
        raw = self.private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._public_b64 = b64encode(raw)

    # -- identity ---------------------------------------------------------- #
    @property
    def public_key(self) -> str:
        return self._public_b64

    @property
    def short(self) -> str:
        return self._public_b64[:12]

    # -- operations -------------------------------------------------------- #
    def sign(self, data: bytes) -> str:
        return b64encode(self.private_key.sign(data))

    def sign_operation(self, op: dict) -> dict:
        """Attach ``actor`` and ``sig`` to an unsigned operation."""
        unsigned = {k: v for k, v in op.items() if k != "sig"}
        unsigned["actor"] = self.public_key
        unsigned.pop("sig", None)
        unsigned["sig"] = self.sign(signing_bytes(unsigned))
        return unsigned

    # -- serialisation ----------------------------------------------------- #
    def to_dict(self, include_private: bool = True) -> dict:
        data = {
            "label": self.label,
            "role": self.role,
            "member_of": self.member_of,
            "public_key": self.public_key,
        }
        if include_private:
            seed = self.private_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            data["private_key"] = b64encode(seed)
        return data

    @classmethod
    def generate(cls, label: str = "anonymous", role: str = "participant",
                 member_of: str | None = None) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate(), label=label, role=role,
                   member_of=member_of)

    @classmethod
    def from_dict(cls, data: dict) -> "KeyPair":
        seed = b64decode(data["private_key"])
        return cls(
            Ed25519PrivateKey.from_private_bytes(seed),
            label=data.get("label", "imported"),
            role=data.get("role", "participant"),
            member_of=data.get("member_of"),
        )


def verify_signature(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    try:
        raw = b64decode(public_key_b64)
    except Exception:
        return False
    if len(raw) != PUBKEY_LEN:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(
            b64decode(signature_b64), data
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:
        return False


def valid_public_key(public_key_b64: str) -> bool:
    try:
        return len(b64decode(public_key_b64)) == PUBKEY_LEN
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# operation envelopes
# --------------------------------------------------------------------------- #
def signing_bytes(unsigned_op: dict) -> bytes:
    payload = {k: v for k, v in unsigned_op.items() if k != "sig"}
    return SIGNING_CONTEXT + canonical_json(payload)


def new_nonce() -> str:
    return secrets.token_hex(16)


def build_unsigned(op: str, body: dict, actor: str | None = None) -> dict:
    envelope = {
        "v": 1,
        "op": op,
        "nonce": new_nonce(),
        "ts": int(time.time()),
        "body": body,
    }
    if actor:
        envelope["actor"] = actor
    return envelope


def sign_op(key: KeyPair, op: str, body: dict) -> dict:
    """Convenience: build + sign a complete operation."""
    return key.sign_operation(build_unsigned(op, body))


# --------------------------------------------------------------------------- #
# key files
# --------------------------------------------------------------------------- #
def save_keypair(key: KeyPair, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(key.to_dict(), fh, indent=2)
    try:  # best effort on POSIX; on Windows this is a no-op
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_keypair(path: str) -> KeyPair:
    with open(path, "r", encoding="utf-8") as fh:
        return KeyPair.from_dict(json.load(fh))


def fingerprint(public_key_b64: str) -> str:
    """Short, human-comparable fingerprint (like an SSH key fingerprint)."""
    digest = hashlib.sha256(b64decode(public_key_b64)).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 16, 2))
