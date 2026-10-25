"""Create the demo identities used by the prototype.

Each identity is an Ed25519 key pair stored as a JSON file. The registry never
sees the private half: it authenticates operations purely by verifying the
signature against the public key carried inside the operation.

NOTE FOR THE PROTOTYPE: these key files live on disk so that the demo portal can
sign on the user's behalf. In a real deployment signing happens on the client
(browser wallet / HSM) and the private key never leaves the user's device.
"""

from __future__ import annotations

import argparse
import json
import os

from . import crypto

DEFAULT_IDENTITIES = [
    ("root", "Campus Root Authority", "root", None),
    ("cs-admin", "Computer Science Department", "department", "cs.test"),
    ("library-admin", "Library Administration", "department", "library.test"),
    ("alice", "Alice Rivera (CS student)", "student", "cs.test"),
    ("bob", "Bob Chen (CS student)", "student", "cs.test"),
    ("mallory", "Mallory (unaffiliated attacker)", "outsider", None),
]


def create_identities(directory: str) -> dict[str, crypto.KeyPair]:
    os.makedirs(directory, exist_ok=True)
    keys: dict[str, crypto.KeyPair] = {}
    index = []

    for name, label, role, member_of in DEFAULT_IDENTITIES:
        path = os.path.join(directory, f"{name}.json")
        if os.path.exists(path):
            key = crypto.load_keypair(path)
        else:
            key = crypto.KeyPair.generate(label, role, member_of)
            crypto.save_keypair(key, path)
        keys[name] = key
        index.append(
            {
                "file": f"{name}.json",
                "name": name,
                "label": key.label,
                "role": key.role,
                "member_of": key.member_of,
                "public_key": key.public_key,
                "fingerprint": crypto.fingerprint(key.public_key),
            }
        )

    with open(os.path.join(directory, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)

    return keys


def load_identities(directory: str) -> list[dict]:
    index_path = os.path.join(directory, "index.json")
    with open(index_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create DCDNS demo identities")
    parser.add_argument("--dir", default="identities")
    args = parser.parse_args()

    keys = create_identities(args.dir)
    print(f"identities written to {os.path.abspath(args.dir)}\n")
    for name, key in keys.items():
        print(f"  {name:<14} {key.role:<12} {crypto.fingerprint(key.public_key)}  {key.label}")
    print(f"\nroot public key: {keys['root'].public_key}")


if __name__ == "__main__":
    main()
