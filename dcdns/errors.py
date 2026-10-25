"""Error types shared across the registry.

Every rejection carries a stable machine-readable ``code`` so that the test
suite, the API and the portal all describe failures identically.
"""

from __future__ import annotations


class RegistryError(Exception):
    """A deterministic protocol-level rejection."""

    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status

    def as_dict(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message}}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"RegistryError({self.code!r}, {self.message!r})"


class NotLeader(Exception):
    """Raised when a write reaches a node that is not the current leader."""

    def __init__(self, leader_id: str | None = None, leader_url: str | None = None):
        super().__init__(f"not the leader (current leader: {leader_id})")
        self.leader_id = leader_id
        self.leader_url = leader_url


class NoQuorum(Exception):
    """Raised when a write cannot be committed by a majority of nodes."""
