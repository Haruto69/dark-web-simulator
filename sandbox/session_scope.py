"""Per-session sandbox scoping.

Milestone 2 replaces the single shared ``primary`` sandbox with one logical
sandbox per learner session. The mapping is a *derived* one:

    flask session uuid  --(sha256)-->  sandbox id

so the sandbox id is:

  * stable for the lifetime of a session (idempotent create/reset),
  * never taken verbatim from request data (the cookie value is server-issued
    and signed, and it is hashed before it ever reaches a backend),
  * still validated by :func:`sandbox.backends.base.validate_sandbox_id`.

Nothing here trusts a client-supplied sandbox id. There is deliberately no
inverse function: an instructor enumerates sandboxes from the backend, not by
un-hashing an id.
"""

import hashlib

from .backends.base import validate_sandbox_id

#: Prefix marking a session-scoped sandbox, so instructor listings can tell
#: them apart from anything seeded manually in a lab.
SESSION_PREFIX = "sess-"

#: Length of the hex digest slice used. 16 hex chars = 64 bits of the digest;
#: collisions between concurrent classroom sessions are not a practical
#: concern, and a collision would only merge two workspaces, never leak a
#: credential (credentials are derived from the session id itself).
DIGEST_CHARS = 16


def sandbox_id_for_session(session_id):
    """Return the derived, validated sandbox id for ``session_id``."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")
    digest = hashlib.sha256(session_id.strip().encode("utf-8")).hexdigest()
    return validate_sandbox_id(SESSION_PREFIX + digest[:DIGEST_CHARS])


def is_session_sandbox(sandbox_id):
    return isinstance(sandbox_id, str) and sandbox_id.startswith(SESSION_PREFIX)
