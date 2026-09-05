"""Shared identity/derivation helpers for the simulation domain.

Mirrors the identity rules already established in ``rewindsec.core`` (events,
scheduler): ASCII identities restricted to a charset that excludes ``|`` (the
derivation delimiter), and SHA-256-derived ids rather than ``uuid4`` wherever
an id must be *reproducible* from ``(owning identity, sequence number)``.

Domain-derived ids (action ids, consequence ids, incident ids, world-mutation
ids, scheduling-audit ids) each use their own domain-separation label, defined
next to the type they identify, so that two different kinds of id built from
the same ``(session_id, seq)`` pair can never collide.
"""

import hashlib

from rewindsec.domain.errors import InvalidIdentityError

__all__ = [
    "MAX_JSON_SAFE_INT",
    "MAX_IDENTITY_LENGTH",
    "DERIVED_ID_LENGTH",
    "validate_identity",
    "validate_nonneg_int",
    "validate_bounded_str",
    "derive_id",
]

MAX_JSON_SAFE_INT = 2 ** 53 - 1
MAX_IDENTITY_LENGTH = 128
DERIVED_ID_LENGTH = 32


def validate_identity(value, what="identity"):
    """Return *value* if it is a stable, derivable identity string, else raise."""
    if not isinstance(value, str):
        raise InvalidIdentityError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if not value:
        raise InvalidIdentityError("%s must not be empty" % what)
    if len(value) > MAX_IDENTITY_LENGTH:
        raise InvalidIdentityError(
            "%s must be at most %d characters, got %d"
            % (what, MAX_IDENTITY_LENGTH, len(value)))
    for char in value:
        if not char.isascii():
            raise InvalidIdentityError("%s must be ASCII: %r" % (what, value))
        if not (char.isalnum() or char in "-_.:"):
            raise InvalidIdentityError(
                "%s may contain only [A-Za-z0-9_.:-]: %r" % (what, value))
    return value


def validate_nonneg_int(value, what, max_value=MAX_JSON_SAFE_INT):
    """Return *value* if it is a non-negative, JSON-safe int, else raise.

    ``bool`` is rejected explicitly even though it is an ``int`` subclass: a
    caller passing ``True`` where a count or sequence number is expected is
    always a mistake, and silently treating it as ``1`` would hide it.
    """
    if isinstance(value, bool):
        raise InvalidIdentityError(
            "%s must be an int, not a bool; got %r" % (what, value))
    if not isinstance(value, int):
        raise InvalidIdentityError(
            "%s must be an int, got %s" % (what, type(value).__name__))
    if value < 0:
        raise InvalidIdentityError("%s must not be negative, got %d" % (what, value))
    if value > max_value:
        raise InvalidIdentityError(
            "%s exceeds the bound %d: %d" % (what, max_value, value))
    return value


def validate_bounded_str(value, what, max_length, allow_empty=False):
    """Return *value* if it is a ``str`` within length bounds, else raise."""
    if not isinstance(value, str):
        raise InvalidIdentityError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if not allow_empty and not value:
        raise InvalidIdentityError("%s must not be empty" % what)
    if len(value) > max_length:
        raise InvalidIdentityError(
            "%s must be at most %d characters, got %d" % (what, max_length, len(value)))
    return value


def derive_id(label, owner_identity, seq, length=DERIVED_ID_LENGTH):
    """Derive a stable, lowercase-hex id from ``(label, owner_identity, seq)``.

    SHA-256 rather than ``uuid4``: the same triple always yields the same id,
    in any process, under any ``PYTHONHASHSEED``, which is what makes a
    restored aggregate's ids match the ones recorded before it was persisted.
    """
    owner_identity = validate_identity(owner_identity, "owner identity")
    seq = validate_nonneg_int(seq, "seq")
    material = "%s|%s|%d" % (label, owner_identity, seq)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return digest[:length]
