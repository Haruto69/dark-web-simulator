"""Shared error hierarchy for the RewindSec 2.0 simulation domain.

Every domain module raises a subclass of :class:`DomainError` so a caller can
catch "something in the domain rejected this" without enumerating every
module. Modules still define narrower subclasses (``ContextLedger`` has its
own "unknown fact" error, for instance) because a caller that *does* want to
distinguish causes should not have to parse an error message to do it.
"""

__all__ = [
    "DomainError",
    "InvalidIdentityError",
    "IdentityMismatchError",
    "UnknownReferenceError",
    "ForeignSessionReferenceError",
    "SessionNotActiveError",
    "InvalidDomainStateError",
    "SequenceOverflowError",
    "InvalidJsonValueError",
]


class DomainError(Exception):
    """Base class for every failure raised by ``rewindsec.domain``."""


class InvalidIdentityError(DomainError, ValueError):
    """An identity string (session id, learner ref, fact id, ...) is malformed."""


class IdentityMismatchError(DomainError, ValueError):
    """A captured state payload belongs to a different owning identity."""


class UnknownReferenceError(DomainError, KeyError):
    """A reference (event id, action id, fact id, consequence id, ...) is unknown."""

    def __str__(self):
        # KeyError reprs its argument by default; this reads better in a log.
        return self.args[0] if self.args else ""


class ForeignSessionReferenceError(DomainError, ValueError):
    """A reference was derived under a different session identity."""


class SessionNotActiveError(DomainError, ValueError):
    """A mutating operation was attempted on a session that is not active."""


class InvalidDomainStateError(DomainError, ValueError):
    """A serialised domain object is malformed, foreign, or of an unknown version."""


class SequenceOverflowError(DomainError, ValueError):
    """A sequence counter has been exhausted."""


class InvalidJsonValueError(DomainError, ValueError):
    """A value is not JSON-safe, canonicalisable and deterministic."""
