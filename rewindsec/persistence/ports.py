"""The storage-independent repository contract for :class:`SimulationSession`.

This module defines the *port* (in the hexagonal-architecture sense): the
interface every persistence adapter must satisfy, expressed only in terms of
``rewindsec.domain`` objects and stdlib exceptions. It imports nothing from
SQLAlchemy, Flask, or any other storage technology, so the domain -- and any
test exercising it -- never has to know which adapter, if any, is behind it.

Concurrency contract
---------------------
Every session aggregate carries a ``revision`` counter
(:attr:`~rewindsec.domain.session.SimulationSession.revision`), bumped on
every accepted mutation. A caller loads a session at some revision, applies
zero or more in-memory mutations (which may bump the revision by any amount),
and then calls :meth:`SessionRepository.update` passing the revision it
*loaded at* as ``expected_revision``. The adapter must reject the update with
:class:`StaleRevisionError` unless ``expected_revision`` equals the revision
currently stored -- optimistic concurrency, not a lock -- so a caller working
from a stale read learns that immediately instead of silently overwriting
whatever another writer stored in the meantime.
"""

from abc import ABC, abstractmethod

__all__ = [
    "SessionRepository",
    "SessionAlreadyExistsError",
    "SessionNotFoundError",
    "StaleRevisionError",
    "RepositoryError",
]


class RepositoryError(Exception):
    """Base class for every failure raised by a :class:`SessionRepository`."""


class SessionAlreadyExistsError(RepositoryError):
    """:meth:`SessionRepository.create` was called with an existing session id."""


class SessionNotFoundError(RepositoryError):
    """No session exists with the requested id."""


class StaleRevisionError(RepositoryError):
    """The session being saved is not one revision ahead of what is stored.

    Raised whether the incoming revision is behind (a caller working from a
    stale read) or has jumped ahead by more than one (a caller that bypassed
    this repository's own mutation tracking) -- both mean the caller's copy
    and the stored copy have diverged in a way that must not be silently
    resolved by picking one.
    """


class SessionRepository(ABC):
    """The persistence port a :class:`~rewindsec.domain.session.SimulationSession`
    is saved through and loaded back from.

    Every method takes and returns plain
    :class:`~rewindsec.domain.session.SimulationSession` instances; no
    adapter-specific type ever crosses this boundary.
    """

    @abstractmethod
    def create(self, session):
        """Persist a brand-new session.

        Raises :class:`SessionAlreadyExistsError` if a session with the same
        id is already stored -- creation is not upsert, so a caller cannot
        accidentally overwrite existing history by calling the wrong method.
        """
        raise NotImplementedError

    @abstractmethod
    def load(self, session_id):
        """Return the session stored under ``session_id``.

        Raises :class:`SessionNotFoundError` if none exists.
        """
        raise NotImplementedError

    @abstractmethod
    def update(self, session, expected_revision):
        """Persist a mutated session, atomically, subject to the revision contract.

        ``expected_revision`` is the revision the caller loaded this session
        at. Raises :class:`SessionNotFoundError` if the session does not
        already exist (an update is not upsert either), and
        :class:`StaleRevisionError` if ``expected_revision`` does not equal
        the revision currently stored for that id -- including the case
        where ``session.revision`` has not advanced past it at all.
        """
        raise NotImplementedError

    @abstractmethod
    def exists(self, session_id):
        """Whether a session with this id is currently stored."""
        raise NotImplementedError
