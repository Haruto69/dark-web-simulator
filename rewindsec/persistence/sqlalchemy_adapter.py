"""The SQLAlchemy-backed :class:`~rewindsec.persistence.ports.SessionRepository`.

Reuses the SQLAlchemy dependency the app already has (``app.py`` already
depends on Flask-SQLAlchemy, which depends on SQLAlchemy) rather than adding a
second persistence library, but is otherwise fully isolated from Flask: this
module constructs its own :class:`~sqlalchemy.engine.Engine`-bound tables and
is testable directly against any Engine, in-process, with no Flask app
context and no ``app.py`` import anywhere in this module.

Storage shape
-------------
Three tables, matching the requirement for separate persisted rows for the
session aggregate snapshot, each :class:`~rewindsec.core.events.Event`, and
each :class:`~rewindsec.domain.actions.LearnerAction`:

``rewindsec2_sessions``
    One row per session: identity, lifecycle fields, the revision counter,
    and the complete canonical JSON snapshot (``capture_state()``) that
    :meth:`load` rebuilds the aggregate from. This is the single source of
    truth on load; the event/action tables below are a queryable, auditable
    *projection* of what the snapshot already contains, not a second copy a
    restore depends on.
``rewindsec2_session_events`` / ``rewindsec2_learner_actions``
    One row per event / learner action, keyed by ``(session_id, seq)``,
    holding that record's own canonical JSON. Rewritten in full on every
    :meth:`update`, inside the same transaction as the snapshot -- see the
    module docstring's atomicity note.

No pickle anywhere: every payload column is JSON text produced by
``rewindsec.domain`` / ``rewindsec.core`` canonical serialisation and read
back with :func:`json.loads`.
"""

import json

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from rewindsec.domain.session import SimulationSession
from rewindsec.persistence.ports import (RepositoryError, SessionAlreadyExistsError,
                                         SessionNotFoundError, SessionRepository,
                                         StaleRevisionError)

__all__ = [
    "SqlAlchemySessionRepository",
    "UnsupportedSnapshotVersionError",
    "CorruptSnapshotError",
    "metadata",
    "sessions_table",
    "session_events_table",
    "learner_actions_table",
    "CURRENT_SNAPSHOT_SCHEMA_VERSION",
]

#: The schema version this build writes and the only one it will load. Bumped
#: only when the on-disk row shape changes incompatibly; an older or newer
#: value on load fails safely rather than being guessed at.
CURRENT_SNAPSHOT_SCHEMA_VERSION = 1

metadata = sa.MetaData()

sessions_table = sa.Table(
    "rewindsec2_sessions", metadata,
    sa.Column("session_id", sa.String(128), primary_key=True),
    sa.Column("schema_version", sa.Integer, nullable=False),
    sa.Column("learner_ref", sa.String(128), nullable=False),
    sa.Column("focus", sa.String(32), nullable=False),
    sa.Column("mode", sa.String(32), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("revision", sa.Integer, nullable=False),
    sa.Column("snapshot_json", sa.Text, nullable=False),
)

session_events_table = sa.Table(
    "rewindsec2_session_events", metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("session_id", sa.String(128), nullable=False, index=True),
    sa.Column("seq", sa.Integer, nullable=False),
    sa.Column("event_id", sa.String(32), nullable=False),
    sa.Column("event_json", sa.Text, nullable=False),
    sa.UniqueConstraint("session_id", "seq", name="uq_rewindsec2_event_session_seq"),
    sa.UniqueConstraint("session_id", "event_id", name="uq_rewindsec2_event_session_id"),
)

learner_actions_table = sa.Table(
    "rewindsec2_learner_actions", metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("session_id", sa.String(128), nullable=False, index=True),
    sa.Column("seq", sa.Integer, nullable=False),
    sa.Column("action_id", sa.String(32), nullable=False),
    sa.Column("action_json", sa.Text, nullable=False),
    sa.UniqueConstraint("session_id", "seq", name="uq_rewindsec2_action_session_seq"),
    sa.UniqueConstraint("session_id", "action_id", name="uq_rewindsec2_action_session_id"),
)


class UnsupportedSnapshotVersionError(RepositoryError):
    """A stored snapshot's schema version is not one this build can load."""


class CorruptSnapshotError(RepositoryError):
    """A stored snapshot is not valid JSON, or does not parse as a session."""


def _dumps(state):
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


class SqlAlchemySessionRepository(SessionRepository):
    """A :class:`~rewindsec.persistence.ports.SessionRepository` over SQLAlchemy.

    Construct with any :class:`~sqlalchemy.engine.Engine` -- a real
    application database, or a throwaway in-memory SQLite engine in a test.
    :meth:`create_schema` must be called once per engine before use; it is
    non-destructive (``checkfirst=True``), so calling it against a database
    that already has other tables never touches them.
    """

    def __init__(self, engine):
        self._engine = engine

    def create_schema(self):
        """Create this adapter's tables if they do not already exist."""
        metadata.create_all(self._engine, checkfirst=True)

    # -- port implementation -------------------------------------------------

    def create(self, session):
        if not isinstance(session, SimulationSession):
            raise TypeError(
                "session must be a SimulationSession, got %s" % type(session).__name__)
        row = self._session_row(session)
        event_rows = self._event_rows(session)
        action_rows = self._action_rows(session)
        try:
            with self._engine.begin() as conn:
                conn.execute(sessions_table.insert().values(**row))
                if event_rows:
                    conn.execute(session_events_table.insert(), event_rows)
                if action_rows:
                    conn.execute(learner_actions_table.insert(), action_rows)
        except IntegrityError as exc:
            raise SessionAlreadyExistsError(
                "session %r already exists" % session.session_id) from exc

    def load(self, session_id):
        with self._engine.begin() as conn:
            result = conn.execute(
                sa.select(sessions_table)
                .where(sessions_table.c.session_id == session_id)
            ).mappings().first()
        if result is None:
            raise SessionNotFoundError("no session with id %r" % session_id)

        schema_version = result["schema_version"]
        if schema_version != CURRENT_SNAPSHOT_SCHEMA_VERSION:
            raise UnsupportedSnapshotVersionError(
                "session %r has snapshot schema version %r; this build reads "
                "only version %d" % (session_id, schema_version,
                                     CURRENT_SNAPSHOT_SCHEMA_VERSION))

        try:
            state = json.loads(result["snapshot_json"])
        except (ValueError, TypeError) as exc:
            raise CorruptSnapshotError(
                "session %r snapshot is not valid JSON: %s" % (session_id, exc)) from exc

        try:
            return SimulationSession.from_state(state)
        except Exception as exc:
            raise CorruptSnapshotError(
                "session %r snapshot did not parse as a session: %s"
                % (session_id, exc)) from exc

    def update(self, session, expected_revision):
        if not isinstance(session, SimulationSession):
            raise TypeError(
                "session must be a SimulationSession, got %s" % type(session).__name__)
        session_id = session.session_id
        row = self._session_row(session)
        event_rows = self._event_rows(session)
        action_rows = self._action_rows(session)

        with self._engine.begin() as conn:
            current = conn.execute(
                sa.select(sessions_table.c.revision)
                .where(sessions_table.c.session_id == session_id)
            ).scalar_one_or_none()
            if current is None:
                raise SessionNotFoundError("no session with id %r" % session_id)
            if current != expected_revision:
                raise StaleRevisionError(
                    "session %r is at revision %d, not the expected %d; reload "
                    "before saving" % (session_id, current, expected_revision))

            conn.execute(
                sessions_table.update()
                .where(sessions_table.c.session_id == session_id)
                .values(**row)
            )
            conn.execute(
                session_events_table.delete()
                .where(session_events_table.c.session_id == session_id)
            )
            if event_rows:
                conn.execute(session_events_table.insert(), event_rows)
            conn.execute(
                learner_actions_table.delete()
                .where(learner_actions_table.c.session_id == session_id)
            )
            if action_rows:
                conn.execute(learner_actions_table.insert(), action_rows)

    def exists(self, session_id):
        with self._engine.begin() as conn:
            found = conn.execute(
                sa.select(sessions_table.c.session_id)
                .where(sessions_table.c.session_id == session_id)
            ).first()
        return found is not None

    # -- row construction ------------------------------------------------

    @staticmethod
    def _session_row(session):
        return {
            "session_id": session.session_id,
            "schema_version": CURRENT_SNAPSHOT_SCHEMA_VERSION,
            "learner_ref": session.learner_ref,
            "focus": session.focus.value,
            "mode": session.mode.value,
            "status": session.status.value,
            "revision": session.revision,
            "snapshot_json": _dumps(session.capture_state()),
        }

    @staticmethod
    def _event_rows(session):
        return [
            {
                "session_id": session.session_id,
                "seq": event.seq,
                "event_id": event.event_id,
                "event_json": _dumps(event.to_state()),
            }
            for event in session.event_log.events()
        ]

    @staticmethod
    def _action_rows(session):
        return [
            {
                "session_id": session.session_id,
                "seq": action.seq,
                "action_id": action.action_id,
                "action_json": _dumps(action.to_state()),
            }
            for action in session.action_log.actions()
        ]
