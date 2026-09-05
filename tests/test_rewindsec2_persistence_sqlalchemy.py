"""Adversarial tests for the SQLAlchemy-backed session repository.

Uses a fresh in-memory SQLite engine per test -- never the application's real
``simulator.db`` -- so these tests are hermetic and destroy nothing.
"""

import json

import pytest
import sqlalchemy as sa

from rewindsec.domain.enums import ActionClass, Focus, Mode
from rewindsec.domain.session import SimulationSession
from rewindsec.persistence.ports import (SessionAlreadyExistsError, SessionNotFoundError,
                                         StaleRevisionError)
from rewindsec.persistence.sqlalchemy_adapter import (CorruptSnapshotError,
                                                       CURRENT_SNAPSHOT_SCHEMA_VERSION,
                                                       SqlAlchemySessionRepository,
                                                       UnsupportedSnapshotVersionError,
                                                       sessions_table)


@pytest.fixture
def repo():
    engine = sa.create_engine("sqlite:///:memory:")
    repository = SqlAlchemySessionRepository(engine)
    repository.create_schema()
    return repository


def _fresh(session_id="s1", seed=1):
    return SimulationSession.create(session_id, "learner-1", Focus.PHISHING,
                                    Mode.PRACTICE, root_seed=seed)


def test_create_then_load_roundtrips_exactly(repo):
    session = _fresh()
    session.record_immediate_event("mail.delivered")
    repo.create(session)
    loaded = repo.load("s1")
    assert loaded.capture_state() == session.capture_state()


def test_create_duplicate_session_id_rejected(repo):
    session = _fresh()
    repo.create(session)
    with pytest.raises(SessionAlreadyExistsError):
        repo.create(_fresh())


def test_create_is_transactional_on_duplicate_insert(repo):
    """A rejected create() must not leave partial event/action rows behind."""
    session = _fresh()
    session.record_immediate_event("mail.delivered")
    repo.create(session)
    duplicate = _fresh()
    duplicate.record_action("inspect.open_mail", ActionClass.OBSERVATIONAL)
    with pytest.raises(SessionAlreadyExistsError):
        repo.create(duplicate)
    reloaded = repo.load("s1")
    assert len(reloaded.action_log.actions()) == 0  # the duplicate's action never landed


def test_load_missing_session_raises(repo):
    with pytest.raises(SessionNotFoundError):
        repo.load("does-not-exist")


def test_update_requires_matching_expected_revision(repo):
    session = _fresh()
    repo.create(session)
    loaded = repo.load("s1")
    base_revision = loaded.revision
    loaded.record_immediate_event("mail.delivered")
    repo.update(loaded, expected_revision=base_revision)

    stale_copy = repo.load("s1")
    stale_copy.record_immediate_event("mail.opened")
    with pytest.raises(StaleRevisionError):
        # base_revision is now behind what is actually stored
        repo.update(stale_copy, expected_revision=base_revision)


def test_update_missing_session_raises(repo):
    session = _fresh()
    with pytest.raises(SessionNotFoundError):
        repo.update(session, expected_revision=0)


def test_update_does_not_silently_overwrite_newer_state(repo):
    """Two writers both loading at revision N: the second writer using a
    stale expected_revision must be rejected, never merged or overwritten."""
    session = _fresh()
    repo.create(session)

    writer_a = repo.load("s1")
    writer_b = repo.load("s1")
    base = writer_a.revision

    writer_a.record_immediate_event("mail.delivered")
    repo.update(writer_a, expected_revision=base)

    writer_b.record_action("inspect.open_mail", ActionClass.OBSERVATIONAL)
    with pytest.raises(StaleRevisionError):
        repo.update(writer_b, expected_revision=base)

    final = repo.load("s1")
    assert len(final.event_log.events()) == 1
    assert len(final.action_log.actions()) == 0


def test_update_replaces_event_and_action_projection_rows(repo):
    session = _fresh()
    session.record_immediate_event("mail.delivered")
    repo.create(session)

    loaded = repo.load("s1")
    base = loaded.revision
    loaded.record_immediate_event("mail.opened")
    repo.update(loaded, expected_revision=base)

    with repo._engine.begin() as conn:
        from rewindsec.persistence.sqlalchemy_adapter import session_events_table
        rows = conn.execute(
            sa.select(session_events_table).where(session_events_table.c.session_id == "s1")
        ).fetchall()
    assert len(rows) == 2


def test_exists(repo):
    assert not repo.exists("s1")
    repo.create(_fresh())
    assert repo.exists("s1")


def test_unsupported_schema_version_fails_safely(repo):
    session = _fresh()
    repo.create(session)
    with repo._engine.begin() as conn:
        conn.execute(
            sessions_table.update().where(sessions_table.c.session_id == "s1")
            .values(schema_version=CURRENT_SNAPSHOT_SCHEMA_VERSION + 1)
        )
    with pytest.raises(UnsupportedSnapshotVersionError):
        repo.load("s1")


def test_corrupt_snapshot_json_fails_safely(repo):
    session = _fresh()
    repo.create(session)
    with repo._engine.begin() as conn:
        conn.execute(
            sessions_table.update().where(sessions_table.c.session_id == "s1")
            .values(snapshot_json="{not valid json")
        )
    with pytest.raises(CorruptSnapshotError):
        repo.load("s1")


def test_snapshot_json_is_never_pickled():
    session = _fresh()
    session.record_immediate_event("mail.delivered")
    from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository
    row = SqlAlchemySessionRepository._session_row(session)
    parsed = json.loads(row["snapshot_json"])  # must be plain JSON, not pickle bytes
    assert parsed["session_id"] == "s1"


def test_full_persist_discard_restore_continue_via_repository(repo):
    session = _fresh(seed=123)
    ev = session.record_immediate_event("mail.delivered")
    session.schedule_event("mail.delivered", delay_ms=1000)
    repo.create(session)

    del session  # simulate discarding all in-memory state

    resumed = repo.load("s1")
    base = resumed.revision
    fired = resumed.advance_time(1000)
    assert len(fired) == 1
    repo.update(resumed, expected_revision=base)

    final = repo.load("s1")
    assert len(final.event_log.events()) == 2
    assert final.now_ms == 1000
