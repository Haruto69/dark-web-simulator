"""The idempotency ledger that makes progression milestones exactly-once.

WHAT PROBLEM THIS SOLVES
------------------------
``GET`` routes emit telemetry. A refresh, a browser prefetch, a link-preview
fetch or a crawler re-issues that ``GET``, and before Milestone 4.2 each repeat
appended another "stage reached" row. Funnel counts and every conversion rate
derived from them grew with request volume rather than with learner behaviour.

WHAT THIS IS
------------
A tiny write-path gate. Before a **progression milestone** (see
``sandbox/telemetry.py``) is written to ``security_event``, the writer claims
the key ``(session_id, scenario_id, event_type)`` here. The first claim wins and
the event is recorded; every later claim for the same key is refused and no
second row is appended.

WHAT THIS IS NOT
----------------
**It is not a second analytics table.** Nothing reads it to produce a number:
not the dashboard, not the debrief, not the evaluation harness. Those all still
read ``security_event``, which remains the single authoritative telemetry model
(Milestone 3). The ledger holds no counts, no stages and no timings that could
drift out of step with the event stream -- only the fact that a key was already
seen, and when it was first seen.

Correctness under concurrency comes from the database, not from the read: the
unique constraint is the arbiter, so two simultaneous requests racing on the
same key end with exactly one event row regardless of interleaving.
"""

from datetime import timedelta

import sqlalchemy

from sandbox.telemetry import milestone_key
from sandbox.timeutil import utcnow

TABLE_NAME = "progression_milestone"

#: Floor for :func:`reap_claims`, so a mistyped age cannot clear the ledger of
#: an in-progress classroom run.
MIN_MAX_AGE_SECONDS = 60

#: Set once by :func:`attach`, from the application's metadata, so both write
#: paths (``app.record_event`` and the sandbox recorder) claim against the same
#: table without either importing the other.
_TABLE = None


def attach(metadata):
    """Define the ledger table on ``metadata`` (idempotent). Returns the table.

    Because it is a plain table on the application's metadata,
    ``db.create_all()`` creates it on start-up like any other -- adding it to an
    existing database is non-destructive, which is precisely why the
    deduplication key lives in its own table rather than as a new column on
    ``security_event``.
    """
    global _TABLE
    if _TABLE is not None:
        return _TABLE
    _TABLE = sqlalchemy.Table(
        TABLE_NAME, metadata,
        sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
        sqlalchemy.Column("session_id", sqlalchemy.String(100), nullable=False),
        sqlalchemy.Column("scenario_id", sqlalchemy.String(64), nullable=False),
        sqlalchemy.Column("event_type", sqlalchemy.String(64), nullable=False),
        sqlalchemy.Column("first_seen_at", sqlalchemy.DateTime, nullable=False),
        sqlalchemy.UniqueConstraint("session_id", "scenario_id", "event_type",
                                    name="uq_progression_milestone"),
    )
    return _TABLE


def table():
    """The ledger table, or ``None`` when :func:`attach` has not run."""
    return _TABLE


def claim(db_session, event, now=None):
    """Reserve this event's milestone. ``True`` means "write the event row".

    Returns ``True`` -- meaning the caller should record the event -- when:

    * the event is raw interaction telemetry (repeatable by definition), or
    * it is a milestone that is not correlated to both a session and a scenario,
      so there is no key to deduplicate on. Dropping uncorrelated telemetry
      would lose data, which is worse than the duplicate this guards against, or
    * it is a correlated milestone whose key has not been claimed before.

    Returns ``False`` only for a repeat of an already-recorded milestone.

    The claim is made inside a ``SAVEPOINT`` so that losing the race raises
    ``IntegrityError`` against the savepoint alone and leaves the caller's
    transaction usable.
    """
    if _TABLE is None:
        return True
    key = milestone_key(event.get("session_id"), event.get("scenario_id"),
                        event.get("event_type"))
    if key is None:
        return True
    session_id, scenario_id, event_type = key

    where = sqlalchemy.and_(_TABLE.c.session_id == session_id,
                            _TABLE.c.scenario_id == scenario_id,
                            _TABLE.c.event_type == event_type)
    # Cheap common case: already claimed, so no exception is raised at all.
    if db_session.execute(sqlalchemy.select(_TABLE.c.id).where(where)).first():
        return False

    try:
        with db_session.begin_nested():
            db_session.execute(_TABLE.insert().values(
                session_id=session_id, scenario_id=scenario_id,
                event_type=event_type, first_seen_at=now or utcnow()))
    except sqlalchemy.exc.IntegrityError:
        # Another request claimed the same key between the select and the
        # insert. The unique constraint, not the read, is what makes this safe.
        return False
    return True


def claimed_keys(db_session, session_id=None):
    """Every claimed key, optionally for one session. Diagnostics and tests."""
    if _TABLE is None:
        return []
    query = sqlalchemy.select(_TABLE.c.session_id, _TABLE.c.scenario_id,
                              _TABLE.c.event_type)
    if session_id is not None:
        query = query.where(_TABLE.c.session_id == session_id)
    return [tuple(row) for row in db_session.execute(query).all()]


def reap_claims(db_session, max_age_seconds, now=None):
    """Delete claims older than ``max_age_seconds``. Explicit maintenance only.

    The ledger is append-only during normal operation, so it grows with the
    number of distinct runs. This is the release valve, and it is deliberately
    **age-based only**: there is no session or scenario parameter, so no request
    input can select which claims to drop and thereby re-arm a duplicate for a
    chosen learner. Dropping a claim only means a *future* request could record
    that milestone again; no recorded event is ever removed here.

    Returns the number of claims released.
    """
    if _TABLE is None:
        return 0
    max_age_seconds = float(max_age_seconds)
    if max_age_seconds < MIN_MAX_AGE_SECONDS:
        raise ValueError("max_age_seconds must be at least %d"
                         % MIN_MAX_AGE_SECONDS)
    cutoff = (now or utcnow()) - timedelta(seconds=max_age_seconds)
    result = db_session.execute(
        _TABLE.delete().where(_TABLE.c.first_seen_at < cutoff))
    return int(result.rowcount or 0)
