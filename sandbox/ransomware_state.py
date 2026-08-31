"""Session-scoped state for the ransomware-awareness scenario.

Until Milestone 4.1 this scenario mutated the application-global ``DemoFile``
rows: one learner clicking the lure flipped every row to ``encrypted`` for
*everybody*, and one learner reaching the debrief restored the display for
everybody. That is a cross-session leak of scenario state, and it makes the
per-session telemetry unreproducible.

The state now belongs to a ``(session_id, scenario_id)`` pair, exactly like
the phishing scenario's, and ``DemoFile`` is a **baseline catalogue only** --
a fixed list of synthetic filenames that no request ever mutates.

This module holds the framework-independent part: the tiny state machine and
the presentation rows it produces. The Flask layer supplies persistence (see
``RansomwareRunState`` in ``app.py``) and the session/scenario identifiers.

Safety model is unchanged and unchanged-able here: the "impact" is a string in
a table column. Nothing in this module touches a filesystem, and there is no
cryptography of any kind.
"""

from .timeutil import utcnow

#: The two states a learner's run can be in.
STATE_BASELINE = "baseline"
STATE_IMPACTED = "impacted"
STATES = (STATE_BASELINE, STATE_IMPACTED)

#: Display labels for the simulated impact, keyed by the route that triggered
#: it. Not learner-supplied: the caller passes one of these keys.
VARIANTS = {
    "browser": "LockBit Simulator",
    "download": "WannaCry Simulator",
    "instructor": "Instructor demonstration",
}
DEFAULT_VARIANT = "browser"

BASELINE_STATUS = "available"
IMPACTED_STATUS = "encrypted"


def normalise_variant(variant):
    """Return a known variant key; anything unrecognised falls back."""
    return variant if variant in VARIANTS else DEFAULT_VARIANT


def impact_remark(variant, when=None):
    """The simulated remark shown against a file while a run is impacted."""
    when = when or utcnow()
    return "Marked encrypted by %s (simulation, no real file touched) - %s" % (
        VARIANTS[normalise_variant(variant)], when.strftime("%Y-%m-%d %H:%M:%S"))


BASELINE_REMARK = "Baseline synthetic catalogue entry"
RESTORED_REMARK = "Restored after simulation"


def file_rows(names, state=STATE_BASELINE, remark=None):
    """Project the baseline catalogue through one session's run state.

    ``names`` is the immutable catalogue; the returned rows are plain dicts
    built per request, so no learner's view can ever be written back into
    shared storage.
    """
    impacted = state == STATE_IMPACTED
    status = IMPACTED_STATUS if impacted else BASELINE_STATUS
    if remark is None:
        remark = impact_remark(DEFAULT_VARIANT) if impacted else BASELINE_REMARK
    return [{"id": index, "name": name, "status": status, "remark": remark}
            for index, name in enumerate(names, start=1)]


# -- stale run-state selection (Milestone 4.2) -------------------------------
#
# A ``RansomwareRunState`` row is created the first time a learner triggers the
# scenario and then persists for ever. Across a conference that is an unbounded
# accumulation of per-session simulation state -- small, but state nobody ever
# removes and nobody needs after the session it belongs to has ended.
#
# The selection rule lives here, as a pure function over ``updated_at``, so it
# can be tested without a database and so the Flask layer has nothing to decide.
# Two properties matter and are asserted by the tests:
#
#   * a row whose ``updated_at`` is unknown is **never** selected. An unreadable
#     age means "leave it alone", never "assume it is old".
#   * selection is by age only. There is no session, scenario or id parameter,
#     so no request input can be used to pick a victim row. Reaping is explicit
#     maintenance (``python manage.py reap-state``), not something a request can
#     ask for.

#: Default staleness threshold: a day, comfortably longer than any single
#: classroom session, so a same-day run is never a candidate.
DEFAULT_MAX_AGE_SECONDS = 86400

#: Floor beneath which the reaper refuses to operate, so a mistyped threshold
#: cannot clear the state of a class that is mid-exercise.
MIN_MAX_AGE_SECONDS = 60


def age_seconds(updated_at, now=None):
    """Age of a run-state row in seconds, or ``None`` when it has no timestamp."""
    if updated_at is None:
        return None
    return ((now or utcnow()) - updated_at).total_seconds()


def is_stale(updated_at, max_age_seconds, now=None):
    """True when a row is at least ``max_age_seconds`` old.

    The boundary is inclusive: a row exactly at the threshold is stale, which
    makes the behaviour deterministic rather than dependent on clock jitter.
    """
    age = age_seconds(updated_at, now)
    return age is not None and age >= float(max_age_seconds)


def select_stale(rows, max_age_seconds, now=None):
    """The subset of ``rows`` that is stale, as ``(row, age_seconds)`` pairs.

    ``rows`` is any iterable of objects carrying ``updated_at``; nothing here
    knows about SQLAlchemy. Raises ``ValueError`` for a threshold below
    ``MIN_MAX_AGE_SECONDS`` rather than quietly widening the selection.
    """
    max_age_seconds = float(max_age_seconds)
    if max_age_seconds < MIN_MAX_AGE_SECONDS:
        raise ValueError("max_age_seconds must be at least %d"
                         % MIN_MAX_AGE_SECONDS)
    now = now or utcnow()
    selected = []
    for row in rows:
        age = age_seconds(getattr(row, "updated_at", None), now)
        if age is not None and age >= max_age_seconds:
            selected.append((row, age))
    return selected
