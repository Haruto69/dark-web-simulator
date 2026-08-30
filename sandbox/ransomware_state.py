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
