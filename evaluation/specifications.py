"""Frozen, independent correctness specifications for the evaluated scenarios.

HISTORICAL: this is the oracle for the earlier conference-simulator
architecture's milestone-4 measurements, preserved untouched and functionally
unmodified. The newer paired-counterfactual RewindSec architecture has its own,
separate, independent oracle in ``evaluation/rewindsec_specifications.py``
(``REWINDSEC_SPECIFICATION_VERSION``) -- the two are never merged or conflated.

WHY THIS FILE EXISTS
--------------------
The production code already knows what a scenario is supposed to emit: see
``sandbox/progression.py``. If the experimental oracle imported that table, the
experiments would be checking the implementation against *itself*, and any
scenario that silently changed its telemetry would still score 1.0. That is not
a defensible experimental result.

So this module is deliberately **independent**:

  * every event type is written out as a literal string. Nothing is imported
    from ``sandbox`` -- not ``EventType``, not ``EXPECTED_SEQUENCES``, not the
    dataset. A test asserts that this remains true.
  * the sequences below are **frozen** for the conference measurements. If the
    production implementation changes its telemetry, these specifications do
    not follow it; the experiments report a mismatch, which is the point.
  * the comparison logic here is written separately from
    ``sandbox.progression.matches_expected_sequence`` rather than reusing it.

WHAT A SPECIFICATION DECLARES
-----------------------------
``required``   ordered event types that a successful run must emit, in order.
``repeatable`` required types that may legitimately fire more than once
               (``FILE_IMPACT`` fires once per synthetic file), collapsed
               before the order comparison.
``optional``   types that are permitted but neither required nor ordered.
``forbidden``  types whose presence invalidates the run outright.

WHAT IT DOES NOT DECLARE
------------------------
Nothing about people. These specifications describe machine-observable event
streams and nothing else.
"""

#: Bumped by hand whenever a frozen specification is deliberately changed.
#: Recorded in every formal result file so a number can always be traced back to
#: the oracle version that produced it.
#: 2026-08-31.1 -- the file-impact scenario's expected filesystem semantics
#: changed from rename-only to content replacement by a fixed demo placeholder.
#: The telemetry sequence below is unchanged; the version moves because results
#: produced under the previous semantics are not comparable to new ones.
SPECIFICATION_VERSION = "2026-08-31.1"


#: Raw interaction telemetry that scoring **ignores**.
#:
#: Milestone 4.2 split the event model into progression milestones (recorded
#: once per run) and repeatable interaction telemetry. The interaction events
#: below carry a ``scenario_id``, so they turn up inside a scenario-scoped
#: query, but they record that a page was *requested* rather than that a stage
#: was reached: twenty refreshes legitimately produce twenty of them. They are
#: dropped before an observed stream is compared against a specification, so
#: browsing noise can neither complete a run nor invalidate one.
#:
#: Written out as literal strings and kept deliberately **short**, like every
#: other declaration in this module: the oracle must not import the
#: implementation's classification, or a production change that reclassified an
#: event as "noise" would silently exempt it from scoring.
IGNORED_INTERACTION_TYPES = frozenset({
    "PAGE_VIEW",
})


class ScenarioSpecification:
    """One scenario's frozen expected observable behaviour."""

    __slots__ = ("scenario", "required", "repeatable", "optional", "forbidden",
                 "description")

    def __init__(self, scenario, required, repeatable=(), optional=(),
                 forbidden=(), description=""):
        self.scenario = scenario
        self.required = tuple(required)
        self.repeatable = frozenset(repeatable)
        self.optional = frozenset(optional)
        self.forbidden = frozenset(forbidden)
        self.description = description

    @property
    def permitted(self):
        """Every event type this scenario may legitimately emit."""
        return frozenset(self.required) | self.optional

    def as_dict(self):
        return {
            "scenario": self.scenario,
            "required": list(self.required),
            "repeatable": sorted(self.repeatable),
            "optional": sorted(self.optional),
            "forbidden": sorted(self.forbidden),
            "description": self.description,
        }


FILE_IMPACT = ScenarioSpecification(
    scenario="file_impact",
    required=(
        "SCENARIO_STARTED",
        "FILE_IMPACT_STARTED",
        "FILE_IMPACT",
        "FILE_IMPACT_COMPLETED",
        "SCENARIO_COMPLETED",
    ),
    repeatable=("FILE_IMPACT",),
    optional=("FILE_IMPACT_REJECTED",),
    forbidden=("SCENARIO_FAILED",),
    description="Disposable sandbox applies the constrained demo file impact "
                "to the fixed synthetic dataset: allow-listed files whose "
                "content still matches the known baseline are replaced by a "
                "fixed placeholder record and renamed.",
)

CREDENTIAL_REUSE_PHISHING = ScenarioSpecification(
    scenario="credential_reuse_phishing",
    required=(
        "SCENARIO_STARTED",
        "PHISHING_EXPOSED",
        "CONSENT_GRANTED",
        "PHISHING_FORM_VIEWED",
        "CREDENTIAL_SUBMITTED",
        "CREDENTIAL_VALIDATED",
        "SANDBOX_LOGIN_SUCCEEDED",
        "SYNTHETIC_RESOURCE_ACCESSED",
        "SCENARIO_COMPLETED",
    ),
    repeatable=(),
    optional=(
        # A learner may mistype an identity before succeeding; the retry is
        # permitted but is not part of the successful sequence.
        "CREDENTIAL_VALIDATION_FAILED",
    ),
    forbidden=("SCENARIO_FAILED",),
    description="Marketplace lure to consent to phishing-style login to "
                "sandbox-only reuse of a synthetic identity to debrief.",
)

RANSOMWARE_AWARENESS = ScenarioSpecification(
    scenario="ransomware_awareness",
    required=(
        "RANSOMWARE_LURE_VIEWED",
        "RANSOMWARE_DOWNLOAD_CLICKED",
        "RANSOMWARE_TRIGGERED",
        "RANSOMWARE_DEBRIEFED",
    ),
    repeatable=(),
    optional=(),
    forbidden=("SCENARIO_FAILED",),
    description="Fake-tool lure to download to simulated encryption screen to "
                "educational reveal. Marks demo rows only; no file is touched.",
)

SPECIFICATIONS = {
    FILE_IMPACT.scenario: FILE_IMPACT,
    CREDENTIAL_REUSE_PHISHING.scenario: CREDENTIAL_REUSE_PHISHING,
    RANSOMWARE_AWARENESS.scenario: RANSOMWARE_AWARENESS,
}


# -- invariants that hold for every scenario ---------------------------------

#: Event types that must never appear in *any* observed sequence, because the
#: simulator has no code path that should produce them during a scored run.
GLOBAL_FORBIDDEN = frozenset({"SCENARIO_FAILED"})

#: Field names every scored event must carry a non-empty value for.
REQUIRED_FIELDS = ("event_type", "scenario_id", "session_id", "timestamp")


def field(event, name):
    """Read ``name`` from a dict, a SQLAlchemy row, or a plain object.

    Written independently of ``sandbox.progression._field`` so the oracle does
    not inherit a bug from the implementation it is judging.
    """
    if isinstance(event, dict):
        return event.get(name)
    return getattr(event, name, None)


def observed_types(events):
    return [field(e, "event_type") for e in events]


class Verdict:
    """The oracle's judgement on one observed event sequence.

    Every failure mode is reported as its own field so an experiment row can
    record *why* a run was judged incorrect, not merely that it was.
    """

    __slots__ = ("scenario", "ok", "missing", "unexpected", "forbidden_seen",
                 "order_correct", "scenario_id_correct", "session_id_correct",
                 "fields_complete", "timestamps_ordered", "observed",
                 "expected", "completeness")

    def __init__(self, **kwargs):
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))

    def as_dict(self):
        return {name: getattr(self, name) for name in self.__slots__}

    def __repr__(self):
        return "<Verdict %s ok=%s missing=%s unexpected=%s order=%s>" % (
            self.scenario, self.ok, self.missing, self.unexpected,
            self.order_correct)


def _collapse(types, repeatable):
    """Collapse consecutive repeats of types declared repeatable.

    Only *declared-repeatable* types are collapsed. A non-repeatable type
    emitted twice in a row therefore survives collapsing and breaks the order
    comparison, which is the behaviour we want from an oracle.
    """
    collapsed = []
    for event_type in types:
        if (collapsed and collapsed[-1] == event_type
                and event_type in repeatable):
            continue
        collapsed.append(event_type)
    return collapsed


def evaluate(events, scenario, scenario_id=None, session_id=None):
    """Judge ``events`` against the frozen specification for ``scenario``.

    ``scenario_id`` / ``session_id``, when given, are the values the caller
    *expected* every event to carry. Supplying them is what makes correlation
    and cross-session leakage detectable: an event that belongs to a different
    run or a different learner fails the verdict rather than being ignored.

    Returns a :class:`Verdict`. Raises ``KeyError`` for an unknown scenario --
    silently scoring an unrecognised scenario would be worse than failing.
    """
    spec = SPECIFICATIONS[scenario]
    # Drop raw interaction telemetry before anything is judged, so a refresh or
    # a prefetch cannot make a correct run look incorrect (or an incomplete one
    # look finished). Correlation and field checks below therefore also apply to
    # the scored events only.
    events = [e for e in events
              if field(e, "event_type") not in IGNORED_INTERACTION_TYPES]
    types = observed_types(events)
    permitted = spec.permitted

    missing = [t for t in spec.required if t not in set(types)]
    unexpected = sorted({t for t in types if t not in permitted})
    forbidden_seen = sorted({t for t in types
                             if t in spec.forbidden or t in GLOBAL_FORBIDDEN})

    # Order: drop optional events, then collapse declared-repeatable runs, then
    # require an exact match against the frozen required sequence.
    ordered_core = [t for t in types if t in set(spec.required)]
    order_correct = _collapse(ordered_core, spec.repeatable) == list(spec.required)

    scenario_ids = {field(e, "scenario_id") for e in events}
    session_ids = {field(e, "session_id") for e in events}
    if scenario_id is None:
        scenario_id_correct = len(scenario_ids) == 1 and None not in scenario_ids
    else:
        scenario_id_correct = scenario_ids == {scenario_id}
    if session_id is None:
        session_id_correct = len(session_ids) == 1 and None not in session_ids
    else:
        session_id_correct = session_ids == {session_id}

    fields_complete = all(
        field(e, name) not in (None, "") for e in events for name in REQUIRED_FIELDS)

    stamps = [field(e, "timestamp") for e in events]
    timestamps_ordered = (
        bool(stamps) and all(s is not None for s in stamps)
        and all(a <= b for a, b in zip(stamps, stamps[1:])))

    captured = sum(1 for t in spec.required if t in set(types))
    completeness = captured / len(spec.required) if spec.required else 0.0

    ok = (not missing and not unexpected and not forbidden_seen
          and order_correct and scenario_id_correct and session_id_correct
          and fields_complete and timestamps_ordered)

    return Verdict(
        scenario=scenario, ok=ok, missing=missing, unexpected=unexpected,
        forbidden_seen=forbidden_seen, order_correct=order_correct,
        scenario_id_correct=scenario_id_correct,
        session_id_correct=session_id_correct, fields_complete=fields_complete,
        timestamps_ordered=timestamps_ordered, observed=list(types),
        expected=list(spec.required), completeness=completeness)


def specification_manifest():
    """Every frozen specification, for embedding in a result file."""
    return {
        "specification_version": SPECIFICATION_VERSION,
        "ignored_interaction_types": sorted(IGNORED_INTERACTION_TYPES),
        "global_forbidden": sorted(GLOBAL_FORBIDDEN),
        "required_fields": list(REQUIRED_FIELDS),
        "scenarios": {name: spec.as_dict()
                      for name, spec in sorted(SPECIFICATIONS.items())},
    }
