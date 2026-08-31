"""Application integration for the RewindSec counterfactual runtime.

This is the seam between three layers that must stay distinct:

    training/          pure research runtime. No Flask, no SQLAlchemy, no
                       sandbox, no Docker. It does not know what an
                       ``execution_id`` or a ``SecurityEvent`` is.
    this module        Flask/SQLAlchemy aware. Generates execution identity,
                       persists the result artifact, and translates the
                       runtime's generic lifecycle observations into
                       authoritative SecurityEvent telemetry.
    sandbox/           the existing validated execution primitives.

Two records come out of one run, and they are not the same kind of thing:

    TrainingExecution  the materialised paired-experiment *result*. One
                       execution, one row, updated in place. Not an event log.
    SecurityEvent      the authoritative ordered *timeline*, unchanged in
                       schema and shared with every existing scenario.

Correlation without a migration
-------------------------------
``SecurityEvent`` is not altered in R2. For ``TRAINING_*`` events the existing
``scenario_id`` column carries the unique ``execution_id`` of the paired
execution. That is a deliberate, documented overload: it gives exact
per-execution correlation, and it makes the existing progression-idempotency
gate key on ``(session_id, execution_id, event_type)`` -- which is precisely the
exactly-once-per-execution property the lifecycle needs, with no change to
``telemetry_ledger``. Existing phishing/ransomware event semantics are untouched.
"""

import uuid

from sandbox.events import EventType, make_event
from sandbox.sanitize import error_reference, internal_diagnostic
from sandbox.timeutil import utcnow
from training import observation as obs
from training.runtime import CounterfactualRuntime
from training.snapshots import canonical_json

#: ``SecurityEvent.source`` for every training lifecycle event. Stable, so a
#: query can select the whole subsystem without pattern-matching event names.
TELEMETRY_SOURCE = "training:counterfactual"

#: Runtime observation stage -> SecurityEvent type, for the stages emitted
#: from inside the run as each step happens.
#:
#: ``obs.PAIR_COMPLETED`` is deliberately absent. Its facts are captured when
#: the runtime emits it, but ``TRAINING_EXECUTION_COMPLETED`` is written only
#: after the result row is stored -- so a persistence failure can never leave a
#: timeline claiming the execution completed. It is still the last event in the
#: sequence either way.
STAGE_EVENTS = {
    obs.BASELINE_CAPTURED: EventType.TRAINING_BASELINE_CAPTURED,
    obs.FACTUAL_CAPTURED: EventType.TRAINING_FACTUAL_CAPTURED,
    obs.REWIND_VERIFIED: EventType.TRAINING_REWIND_VERIFIED,
    obs.COUNTERFACTUAL_CAPTURED: EventType.TRAINING_COUNTERFACTUAL_CAPTURED,
}

#: The order a successful execution produces. Cited by the ordering test.
SUCCESS_EVENT_ORDER = (
    EventType.TRAINING_EXECUTION_STARTED,
    EventType.TRAINING_BASELINE_CAPTURED,
    EventType.TRAINING_FACTUAL_CAPTURED,
    EventType.TRAINING_REWIND_VERIFIED,
    EventType.TRAINING_COUNTERFACTUAL_CAPTURED,
    EventType.TRAINING_EXECUTION_COMPLETED,
)

#: Detail keys allowed to reach SecurityEvent.details. An allow-list, not a
#: deny-list: a value the runtime starts emitting later cannot leak by default.
SAFE_DETAIL_KEYS = frozenset({
    "baseline_digest", "rewound_digest", "state_digest", "factual_digest",
    "counterfactual_digest", "choice_id", "action_key", "confidence",
    "response_time_ms", "pair_id", "branches_diverged", "change_count",
    "scenario_version", "failure_type", "error_ref", "stage",
})

#: Hard cap, well inside the SecurityEvent.details column width.
MAX_DETAIL_CHARS = 400


class TrainingExecutionError(RuntimeError):
    """A paired execution failed and was recorded as failed.

    Carries only the exception *class name* of the cause and an opaque
    reference -- never the underlying message. The original exception is
    chained for the application log, not for the response or the database.
    """

    def __init__(self, execution_id, failure_type, error_ref):
        self.execution_id = execution_id
        self.failure_type = failure_type
        self.error_ref = error_ref
        super().__init__(
            "training execution %s failed (%s, ref=%s)"
            % (execution_id, failure_type, error_ref))


class TrainingPersistenceError(RuntimeError):
    """The experiment ran but its result could not be stored.

    Deliberately distinct from :class:`TrainingExecutionError`. The consequence
    environment cannot be rolled back by a SQL transaction, so a persistence
    failure after a real run must not be reported as "the experiment failed" --
    it did not; we merely lost the record of it.
    """


def new_execution_id():
    """A unique, server-side, non-guessable identity for one invocation.

    ``uuid4`` -- random, not time-derived, and independent of the runtime's
    deterministic ``pair_id``. Two identical experiments share a ``pair_id``
    and never share an ``execution_id``.
    """
    return "exec-" + uuid.uuid4().hex


def safe_details(mapping):
    """Bounded ``key=value`` detail string built only from allow-listed keys."""
    parts = []
    for key in sorted(mapping or {}):
        if key not in SAFE_DETAIL_KEYS:
            continue
        value = mapping[key]
        if value is None:
            continue
        parts.append("%s=%s" % (key, value))
    return ",".join(parts)[:MAX_DETAIL_CHARS] or None


class TrainingService:
    """Orchestrates identity, persistence and telemetry around one paired run.

    Dependencies are injected rather than imported from ``app``: the service
    needs a SQLAlchemy session holder, the model class, and a recorder callable
    with the same ``event dict -> persisted`` shape the sandbox subsystem
    already uses. That keeps it testable and keeps ``app.py`` the only place
    that knows how those three are wired together.
    """

    def __init__(self, db, model, recorder, logger=None,
                 source=TELEMETRY_SOURCE):
        self.db = db
        self.model = model
        self.recorder = recorder
        self.logger = logger
        self.source = source

    # -- telemetry ---------------------------------------------------------
    def _emit(self, event_type, execution_id, session_id, target=None,
              details=None):
        """Write one lifecycle event.

        ``scenario_id`` carries ``execution_id``; see the module docstring.
        """
        return self.recorder(make_event(
            event_type,
            scenario_id=execution_id,
            session_id=session_id,
            source=self.source,
            target=(str(target)[:300] if target else None),
            details=safe_details(details),
            timestamp=utcnow()))

    def _observer(self, execution_id, session_id, completion):
        """Translate generic runtime observations into SecurityEvent rows.

        Called from inside the runtime as each step happens, so the recorded
        timeline is the causal order of the experiment. The runtime knows
        nothing about EventType; it hands back the opaque context we gave it.

        ``completion`` is a dict the final observation's facts are stashed in,
        for the completion event the service emits after persistence.
        """
        def observe(observation):
            if observation.stage == obs.PAIR_COMPLETED:
                completion.update(observation.details)
                completion["target"] = "%s/%s" % (observation.scenario_key,
                                                  observation.decision_id)
                return None
            event_type = STAGE_EVENTS.get(observation.stage)
            if event_type is None:
                return None
            details = dict(observation.details)
            details["scenario_version"] = observation.scenario_version
            target = "%s/%s" % (observation.scenario_key,
                                observation.decision_id)
            return self._emit(event_type, execution_id, session_id,
                              target=target, details=details)
        return observe

    # -- persistence -------------------------------------------------------
    def _start_row(self, execution_id, session_id, scenario, decision_id):
        """Persist the ``started`` row *before* the environment is touched.

        A run that dies mid-experiment must still be observable, so this row
        exists before anything can fail. It is never left at ``started``: every
        exit path below moves it to ``completed`` or ``failed``.
        """
        row = self.model(
            execution_id=execution_id,
            session_id=session_id,
            scenario_key=scenario.scenario_key,
            scenario_version=scenario.version,
            decision_id=decision_id,
            status=self.model.STATUS_STARTED,
            created_at=utcnow())
        self.db.session.add(row)
        self.db.session.commit()
        return row

    def _complete_row(self, row, pair):
        """Record the result. Refuses to store an unverifiable comparison."""
        # The research invariant, enforced at the application layer and not
        # only in tests: a stored execution may not claim counterfactual
        # comparability unless both branches provably began from one baseline.
        # (The runtime already refuses to build such a pair; this is the second
        # gate, on the record itself.)
        if pair.baseline_digest != pair.rewound_snapshot.digest:
            raise TrainingPersistenceError(
                "refusing to persist a completed execution whose baseline and "
                "rewound digests differ")

        row.pair_id = pair.pair_id
        row.baseline_digest = pair.baseline_digest
        row.rewound_digest = pair.rewound_snapshot.digest

        row.factual_choice_id = pair.factual.choice_id
        row.factual_action_key = pair.factual.action_key
        row.factual_confidence = pair.factual.confidence
        row.factual_response_time_ms = pair.factual.response_time_ms
        row.factual_result_digest = pair.factual.digest

        row.counterfactual_choice_id = pair.counterfactual.choice_id
        row.counterfactual_action_key = pair.counterfactual.action_key
        row.counterfactual_confidence = pair.counterfactual.confidence
        row.counterfactual_response_time_ms = pair.counterfactual.response_time_ms
        row.counterfactual_result_digest = pair.counterfactual.digest

        # The runtime's own canonical serializer, reused rather than
        # reimplemented -- the stored text is byte-identical to what was
        # fingerprinted, so a digest can be re-derived from the stored state.
        row.factual_state_json = pair.factual.resulting_snapshot.canonical_json
        row.counterfactual_state_json = (
            pair.counterfactual.resulting_snapshot.canonical_json)
        row.difference_json = canonical_json(pair.difference.as_dict())

        row.status = self.model.STATUS_COMPLETED
        row.completed_at = utcnow()
        self.db.session.commit()
        return row

    def _fail_row(self, row, exc):
        """Move the row to ``failed`` with sanitised metadata only."""
        reference = error_reference()
        row_id, execution_id = row.id, row.execution_id
        if self.logger is not None:
            # The scrubbed diagnostic goes to the operator's log, never to the
            # database and never to a response.
            self.logger.error("training execution failed ref=%s execution=%s: %s",
                              reference, execution_id,
                              internal_diagnostic(exc))
        # A half-applied write from the failed step must not ride along with
        # the failure record.
        self.db.session.rollback()
        row = self.db.session.get(self.model, row_id)
        row.failure_type = type(exc).__name__[:64]
        row.error_ref = reference
        row.status = self.model.STATUS_FAILED
        row.completed_at = utcnow()
        self.db.session.commit()
        return row, reference

    # -- public API --------------------------------------------------------
    def run_pair(self, scenario, adapter, decision_id, factual_choice_id,
                 counterfactual_choice_id, session_id,
                 factual_confidence=None, counterfactual_confidence=None,
                 factual_response_ms=None, counterfactual_response_ms=None):
        """Run one counterfactual pair, persisting and observing it.

        Returns ``(execution_id, CounterfactualPair)``.

        Lifecycle, in order:

        1. mint ``execution_id``, persist the ``started`` row, emit
           ``TRAINING_EXECUTION_STARTED``;
        2. run the paired experiment, whose observer emits the four lifecycle
           events as each step actually happens;
        3. on success, persist the result and mark ``completed`` (the
           ``TRAINING_EXECUTION_COMPLETED`` event is emitted by the runtime's
           final observation, before the result row is written);
        4. on failure, mark ``failed`` with a class name and an opaque
           reference, emit ``TRAINING_EXECUTION_FAILED``, and raise
           :class:`TrainingExecutionError`.

        This is explicitly **not** one atomic transaction. A consequence
        environment cannot be rolled back by a database, so pretending
        otherwise would be a lie about what happened.
        """
        execution_id = new_execution_id()
        row = self._start_row(execution_id, session_id, scenario, decision_id)
        self._emit(EventType.TRAINING_EXECUTION_STARTED, execution_id,
                   session_id,
                   target="%s/%s" % (scenario.scenario_key, decision_id),
                   details={"scenario_version": scenario.version})

        completion = {}
        try:
            # Constructed inside the handler: an unresolvable action key is
            # refused here, before the environment is touched, and that refusal
            # must still leave a recorded ``failed`` row rather than a row stuck
            # at ``started``.
            runtime = CounterfactualRuntime(
                scenario, adapter,
                observer=self._observer(execution_id, session_id, completion),
                observer_context={"execution_id": execution_id,
                                  "session_id": session_id})
            pair = runtime.run_decision_pair(
                decision_id,
                factual_choice_id=factual_choice_id,
                counterfactual_choice_id=counterfactual_choice_id,
                factual_confidence=factual_confidence,
                counterfactual_confidence=counterfactual_confidence,
                factual_response_ms=factual_response_ms,
                counterfactual_response_ms=counterfactual_response_ms,
                session_ref=session_id)
        except Exception as exc:  # noqa: BLE001 -- every failure is recorded
            row, reference = self._fail_row(row, exc)
            self._emit(EventType.TRAINING_EXECUTION_FAILED, execution_id,
                       session_id,
                       target="%s/%s" % (scenario.scenario_key, decision_id),
                       details={"failure_type": row.failure_type,
                                "error_ref": reference})
            raise TrainingExecutionError(execution_id, row.failure_type,
                                         reference) from exc

        try:
            self._complete_row(row, pair)
        except Exception as exc:
            # The experiment really ran; only the record failed. Say so, rather
            # than reporting a failed experiment or a completed one.
            row, reference = self._fail_row(row, exc)
            self._emit(EventType.TRAINING_EXECUTION_FAILED, execution_id,
                       session_id,
                       details={"failure_type": row.failure_type,
                                "error_ref": reference})
            raise TrainingPersistenceError(
                "training execution %s ran but its result could not be stored "
                "(%s, ref=%s)" % (execution_id, row.failure_type, reference)
            ) from exc

        # Last, and only now that the result is durable.
        self._emit(EventType.TRAINING_EXECUTION_COMPLETED, execution_id,
                   session_id, target=completion.pop("target", None),
                   details=completion)
        return execution_id, pair
