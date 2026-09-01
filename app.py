# app.py - RewindSec (educational) with Funnel Tracking

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import os
import random
import secrets
import uuid

import sqlalchemy

from sandbox import (SYNTHETIC_RESOURCES, EventType, PhishingScenario,
                     SandboxError, ScenarioStateError, SyntheticIdentityStore,
                     new_scenario_id, stage_index)
from sandbox.progression import (PHISHING_FUNNEL, RANSOMWARE_FUNNEL,
                                 STAGE_BY_EVENT, conversion_rates)
from sandbox.pseudonym import session_label, short_id
from sandbox.ransomware_state import (BASELINE_REMARK, DEFAULT_MAX_AGE_SECONDS,
                                      MIN_MAX_AGE_SECONDS, RESTORED_REMARK,
                                      STATE_BASELINE, STATE_IMPACTED,
                                      file_rows, impact_remark,
                                      normalise_variant, select_stale)
from sandbox.timeutil import utcnow
from security import (check_instructor_password, init_csrf,
                      instructor_auth_configured, login_instructor,
                      login_throttle, logout_instructor,
                      render_instructor_login, require_instructor, safe_next,
                      throttle_key)

import telemetry_ledger

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Secret key comes from the environment. The development fallback is a random
# per-process value, so a forgotten key can never become a shared static secret.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "SIMULATOR_DATABASE_URI", "sqlite:///simulator.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Project-controlled scratch root for the local sandbox backend. Never derived
# from request data; the Docker backend uses no host directory at all.
app.config['SANDBOX_LOCAL_ROOT'] = os.environ.get(
    "SANDBOX_LOCAL_ROOT", os.path.join(BASE_DIR, "instance", "sandbox_workspaces"))

# CSRF is enforced globally on every state-changing request.
init_csrf(app)

# Secret used to derive the session-scoped synthetic lab identities. It is a
# derivation key only: no identity or password is ever written to disk.
IDENTITIES = SyntheticIdentityStore(
    os.environ.get("SYNTHETIC_IDENTITY_SECRET") or app.secret_key)

db = SQLAlchemy(app)

# The progression-milestone idempotency ledger is a plain table on the same
# metadata, so ``db.create_all()`` creates it like any other and adding it to an
# existing database stays non-destructive. See telemetry_ledger.py.
PROGRESSION_MILESTONE = telemetry_ledger.attach(db.metadata)

# --- Models ---

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image = db.Column(db.String(256))

class DemoFile(db.Model):
    """The synthetic filename **catalogue** -- baseline data, never run state.

    Milestone 4.1: this table used to carry ``status``/``remark`` columns that
    the ransomware routes rewrote in place. Because the table is global, one
    learner's click changed what every other learner saw. Those columns are
    gone. What a given learner currently sees is derived per request from
    their own :class:`RansomwareRunState` row (see
    ``sandbox/ransomware_state.py``); the catalogue itself is read-only at
    runtime and is written only by the seeding path.
    """
    __tablename__ = 'demo_file'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))


class RansomwareRunState(db.Model):
    """One learner session's ransomware-awareness run state.

    Scoped by ``session_id`` (server-issued, held in the signed cookie) and
    correlated to ``scenario_id``. No route accepts either value from request
    data, so no request can select or mutate another learner's run.
    """
    __tablename__ = 'ransomware_run_state'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, index=True,
                           nullable=False)
    scenario_id = db.Column(db.String(64), index=True)
    state = db.Column(db.String(32), default=STATE_BASELINE, nullable=False)
    variant = db.Column(db.String(32), default="browser")
    remark = db.Column(db.String(256), default=BASELINE_REMARK)
    updated_at = db.Column(db.DateTime, default=utcnow, index=True)

    def to_dict(self):
        """Canonical form, carrying the real ``session_id`` for correlation."""
        return {
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "state": self.state,
            "variant": self.variant,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def display_dict(self):
        """Instructor-HTML form: pseudonymous label instead of the session id.

        The raw identifier is not merely hidden by the template, it is absent
        from the context, so it cannot be rendered by a later edit. See
        ``sandbox/pseudonym.py``.
        """
        row = self.to_dict()
        row["session_label"] = session_label(row.pop("session_id"))
        return row

class CredentialInteraction(db.Model):
    """Metadata about a credential submission -- never the credential itself.

    This model replaces the Milestone 1 ``SimulatedCredential`` table, which
    stored learner-submitted usernames *and passwords* in plaintext. There is
    deliberately no password column here and there never will be: the phishing
    scenario compares a submitted password against a derived synthetic one and
    drops it. ``synthetic_username`` holds a recognised ``*@lab.local`` sandbox
    identity -- not a secret -- or the ``<non-sandbox-identity>`` placeholder
    when the learner typed something that is not one, so an address they should
    never have entered is not retained either.

    The Milestone 1 table is not created by any current model; a leftover
    one is removed by ``python manage.py drop-legacy``.
    """
    __tablename__ = 'credential_interaction'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), index=True)
    scenario_id = db.Column(db.String(64), index=True)
    synthetic_username = db.Column(db.String(120))
    credential_valid = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    product_id = db.Column(db.Integer, nullable=True)
    event_type = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "synthetic_username": self.synthetic_username,
            "credential_valid": bool(self.credential_valid),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "product_id": self.product_id,
            "event_type": self.event_type,
        }

# NOTE (Milestone 3): ``PhishingFunnel`` and ``RansomwareFunnel`` used to live
# here. They were a second, parallel analytics system whose stage strings could
# drift out of step with the scenario telemetry. Both models are gone, so their
# tables are never created; a database left over from an older build is cleaned
# with ``python manage.py drop-legacy``. Every funnel figure the dashboard shows
# is derived from ``SecurityEvent`` via ``sandbox/progression.py``. There is
# exactly one authoritative telemetry model.


def _iso(value):
    """``datetime`` -> ISO 8601 string, or ``None``. One conversion, one place."""
    return value.isoformat() if value else None


class SecurityEvent(db.Model):
    """Structured telemetry from the conference sandbox subsystem.

    Holds only simulation metadata (synthetic filenames, sandbox ids, event
    types). No credentials, no host paths outside the sandbox workspace, and
    no personal data are stored here.
    """
    __tablename__ = 'security_event'
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.String(64), index=True)
    session_id = db.Column(db.String(100), index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    source = db.Column(db.String(120))
    target = db.Column(db.String(300))
    details = db.Column(db.String(500))

    def to_dict(self):
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "target": self.target,
            "details": self.details,
        }


class TrainingExecution(db.Model):
    """One paired counterfactual execution, materialised as a single row.

    **This is not a second telemetry stream.** ``SecurityEvent`` remains the
    authoritative ordered event timeline; this table holds the *result artifact*
    of one experiment -- the evidence a later analysis or replay UI needs to
    reconstruct the comparison. One execution is exactly one row, updated in
    place from ``started`` to ``completed``/``failed``. It is never appended to,
    and nothing derives a funnel or progression count from it. (Milestone 3
    removed ``PhishingFunnel``/``RansomwareFunnel`` for being a parallel
    analytics system; this must not become another.)

    Data minimisation: the two *resulting* synthetic states are kept, because a
    comparison cannot be reconstructed without them. The baseline state is not
    -- its fingerprint is the whole of the evidence needed to show both branches
    started from the same place. No credentials, no learner free text, no
    exception messages, no host paths.
    """
    __tablename__ = 'training_execution'

    STATUS_STARTED = "started"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    id = db.Column(db.Integer, primary_key=True)
    # Unique per actual invocation. Generated server-side (uuid4), never
    # derived from a timestamp, safe to quote in logs and APIs.
    execution_id = db.Column(db.String(64), unique=True, index=True,
                             nullable=False)
    # Deterministic content identity from the runtime: equivalent experiments
    # share it deliberately. Null until a pair is successfully produced.
    pair_id = db.Column(db.String(64), index=True, nullable=True)
    session_id = db.Column(db.String(100), index=True)

    scenario_key = db.Column(db.String(64), index=True)
    scenario_version = db.Column(db.Integer)
    decision_id = db.Column(db.String(64), index=True)

    status = db.Column(db.String(16), nullable=False,
                       default=STATUS_STARTED, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Baseline evidence: digests only, never the baseline state itself.
    baseline_digest = db.Column(db.String(64))
    rewound_digest = db.Column(db.String(64))

    factual_choice_id = db.Column(db.String(64))
    factual_action_key = db.Column(db.String(64))
    factual_confidence = db.Column(db.Integer, nullable=True)
    factual_response_time_ms = db.Column(db.Integer, nullable=True)
    factual_result_digest = db.Column(db.String(64))

    counterfactual_choice_id = db.Column(db.String(64))
    counterfactual_action_key = db.Column(db.String(64))
    counterfactual_confidence = db.Column(db.Integer, nullable=True)
    counterfactual_response_time_ms = db.Column(db.Integer, nullable=True)
    counterfactual_result_digest = db.Column(db.String(64))

    # Canonical JSON produced by the runtime's own serializer. Text keeps the
    # schema portable to SQLite; there is deliberately no second serializer.
    factual_state_json = db.Column(db.Text, nullable=True)
    counterfactual_state_json = db.Column(db.Text, nullable=True)
    difference_json = db.Column(db.Text, nullable=True)

    # Failure metadata: an exception *class name* and an opaque correlation
    # reference. Never a message, never a traceback (see sandbox/sanitize.py).
    failure_type = db.Column(db.String(64), nullable=True)
    error_ref = db.Column(db.String(32), nullable=True)

    @property
    def baseline_verified(self):
        """Whether both branches provably started from the same state."""
        return bool(self.baseline_digest
                    and self.baseline_digest == self.rewound_digest)

    def to_dict(self):
        """Canonical internal form. Carries the real ``session_id``."""
        return {
            "execution_id": self.execution_id,
            "pair_id": self.pair_id,
            "session_id": self.session_id,
            "scenario_key": self.scenario_key,
            "scenario_version": self.scenario_version,
            "scenario_identity": ("%s@%s" % (self.scenario_key,
                                             self.scenario_version)
                                  if self.scenario_key else None),
            "decision_id": self.decision_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": (self.completed_at.isoformat()
                             if self.completed_at else None),
            "baseline_digest": self.baseline_digest,
            "rewound_digest": self.rewound_digest,
            "baseline_verified": self.baseline_verified,
            "factual": {
                "choice_id": self.factual_choice_id,
                "action_key": self.factual_action_key,
                "confidence": self.factual_confidence,
                "response_time_ms": self.factual_response_time_ms,
                "state_digest": self.factual_result_digest,
            },
            "counterfactual": {
                "choice_id": self.counterfactual_choice_id,
                "action_key": self.counterfactual_action_key,
                "confidence": self.counterfactual_confidence,
                "response_time_ms": self.counterfactual_response_time_ms,
                "state_digest": self.counterfactual_result_digest,
            },
            "failure_type": self.failure_type,
            "error_ref": self.error_ref,
        }

    def display_dict(self):
        """Instructor-facing form: pseudonymous label instead of session id.

        The raw identifier is absent from the context rather than merely hidden
        by a template, matching ``RansomwareRunState.display_dict``. No HTTP
        route exposes this yet; R2 adds no API.
        """
        row = self.to_dict()
        row["session_label"] = session_label(row.pop("session_id"))
        return row


# --- RewindSec learning artifacts (Milestone R6) ---
# Three small tables, deliberately *separate* from TrainingExecution.
#
# TrainingExecution stays exactly what R2 made it: the technical paired-execution
# result artifact. Nothing about reflection, concept evidence, a transfer probe
# or a learning score is added to it, because a technical record that also
# carried pedagogical interpretation would have two owners and no clear meaning.
# These tables link to it by ``execution_id`` and nothing else.
#
# Portability: plain columns and Text only. No vendor JSON type, no server-side
# default, nothing SQLite cannot create through ``db.create_all()`` -- the
# repository still has no migration machinery and R6 does not introduce any.

class LearningReflection(db.Model):
    """One learner's structured self-explanation of a completed comparison.

    **Exactly one per completed TrainingExecution**, enforced by a unique
    constraint on ``execution_id`` rather than by route discipline alone. The
    first recorded explanation is the research datum; a refresh, a Back-button
    resubmission or a repeated POST re-reads it and never overwrites it.

    Data minimisation is the whole design: what is stored is the *identifier*
    of an authored option the learner selected. There is no free-text column
    here and no free-text input anywhere in the R6 flow, so a learner cannot
    write personal information into the research record even by accident.
    """
    __tablename__ = 'learning_reflection'

    id = db.Column(db.Integer, primary_key=True)
    # Server-issued uuid4. Never derived from a timestamp, safe to quote.
    reflection_id = db.Column(db.String(64), unique=True, index=True,
                              nullable=False)
    # The completed technical execution this explains. Unique: the one-per-
    # execution rule is a database constraint, not a convention.
    execution_id = db.Column(db.String(64), unique=True, index=True,
                             nullable=False)
    session_id = db.Column(db.String(100), index=True)

    scenario_key = db.Column(db.String(64), index=True)
    prompt_key = db.Column(db.String(64))
    # An authored explanation id from learning/reflection.py. Validated against
    # that scenario's own option list before it is ever written.
    selected_explanation_id = db.Column(db.String(64), nullable=False)
    # Derived server-side from the authored definition at write time, and
    # recomputable from it; stored so an analysis need not re-resolve the
    # definition version that was live.
    preferred_explanation = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def to_dict(self):
        """Canonical internal form. Carries the real ``session_id``."""
        return {
            "reflection_id": self.reflection_id,
            "execution_id": self.execution_id,
            "session_id": self.session_id,
            "scenario_key": self.scenario_key,
            "prompt_key": self.prompt_key,
            "selected_explanation_id": self.selected_explanation_id,
            "preferred_explanation": bool(self.preferred_explanation),
            "created_at": (self.created_at.isoformat()
                           if self.created_at else None),
        }

    def display_dict(self):
        """Instructor-facing form: pseudonymous label instead of session id."""
        row = self.to_dict()
        row["session_label"] = session_label(row.pop("session_id"))
        return row


class ConceptEvidence(db.Model):
    """One authored signal, about one concept, from one learner act.

    **What a row means.** "In this exercise, this response was authored as
    evidence of this kind about this concept." That is the whole claim.

    **What a row is not.** Not a psychological diagnosis, not a permanent
    learner trait, not a validated mastery score, and not a clinical or
    educational assessment. R6 deliberately computes no global mastery
    percentage and averages nothing: rows are counted and grouped, never summed
    into a number about a person.

    ``evidence_source`` separates the two kinds of act, and the distinction
    matters for the paper. ``factual_decision`` is the learner's behaviour
    before the intervention; ``structured_reflection`` is their explanation
    after seeing it. The counterfactual branch produces neither -- it is part
    of the intervention, and is never recorded as behavioural evidence.
    """
    __tablename__ = 'concept_evidence'

    #: Evidence sources, mirroring ``learning``'s constants. Declared here so a
    #: query can be written against the model without importing the domain.
    SOURCE_FACTUAL_DECISION = "factual_decision"
    SOURCE_STRUCTURED_REFLECTION = "structured_reflection"
    SOURCE_TRANSFER_PROBE = "transfer_probe"

    __table_args__ = (
        # Idempotency as a constraint. Re-deriving evidence for an execution --
        # on a refresh, a repeated POST, or a second visit to the feedback page
        # -- collides here rather than appending a duplicate row.
        db.UniqueConstraint('execution_id', 'evidence_source', 'concept_tag',
                            name='uq_concept_evidence_execution_source_tag'),
    )

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), index=True)
    # The technical execution the evidence was derived from. For transfer-probe
    # evidence this is the *source* execution that unlocked the probe.
    execution_id = db.Column(db.String(64), index=True, nullable=False)

    scenario_key = db.Column(db.String(64), index=True)
    concept_tag = db.Column(db.String(64), index=True, nullable=False)
    evidence_source = db.Column(db.String(32), index=True, nullable=False)
    evidence_signal = db.Column(db.String(32), index=True, nullable=False)
    response_quality = db.Column(db.String(16), index=True)
    # The raw 0..100 reading, kept as the measurement it is. Null where the act
    # carried no confidence (a structured reflection does not ask for one).
    confidence = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def to_dict(self):
        """Canonical internal form. Carries the real ``session_id``."""
        return {
            "session_id": self.session_id,
            "execution_id": self.execution_id,
            "scenario_key": self.scenario_key,
            "concept_tag": self.concept_tag,
            "evidence_source": self.evidence_source,
            "evidence_signal": self.evidence_signal,
            "response_quality": self.response_quality,
            "confidence": self.confidence,
            "created_at": (self.created_at.isoformat()
                           if self.created_at else None),
        }

    def display_dict(self):
        """Instructor-facing form: pseudonymous label instead of session id."""
        row = self.to_dict()
        row["session_label"] = session_label(row.pop("session_id"))
        return row


class TransferAttempt(db.Model):
    """A learner's first response to an unseen transfer probe.

    This is the one measurement in RewindSec taken *after* the intervention and
    *without* it: no rewind, no comparison, no feedback until it is recorded.
    The first response is therefore the datum, and the unique constraint below
    is what makes that true rather than merely intended -- a resubmission, a
    Back-button repost or a refresh cannot replace it.

    No ``TrainingExecution`` row is created by a probe, no
    ``CounterfactualRuntime`` runs, no sandbox is touched and no ``TRAINING_*``
    lifecycle event is emitted. ``source_execution_id`` is a reference to the
    training execution that unlocked the probe, resolved server-side from the
    session; it is never accepted from a browser.
    """
    __tablename__ = 'transfer_attempt'

    __table_args__ = (
        # Exactly one attempt per source execution and probe.
        db.UniqueConstraint('source_execution_id', 'probe_key',
                            name='uq_transfer_attempt_source_probe'),
    )

    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.String(64), unique=True, index=True,
                           nullable=False)
    session_id = db.Column(db.String(100), index=True)
    source_execution_id = db.Column(db.String(64), index=True, nullable=False)
    source_scenario_key = db.Column(db.String(64), index=True)

    probe_key = db.Column(db.String(64), index=True, nullable=False)
    probe_version = db.Column(db.Integer, nullable=False, default=1)

    # An authored probe choice id, validated against that probe's own option
    # list before it is written. Never free text.
    choice_id = db.Column(db.String(64), nullable=False)
    response_quality = db.Column(db.String(16), index=True)
    confidence = db.Column(db.Integer, nullable=True)
    # Measured server-side from when the probe was rendered, bounded, and null
    # when implausible -- exactly as the training flow measures latency.
    response_time_ms = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def to_dict(self):
        """Canonical internal form. Carries the real ``session_id``."""
        return {
            "attempt_id": self.attempt_id,
            "session_id": self.session_id,
            "source_execution_id": self.source_execution_id,
            "source_scenario_key": self.source_scenario_key,
            "probe_key": self.probe_key,
            "probe_version": self.probe_version,
            "choice_id": self.choice_id,
            "response_quality": self.response_quality,
            "confidence": self.confidence,
            "response_time_ms": self.response_time_ms,
            "created_at": (self.created_at.isoformat()
                           if self.created_at else None),
        }

    def display_dict(self):
        """Instructor-facing form: pseudonymous label instead of session id."""
        row = self.to_dict()
        row["session_label"] = session_label(row.pop("session_id"))
        return row



# --- RewindSec research-study artifacts (Milestone R7) ---
# Three tables supporting a randomised pilot of the phishing module. They are
# *research* artifacts and are deliberately separate from everything above.
#
# The distinction that matters most: ``TrainingExecution`` keeps its R2 meaning
# exactly -- **one paired counterfactual execution**. Only the
# ``counterfactual_replay`` arm produces one. The awareness-debrief arm executes
# no consequence at all and the factual-consequence arm executes one branch, so
# neither has a pair to record; ``StudyIntervention`` exists precisely so that
# neither has to be squeezed into a table whose name would then be a lie.
#
# Privacy: no name, email, student id, phone number, registration number, date
# of birth, gender, demographic field, IP address or user agent appears in any
# of these tables. A participant is a UUID4 and an allocation slot.
#
# Portability: plain columns and Text only, exactly as R6 -- everything here is
# created by ``db.create_all()`` and the repository still carries no migrations.

class StudyEnrollment(db.Model):
    """One participant's allocation and progress through the pilot protocol.

    **The allocation is written once, at enrollment, and never rewritten.** No
    route updates ``arm_key`` or ``allocation_slot``; a learner cannot request
    an arm, submit one, or change one by refreshing, and an instructor has no
    surface that edits one. That is what makes the allocation auditable.

    ``allocation_slot`` is unique *within a protocol version*, and that
    uniqueness is how concurrent enrollment stays balanced: two simultaneous
    enrollments cannot both take slot 7, because the second insert collides and
    retries onto slot 8 (see ``study_service.enroll``). A count-then-choose
    scheme with no constraint would hand both the same arm.

    ``session_id`` is kept for authorisation only -- it says which browser
    session currently owns this enrollment, and the return-code resume flow
    rebinds it. It is deliberately **absent from the research export**;
    ``participant_id`` is the correlation identifier for analysis.
    """
    __tablename__ = 'study_enrollment'

    STATUS_ACTIVE = "active"
    STATUS_COMPLETED = "completed"

    __table_args__ = (
        # Balanced allocation as a database constraint rather than a
        # convention. See the class docstring.
        db.UniqueConstraint('protocol_key', 'protocol_version',
                            'allocation_slot',
                            name='uq_study_enrollment_protocol_slot'),
    )

    id = db.Column(db.Integer, primary_key=True)
    # The research correlation identifier. Server-issued uuid4, derived from
    # nothing: not the session, not the slot, not a clock.
    participant_id = db.Column(db.String(64), unique=True, index=True,
                               nullable=False)
    # Authorisation only, and mutable: the resume flow points it at the
    # participant's current browser session. Never exported.
    session_id = db.Column(db.String(100), index=True)

    protocol_key = db.Column(db.String(64), index=True, nullable=False)
    protocol_version = db.Column(db.Integer, nullable=False, default=1)
    arm_key = db.Column(db.String(32), index=True, nullable=False)
    allocation_slot = db.Column(db.Integer, nullable=False)

    # Keyed digest of the participant's return code. The raw code is shown once
    # at enrollment and never stored, logged, exported or placed in a URL.
    return_code_digest = db.Column(db.String(64), unique=True, index=True)

    status = db.Column(db.String(16), nullable=False, default=STATUS_ACTIVE,
                       index=True)
    # Server-authoritative position in this arm's authored progression. Never
    # read from a form, a hidden field or a query string.
    phase = db.Column(db.String(40), nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    intervention_started_at = db.Column(db.DateTime, nullable=True)
    intervention_completed_at = db.Column(db.DateTime, nullable=True)
    immediate_transfer_completed_at = db.Column(db.DateTime, nullable=True)
    retention_open_at = db.Column(db.DateTime, nullable=True, index=True)
    retention_close_at = db.Column(db.DateTime, nullable=True, index=True)
    retention_completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        """Canonical internal form. Carries the real ``session_id``."""
        return {
            "participant_id": self.participant_id,
            "session_id": self.session_id,
            "protocol_key": self.protocol_key,
            "protocol_version": self.protocol_version,
            "arm_key": self.arm_key,
            "allocation_slot": self.allocation_slot,
            "status": self.status,
            "phase": self.phase,
            "created_at": _iso(self.created_at),
            "intervention_started_at": _iso(self.intervention_started_at),
            "intervention_completed_at": _iso(self.intervention_completed_at),
            "immediate_transfer_completed_at": _iso(
                self.immediate_transfer_completed_at),
            "retention_open_at": _iso(self.retention_open_at),
            "retention_close_at": _iso(self.retention_close_at),
            "retention_completed_at": _iso(self.retention_completed_at),
        }

    def display_dict(self):
        """Instructor-facing form.

        Neither the raw ``session_id`` nor the return-code digest is present in
        the returned mapping -- they are removed rather than merely omitted by a
        template. ``participant_id`` stays, because it is the pseudonymous
        research identifier the dashboard and the export are both keyed on.
        """
        row = self.to_dict()
        row.pop("session_id", None)
        row["study_label"] = "P-" + short_id(self.participant_id, 6)
        return row


class StudyIntervention(db.Model):
    """What one participant's assigned intervention actually did.

    One row per enrollment. It holds the **pre-intervention behavioural
    measure** -- the first phishing decision, taken before any arm-specific
    feedback and identical in presentation across all three arms -- plus
    whatever technical evidence that arm produced.

    Which columns are populated is the arm difference, made explicit:

    ``awareness_debrief``    no digest, no state, no execution, no reflection.
                             Nothing was executed, so nothing is recorded as
                             though it had been.
    ``factual_consequence``  ``baseline_digest``, ``factual_result_digest`` and
                             ``factual_state_json`` from one real adapter run.
                             Still no execution and no reflection: one branch is
                             not a pair.
    ``counterfactual_replay`` all of the above, plus ``training_execution_id``
                             and ``reflection_id``. The paired result itself is
                             **not** duplicated here -- ``TrainingExecution``
                             already owns it, and two copies would eventually
                             disagree.
    """
    __tablename__ = 'study_intervention'

    id = db.Column(db.Integer, primary_key=True)
    intervention_id = db.Column(db.String(64), unique=True, index=True,
                                nullable=False)
    # One intervention per enrollment, as a constraint: a repeated POST
    # collides here rather than recording a second first-decision.
    enrollment_id = db.Column(db.Integer, unique=True, index=True,
                              nullable=False)
    participant_id = db.Column(db.String(64), index=True, nullable=False)

    scenario_key = db.Column(db.String(64), index=True)
    arm_key = db.Column(db.String(32), index=True, nullable=False)

    # -- the pre-intervention behavioural measure, recorded exactly once ----
    factual_choice_id = db.Column(db.String(64))
    factual_response_quality = db.Column(db.String(16), index=True)
    factual_confidence = db.Column(db.Integer, nullable=True)
    factual_response_time_ms = db.Column(db.Integer, nullable=True)

    # -- technical evidence, where the arm produced any ---------------------
    baseline_digest = db.Column(db.String(64), nullable=True)
    factual_result_digest = db.Column(db.String(64), nullable=True)
    factual_state_json = db.Column(db.Text, nullable=True)

    # Populated only for ``counterfactual_replay``.
    training_execution_id = db.Column(db.String(64), index=True, nullable=True)
    reflection_id = db.Column(db.String(64), index=True, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "intervention_id": self.intervention_id,
            "enrollment_id": self.enrollment_id,
            "participant_id": self.participant_id,
            "scenario_key": self.scenario_key,
            "arm_key": self.arm_key,
            "factual_choice_id": self.factual_choice_id,
            "factual_response_quality": self.factual_response_quality,
            "factual_confidence": self.factual_confidence,
            "factual_response_time_ms": self.factual_response_time_ms,
            "baseline_digest": self.baseline_digest,
            "factual_result_digest": self.factual_result_digest,
            "training_execution_id": self.training_execution_id,
            "reflection_id": self.reflection_id,
            "created_at": _iso(self.created_at),
            "completed_at": _iso(self.completed_at),
        }

    def display_dict(self):
        return self.to_dict()


class StudyAssessmentAttempt(db.Model):
    """One participant's **first** response to one study measurement probe.

    Separate from ``TransferAttempt`` on purpose. That table keys an attempt to
    a ``source_execution_id``, which only the counterfactual-replay arm has;
    keying research measurements to it would have made the immediate probe
    unreachable for two of the three arms, or forced a fake execution row into
    existence for them. This table keys on the enrollment instead, which every
    arm has.

    No ``TrainingExecution`` is created by a probe, no ``CounterfactualRuntime``
    runs, no adapter is prepared, no sandbox is touched and no ``TRAINING_*``
    event is emitted.

    The unique constraint is what makes "first response" true rather than
    merely intended: a resubmission, a Back-button repost or a refresh re-reads
    the stored row and cannot revise it.
    """
    __tablename__ = 'study_assessment_attempt'

    __table_args__ = (
        db.UniqueConstraint('enrollment_id', 'phase', 'probe_key',
                            name='uq_study_attempt_enrollment_phase_probe'),
    )

    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.String(64), unique=True, index=True,
                           nullable=False)
    enrollment_id = db.Column(db.Integer, index=True, nullable=False)
    participant_id = db.Column(db.String(64), index=True, nullable=False)

    # ``immediate_transfer`` or ``retention_transfer``.
    phase = db.Column(db.String(32), index=True, nullable=False)
    probe_key = db.Column(db.String(64), index=True, nullable=False)
    probe_version = db.Column(db.Integer, nullable=False, default=1)

    # An authored probe choice id, validated against that probe's own option
    # list before it is written. Never free text.
    choice_id = db.Column(db.String(64), nullable=False)
    response_quality = db.Column(db.String(16), index=True)
    confidence = db.Column(db.Integer, nullable=True)
    # Measured server-side from when the probe was rendered, bounded, and null
    # when implausible -- exactly as the training and R6 probe flows measure it.
    response_time_ms = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def to_dict(self):
        return {
            "attempt_id": self.attempt_id,
            "enrollment_id": self.enrollment_id,
            "participant_id": self.participant_id,
            "phase": self.phase,
            "probe_key": self.probe_key,
            "probe_version": self.probe_version,
            "choice_id": self.choice_id,
            "response_quality": self.response_quality,
            "confidence": self.confidence,
            "response_time_ms": self.response_time_ms,
            "created_at": _iso(self.created_at),
        }

    def display_dict(self):
        return self.to_dict()



# --- Conference sandbox (instructor-only control surface) ---
# All Docker / filesystem logic lives in the sandbox package; routes only
# delegate. See README "Conference Sandbox Architecture".
from sandbox_routes import (create_sandbox_blueprint, ensure_manager,
                            make_recorder, sandbox_dashboard_context,
                            session_sandbox_id)
from training_service import TrainingService

app.register_blueprint(create_sandbox_blueprint(
    db, SecurityEvent, app.config['SANDBOX_LOCAL_ROOT']))


def sandbox_manager():
    return ensure_manager(app, db, SecurityEvent,
                          app.config['SANDBOX_LOCAL_ROOT'])


# --- RewindSec counterfactual training (Milestone R2) ---
# The service owns execution identity, result persistence and lifecycle
# telemetry; the pure runtime in ``training/`` stays free of Flask, SQLAlchemy
# and the sandbox.
#
# Milestone R3 adds the first learner-facing flow on top of it: the
# ``/training`` blueprint in ``training_routes.py``, whose phishing scenario
# definition and consequence adapter live in the application-level
# ``scenario_adapters`` package (never under ``training/``, which must stay
# framework-independent). R4 adds the ransomware module on the same loop, with
# the contained Docker sandbox as its consequence environment.

def training_service():
    """The configured TrainingService for this app. One per process.

    Wired to the same telemetry write path the sandbox subsystem uses, so
    TRAINING_* events pass through the identical progression-idempotency gate
    and land in the one authoritative SecurityEvent table.
    """
    service = getattr(app, "_training_service", None)
    if service is None:
        service = TrainingService(db, TrainingExecution,
                                  make_recorder(db, SecurityEvent),
                                  logger=app.logger)
        app._training_service = service
    return service


# The learner-facing RewindSec flow. Registered after ``training_service`` is
# defined and given it as a callable, so the blueprint never imports ``app``.
from training_routes import create_training_blueprint  # noqa: E402

app.register_blueprint(create_training_blueprint(
    db, TrainingExecution, IDENTITIES, training_service,
    # Milestone R4: the ransomware module's consequence environment is the real
    # disposable sandbox. It is handed the manager factory and the *derived*
    # session->sandbox id function, never a sandbox id from a request.
    sandbox_manager=sandbox_manager,
    sandbox_id_for_session=session_sandbox_id))


# --- RewindSec learning layer (Milestone R6) ---
# The layer *after* the technical comparison: structured self-explanation,
# confidence-aware concept evidence and unseen transfer probes.
#
# It consumes completed executions and never alters them. No adapter, no
# CounterfactualRuntime, no sandbox and no TRAINING_* event is reachable from
# this blueprint; the pure authored pedagogy lives in ``learning/``, which -- like
# ``training/`` -- imports nothing but the standard library.

from learning_service import LearningService  # noqa: E402


def learning_service():
    """The configured LearningService for this app. One per process."""
    service = getattr(app, "_learning_service", None)
    if service is None:
        service = LearningService(db, TrainingExecution, LearningReflection,
                                  ConceptEvidence, TransferAttempt,
                                  logger=app.logger)
        app._learning_service = service
    return service


from learning_routes import create_learning_blueprint  # noqa: E402

app.register_blueprint(create_learning_blueprint(
    TrainingExecution, learning_service,
    # The canonical session id, read server-side. Never a pseudonymous label:
    # a label is a display artifact and must not become an authenticator.
    lambda: session.get("session_id")))


# --- RewindSec research study (Milestone R7) ---
# A randomised pilot of the phishing module, built on top of R1-R6 and
# **disabled by default**. With ``REWINDSEC_STUDY_ENABLED`` unset there is no
# study surface at all: every route in the blueprint 404s, no enrollment can be
# created, and the ordinary training and learning flows are untouched.
#
# Enabling it is an operational setting. It is not ethics approval, participant
# consent, or study registration, and nothing in this codebase claims otherwise.
# See docs/study-protocol.md.
#
# Two independent secrets -- one for arm allocation, one for return-code
# continuity -- plus an access code are read here, and are deliberately *not*
# Flask's ``secret_key``: that key has a documented random development
# fallback and is rotated for reasons unrelated to the study, and neither an
# allocation sequence nor a set of issued return codes may be invalidated by a
# redeploy. The two study secrets are kept separate from each other as well:
# allocation randomisation and return-code authentication are different
# security domains.


def _study_flag(value):
    """Whether an environment value means "on". Absent means off."""
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


app.config["STUDY_ENABLED"] = _study_flag(
    os.environ.get("REWINDSEC_STUDY_ENABLED"))
# No fallback for either. When research mode is on and one of them is missing,
# the blueprint fails closed with a 503 rather than allocating under an empty
# key or serving the flow with no gate.
app.config["STUDY_ASSIGNMENT_SECRET"] = os.environ.get(
    "REWINDSEC_STUDY_ASSIGNMENT_SECRET", "")
app.config["STUDY_ACCESS_CODE"] = os.environ.get(
    "REWINDSEC_STUDY_ACCESS_CODE", "")
# Independent from the assignment secret: arm allocation and return-code
# continuity are separate security domains and must not share key material.
app.config["STUDY_CONTINUITY_SECRET"] = os.environ.get(
    "REWINDSEC_STUDY_CONTINUITY_SECRET", "")


def study_settings():
    """The live research-mode configuration, read per request.

    Read from ``app.config`` rather than captured at import, so a test (and an
    operator restarting under a different environment) sees the current values
    rather than whatever was true when the object graph was built. The access
    code is returned for comparison only; it is never persisted on an
    enrollment row, rendered, or logged.
    """
    return {
        "enabled": bool(app.config.get("STUDY_ENABLED")),
        "assignment_secret": app.config.get("STUDY_ASSIGNMENT_SECRET") or "",
        "access_code": app.config.get("STUDY_ACCESS_CODE") or "",
        "continuity_secret": app.config.get("STUDY_CONTINUITY_SECRET") or "",
    }


from study_service import StudyService  # noqa: E402


def study_service():
    """The configured StudyService for this app. One per process."""
    service = getattr(app, "_study_service", None)
    if service is None:
        service = StudyService(
            db, StudyEnrollment, StudyIntervention, StudyAssessmentAttempt,
            TrainingExecution, LearningReflection,
            # The third arm delegates its paired execution and its structured
            # reflection to the existing services rather than reimplementing
            # either. Passed as callables so nothing is constructed twice.
            training_service, learning_service, study_settings,
            logger=app.logger)
        app._study_service = service
    return service


from study_routes import create_study_blueprint  # noqa: E402

app.register_blueprint(create_study_blueprint(
    study_service,
    # The canonical session id, read server-side. The study flow uses it for
    # authorisation only and never exports it.
    lambda: session.get("session_id"),
    study_settings))


def record_event(event_type, scenario_id=None, source=None, target=None,
                 details=None, session_id=None):
    """Persist one application-level SecurityEvent.

    The single write path for telemetry emitted by Flask routes (the sandbox
    subsystem has its own recorder, which writes the same table). Every event
    carries session_id, scenario_id, event_type, timestamp and source; target
    and details are filled in where they apply. No caller may pass a credential
    value -- there is none available at any call site.
    """
    session_id = session_id if session_id is not None else session.get('session_id')
    target = (str(target)[:300] if target else None)
    details = (str(details)[:500] if details else None)

    # Milestone 4.2: a progression milestone is written at most once per
    # (session_id, scenario_id, event_type). A refresh, a browser prefetch or a
    # crawler re-issuing the same GET therefore cannot append a second
    # "stage reached" row and cannot move a funnel count. Raw interaction
    # telemetry (PAGE_VIEW and friends) is not gated and stays repeatable.
    if not telemetry_ledger.claim(db.session, {
            "event_type": event_type, "scenario_id": scenario_id,
            "session_id": session_id}):
        db.session.commit()
        return None

    row = SecurityEvent(
        event_type=event_type,
        scenario_id=scenario_id,
        session_id=session_id,
        timestamp=utcnow(),
        source=source,
        target=target,
        details=details,
    )
    db.session.add(row)
    db.session.commit()
    return row


def record_page_view(source, scenario_id=None, target=None, details=None):
    """Record one raw ``PAGE_VIEW``. Deliberately repeatable.

    This is the telemetry that a refresh *should* produce: it says a page was
    requested, nothing more. It is never a scenario stage, it is excluded from
    every funnel and conversion figure, and sequence scoring drops it as noise
    (``sandbox.telemetry.SCORING_NOISE``). Keeping it means Milestone 4.2 makes
    progression idempotent without throwing away observation data.
    """
    return record_event(EventType.PAGE_VIEW, scenario_id=scenario_id,
                        source=source, target=target, details=details)


# -- ransomware-awareness scenario correlation ------------------------------
RANSOMWARE_SESSION_KEY = "ransomware_scenario_id"


def ransomware_scenario_id(reset=False):
    """Stable scenario id for this session's ransomware run.

    Mirrors the phishing scenario's correlation model so both scenarios can be
    reconstructed from SecurityEvent alone.
    """
    if reset:
        session.pop(RANSOMWARE_SESSION_KEY, None)
    scenario_id = session.get(RANSOMWARE_SESSION_KEY)
    if not scenario_id:
        scenario_id = new_scenario_id()
        session[RANSOMWARE_SESSION_KEY] = scenario_id
        session.modified = True
    return scenario_id

# -- ransomware run state, scoped to one learner session --------------------

def _catalogue_names():
    """The baseline synthetic filenames, in a stable order."""
    return [row.name for row in DemoFile.query.order_by(DemoFile.id.asc()).all()]


def ransomware_run(create=False):
    """This session's run-state row, or ``None``.

    The lookup key is ``session['session_id']`` -- server-issued and never
    read from request data -- so there is no parameter with which one learner
    could address another learner's run.
    """
    session_id = session.get("session_id")
    if not session_id:
        return None
    run = RansomwareRunState.query.filter_by(session_id=session_id).first()
    if run is None and create:
        run = RansomwareRunState(session_id=session_id,
                                 scenario_id=ransomware_scenario_id(),
                                 state=STATE_BASELINE,
                                 remark=BASELINE_REMARK,
                                 updated_at=utcnow())
        db.session.add(run)
        db.session.commit()
    return run


def set_ransomware_state(state, variant="browser", remark=None):
    """Move *this session's* run to ``state``. Touches no other session.

    The "impact" is a status string on this session's own row: no file is
    read, written, renamed or encrypted anywhere by this call.
    """
    run = ransomware_run(create=True)
    if run is None:
        return None
    run.state = state
    run.variant = normalise_variant(variant)
    run.scenario_id = ransomware_scenario_id()
    if remark is None:
        remark = (impact_remark(run.variant) if state == STATE_IMPACTED
                  else RESTORED_REMARK)
    run.remark = remark[:256]
    run.updated_at = utcnow()
    db.session.commit()
    return run


def reap_ransomware_state(max_age_seconds=DEFAULT_MAX_AGE_SECONDS, now=None,
                         dry_run=False):
    """Delete ``RansomwareRunState`` rows that have gone stale.

    **Explicit maintenance only.** There is no scheduler, no background thread
    and no request handler that calls this: it runs when an operator asks, via
    ``python manage.py reap-state``. That is deliberate -- an automatic reaper
    is one clock skew away from deleting the state of a class that is mid
    exercise.

    Safety properties, in order of importance:

    1. **Selection is by age alone.** ``select_stale`` takes no session id, no
       scenario id and no row id, so there is no parameter through which
       request data could ever name a victim row. Compare
       ``SandboxManager.reap_stale``, which has the same shape for sandboxes.
    2. **A row with no ``updated_at`` is never selected.** An unknown age means
       "leave it alone".
    3. **The threshold has a floor** (``MIN_MAX_AGE_SECONDS``); a value below it
       raises rather than widening the selection.
    4. ``dry_run=True`` reports the selection and deletes nothing.
    5. **Only this table is touched.** No SecurityEvent, product, demo-file or
       credential-interaction row is read or written here, so removing stale
       simulation state never removes recorded telemetry.

    Returns one dict per selected row, oldest first.
    """
    rows = RansomwareRunState.query.all()
    selected = select_stale(rows, max_age_seconds, now=now)
    selected.sort(key=lambda pair: pair[1], reverse=True)
    reaped = [{"session_label": session_label(row.session_id),
               "scenario_id": row.scenario_id,
               "state": row.state,
               "age_seconds": age,
               "deleted": not dry_run}
              for row, age in selected]
    if not dry_run:
        for row, _age in selected:
            db.session.delete(row)
        db.session.commit()
    return reaped


def ransomware_files():
    """The catalogue projected through *this session's* state (plain dicts)."""
    run = ransomware_run()
    if run is None:
        return file_rows(_catalogue_names())
    return file_rows(_catalogue_names(), run.state, run.remark)


# Session tracking
@app.before_request
def ensure_session_id():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())

#: Tables from superseded milestones. ``simulated_credential`` (Milestone 1)
#: stored learner-submitted plaintext passwords; ``phishing_funnel`` and
#: ``ransomware_funnel`` (Milestone 2) were a parallel analytics system replaced
#: by SecurityEvent-derived progression. No current model creates any of them,
#: so a database created by this build never contains one.
LEGACY_TABLES = (
    "simulated_credential",
    "phishing_funnel",
    "ransomware_funnel",
)


def drop_legacy_tables():
    """Drop the superseded tables. **Explicit, never automatic.**

    Until Milestone 4 this ran on every import, so simply starting the app
    silently executed DROP TABLE against the configured database -- including
    one an instructor had pointed at a captured classroom run. Destroying data
    is now something an operator asks for by name:

        python manage.py drop-legacy

    This project is a SQLite-backed teaching demo, so it deliberately does not
    carry an Alembic history; the development reset commands in ``manage.py``
    are the whole migration story. Returns the tables actually dropped.
    """
    inspector = sqlalchemy.inspect(db.engine)
    present = [t for t in LEGACY_TABLES if t in inspector.get_table_names()]
    with db.engine.begin() as connection:
        for table in present:
            connection.exec_driver_sql("DROP TABLE IF EXISTS %s" % table)
    return present


def init_db(force_reseed=False):
    """Create the schema and seed the demo content.

    Idempotent by default: the marketplace products and the ransomware demo
    rows are written only when their tables are empty, so restarting the app
    no longer deletes whatever a classroom session recorded. Pass
    ``force_reseed=True`` (``python manage.py reset-demo``) to replace them
    deliberately.
    """
    db.create_all()

    already_seeded = bool(Product.query.first()) and bool(DemoFile.query.first())
    if already_seeded and not force_reseed:
        return False

    if force_reseed:
        Product.query.delete()
        DemoFile.query.delete()

    # Initialize demo files for ransomware simulation
    files = [
        DemoFile(name="employee_list.csv"),
        DemoFile(name="sample_financials.xlsx"),
        DemoFile(name="project_docs.pdf"),
        DemoFile(name="family_photos_2024.zip"),
        DemoFile(name="tax_returns_2023.pdf"),
        DemoFile(name="passwords_backup.txt"),
        DemoFile(name="business_contract.docx"),
        DemoFile(name="vacation_photos.jpg"),
        DemoFile(name="thesis_final_draft.docx"),
        DemoFile(name="cryptocurrency_keys.txt"),
        DemoFile(name="bank_statements.pdf"),
        DemoFile(name="client_database.xlsx"),
        DemoFile(name="personal_diary.docx"),
        DemoFile(name="wedding_photos.zip"),
        DemoFile(name="medical_records.pdf")
    ]
    
    for file in files:
        db.session.add(file)
    
    # Initialize products
    products = [
        # Equipment Section
        Product(
            name="AK-47 Replica",
            description="Detailed replica for collectors.",
            price=299.99,
            image="images/products/ak47.jpeg"
        ),
        Product(
            name="Multi-Purpose Calculator",
            description="Advanced calculation device for both botanical measurements and general use.",
            price=149.99,
            image="images/products/calc.jpeg"
        ),
        Product(
            name="Professional Drone",
            description="High-performance aerial device.",
            price=2999.99,
            image="images/products/drone.jpeg"
        ),
        Product(
            name="Glock 19 Replica",
            description="Collector's item replica.",
            price=199.99,
            image="images/products/glock19.jpeg"
        ),
        Product(
            name="M16 Model",
            description="Detailed model for display.",
            price=399.99,
            image="images/products/m16.jpeg"
        ),
        Product(
            name="MH12 Tactical",
            description="High-precision tactical replica MH12 for collectors and display.",
            price=1299.99,
            image="images/products/MH12.jpeg"
        ),
        Product(
            name="AWM Sniper Replica",
            description="Accurate AWM replica model suitable for exhibition and educational displays.",
            price=1599.99,
            image="images/products/AWM.jpeg"
        ),
        Product(
            name="Guns Collection 1",
            description="Mixed collection of classic firearm replicas for collectors.",
            price=749.99,
            image="images/products/guns1.jpeg"
        ),
        # Plants Section
        Product(
            name="Special Blend",
            description="Premium crystalline botanical extract.",
            price=899.99,
            image="images/products/coke1.jpeg"
        ),
        Product(
            name="Crystal Formation",
            description="Naturally formed crystal specimens.",
            price=1299.99,
            image="images/products/crystals.jpeg"
        ),
        Product(
            name="Plant Nutrient Injector",
            description="Specialized botanical feeding system.",
            price=449.99,
            image="images/products/injection.jpeg"
        ),
        Product(
            name="Rare Plant Collection A",
            description="Exotic botanical specimens.",
            price=499.99,
            image="images/products/plant1.jpeg"
        ),
        Product(
            name="Rare Plant Collection B",
            description="Premium plant varieties.",
            price=599.99,
            image="images/products/plant2.jpeg"
        ),
        Product(
            name="Rare Plant Collection C",
            description="Exclusive botanical selection.",
            price=699.99,
            image="images/products/plant3.jpeg"
        ),
        Product(
            name="Herbal Blend",
            description="Special aromatic mixture.",
            price=349.99,
            image="images/products/smoke.jpeg"
        )
    ]
    
    for product in products:
        db.session.add(product)

    db.session.commit()
    return True


with app.app_context():
    # Creating missing tables and seeding empty ones is safe and non-destructive.
    # Dropping anything is not, and is reserved for ``manage.py``.
    init_db()

@app.route("/")
def index():
    q = request.args.get('q', '').lower()
    results = []
    navigation_links = []
    
    # Mock pages for search results
    mock_pages = [
        # Plant-related pages
        {
            'slug': 'exotic-plants',
            'title': 'Exotic Plants Market',
            'content': 'Rare and exotic botanical specimens from around the world. Premium selection of unique plants and herbs.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'rare-specimens',
            'title': 'Rare Plant Specimens',
            'content': 'Premium collection of hard-to-find botanical varieties. Exclusive selection of rare plants and crystalline extracts.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'herbal-market',
            'title': 'Premium Herbal Market',
            'content': 'Special aromatic mixtures and botanical blends. Features rare plant collections.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'crystal-botanicals',
            'title': 'Crystal Botanical Exchange',
            'content': 'Specialized marketplace for crystalline botanical specimens and extracts.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'plant-nutrients',
            'title': 'Plant Nutrient Systems',
            'content': 'Advanced feeding and nutrient delivery systems for specialized plant cultivation.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'smoke-blends',
            'title': 'Aromatic Smoke Blends',
            'content': 'Curated collection of premium aromatic blends and mixtures.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'botanical-research',
            'title': 'Botanical Research Supplies',
            'content': 'Specialized equipment and supplies for botanical research and experimentation.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'plant-extracts',
            'title': 'Premium Plant Extracts',
            'content': 'High-quality botanical extracts and concentrates from rare specimens.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'herb-collection',
            'title': 'Rare Herb Collection',
            'content': 'Exclusive collection of rare and exotic herbal specimens.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        {
            'slug': 'botanical-lab',
            'title': 'Botanical Laboratory',
            'content': 'Professional equipment for botanical processing and research.',
            'category': 'plants',
            'url': '/marketplace/plants'
        },
        # Equipment-related pages
        {
            'slug': 'tactical-gear',
            'title': 'Tactical Equipment Market',
            'content': 'Professional grade tactical equipment and accessories.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'military-surplus',
            'title': 'Military Equipment Market',
            'content': 'Specialized military-grade equipment and collectibles.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'weapon-collect',
            'title': 'Equipment Collection Market',
            'content': 'Premium collection of specialized equipment and replicas.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'sniper-gear',
            'title': 'Precision Equipment Market',
            'content': 'High-precision tactical equipment and accessories.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'combat-gear',
            'title': 'Combat Equipment Exchange',
            'content': 'Professional combat equipment and tactical gear.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'collector-items',
            'title': 'Collector Equipment Gallery',
            'content': 'Rare and exclusive collector-grade equipment and replicas.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'aerial-equipment',
            'title': 'Aerial Equipment Market',
            'content': 'Professional aerial devices and related equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'tactical-accessories',
            'title': 'Tactical Accessories Exchange',
            'content': 'Specialized accessories for tactical equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'defense-gear',
            'title': 'Defense Equipment Market',
            'content': 'Professional defense equipment and tactical gear.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        {
            'slug': 'equipment-parts',
            'title': 'Equipment Parts Exchange',
            'content': 'Specialized parts and components for tactical equipment.',
            'category': 'equipment',
            'url': '/marketplace/weapons'
        },
        # Tools pages
        {
            'slug': 'hacking-tools',
            'title': 'Premium Hacking Tools',
            'content': 'Professional exploitation tools and penetration testing suites. Download the most advanced hacking software used by professionals worldwide.',
            'category': 'tools',
            'url': '/marketplace/tools'
        },
        {
            'slug': 'exploit-kits',
            'title': 'Exploit Kits Market',
            'content': 'Advanced exploitation frameworks and zero-day vulnerabilities. Professional hacking tools.',
            'category': 'tools',
            'url': '/marketplace/tools'
        },
        # Storage page
        {
            'slug': 'secure-storage',
            'title': 'Secure File Storage',
            'content': 'Browse and manage your encrypted files. Access your secure document storage system.',
            'category': 'storage',
            'url': '/files/browser'
        }
    ]
    
    if q:
        # Keywords for better categorization
        plant_keywords = ['plant', 'botanic', 'herb', 'crystal', 'specimen', 'extract', 'blend']
        equipment_keywords = ['equipment', 'weapon', 'tactical', 'military', 'gear', 'device']
        tools_keywords = ['hack', 'tool', 'exploit', 'crack', 'penetration', 'software']
        
        # Check if query matches category keywords
        is_plant_search = any(keyword in q for keyword in plant_keywords)
        is_equipment_search = any(keyword in q for keyword in equipment_keywords)
        is_tools_search = any(keyword in q for keyword in tools_keywords)
        
        # Define navigation links based on search category
        if is_plant_search:
            results = [page for page in mock_pages if page['category'] == 'plants']
            navigation_links = [{'title': 'Plants & Botanicals', 'url': '/marketplace/plants'}]
        elif is_equipment_search:
            results = [page for page in mock_pages if page['category'] == 'equipment']
            navigation_links = [{'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'}]
        elif is_tools_search:
            results = [page for page in mock_pages if page['category'] == 'tools']
            navigation_links = [{'title': 'Hacking Tools', 'url': '/marketplace/tools'}]
        else:
            # Regular search in title and content
            results = [page for page in mock_pages if q in page['title'].lower() or q in page['content'].lower()]
            navigation_links = [
                {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
                {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'},
                {'title': 'Hacking Tools', 'url': '/marketplace/tools'}
            ]
    else:
        # Show all navigation links if no search query
        navigation_links = [
            {'title': 'Plants & Botanicals', 'url': '/marketplace/plants'},
            {'title': 'Equipment & Accessories', 'url': '/marketplace/weapons'},
            {'title': 'Hacking Tools', 'url': '/marketplace/tools'}
        ]
    
    return render_template("index.html", results=results, q=q, navigation_links=navigation_links)

@app.route("/marketplace/plants")
def marketplace_plants():
    products = Product.query.filter(
        db.or_(
            Product.image.like('%calc%'),
            Product.image.like('%coke%'),
            Product.image.like('%crystals%'),
            Product.image.like('%injection%'),
            Product.image.like('%plant%'),
            Product.image.like('%smoke%')
        )
    ).all()
    return render_template("marketplace.html", products=products, category="Plants & Botanicals")

@app.route("/marketplace/weapons")
def marketplace_weapons():
    products = Product.query.filter(
        db.or_(
            Product.image.like('%ak%'),
            Product.image.like('%drone%'),
            Product.image.like('%glock%'),
            Product.image.like('%m16%'),
            Product.image.like('%MH12%'),
            Product.image.like('%AWM%'),
            Product.image.like('%guns1%')
        )
    ).all()
    return render_template("marketplace.html", products=products, category="Equipment & Accessories")

# RANSOMWARE ROUTES

@app.route("/ransomware/menu")
def ransomware_menu():
    """Main menu for choosing ransomware simulation type.

    Read-only. It emits raw ``PAGE_VIEW`` telemetry only: browsing the menu is
    not a scenario stage, so refreshing it moves no progression metric.
    """
    record_page_view("scenario:ransomware_awareness",
                     scenario_id=ransomware_scenario_id(),
                     target="ransomware_menu")
    return render_template("ransomware_menu.html")

@app.route("/marketplace/tools")
def marketplace_tools():
    """Fake hacking tools marketplace - ransomware scenario stage 1.

    Two events, deliberately of different kinds: the lure milestone (recorded
    once for this run, however many times the page is fetched) and a repeatable
    page view (recorded every time). Refreshing therefore adds observation data
    without advancing the funnel.
    """
    scenario_id = ransomware_scenario_id()
    record_event(EventType.RANSOMWARE_LURE_VIEWED,
                 scenario_id=scenario_id,
                 source="scenario:ransomware_awareness",
                 details="Viewed hacking tools marketplace")
    record_page_view("scenario:ransomware_awareness", scenario_id=scenario_id,
                     target="marketplace_tools")

    
    fake_tools = [
        {
            'id': 1,
            'name': 'MetaSploit Pro Ultimate',
            'description': 'Advanced exploitation framework. Penetrate any system. Includes all premium modules and zero-day exploits.',
            'price': 499.99,
            'downloads': random.randint(500, 2000),
            'rating': 4.8
        },
        {
            'id': 2,
            'name': 'Network Cracker Suite',
            'description': 'Crack WiFi passwords, bypass firewalls, access any network. Military-grade encryption breaking.',
            'price': 299.99,
            'downloads': random.randint(800, 1500),
            'rating': 4.9
        },
        {
            'id': 3,
            'name': 'Database Exploit Kit',
            'description': 'Extract data from any SQL/NoSQL database. Includes zero-days for MongoDB, MySQL, PostgreSQL.',
            'price': 899.99,
            'downloads': random.randint(300, 900),
            'rating': 4.7
        },
        {
            'id': 4,
            'name': 'RAT Command Center',
            'description': 'Remote access trojan with keylogger, screen capture, webcam access. Undetectable by antivirus.',
            'price': 699.99,
            'downloads': random.randint(600, 1200),
            'rating': 4.6
        },
        {
            'id': 5,
            'name': 'Credential Stealer Pro',
            'description': 'Harvest credentials from browsers, email clients, FTP applications. Works on all platforms.',
            'price': 399.99,
            'downloads': random.randint(900, 1800),
            'rating': 4.8
        },
        {
            'id': 6,
            'name': 'Crypto Miner Botnet',
            'description': 'Deploy mining software across networks. Includes DDoS capabilities and proxy chaining.',
            'price': 1299.99,
            'downloads': random.randint(200, 600),
            'rating': 4.5
        },
        {
            'id': 7,
            'name': 'Mobile Spy Suite',
            'description': 'Complete mobile surveillance. Track location, read messages, access camera remotely.',
            'price': 549.99,
            'downloads': random.randint(700, 1400),
            'rating': 4.7
        },
        {
            'id': 8,
            'name': 'Ransomware Builder Kit',
            'description': 'Build custom ransomware with GUI interface. Automated Bitcoin payment system included.',
            'price': 1999.99,
            'downloads': random.randint(150, 400),
            'rating': 4.9
        }
    ]
    
    return render_template("hacking_tools.html", tools=fake_tools)

@app.route("/download/tool/<int:tool_id>")
def download_tool(tool_id):
    """Show fake download progress screen - ransomware scenario stage 2.

    Milestone once per run; page view every time. See ``marketplace_tools``.
    """
    scenario_id = ransomware_scenario_id()
    record_event(EventType.RANSOMWARE_DOWNLOAD_CLICKED,
                 scenario_id=scenario_id,
                 source="scenario:ransomware_awareness",
                 target="tool:%d" % tool_id,
                 details="Clicked download for tool #%d" % tool_id)
    record_page_view("scenario:ransomware_awareness", scenario_id=scenario_id,
                     target="tool:%d" % tool_id)

    
    return render_template("ransomware_download.html", tool_id=tool_id)

@app.route("/files/browser")
def file_browser():
    """File browser - read-only view of *this session's* catalogue state.

    Raw ``PAGE_VIEW`` only: looking at the catalogue is not a scenario stage.
    """
    record_page_view("scenario:ransomware_awareness",
                     scenario_id=ransomware_scenario_id(),
                     target="file_browser")
    return render_template("file_browser.html", files=ransomware_files())

@app.route("/ransomware/trigger", methods=["POST"])
def ransomware_trigger():
    """Trigger ransomware from file browser - ransomware scenario stage 3.

    POST because it changes state: it therefore inherits the application-wide
    CSRF check in ``security.init_csrf``. The state it changes belongs to the
    calling session alone.
    """
    record_event(EventType.RANSOMWARE_TRIGGERED,
                 scenario_id=ransomware_scenario_id(),
                 source="scenario:ransomware_awareness",
                 target="file_browser",
                 details="Interacted with file browser - ransomware triggered")

    set_ransomware_state(STATE_IMPACTED, variant="browser")
    files = ransomware_files()

    # Generate fake Bitcoin address
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([0.5, 1.0, 1.5, 2.0])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='browser')

@app.route("/ransomware/activate", methods=["POST"])
def ransomware_activate():
    """Trigger ransomware from hacking tools download - scenario stage 3.

    State-changing, therefore POST and therefore CSRF-protected. Scoped to the
    calling session's own run.
    """
    record_event(EventType.RANSOMWARE_TRIGGERED,
                 scenario_id=ransomware_scenario_id(),
                 source="scenario:ransomware_awareness",
                 target="tool_download",
                 details="Downloaded fake hacking tool - ransomware triggered")

    set_ransomware_state(STATE_IMPACTED, variant="download")
    files = ransomware_files()

    # Generate fake Bitcoin address
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([1.0, 1.5, 2.0, 2.5])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='download')

@app.route("/ransomware/screen")
def ransomware_screen():
    """Direct access to the ransom screen. Read-only: GET never mutates.

    Emits a repeatable ``PAGE_VIEW`` and no milestone: arriving here directly
    is not the same as having triggered the simulation, and must not be counted
    as though it were.
    """
    record_page_view("scenario:ransomware_awareness",
                     scenario_id=ransomware_scenario_id(),
                     target="ransomware_screen")
    files = ransomware_files()
    bitcoin_address = "1" + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))
    ransom_amount = random.choice([1.0, 1.5, 2.0, 2.5])
    
    return render_template("ransomware_screen.html",
                         bitcoin_address=bitcoin_address,
                         ransom_amount=ransom_amount,
                         encrypted_files=files,
                         source='direct')

@app.route("/ransomware/reveal", methods=["POST"])
def ransomware_reveal():
    """Educational reveal - the ransomware scenario's final stage.

    This is the debrief, so it emits ``RANSOMWARE_DEBRIEFED``. Until Milestone 4
    that event type was declared but never produced, which left the scenario's
    telemetry sequence permanently incomplete against its specification.
    """
    # Restore *this session's* run. No real file is touched here, and no other
    # learner's state is read or written: ``state`` is a string on this
    # session's own RansomwareRunState row.
    set_ransomware_state(STATE_BASELINE, remark=RESTORED_REMARK)
    files = ransomware_files()

    record_event(EventType.RANSOMWARE_DEBRIEFED,
                 scenario_id=ransomware_scenario_id(),
                 source="scenario:ransomware_awareness",
                 target="education",
                 details="learner reached the educational debrief; "
                         "%d catalogue entry/entries restored for this "
                         "session" % len(files))

    return render_template("ransomware_education.html")

# PHISHING ROUTES

@app.route('/product/<int:product_id>')
def product(product_id):
    """Product page - the phishing lure (scenario stage 1)."""
    product = db.get_or_404(Product, product_id)

    # Correlated scenario telemetry: PHISHING_EXPOSED, once per run. This event
    # *is* the funnel's first stage -- there is no separate counter table any
    # more -- so it must not fire again when the page is refreshed, prefetched
    # or crawled. The repeatable observation lives in the PAGE_VIEW below.
    state = start_phishing_scenario(product)
    record_page_view("scenario:credential_reuse_phishing",
                     scenario_id=state["scenario_id"],
                     target="product:%d" % product.id)

    return render_template("product.html", product=product)

@app.route("/page/<slug>")
def page(slug):
    # Mock page content
    mock_pages = {
        'exotic-plants': {'title': 'Exotic Plants Market', 'content': 'Coming soon...'},
        'rare-specimens': {'title': 'Rare Plant Specimens', 'content': 'Coming soon...'},
        'tactical-gear': {'title': 'Tactical Equipment Market', 'content': 'Coming soon...'},
        'military-surplus': {'title': 'Military Equipment Market', 'content': 'Coming soon...'},
        'weapon-collect': {'title': 'Weapons Collection Market', 'content': 'Coming soon...'}
    }
    
    page = mock_pages.get(slug)
    if page is None:
        return render_template('404.html'), 404
    return render_template('page.html', page=page)

# --- Multi-stage phishing / synthetic credential-reuse scenario -------------
#
#   product lure -> consent -> phishing-style login -> credential validation
#   -> sandbox-only reuse -> synthetic resource -> debrief
#
# The scenario stage lives in the *server-side* session, so consent and
# credential validation cannot be skipped by requesting a later URL directly.
# All logic lives in sandbox/scenarios/phishing.py; these routes only move the
# state machine along and render templates.

PHISHING_SESSION_KEY = "phishing_scenario"


def phishing_scenario():
    return PhishingScenario(sandbox_manager(), IDENTITIES)


def phishing_state():
    state = session.get(PHISHING_SESSION_KEY)
    if not isinstance(state, dict):
        state = {"scenario_id": None, "stage": "start", "product_id": None,
                 "synthetic_username": None}
    return state


def save_phishing_state(state):
    session[PHISHING_SESSION_KEY] = state
    session.modified = True


def start_phishing_scenario(product=None):
    """Emit PHISHING_EXPOSED once per scenario, and mint at most one run.

    Milestone 4.2: this used to mint a *new* ``scenario_id`` whenever the
    previous run had reached ``completed``, so a learner who finished the
    scenario and then refreshed the product page started a fresh run -- and a
    fresh ``PHISHING_EXPOSED`` -- on every refresh. Twenty refreshes were twenty
    runs at funnel stage 1 and none beyond it, which drove the conversion rate
    towards zero without anybody doing anything.

    A session now keeps one phishing run. The only way to start another is for
    the scenario state to be cleared deliberately (a ``ScenarioStateError``
    recovery in ``/phishing/consent``), which no passive GET can cause. The
    repeatable "the learner looked at the lure again" signal is the PAGE_VIEW
    that ``/product/<id>`` records alongside this call.
    """
    state = phishing_state()
    if state["scenario_id"]:
        return state
    result = phishing_scenario().expose(
        session["session_id"], scenario_id=new_scenario_id(),
        lure=("product:%s" % product.id) if product else "marketplace")
    state = {"scenario_id": result["scenario_id"], "stage": result["stage"],
             "product_id": product.id if product else None,
             "synthetic_username": None}
    save_phishing_state(state)
    return state


def _requested_product():
    """Resolve ``product_id`` from the query string, or None. Never trusted."""
    raw = request.args.get("product_id")
    if not raw or not raw.isdigit():
        return None
    return db.session.get(Product, int(raw))


@app.route("/phishing/consent", methods=["GET", "POST"])
def phishing_consent():
    """Learner-facing briefing. Consent is recorded server-side on POST."""
    product = _requested_product()
    state = phishing_state()
    if not state["scenario_id"]:
        state = start_phishing_scenario(product)
    if product and not state.get("product_id"):
        state["product_id"] = product.id
        save_phishing_state(state)

    if request.method == "POST":
        if request.form.get("consent") != "yes":
            flash("You must accept the simulation briefing to continue.", "warning")
            return redirect(url_for("phishing_consent",
                                    product_id=state.get("product_id")))
        try:
            result = phishing_scenario().grant_consent(
                session["session_id"], state["scenario_id"], state["stage"])
        except ScenarioStateError:
            flash("Scenario restarted - please read the briefing again.", "warning")
            session.pop(PHISHING_SESSION_KEY, None)
            return redirect(url_for("phishing_consent"))
        state["stage"] = result["stage"]
        save_phishing_state(state)
        return redirect(url_for("phishing_login"))

    return render_template(
        "phishing_consent.html",
        product=(db.session.get(Product, state["product_id"])
                 if state.get("product_id") else None),
        identities=IDENTITIES.identities(session["session_id"]),
        lab_domain=IDENTITIES.domain)


@app.route("/phishing/login", methods=["GET", "POST"])
def phishing_login():
    """Phishing-style login. Only sandbox identities can ever validate."""
    state = phishing_state()
    if stage_index(state["stage"]) < stage_index("consented"):
        flash("Read and accept the simulation briefing first.", "warning")
        return redirect(url_for("phishing_consent",
                                product_id=request.args.get("product_id")))

    product = (db.session.get(Product, state["product_id"])
               if state.get("product_id") else None)

    if request.method == "GET":
        result = phishing_scenario().view_form(
            session["session_id"], state["scenario_id"], state["stage"])
        state["stage"] = result["stage"]
        save_phishing_state(state)
        return render_template("phishing_login.html", product=product,
                               identities=IDENTITIES.identities(session["session_id"]),
                               error=None)

    # POST: validate, then discard. The submitted password is never assigned to
    # any longer-lived name, never logged and never persisted.
    outcome = phishing_scenario().submit_credential(
        session["session_id"], state["scenario_id"], state["stage"],
        request.form.get("username", ""), request.form.get("password", ""))

    db.session.add(CredentialInteraction(
        session_id=session["session_id"],
        scenario_id=state["scenario_id"],
        synthetic_username=(outcome["synthetic_username"][:120] or None),
        credential_valid=outcome["valid"],
        product_id=state.get("product_id"),
        event_type=("CREDENTIAL_VALIDATED" if outcome["valid"]
                    else "CREDENTIAL_VALIDATION_FAILED")))
    db.session.commit()

    if not outcome["valid"]:
        return render_template(
            "phishing_login.html", product=product,
            identities=IDENTITIES.identities(session["session_id"]),
            error="That is not a sandbox identity issued to this session. "
                  "Use one of the lab identities shown below."), 401

    state["stage"] = outcome["stage"]
    state["synthetic_username"] = outcome["synthetic_username"]
    save_phishing_state(state)

    # The contained "reuse" transition: the validated synthetic identity is
    # replayed against this session's own sandbox. No destination is accepted
    # from the request and no network call is made.
    try:
        sandbox_manager().ensure_ready(session_sandbox_id(),
                                       session_id=session["session_id"])
        result = phishing_scenario().reuse_credential(
            session["session_id"], state["scenario_id"], state["stage"],
            state["synthetic_username"])
    except SandboxError:
        flash("The sandbox is unavailable; the scenario cannot continue.", "danger")
        return redirect(url_for("phishing_consent"))
    state["stage"] = result["stage"]
    save_phishing_state(state)
    return redirect(url_for("phishing_portal"))


@app.route("/phishing/portal")
def phishing_portal():
    """Synthetic internal resource reached by the reused sandbox identity."""
    state = phishing_state()
    if stage_index(state["stage"]) < stage_index("sandbox_login"):
        flash("Complete the login stage first.", "warning")
        return redirect(url_for("phishing_consent"))

    # Only an allow-listed *key* is accepted -- never a URL, host or path.
    requested = request.args.get("resource")
    if requested not in SYNTHETIC_RESOURCES:
        requested = None
    try:
        result = phishing_scenario().access_resource(
            session["session_id"], state["scenario_id"], state["stage"], requested)
    except ScenarioStateError:
        flash("Scenario state is out of order; restarting.", "warning")
        session.pop(PHISHING_SESSION_KEY, None)
        return redirect(url_for("phishing_consent"))
    state["stage"] = result["stage"]
    save_phishing_state(state)

    try:
        files = sandbox_manager().workspace_state(session_sandbox_id())
    except SandboxError:
        files = []

    return render_template("phishing_portal.html",
                           resource=result["resource"],
                           resources=SYNTHETIC_RESOURCES,
                           synthetic_username=state.get("synthetic_username"),
                           files=files,
                           scenario_id=state["scenario_id"])


@app.route("/phishing/debrief")
def phishing_debrief():
    """Educational debrief; marks the scenario complete."""
    state = phishing_state()
    if stage_index(state["stage"]) < stage_index("resource_accessed"):
        flash("Finish the scenario before viewing the debrief.", "warning")
        return redirect(url_for("phishing_consent"))
    if stage_index(state["stage"]) < stage_index("completed"):
        result = phishing_scenario().complete(
            session["session_id"], state["scenario_id"], state["stage"])
        state["stage"] = result["stage"]
        save_phishing_state(state)

    events = (SecurityEvent.query
              .filter(SecurityEvent.scenario_id == state["scenario_id"],
                      SecurityEvent.session_id == session["session_id"])
              .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
              .all())
    product = (db.session.get(Product, state["product_id"])
               if state.get("product_id") else None)
    return render_template("phishing_result.html",
                           product=product,
                           synthetic_username=state.get("synthetic_username"),
                           scenario_id=state["scenario_id"],
                           events=events)


@app.route("/payment/<product_id>")
def payment(product_id):
    """Legacy entry point.

    The old payment page existed only to funnel learners into the plaintext
    credential capture that Milestone 2 removed. It now redirects into the
    consent-gated scenario, so bookmarked links keep working without reviving
    the old behaviour. ``/process_payment`` is gone entirely.
    """
    product = db.get_or_404(Product, product_id)
    return redirect(url_for("phishing_consent", product_id=product.id))


# --- Instructor authentication ---------------------------------------------
# One role, one password, held in INSTRUCTOR_PASSWORD. When it is unset,
# instructor login is impossible and every instructor route stays closed.

@app.route("/instructor/login", methods=["GET", "POST"])
def instructor_login():
    next_path = safe_next(request.values.get("next", ""), fallback="/dashboard")
    if request.method == "GET":
        return render_instructor_login(next_path=next_path)

    # Throttle first, so a locked-out source cannot even reach the comparison.
    key = throttle_key()
    retry_after = login_throttle.retry_after(key)
    if retry_after:
        response = render_instructor_login(
            error="Too many failed attempts. Try again in %d second(s)."
                  % retry_after,
            status=429, next_path=next_path)
        return response[0], response[1], {"Retry-After": str(retry_after)}

    if not instructor_auth_configured():
        return render_instructor_login(
            error="Instructor authentication is not configured on this "
                  "deployment (INSTRUCTOR_PASSWORD is unset).",
            status=503, next_path=next_path)

    if not check_instructor_password(request.form.get("password", "")):
        # Deliberately generic, and the submitted value is never echoed back.
        locked_for = login_throttle.record_failure(key)
        db.session.add(SecurityEvent(
            event_type=EventType.INSTRUCTOR_LOGIN_FAILED,
            timestamp=utcnow(), source="auth:instructor",
            details="failed instructor login (lockout=%ds)" % locked_for))
        db.session.commit()
        message = "Incorrect password."
        if locked_for:
            message += (" Too many failed attempts; locked for %d second(s)."
                        % locked_for)
        return render_instructor_login(error=message, status=401,
                                       next_path=next_path)

    # Successful authentication: clear the throttle bucket, then rotate the
    # whole session (fresh CSRF token, instructor flag re-set) inside
    # login_instructor().
    login_throttle.record_success(key)
    login_instructor()
    db.session.add(SecurityEvent(
        event_type=EventType.INSTRUCTOR_LOGIN_SUCCEEDED,
        session_id=session.get("session_id"), timestamp=utcnow(),
        source="auth:instructor",
        details="instructor session established; session state rotated"))
    db.session.commit()
    return redirect(next_path)


@app.route("/instructor/logout", methods=["POST"])
def instructor_logout():
    db.session.add(SecurityEvent(
        event_type=EventType.INSTRUCTOR_LOGGED_OUT,
        session_id=session.get("session_id"), timestamp=utcnow(),
        source="auth:instructor", details="instructor session cleared"))
    db.session.commit()
    logout_instructor()
    flash("Signed out of the instructor console.", "info")
    return redirect(url_for("instructor_login"))


# DASHBOARD -- every figure below is derived from SecurityEvent


def funnel_event_counts(funnel):
    """Stage counts for a funnel: **distinct runs** that reached each stage.

    Every funnel stage is a progression milestone, and Milestone 4.2 makes those
    idempotent at the write path, so counting rows would already be correct. This
    counts ``DISTINCT (session_id, scenario_id)`` anyway, as defence in depth: a
    duplicate that reached the table some other way -- an older database, a
    direct insert, a future code path that forgets the ledger -- still cannot
    inflate a stage, because the figure is "how many runs got here", not "how
    many rows exist".
    """
    counts = {}
    for stage, event_type in funnel:
        counts[stage] = (
            db.session.query(SecurityEvent.session_id, SecurityEvent.scenario_id)
            .filter(SecurityEvent.event_type == event_type)
            .distinct().count())
    return counts


def recent_funnel_activity(funnel, limit=15):
    """Recent events for a funnel, adapted to the template's stage/details shape."""
    wanted = [event_type for _, event_type in funnel]
    rows = (SecurityEvent.query
            .filter(SecurityEvent.event_type.in_(wanted))
            .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
            .limit(limit).all())
    # ``session_label`` is what the template renders. The canonical session id
    # is deliberately not placed in the template context at all, so it cannot
    # be printed by accident; correlation still happens on the stored value.
    return [{"stage": STAGE_BY_EVENT.get(row.event_type, row.event_type),
             "details": row.details or row.event_type,
             "timestamp": row.timestamp,
             "session_label": session_label(row.session_id),
             "scenario_id": row.scenario_id}
            for row in rows]


@app.route("/dashboard")
@require_instructor
def dashboard():
    # Funnel metrics, derived entirely from SecurityEvent. There is no second
    # analytics table to fall out of step with the scenario telemetry: a stage
    # count is literally a count of the event that defines that stage.
    phish_counts = funnel_event_counts(PHISHING_FUNNEL)
    ransom_counts = funnel_event_counts(RANSOMWARE_FUNNEL)
    phish_conv = conversion_rates(phish_counts, PHISHING_FUNNEL)
    ransom_conv = conversion_rates(ransom_counts, RANSOMWARE_FUNNEL)

    phish_stage1, phish_stage2, phish_stage3 = (
        phish_counts[stage] for stage, _ in PHISHING_FUNNEL)
    ransom_stage1, ransom_stage2, ransom_stage3 = (
        ransom_counts[stage] for stage, _ in RANSOMWARE_FUNNEL)

    # Recent activity, shaped for the existing template (stage/details/timestamp).
    recent_phish = recent_funnel_activity(PHISHING_FUNNEL)
    recent_ransom = recent_funnel_activity(RANSOMWARE_FUNNEL)
    
    # Credential *interactions* -- metadata only. There is no password to show,
    # because none is ever stored. Reshaped to carry the pseudonymous session
    # label rather than the raw session id (Milestone 4.2); ``timestamp`` stays
    # a datetime because the template formats it.
    interactions = [
        {"id": row.id, "session_label": session_label(row.session_id),
         "scenario_id": row.scenario_id,
         "synthetic_username": row.synthetic_username,
         "credential_valid": row.credential_valid,
         "event_type": row.event_type, "timestamp": row.timestamp}
        for row in (CredentialInteraction.query
                    .order_by(CredentialInteraction.timestamp.desc())
                    .limit(50).all())]

    metrics = {
        'phishing': dict(stage1=phish_stage1, stage2=phish_stage2,
                         stage3=phish_stage3, **phish_conv),
        'ransomware': dict(stage1=ransom_stage1, stage2=ransom_stage2,
                           stage3=ransom_stage3, **ransom_conv),
    }
    
    sandbox_ctx = sandbox_dashboard_context(
        app, db, SecurityEvent, app.config['SANDBOX_LOCAL_ROOT'])

    return render_template("dashboard.html",
                         metrics=metrics,
                         recent_phish=recent_phish,
                         recent_ransom=recent_ransom,
                         interactions=interactions,
                         **sandbox_ctx)

# OTHER ROUTES

@app.route("/ransomware/simulate", methods=["POST"])
@require_instructor
def ransomware_simulate():
    """Instructor demonstration -- scoped to the instructor's own session.

    It used to flip the global catalogue, which changed what every learner in
    the room saw mid-exercise.
    """
    set_ransomware_state(STATE_IMPACTED, variant="instructor")
    flash("Ransomware simulation executed on your own demo view "
          "(NO REAL FILES TOUCHED, no other session affected).", "info")
    return redirect(url_for("dashboard"))

@app.route("/ransomware/restore", methods=["POST"])
@require_instructor
def ransomware_restore():
    """Restore the instructor's own demo view. No other session is altered."""
    set_ransomware_state(STATE_BASELINE, remark="Restored in simulation.")
    flash("Your demo files restored (simulation).", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/logs")
@require_instructor
def api_logs():
    """Instructor telemetry feed.

    Previously this returned every captured username from every session to
    anyone who asked. It now returns scenario telemetry only -- event metadata
    that has never contained a credential value -- and requires the instructor
    session.

    **Identifier policy (Milestone 4.2).** This endpoint and ``/sandbox/events``
    are the *internal evaluation* APIs: they return the canonical
    ``session_id``/``scenario_id``, because the formal harness joins runs on
    them and a one-way display label cannot be joined on. Instructor **HTML**
    (``/dashboard``, ``/deets``) shows the pseudonymous label instead. Both are
    behind ``@require_instructor``; the distinction is about what ends up on a
    projected screen, not about who may read the data.

    Query parameters: ``limit`` (1..500, default 200) and an optional
    ``session_id`` exact-equality filter on the canonical identifier.
    """
    limit = min(max(request.args.get("limit", 200, type=int), 1), 500)
    query = SecurityEvent.query
    # Optional exact-equality filter on the canonical id, mirroring the one
    # ``/sandbox/events`` already exposes. Without it, asking for one learner's
    # rows means paging a *global* newest-first window that unrelated volume can
    # push them out of -- which is a property of how much other telemetry
    # exists, not of that learner. Read-only, instructor-only, and canonical
    # ids only: a pseudonymous label is a printed nickname and is never accepted
    # as a lookup key here. Absent the parameter, behaviour is unchanged.
    session_filter = request.args.get("session_id")
    if session_filter:
        query = query.filter(SecurityEvent.session_id == session_filter)
    rows = (query
            .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
            .limit(limit).all())
    return jsonify([row.to_dict() for row in rows])

@app.route("/deets")
@require_instructor
def deets():
    """Instructor-only lab state view.

    The credential table it used to render (usernames *and* plaintext
    passwords, across every session) no longer exists. What remains is
    interaction metadata plus the synthetic demo dataset.
    """
    rows = (CredentialInteraction.query
            .order_by(CredentialInteraction.id.desc()).limit(200).all())
    # Milestone 4.2: instructor HTML shows a stable pseudonymous label, never
    # the raw session id. The stored identifier is unchanged -- correlation and
    # the internal evaluation APIs still use it (see ``/api/logs`` below) -- but
    # a projected page no longer puts a learner's session UUID on a wall.
    interactions = [dict(row.to_dict(), session_label=session_label(row.session_id))
                    for row in rows]
    for row in interactions:
        row.pop("session_id", None)
    files = list(reversed(ransomware_files()))
    # Instructors may *aggregate* run state; learners never see another row.
    runs = (RansomwareRunState.query
            .order_by(RansomwareRunState.updated_at.desc()).limit(200).all())
    return render_template("deets.html", interactions=interactions,
                           files=files,
                           products=Product.query.order_by(Product.id.desc()).all(),
                           ransomware_runs=[r.display_dict() for r in runs])

@app.route('/resources')
def resources():
    return render_template('resources.html')

if __name__ == "__main__":
    # Defaults are loopback-only and debug-off. Override deliberately via the
    # environment when running a supervised classroom session on a LAN.
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
