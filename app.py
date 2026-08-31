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
from sandbox.pseudonym import session_label
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
# and the sandbox. R2 adds no learner-facing route: future scenario routes call
# ``training_service().run_pair(...)``.

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
    """
    limit = min(max(request.args.get("limit", 200, type=int), 1), 500)
    rows = (SecurityEvent.query
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
