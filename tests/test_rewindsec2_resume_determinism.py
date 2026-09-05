"""The deterministic resume-equivalence integration test.

Architecture Spec v1.1's central promise: a session persisted, fully
discarded from memory, and restored behaves identically to one that ran
continuously, given the same seed and the same subsequent inputs -- future
scheduler firing order and future named-RNG draws included.

Path A runs continuously to T2. Path B runs to T1, is captured, is thrown
away completely (a brand-new process-local object tree is built from nothing
but the captured JSON), and then runs from T1 to T2. Both paths receive
exactly the same operations after the divergence point, and the assertion is
full state equivalence at T2 plus identical scheduler firing order and
identical subsequent RNG draws.
"""

import copy

import sqlalchemy as sa

from rewindsec.domain.enums import ActionClass, Focus, Mode
from rewindsec.domain.session import SimulationSession
from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository


def _build_phase_one(session_id, seed):
    """The operations both paths share, up to the T1 checkpoint."""
    session = SimulationSession.create(session_id, "learner-1", Focus.BEC,
                                       Mode.SIMULATION, root_seed=seed)
    ev1 = session.record_immediate_event("mail.delivered", payload={"n": 1})
    session.schedule_event("mail.delivered", delay_ms=500, payload={"n": 2})
    session.schedule_event("wire.request", delay_ms=1500, payload={"n": 3})
    session.advance_time(500)  # fires the first scheduled event -> T1 = 500
    act1 = session.record_action("inspect.open_mail", ActionClass.OBSERVATIONAL,
                                 target=ev1.event_id)
    session.introduce_fact("finance_contact", "org", "cfo@acme.example", "directory",
                           introduced_by_event_id=ev1.event_id)
    session.observe_fact("finance_contact", act1.action_id)
    mutation = session.mutate_world("mailbox", "unread", 2, cause_event_id=ev1.event_id)
    incident = session.open_incident("BEC attempt", opening_event_id=ev1.event_id)
    session.record_consequence(incident.incident_id, cause_event_id=ev1.event_id,
                               triggering_action_id=act1.action_id,
                               mutation_ref=mutation.mutation_id)
    # Draw from a named stream so its position is part of what must match.
    session.rng.stream("timing").random()
    return session


def _run_phase_two(session):
    """The operations applied identically after the T1 checkpoint, to T2."""
    session.record_action("mail.forward", ActionClass.CONSEQUENTIAL)
    fired = session.advance_time(1000)  # fires the wire.request event -> T2 = 1500
    draw = session.rng.stream("timing").random()
    draw2 = session.rng.stream("distractors").randint(1, 100)
    return fired, draw, draw2


def test_continuous_run_equals_persist_discard_restore_continue():
    # Same session id for both paths: a real resume restores into the same
    # identity it checkpointed, so ids derived from (session_id, seq) --
    # events, actions, mutations, incidents, consequences -- are directly
    # comparable between the two paths without normalisation.
    session_id = "session-under-test"

    # -- Path A: continuous ------------------------------------------------
    path_a = _build_phase_one(session_id, seed=20260906)
    fired_a, draw_a, draw2_a = _run_phase_two(path_a)
    state_a = path_a.capture_state()

    # -- Path B: checkpoint, fully discard, restore, continue --------------
    path_b_live = _build_phase_one(session_id, seed=20260906)
    checkpoint = copy.deepcopy(path_b_live.capture_state())
    del path_b_live  # nothing from the live object may leak into what follows

    path_b_restored = SimulationSession.from_state(checkpoint)
    fired_b, draw_b, draw2_b = _run_phase_two(path_b_restored)
    state_b = path_b_restored.capture_state()

    assert state_a == state_b

    # Firing order/content, and subsequent random draws, must match exactly.
    assert len(fired_a) == len(fired_b) == 1
    assert fired_a[0].type == fired_b[0].type
    assert fired_a[0].payload == fired_b[0].payload
    assert fired_a[0].sim_time_ms == fired_b[0].sim_time_ms == 1500
    assert draw_a == draw_b
    assert draw2_a == draw2_b


def test_resume_equivalence_through_the_real_repository():
    """The same equivalence, but T1 is a genuine persist/load round trip
    through the SQLAlchemy adapter rather than an in-memory deepcopy."""
    engine = sa.create_engine("sqlite:///:memory:")
    repo = SqlAlchemySessionRepository(engine)
    repo.create_schema()

    path_a = _build_phase_one("session-a", seed=777)
    fired_a, draw_a, _ = _run_phase_two(path_a)

    path_b = _build_phase_one("session-b", seed=777)
    repo.create(path_b)
    del path_b

    resumed = repo.load("session-b")
    fired_b, draw_b, _ = _run_phase_two(resumed)

    assert len(fired_a) == len(fired_b) == 1
    assert fired_a[0].type == fired_b[0].type
    assert fired_a[0].sim_time_ms == fired_b[0].sim_time_ms
    assert draw_a == draw_b
