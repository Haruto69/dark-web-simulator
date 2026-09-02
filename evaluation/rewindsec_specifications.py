"""Frozen, independent correctness oracle for the CURRENT RewindSec runtime.

DISTINCT FROM ``evaluation/specifications.py``
------------------------------------------------
That module is the historical Milestone-4 oracle for the old conference
simulator architecture (``credential_reuse_phishing``, ``ransomware_awareness``,
``file_impact``) -- single-branch scenarios with a progression-milestone event
model. It is untouched by this work.

This module is a **new, separate** oracle for the CURRENT paired-counterfactual
architecture (human decision -> technical consequence -> exact rewind ->
counterfactual consequence -> state comparison), the four scenarios registered
under ``scenario_adapters/`` and driven through ``training_service.py``.

INDEPENDENCE
------------
Nothing here imports:

  * scenario/choice tables from ``training.definitions``,
    ``scenario_adapters.*`` or any ``ScenarioDefinition`` instance,
  * ``training_service.SUCCESS_EVENT_ORDER`` / ``TELEMETRY_SOURCE`` or any
    other production ordering/correlation constant,
  * learning-quality mappings from ``learning/`` or ``learning_service.py``,
  * runtime result expectations (digests, difference maps) from
    ``training/runtime.py``, ``training/results.py`` or
    ``training/comparison.py``.

Every scenario key, decision id, choice id, action key, event-type string and
consequence fact below is a **literal string written after reading the current
production code** on 2026-09-02:
``scenario_adapters/phishing.py``, ``scenario_adapters/ransomware.py``,
``scenario_adapters/mfa.py``, ``scenario_adapters/bec.py``,
``training_service.py``, ``training_routes.py``, ``training_flow.py`` and
``sandbox/events.py``. If production silently renames or reorders any of
these, this oracle does not follow it: the systems evaluation reports a
mismatch, which is the entire point of an independent oracle.
``tests/test_rewindsec_formal_evaluation.py`` asserts the no-import property
by source (AST) inspection, not by trusting this docstring.

CORRECTIONS AGAINST THE TASK'S HYPOTHESIS
------------------------------------------
* The four scenario keys, decision ids and choice ids given in the task
  hypothesis were all CORRECT as verified against the adapters -- no
  correction needed there.
* The hypothesis that only ransomware stages a factual preview was WRONG.
  ``training_flow.py``'s ``register_synthetic_module`` (which drives BOTH the
  MFA and BEC learner flows) stages a preview and passes
  ``expected_baseline_digest`` / ``expected_factual_digest`` into
  ``run_pair()`` exactly like the ransomware route in ``training_routes.py``
  does. So THREE of the four scenarios stage a preview -- ransomware, MFA and
  BEC -- and only phishing's route does not. Experiment D therefore measures
  all three.
* A naive "impact count (1, 2, 3, 4)" guess for ransomware would have been
  WRONG: the fourth response ("continue_working") impacts the full five-file
  synthetic dataset, not four, per ``ACTION_IMPACT_TOTAL`` in
  ``scenario_adapters/ransomware.py``. The correct counts (1, 2, 3, 5) are
  frozen below.

This is a SYSTEMS oracle only. It carries no learning-quality label, no
"correct answer" designation, and no claim about what a learner should choose.
Every choice in every scenario is a legitimate, independently-checkable
technical state transition; none is scored as more "educational" than another.
"""

import ast
import hashlib
import json
import os
from itertools import permutations

#: Bumped by hand whenever a frozen declaration below is deliberately changed.
#: Independent of, and never synchronised with, ``evaluation.specifications.
#: SPECIFICATION_VERSION`` -- the two oracles describe different systems.
REWINDSEC_SPECIFICATION_VERSION = "2026-09-02.1"


# =============================================================================
# 1. The six-event training lifecycle (frozen independently of
#    training_service.py / sandbox/events.py -- literal strings only)
# =============================================================================

TRAINING_EXECUTION_STARTED = "TRAINING_EXECUTION_STARTED"
TRAINING_BASELINE_CAPTURED = "TRAINING_BASELINE_CAPTURED"
TRAINING_FACTUAL_CAPTURED = "TRAINING_FACTUAL_CAPTURED"
TRAINING_REWIND_VERIFIED = "TRAINING_REWIND_VERIFIED"
TRAINING_COUNTERFACTUAL_CAPTURED = "TRAINING_COUNTERFACTUAL_CAPTURED"
TRAINING_EXECUTION_COMPLETED = "TRAINING_EXECUTION_COMPLETED"

#: The exact order a successful paired execution must produce. Six events,
#: exactly once each, no more, no fewer.
SUCCESS_EVENT_SEQUENCE = (
    TRAINING_EXECUTION_STARTED,
    TRAINING_BASELINE_CAPTURED,
    TRAINING_FACTUAL_CAPTURED,
    TRAINING_REWIND_VERIFIED,
    TRAINING_COUNTERFACTUAL_CAPTURED,
    TRAINING_EXECUTION_COMPLETED,
)

#: A failed run's lifecycle event, frozen the same way. It must NEVER appear
#: in a run this oracle scores as successful, and a run that emits it must
#: never be scored as successful regardless of what else it emitted.
TRAINING_EXECUTION_FAILED = "TRAINING_EXECUTION_FAILED"

#: The complete set of TRAINING_* event types this systems evaluation knows
#: about. Any TRAINING_* event observed outside this set on a scored run is an
#: "unexpected event" and fails precision/exactness scoring (spec section 24.L).
KNOWN_TRAINING_EVENT_TYPES = frozenset(SUCCESS_EVENT_SEQUENCE) | {
    TRAINING_EXECUTION_FAILED,
}

#: ``SecurityEvent.source`` value the telemetry oracle expects for every
#: TRAINING_* row of a paired execution. Literal, not imported from
#: ``training_service.TELEMETRY_SOURCE``.
EXPECTED_TELEMETRY_SOURCE = "training:counterfactual"


# =============================================================================
# 2. Frozen scenario inventory
# =============================================================================

PHISHING = "phishing_credential_compromise"
RANSOMWARE = "ransomware_incident_response"
MFA = "mfa_fatigue_response"
BEC = "business_email_compromise"

SCENARIO_KEYS = (PHISHING, RANSOMWARE, MFA, BEC)


SCENARIOS = {
    PHISHING: {
        "version": 1,
        "decision_id": "respond_to_message",
        "choice_ids": (
            "follow_link_and_sign_in",
            "inspect_sender",
            "verify_independently",
            "report_message",
        ),
        "action_keys": {
            "follow_link_and_sign_in": "credential_submitted_to_lookalike",
            "inspect_sender": "sender_details_inspected",
            "verify_independently": "request_verified_out_of_band",
            "report_message": "message_reported_to_security",
        },
        "docker_required": False,
        # training_routes.py's phishing route calls run_pair() with no
        # expected_baseline_digest / expected_factual_digest -- verified
        # 2026-09-02. The only scenario whose current learner flow does NOT
        # stage a preview.
        "staged_preview": False,
        "consequence_facts": {
            "follow_link_and_sign_in": {
                "identity.exposed": True,
                "account.synthetic_access": True,
                "resource.accessed": True,
            },
            "inspect_sender": {
                "message.sender_inspected": True,
                "evidence.sender_mismatch_visible": True,
                "identity.exposed": False,
            },
            "verify_independently": {
                "message.verified_independently": True,
                "evidence.verification_outcome": "request_not_legitimate",
                "identity.exposed": False,
            },
            "report_message": {
                "message.reported": True,
                "incident.created": True,
                "identity.exposed": False,
            },
        },
    },
    RANSOMWARE: {
        "version": 1,
        "decision_id": "respond_to_file_impact",
        "choice_ids": (
            "isolate_and_report",
            "report_without_isolating",
            "restart_workstation",
            "continue_working",
        ),
        "action_keys": {
            "isolate_and_report": "workstation_isolated_and_reported",
            "report_without_isolating": "incident_reported_without_isolation",
            "restart_workstation": "workstation_restarted",
            "continue_working": "work_continued_on_workstation",
        },
        "docker_required": True,
        # training_routes.py's ransomware_rewind route passes
        # expected_baseline_digest / expected_factual_digest, from the preview
        # staged in ransomware_decision -- verified 2026-09-02.
        "staged_preview": True,
        # Impacted-file counts, INDEPENDENTLY re-derived from
        # scenario_adapters/ransomware.py: five known synthetic files, S0
        # already has exactly one impacted. A hypothesis of (1, 2, 3, 4) would
        # have been WRONG; "continue_working" impacts the full five-file
        # dataset, not four.
        "impacted_file_counts": {
            "isolate_and_report": 1,
            "report_without_isolating": 2,
            "restart_workstation": 3,
            "continue_working": 5,
        },
        "consequence_facts": {
            "isolate_and_report": {
                "endpoint.isolated": True,
                "endpoint.restarted": False,
                "incident.reported": True,
                "files.impacted_count": 1,
            },
            "report_without_isolating": {
                "endpoint.isolated": False,
                "incident.reported": True,
                "files.impacted_count": 2,
            },
            "restart_workstation": {
                "endpoint.restarted": True,
                "incident.reported": False,
                "files.impacted_count": 3,
            },
            "continue_working": {
                "endpoint.isolated": False,
                "endpoint.restarted": False,
                "incident.reported": False,
                "files.impacted_count": 5,
            },
        },
    },
    MFA: {
        "version": 1,
        "decision_id": "respond_to_unexpected_mfa_prompt",
        "choice_ids": (
            "approve_request",
            "deny_and_report",
            "review_signin_details",
            "verify_through_known_channel",
        ),
        "action_keys": {
            "approve_request": "mfa_request_approved",
            "deny_and_report": "mfa_request_denied_and_reported",
            "review_signin_details": "mfa_signin_details_reviewed",
            "verify_through_known_channel": "mfa_request_verified_out_of_band",
        },
        "docker_required": False,
        # training_flow.py:register_synthetic_module drives the MFA route and
        # stages a preview exactly like the ransomware route -- verified
        # 2026-09-02 (this CORRECTS the task's hypothesis that only ransomware
        # stages a preview).
        "staged_preview": True,
        "consequence_facts": {
            "approve_request": {
                "mfa.approved": True,
                "mfa.request_pending": False,
                "account.synthetic_session_created": True,
                "resource.accessed": True,
            },
            "deny_and_report": {
                "mfa.denied": True,
                "mfa.request_pending": False,
                "incident.reported": True,
                "account.synthetic_session_created": False,
            },
            "review_signin_details": {
                "evidence.details_reviewed": True,
                "mfa.request_pending": True,
                "account.synthetic_session_created": False,
            },
            "verify_through_known_channel": {
                "evidence.verified_out_of_band": True,
                "incident.reported": True,
                "account.synthetic_session_created": False,
            },
        },
    },
    BEC: {
        "version": 1,
        "decision_id": "respond_to_payment_change_request",
        "choice_ids": (
            "authorize_payment",
            "reply_to_request",
            "verify_via_known_contact",
            "escalate_to_finance_security",
        ),
        "action_keys": {
            "authorize_payment": "payment_authorized_to_changed_details",
            "reply_to_request": "unverified_thread_replied_to",
            "verify_via_known_contact": "supplier_verified_via_known_channel",
            "escalate_to_finance_security": "payment_request_escalated",
        },
        "docker_required": False,
        # Same register_synthetic_module staging as MFA -- verified 2026-09-02.
        "staged_preview": True,
        "consequence_facts": {
            "authorize_payment": {
                "payment.authorized": True,
                "payment.synthetic_loss": 18450,
            },
            "reply_to_request": {
                "message.replied_to_unverified_thread": True,
                "payment.authorized": False,
            },
            "verify_via_known_contact": {
                "verification.known_contact_used": True,
                "verification.change_confirmed": False,
                "payment.authorized": False,
            },
            "escalate_to_finance_security": {
                "incident.finance_escalated": True,
                "incident.security_reported": True,
                "payment.authorized": False,
            },
        },
    },
}


def _lookup(state, dotted_path):
    """Read a dotted path out of a plain JSON-decoded dict. Raises KeyError."""
    node = state
    for part in dotted_path.split("."):
        node = node[part]
    return node


def check_consequence_facts(scenario_key, choice_id, resulting_state):
    """Independently verify a resulting canonical state against the oracle.

    Returns a list of failure strings (empty means every fact matched). Never
    raises for a missing/mismatched fact -- callers decide how to fail a trial.
    """
    facts = SCENARIOS[scenario_key]["consequence_facts"].get(choice_id, {})
    failures = []
    for path, expected in facts.items():
        try:
            observed = _lookup(resulting_state, path)
        except (KeyError, TypeError):
            failures.append("missing fact %r (expected %r)" % (path, expected))
            continue
        if observed != expected:
            failures.append("fact %r: expected %r, observed %r"
                            % (path, expected, observed))
    return failures


def ordered_pairs(scenario_key):
    """Every distinct ordered (factual, counterfactual) choice-id pair.

    n choices -> n*(n-1) ordered pairs. All four current scenarios have four
    stable choices (verified above), so this yields 4*3 = 12 pairs per
    scenario, 48 total across the four scenarios -- matching the spec's
    hypothesis exactly; no correction was needed there.
    """
    ids = SCENARIOS[scenario_key]["choice_ids"]
    return tuple(permutations(ids, 2))


def all_pairs():
    """``{scenario_key: [(factual, counterfactual), ...]}`` for every scenario."""
    return {key: ordered_pairs(key) for key in SCENARIO_KEYS}


def total_pair_count():
    return sum(len(pairs) for pairs in all_pairs().values())


def representative_pair(scenario_key):
    """One fixed, deterministic (factual, counterfactual) pair for Experiment
    B / D / F -- the first two choices in the frozen ``choice_ids`` tuple."""
    ids = SCENARIOS[scenario_key]["choice_ids"]
    return (ids[0], ids[1])


def docker_required_scenarios():
    return tuple(k for k in SCENARIO_KEYS if SCENARIOS[k]["docker_required"])


def staged_preview_scenarios():
    """Scenarios whose current learner flow stages a factual preview.

    Ransomware, MFA and BEC -- verified against ``training_routes.py`` /
    ``training_flow.py`` on 2026-09-02. Phishing is the only one that does
    not.
    """
    return tuple(k for k in SCENARIO_KEYS if SCENARIOS[k]["staged_preview"])


def specification_manifest():
    """Everything embedded in every RewindSec-formal result file's metadata."""
    return {
        "rewindsec_specification_version": REWINDSEC_SPECIFICATION_VERSION,
        "scenario_keys": list(SCENARIO_KEYS),
        "success_event_sequence": list(SUCCESS_EVENT_SEQUENCE),
        "failed_event_type": TRAINING_EXECUTION_FAILED,
        "docker_required_scenarios": list(docker_required_scenarios()),
        "staged_preview_scenarios": list(staged_preview_scenarios()),
        "total_ordered_pairs": total_pair_count(),
        "scope": (
            "System properties only: deterministic paired counterfactual "
            "execution, exact rewind integrity, consequence reproducibility, "
            "TrainingExecution persistence integrity, six-event training "
            "lifecycle telemetry, staged factual-preview integrity "
            "(ransomware/MFA/BEC), scenario isolation, Docker containment for "
            "ransomware, execution latency and bounded concurrency. Does NOT "
            "measure educational effectiveness, learning improvement, "
            "behavioural transfer, retention, statistical significance across "
            "study arms, or any property of a human participant."
        ),
    }


# =============================================================================
# 3. Independent digest verification (spec section 8). A second,
#    independently-written implementation of the canonical-JSON + SHA-256
#    scheme -- NOT a reuse of training.snapshots.canonical_json/fingerprint --
#    so it can catch a bug in the production implementation rather than
#    agreeing with it by construction.
# =============================================================================

def independent_canonical_json(state):
    """Re-serialise a plain (already-JSON-decoded) mapping deterministically."""
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def independent_digest(state):
    return hashlib.sha256(
        independent_canonical_json(state).encode("utf-8")).hexdigest()


def independent_digest_of_json_text(canonical_text):
    """Independent digest of an already-serialised ``*_state_json`` column.

    Parses the stored text (never trusts it verbatim), then re-hashes it
    through this module's own canonicalisation.
    """
    return independent_digest(json.loads(canonical_text))


def verify_stored_digest(state_json_text, expected_digest):
    """Return ``(matched, recomputed_digest)``, or ``(False, None)`` if the
    stored text does not even parse as JSON."""
    try:
        recomputed = independent_digest_of_json_text(state_json_text)
    except (TypeError, ValueError):
        return False, None
    return recomputed == expected_digest, recomputed


# =============================================================================
# 4. Self-check: this module imports nothing from the production scenario /
#    training-service layer. Enforced by source inspection so a later edit
#    that adds such an import is caught by the test suite rather than trusted
#    to code review alone.
# =============================================================================

#: Import roots this oracle must never depend on, directly or transitively
#: through an ``import training_service`` / ``from scenario_adapters import``
#: style statement in *this* file.
FORBIDDEN_IMPORT_ROOTS = (
    "training_service",
    "scenario_adapters",
    "training.definitions",
    "training.runtime",
    "training.results",
    "training_flow",
    "training_routes",
    "learning",
    "learning_service",
)


def _imported_module_roots(source_path):
    """Top-level module names this file imports, via AST -- not by executing it."""
    with open(source_path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=source_path)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                roots.add(node.module)
                roots.add(node.module.split(".")[0])
    return roots


def assert_no_production_imports():
    """Raise AssertionError if this file imports a forbidden production root.

    Used both by this module's own ``__main__`` self-test and by
    ``tests/test_rewindsec_formal_evaluation.py`` (which inspects this file
    from outside, independent of whatever this function currently does).
    """
    here = os.path.abspath(__file__)
    roots = _imported_module_roots(here)
    hit = [root for root in FORBIDDEN_IMPORT_ROOTS if root in roots]
    if hit:
        raise AssertionError(
            "rewindsec_specifications.py imports forbidden production "
            "root(s): %s" % hit)


if __name__ == "__main__":
    assert_no_production_imports()
    print("OK: no production scenario/training-service imports")
    print(json.dumps(specification_manifest(), indent=2))
