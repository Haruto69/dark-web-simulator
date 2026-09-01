"""The pure learning domain: authored definitions and deterministic assessment.

Nothing in this module touches Flask, a database, a template or a request. It
tests ``learning/`` as what it is -- a framework-independent set of authored
pedagogical definitions plus a total function over them.
"""

import importlib
import inspect
import pkgutil

import pytest

import learning
from learning import assessment as A
from learning import concepts as C
from learning import feedback as F
from learning import quality as Q
from learning import reflection as R
from learning import transfer as T
from learning.errors import (LearningConfidenceError, UnknownChoiceError,
                             UnknownExplanationError, UnknownProbeError,
                             UnknownScenarioError)

SHIPPED_SCENARIOS = (
    "phishing_credential_compromise",
    "ransomware_incident_response",
    "mfa_fatigue_response",
    "business_email_compromise",
)


# -- A: the shipped scenarios are the registered ones ------------------------
def test_all_four_shipped_scenario_keys_are_registered():
    assert set(learning.LEARNING_SCENARIOS) == set(SHIPPED_SCENARIOS)


def test_registered_keys_match_the_shipped_scenario_definitions():
    """The literals in ``learning.quality`` cannot silently drift.

    ``learning/`` declares scenario keys as literals rather than importing
    ``scenario_adapters`` (which would drag in the sandbox). This test is the
    thing that keeps the duplication honest.
    """
    from scenario_adapters.bec import BEC_SCENARIO_KEY
    from scenario_adapters.mfa import MFA_SCENARIO_KEY
    from scenario_adapters.phishing import PHISHING_SCENARIO_KEY
    from scenario_adapters.ransomware import RANSOMWARE_SCENARIO_KEY

    assert set(learning.LEARNING_SCENARIOS) == {
        PHISHING_SCENARIO_KEY, RANSOMWARE_SCENARIO_KEY, MFA_SCENARIO_KEY,
        BEC_SCENARIO_KEY}


# -- B: every shipped choice is classified exactly once ----------------------
def _shipped_decisions():
    from scenario_adapters.bec import BEC_DECISION_ID, BEC_SCENARIO
    from scenario_adapters.mfa import MFA_DECISION_ID, MFA_SCENARIO
    from scenario_adapters.phishing import (PHISHING_DECISION_ID,
                                            PHISHING_SCENARIO)
    from scenario_adapters.ransomware import (RANSOMWARE_DECISION_ID,
                                              RANSOMWARE_SCENARIO)
    return (
        (PHISHING_SCENARIO, PHISHING_DECISION_ID),
        (RANSOMWARE_SCENARIO, RANSOMWARE_DECISION_ID),
        (MFA_SCENARIO, MFA_DECISION_ID),
        (BEC_SCENARIO, BEC_DECISION_ID),
    )


def test_every_shipped_factual_choice_has_exactly_one_classification():
    for scenario, decision_id in _shipped_decisions():
        shipped = set(scenario.decision(decision_id).choice_ids)
        classified = set(Q.scenario_choice_ids(scenario.scenario_key))
        assert classified == shipped, scenario.scenario_key


def test_every_classified_choice_has_a_concept_map():
    for scenario_key in learning.LEARNING_SCENARIOS:
        for choice_id in Q.scenario_choice_ids(scenario_key):
            tags = learning.concepts_for_choice(scenario_key, choice_id)
            assert tags, (scenario_key, choice_id)


def test_classifications_use_only_the_three_authored_levels():
    assert set(Q.RESPONSE_QUALITY.values()) <= set(learning.RESPONSE_QUALITIES)


# -- C/D: unknown scenario and unknown choice fail closed --------------------
def test_unknown_scenario_is_rejected():
    with pytest.raises(UnknownScenarioError):
        learning.response_quality("no_such_scenario", "inspect_sender")
    with pytest.raises(UnknownScenarioError):
        learning.assess_decision("no_such_scenario", "inspect_sender", 50)


def test_unknown_choice_is_rejected():
    with pytest.raises(UnknownChoiceError):
        learning.response_quality(learning.PHISHING, "no_such_choice")
    with pytest.raises(UnknownChoiceError):
        learning.assess_decision(learning.PHISHING, "no_such_choice", 50)


# -- O: no global choice-id lookup ------------------------------------------
def test_a_choice_id_is_never_classified_outside_its_own_scenario():
    """``isolate_and_report`` is ransomware's. It means nothing in phishing."""
    with pytest.raises(UnknownChoiceError):
        learning.response_quality(learning.PHISHING, "isolate_and_report")
    with pytest.raises(UnknownChoiceError):
        learning.response_quality(learning.MFA, "authorize_payment")
    with pytest.raises(UnknownChoiceError):
        learning.concepts_for_choice(learning.BEC, "approve_request")


def test_every_lookup_table_is_keyed_by_scenario_and_choice():
    for key in Q.RESPONSE_QUALITY:
        assert isinstance(key, tuple) and len(key) == 2
    for key in C.CHOICE_CONCEPTS:
        assert isinstance(key, tuple) and len(key) == 2


# -- E/F/G: confidence validation -------------------------------------------
@pytest.mark.parametrize("confidence", [0, 100, 69, 70, 50])
def test_confidence_inside_the_range_is_accepted(confidence):
    assessment = learning.assess_decision(learning.PHISHING, "inspect_sender",
                                          confidence)
    assert assessment.confidence == confidence


@pytest.mark.parametrize("confidence", [-1, 101, 1000, "70", 70.0, True,
                                        float("nan")])
def test_confidence_outside_the_range_or_the_wrong_type_is_rejected(confidence):
    with pytest.raises(LearningConfidenceError):
        learning.assess_decision(learning.PHISHING, "inspect_sender",
                                 confidence)


def test_an_unstated_confidence_is_carried_as_none_not_as_a_number():
    assessment = learning.assess_decision(learning.PHISHING, "inspect_sender",
                                          None)
    assert assessment.confidence is None
    assert assessment.confidence_band == A.BAND_UNSTATED
    assert not assessment.confidence_stated


# -- H: the threshold boundary is deterministic ------------------------------
def test_high_confidence_threshold_boundary_is_at_or_above():
    assert A.HIGH_CONFIDENCE_THRESHOLD == 70
    assert A.confidence_band(69) == A.BAND_LOW
    assert A.confidence_band(70) == A.BAND_HIGH
    assert A.confidence_band(71) == A.BAND_HIGH


def test_the_raw_confidence_survives_banding():
    """The measurement is authoritative; the band is feedback only."""
    for confidence in (0, 42, 69, 70, 100):
        assessment = learning.assess_decision(learning.BEC,
                                              "verify_via_known_contact",
                                              confidence)
        assert assessment.confidence == confidence


# -- I/J/K/L/M: the five authored interpretations ---------------------------
def test_protective_high_confidence_maps_to_confident_protective():
    a = learning.assess_decision(learning.PHISHING, "verify_independently", 85)
    assert a.response_quality == learning.PROTECTIVE
    assert a.confidence_interpretation == A.CONFIDENT_PROTECTIVE
    assert a.evidence_signal == A.SUPPORTING_EVIDENCE


def test_protective_low_confidence_maps_to_fragile_protective():
    a = learning.assess_decision(learning.PHISHING, "verify_independently", 30)
    assert a.response_quality == learning.PROTECTIVE
    assert a.confidence_interpretation == A.FRAGILE_PROTECTIVE
    assert a.evidence_signal == A.FRAGILE_UNDERSTANDING


def test_risky_high_confidence_maps_to_high_confidence_risk():
    a = learning.assess_decision(learning.MFA, "approve_request", 95)
    assert a.response_quality == learning.RISKY
    assert a.confidence_interpretation == A.HIGH_CONFIDENCE_RISK
    assert a.evidence_signal == A.MISCONCEPTION_CANDIDATE


def test_risky_low_confidence_maps_to_recognized_uncertainty():
    a = learning.assess_decision(learning.MFA, "approve_request", 20)
    assert a.response_quality == learning.RISKY
    assert a.confidence_interpretation == A.RECOGNIZED_UNCERTAINTY
    assert a.evidence_signal == A.NEEDS_REINFORCEMENT


@pytest.mark.parametrize("confidence", [0, 40, 70, 100])
def test_partial_maps_to_partial_response_whatever_the_confidence(confidence):
    a = learning.assess_decision(learning.RANSOMWARE,
                                 "report_without_isolating", confidence)
    assert a.response_quality == learning.PARTIAL
    assert a.confidence_interpretation == A.PARTIAL_RESPONSE
    assert a.evidence_signal == A.PARTIAL_UNDERSTANDING


def test_interpretation_signal_mapping_is_total():
    assert set(A.INTERPRETATION_SIGNALS) == set(A.CONFIDENCE_INTERPRETATIONS)
    assert set(A.INTERPRETATION_SIGNALS.values()) == set(A.EVIDENCE_SIGNALS)


# -- 45/46: the two named signal tests --------------------------------------
def test_high_confidence_risky_factual_choice_creates_misconception_candidate_evidence():
    a = learning.assess_decision(learning.PHISHING,
                                 "follow_link_and_sign_in", 90)
    assert a.response_quality == learning.RISKY
    assert a.evidence_signal == A.MISCONCEPTION_CANDIDATE


def test_low_confidence_protective_choice_creates_fragile_understanding_evidence():
    a = learning.assess_decision(learning.BEC, "verify_via_known_contact", 42)
    assert a.response_quality == learning.PROTECTIVE
    assert a.evidence_signal == A.FRAGILE_UNDERSTANDING


def test_learner_facing_wording_never_uses_the_internal_signal_language():
    """The UI vocabulary must not call anybody misconceived."""
    prose = " ".join(list(F.CONFIDENCE_SENTENCES.values())
                     + list(F.SIGNAL_NOTES.values())
                     + list(F.SIGNAL_HEADINGS.values())
                     + list(F.QUALITY_SUMMARIES.values())
                     + list(F.CONCEPT_STATEMENTS.values())).lower()
    for word in ("misconcept", "misconception_candidate", "diagnos",
                 "mastery", "deficien", "failure", "stupid"):
        assert word not in prose, word


# -- N: concept tags are stable strings -------------------------------------
def test_concept_tags_are_stable_lowercase_identifier_strings():
    tags = set()
    for value in C.CHOICE_CONCEPTS.values():
        tags.update(value)
    for value in C.SCENARIO_CONCEPTS.values():
        tags.update(value)
    assert tags
    for tag in tags:
        assert isinstance(tag, str)
        assert tag and tag == tag.lower()
        assert tag.replace("_", "").isalnum()


def test_a_choice_is_not_tagged_with_every_concept_in_its_scenario():
    """Evidence about everything is evidence about nothing."""
    for scenario_key in learning.LEARNING_SCENARIOS:
        full = set(learning.scenario_concepts(scenario_key))
        for choice_id in Q.scenario_choice_ids(scenario_key):
            tags = set(learning.concepts_for_choice(scenario_key, choice_id))
            assert tags < full, (scenario_key, choice_id)


def test_a_choices_concepts_belong_to_its_own_scenario():
    for scenario_key in learning.LEARNING_SCENARIOS:
        allowed = set(learning.scenario_concepts(scenario_key))
        for choice_id in Q.scenario_choice_ids(scenario_key):
            assert set(learning.concepts_for_choice(
                scenario_key, choice_id)) <= allowed


# -- assessments are immutable and deterministic ----------------------------
def test_assessment_is_frozen_and_two_identical_inputs_are_equal():
    first = learning.assess_decision(learning.BEC, "authorize_payment", 77)
    second = learning.assess_decision(learning.BEC, "authorize_payment", 77)
    assert first == second
    with pytest.raises(Exception):
        first.response_quality = learning.PROTECTIVE


# -- P: framework independence ----------------------------------------------
FORBIDDEN_IMPORTS = ("flask", "sqlalchemy", "app", "sandbox", "docker",
                     "training", "requests", "socket", "subprocess",
                     "urllib", "http")


def _learning_modules():
    modules = [learning]
    for info in pkgutil.iter_modules(learning.__path__):
        modules.append(importlib.import_module("learning." + info.name))
    return modules


def test_learning_package_imports_no_framework_or_sandbox_module():
    """``learning/`` is standard library only, like ``training/``.

    Checked by reading each module's source rather than its ``sys.modules``
    footprint, so an import that happens to be satisfied by another test's
    import cannot hide here.
    """
    for module in _learning_modules():
        source = inspect.getsource(module)
        for line in source.splitlines():
            stripped = line.strip()
            if not (stripped.startswith("import ")
                    or stripped.startswith("from ")):
                continue
            for forbidden in FORBIDDEN_IMPORTS:
                assert not stripped.startswith("import " + forbidden), (
                    module.__name__, stripped)
                assert not stripped.startswith("from " + forbidden + " "), (
                    module.__name__, stripped)
                assert not stripped.startswith("from " + forbidden + "."), (
                    module.__name__, stripped)


def test_learning_modules_contain_no_network_or_process_calls():
    for module in _learning_modules():
        source = inspect.getsource(module)
        for forbidden in ("subprocess", "socket.", "urlopen", "requests.",
                          "os.system", "eval(", "exec("):
            assert forbidden not in source, (module.__name__, forbidden)


# ==========================================================================
# Reflection definitions (Q-V)
# ==========================================================================
def test_four_scenario_reflection_definitions_exist():
    assert set(R.REFLECTIONS) == set(learning.LEARNING_SCENARIOS)
    for scenario_key in learning.LEARNING_SCENARIOS:
        assert learning.reflection_for(scenario_key).scenario_key == scenario_key


def test_each_reflection_has_exactly_one_preferred_explanation():
    for scenario_key in learning.LEARNING_SCENARIOS:
        definition = learning.reflection_for(scenario_key)
        preferred = [o for o in definition.options if o.preferred]
        assert len(preferred) == 1, scenario_key
        assert definition.preferred is preferred[0]


def test_explanation_ids_are_unique_within_a_scenario():
    for scenario_key in learning.LEARNING_SCENARIOS:
        ids = learning.reflection_for(scenario_key).explanation_ids
        assert len(set(ids)) == len(ids) == len(
            learning.reflection_for(scenario_key).options)
        assert 3 <= len(ids) <= 4


def test_unknown_explanation_is_rejected():
    with pytest.raises(UnknownExplanationError):
        learning.explanation_for(learning.PHISHING, "no_such_explanation")
    # And an id belonging to a *different* scenario is just as invalid.
    with pytest.raises(UnknownExplanationError):
        learning.explanation_for(learning.PHISHING,
                                 "isolation_stopped_progression")


def test_unknown_scenario_has_no_reflection():
    with pytest.raises(UnknownScenarioError):
        learning.reflection_for("no_such_scenario")


def test_reflection_definitions_contain_no_callable_or_generated_content():
    """Authored prose, fixed at import time. No templating, no generation."""
    for scenario_key in learning.LEARNING_SCENARIOS:
        definition = learning.reflection_for(scenario_key)
        assert isinstance(definition.prompt, str)
        assert not callable(definition.prompt)
        for option in definition.options:
            assert isinstance(option.text, str) and option.text.strip()
            assert not callable(option.text)
            # No format placeholders: nothing is interpolated into an
            # explanation at render time.
            assert "{" not in option.text and "%s" not in option.text
            assert isinstance(option.concept_tags, tuple)


# -- reflection definitions are scenario-level, never pair-specific ---------
def test_a_reflection_definition_is_addressed_only_by_scenario():
    """There is no pair-by-pair reflection matrix, and no way to build one.

    ``reflection_for`` takes a scenario key and nothing else, and the mapping is
    keyed by scenario key alone. A definition therefore cannot encode one
    specific factual/counterfactual choice pair even by accident.
    """
    assert list(inspect.signature(learning.reflection_for).parameters) == [
        "scenario_key"]
    assert set(R.REFLECTIONS) == set(learning.LEARNING_SCENARIOS)
    for key in R.REFLECTIONS:
        assert isinstance(key, str)
    for definition in R.REFLECTIONS.values():
        # No field carries a choice, a pair, or a branch.
        for field in vars(definition):
            assert not any(word in field for word in
                           ("choice", "pair", "factual", "branch")), field


def test_no_reflection_prompt_or_option_names_a_choice_id():
    """A scenario-level prompt may not be about one specific comparison."""
    for scenario_key in learning.LEARNING_SCENARIOS:
        definition = learning.reflection_for(scenario_key)
        texts = [definition.prompt] + [o.text for o in definition.options]
        prose = " ".join(texts).lower()
        for choice_id in Q.scenario_choice_ids(scenario_key):
            assert choice_id not in prose, (scenario_key, choice_id)
            # Nor the choice id written out as words.
            assert choice_id.replace("_", " ") not in prose, (scenario_key,
                                                              choice_id)


#: Phrases that presuppose the two compared branches produced *different*
#: high-level outcomes, or that narrate one branch against the other. A
#: structural check on fixed literals, not semantic analysis: these forms are
#: simply not allowed in a scenario-level prompt or option, because several
#: valid comparisons are two protective responses whose major outcome is the
#: same (see :data:`SAME_MAJOR_OUTCOME_PAIRS`).
#:
#: Every phrase here appeared in the pre-review wording that this rule replaced;
#: :func:`test_the_divergence_guard_catches_the_wording_it_replaced` pins that,
#: so the guard cannot quietly decay into a list that catches nothing.
DIVERGENCE_PRESUPPOSING = (
    "differed", "different outcomes", "different account-access",
    "the two paths produced", "why the two paths", "one path",
    "the other path", "than on the other", "the other disclosed",
    "changed the outcome", "change the account outcome",
    "changed the account outcome", "change how many", ", while ",
)

#: Additionally forbidden in a *prompt*: forms that contrast two specific named
#: responses, which would make the question about one pair rather than about the
#: scenario's principle. Options may legitimately say "rather than" -- the MFA
#: preferred explanation does -- so this applies to prompts only.
PAIR_SPECIFIC_PROMPT_FORMS = (
    "rather than", "stronger than", "instead of", "why did", "why is",
    "why the",
)


def test_no_reflection_prompt_or_option_presupposes_a_divergent_outcome():
    for scenario_key in learning.LEARNING_SCENARIOS:
        definition = learning.reflection_for(scenario_key)
        texts = [definition.prompt] + [o.text for o in definition.options]
        for text in texts:
            lowered = text.lower()
            for phrase in DIVERGENCE_PRESUPPOSING:
                assert phrase not in lowered, (scenario_key, phrase, text)


def test_no_reflection_prompt_contrasts_two_specific_responses():
    for scenario_key in learning.LEARNING_SCENARIOS:
        prompt = learning.reflection_for(scenario_key).prompt.lower()
        for phrase in PAIR_SPECIFIC_PROMPT_FORMS:
            assert phrase not in prompt, (scenario_key, phrase)
        # And it does ask about the principle.
        assert "principle" in prompt


#: The exact wording the semantic review replaced. Kept verbatim so the guards
#: above are proven to bite rather than merely to pass.
SUPERSEDED_WORDING = (
    ("prompt", "What most directly explains why the two paths produced "
               "different account-access outcomes?"),
    ("option", "One path broke the attack chain by rejecting or independently "
               "verifying the request before any synthetic credentials were "
               "disclosed; the other disclosed them first."),
    ("option", "The account details used on one path were stronger than on "
               "the other, so they were harder to reuse."),
    ("prompt", "Why did the response choice change how many synthetic files "
               "were affected?"),
    ("option", "Isolating the endpoint early stopped the authored file-impact "
               "progression from continuing, while reporting or attempting "
               "recovery without containing the machine left it running."),
    ("prompt", "Why did approving, rather than verifying or denying, the "
               "unexpected request change the account outcome?"),
    ("option", "Approving the unexpected prompt authorised the synthetic "
               "sign-in, while verifying or denying it kept the unrecognised "
               "authentication from becoming an active session."),
    ("prompt", "Why is verifying with a known supplier contact stronger than "
               "replying to the same email thread?"),
)


@pytest.mark.parametrize("kind,text", SUPERSEDED_WORDING)
def test_the_divergence_guard_catches_the_wording_it_replaced(kind, text):
    """Each superseded string trips at least one guard above."""
    lowered = text.lower()
    tripped = [p for p in DIVERGENCE_PRESUPPOSING if p in lowered]
    if kind == "prompt":
        tripped += [p for p in PAIR_SPECIFIC_PROMPT_FORMS if p in lowered]
    assert tripped, text


#: Pairs of distinct choices that are both protective and therefore share the
#: scenario's major security outcome. The reflection must be valid for these
#: exactly as it is for a risky/protective pair.
SAME_MAJOR_OUTCOME_PAIRS = {
    learning.PHISHING: ("inspect_sender", "report_message"),
    learning.MFA: ("deny_and_report", "verify_through_known_channel"),
    learning.BEC: ("verify_via_known_contact",
                   "escalate_to_finance_security"),
}


@pytest.mark.parametrize("scenario_key,pair",
                         sorted(SAME_MAJOR_OUTCOME_PAIRS.items()))
def test_the_named_same_outcome_pairs_really_are_both_protective(scenario_key,
                                                                 pair):
    """Guards the premise the regression cases rest on."""
    first, second = pair
    assert first != second
    assert learning.response_quality(scenario_key, first) == learning.PROTECTIVE
    assert learning.response_quality(scenario_key,
                                     second) == learning.PROTECTIVE


def test_every_pair_of_distinct_choices_shares_one_scenario_reflection():
    """The invariant, stated over every allowed pair rather than a sample.

    For each scenario, every ordered pair of distinct supported choices resolves
    to the *same* definition object, the same prompt key and the same preferred
    explanation. Reflection correctness therefore cannot depend on which branch
    was factual.
    """
    import itertools

    for scenario_key in learning.LEARNING_SCENARIOS:
        definition = learning.reflection_for(scenario_key)
        choices = Q.scenario_choice_ids(scenario_key)
        pairs = list(itertools.permutations(choices, 2))
        assert len(pairs) == len(choices) * (len(choices) - 1) == 12
        for factual, counterfactual in pairs:
            # Resolution takes the scenario only; the pair cannot influence it.
            resolved = learning.reflection_for(scenario_key)
            assert resolved is definition
            assert resolved.prompt_key == definition.prompt_key
            assert (resolved.preferred.explanation_id
                    == definition.preferred.explanation_id)
            # And both members of the pair are classifiable, so the pair is a
            # legitimate comparison rather than a hypothetical one.
            assert learning.response_quality(scenario_key, factual)
            assert learning.response_quality(scenario_key, counterfactual)


def test_preferred_explanations_map_to_the_intended_concepts():
    expected = {
        learning.PHISHING: {C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE},
        learning.RANSOMWARE: {C.ENDPOINT_ISOLATION, C.INCIDENT_REPORTING},
        learning.MFA: {C.MFA_PROMPT_VERIFICATION,
                       C.UNEXPECTED_AUTHENTICATION},
        learning.BEC: {C.SECONDARY_CHANNEL_VERIFICATION,
                       C.PAYMENT_CHANGE_VERIFICATION},
    }
    for scenario_key, tags in expected.items():
        preferred = learning.reflection_for(scenario_key).preferred
        assert set(preferred.concept_tags) == tags, scenario_key


def test_preferred_phishing_explanation_is_about_breaking_the_chain():
    text = R.PHISHING_REFLECTION.preferred.text.lower()
    assert "verif" in text and "credential" in text


def test_ransomware_reflection_does_not_claim_to_model_real_propagation():
    """The authored file-count model is a controlled comparison, not physics."""
    preferred = R.RANSOMWARE_REFLECTION.preferred.text.lower()
    assert "authored" in preferred
    assert "predict" not in preferred


def test_every_explanation_concept_belongs_to_its_own_scenario():
    for scenario_key in learning.LEARNING_SCENARIOS:
        allowed = set(learning.scenario_concepts(scenario_key))
        for option in learning.reflection_for(scenario_key).options:
            assert set(option.concept_tags) <= allowed, (scenario_key,
                                                         option.explanation_id)


# ==========================================================================
# Transfer probe definitions
# ==========================================================================
def test_exactly_two_probes_ship_in_r6():
    assert set(T.TRANSFER_PROBES) == {"quishing_portal_qr",
                                      "unexpected_update_attachment"}


def test_probes_are_bound_to_their_source_scenarios():
    assert learning.probe_for_scenario(
        learning.PHISHING).probe_key == "quishing_portal_qr"
    assert learning.probe_for_scenario(
        learning.RANSOMWARE).probe_key == "unexpected_update_attachment"


def test_mfa_and_bec_have_no_transfer_probe_in_r6():
    assert learning.probe_for_scenario(learning.MFA) is None
    assert learning.probe_for_scenario(learning.BEC) is None


def test_unknown_probe_is_rejected():
    with pytest.raises(UnknownProbeError):
        learning.probe_for_key("no_such_probe")


@pytest.mark.parametrize("probe_key", ["quishing_portal_qr",
                                       "unexpected_update_attachment"])
def test_each_probe_offers_exactly_four_classified_choices(probe_key):
    probe = learning.probe_for_key(probe_key)
    assert len(probe.choices) == 4
    for choice in probe.choices:
        assert choice.response_quality in learning.RESPONSE_QUALITIES
        assert choice.concept_tags


def test_quishing_choice_classifications():
    probe = learning.probe_for_key("quishing_portal_qr")
    assert probe.choice("scan_and_sign_in").response_quality == learning.RISKY
    assert probe.choice(
        "inspect_qr_request").response_quality == learning.PARTIAL
    assert probe.choice(
        "verify_via_official_portal").response_quality == learning.PROTECTIVE
    assert probe.choice(
        "report_qr_message").response_quality == learning.PROTECTIVE


def test_update_attachment_choice_classifications():
    probe = learning.probe_for_key("unexpected_update_attachment")
    assert probe.choice("run_attached_update").response_quality == learning.RISKY
    assert probe.choice(
        "restart_then_try_update").response_quality == learning.RISKY
    assert probe.choice(
        "verify_update_through_it").response_quality == learning.PROTECTIVE
    assert probe.choice(
        "isolate_and_report_attachment").response_quality == learning.PROTECTIVE


def test_a_probe_choice_id_is_never_classified_by_the_other_probe():
    with pytest.raises(UnknownChoiceError):
        learning.classify_probe_choice("quishing_portal_qr",
                                       "run_attached_update")
    with pytest.raises(UnknownChoiceError):
        learning.classify_probe_choice("unexpected_update_attachment",
                                       "scan_and_sign_in")


# -- BC/50 (structural half): probes carry no destination and no payload -----
def test_probe_definitions_contain_no_url_host_path_or_payload():
    """Checked against the authored *data*, not the prose that describes it.

    A docstring may say the word "download"; a probe definition may not carry
    one. Every string a learner could ever be shown is scanned here.
    """
    authored = []
    for probe in T.TRANSFER_PROBES.values():
        authored.extend([probe.title, probe.prompt, probe.principle])
        authored.extend(probe.situation)
        authored.extend(c.label for c in probe.choices)
    prose = " ".join(authored).lower()
    for forbidden in ("http://", "https://", "ftp://", "www.", ".exe", ".msi",
                      ".zip", ".dll", "://", "c:\\", "/etc/"):
        assert forbidden not in prose, forbidden


def test_probe_authored_text_names_no_scannable_destination():
    for probe in T.TRANSFER_PROBES.values():
        prose = " ".join((probe.prompt, probe.principle) + probe.situation)
        assert "http" not in prose.lower()
        assert "://" not in prose


def test_quishing_probe_does_not_reuse_the_phishing_message_wording():
    """A probe on the same surface, in the same words, would not be unseen."""
    from training_routes import BRANCH_EVIDENCE, ORG

    probe = learning.probe_for_key("quishing_portal_qr")
    prose = " ".join(probe.situation + (probe.prompt,)).lower()
    # None of the R3 scenario's fictional organisation, sender or domain.
    for value in ORG.values():
        assert value.lower() not in prose, value
    for entry in BRANCH_EVIDENCE.values():
        for line in entry["lines"]:
            assert line.lower() not in prose


def test_transfer_probes_are_not_labelled_near_or_far():
    """R6 records unseen probes; the transfer taxonomy is a study decision."""
    for probe in T.TRANSFER_PROBES.values():
        # No authored field claims a transfer distance, and none of the text a
        # learner or an analysis reads asserts one.
        assert not hasattr(probe, "transfer_distance")
        assert not hasattr(probe, "transfer_class")
        prose = " ".join((probe.title, probe.prompt, probe.principle)
                         + probe.situation).lower()
        assert "far transfer" not in prose
        assert "near transfer" not in prose
    assert set(vars(T)) & {"NEAR_TRANSFER", "FAR_TRANSFER"} == set()


# ==========================================================================
# Feedback vocabulary
# ==========================================================================
def test_every_interpretation_has_an_authored_confidence_sentence():
    assert set(F.CONFIDENCE_SENTENCES) == set(A.CONFIDENCE_INTERPRETATIONS)


def test_every_evidence_signal_has_a_heading_and_a_note():
    assert set(F.SIGNAL_HEADINGS) == set(A.EVIDENCE_SIGNALS)
    assert set(F.SIGNAL_NOTES) == set(A.EVIDENCE_SIGNALS)


def test_every_scenario_concept_has_an_authored_carry_forward_statement():
    for scenario_key in learning.LEARNING_SCENARIOS:
        for tag in learning.scenario_concepts(scenario_key):
            assert F.concept_statement(scenario_key, tag), (scenario_key, tag)


def test_carry_forward_returns_between_one_and_three_statements():
    for scenario_key in learning.LEARNING_SCENARIOS:
        for choice_id in Q.scenario_choice_ids(scenario_key):
            a = learning.assess_decision(scenario_key, choice_id, 60)
            statements = F.carry_forward(scenario_key, a.concept_tags)
            assert 1 <= len(statements) <= 3


def test_confidence_statement_interpolates_only_the_learners_own_number():
    a = learning.assess_decision(learning.PHISHING,
                                 "follow_link_and_sign_in", 82)
    assert F.confidence_statement(a) == (
        "You chose this response with 82% confidence.")
    unstated = learning.assess_decision(learning.PHISHING,
                                        "follow_link_and_sign_in", None)
    assert F.confidence_statement(unstated) is None


def test_no_global_mastery_score_exists_anywhere_in_the_domain():
    for module in _learning_modules():
        source = inspect.getsource(module).lower()
        for forbidden in ("mastery_score", "overall_score", "percent_correct",
                          "def score(", "total_score"):
            assert forbidden not in source, (module.__name__, forbidden)
