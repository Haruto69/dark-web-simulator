"""The pure study domain: protocol, phases, retention window, probes.

No Flask, no database, no HTTP. These tests hold the authored protocol to its
own rules and tie its duplicated literals back to the packages they mirror --
``study/`` repeats the phishing scenario key rather than importing it, and that
duplication must not be allowed to drift silently.
"""

from datetime import datetime, timedelta

import pytest

import learning
import study
from study.errors import (PhaseTransitionError, UnknownArmError,
                          UnknownPhaseError, UnknownStudyProbeError)


class TestPurity:
    def test_study_package_imports_no_framework(self):
        """``study/`` must stay importable with nothing but stdlib + learning."""
        import sys
        import types
        forbidden = ("flask", "sqlalchemy", "flask_sqlalchemy", "docker",
                     "requests", "subprocess", "app", "sandbox")
        modules = [study.protocol, study.assignment, study.assessment,
                   study.continuity, study.errors]
        for module in modules:
            for name, value in vars(module).items():
                if isinstance(value, types.ModuleType):
                    root = value.__name__.split(".")[0]
                    assert root not in forbidden, (
                        "%s imports %s" % (module.__name__, value.__name__))

    def test_learning_is_the_only_project_dependency(self):
        import types
        allowed = {"learning", "study", "datetime", "types", "hashlib", "hmac",
                   "secrets"}
        for module in (study.protocol, study.assignment, study.assessment,
                       study.continuity):
            for value in vars(module).values():
                if isinstance(value, types.ModuleType):
                    assert value.__name__.split(".")[0] in allowed


class TestProtocolIdentity:
    def test_protocol_key_and_version_are_fixed(self):
        assert study.PROTOCOL_KEY == "rewindsec_phishing_pilot"
        assert study.PROTOCOL_VERSION == 1

    def test_source_scenario_is_the_shipped_phishing_scenario(self):
        """The literal in ``study/`` is the real scenario key, not a near-miss."""
        from scenario_adapters.phishing import (PHISHING_DECISION_ID,
                                                PHISHING_SCENARIO_KEY)
        assert study.SOURCE_SCENARIO_KEY == PHISHING_SCENARIO_KEY
        assert study.SOURCE_DECISION_ID == PHISHING_DECISION_ID

    def test_only_phishing_is_in_the_pilot(self):
        """Ransomware, MFA and BEC are deliberately not part of this protocol."""
        assert study.SOURCE_SCENARIO_KEY == learning.PHISHING
        for scenario in (learning.RANSOMWARE, learning.MFA, learning.BEC):
            assert study.SOURCE_SCENARIO_KEY != scenario

    def test_three_arms_with_stable_keys(self):
        assert study.ARMS == ("awareness_debrief", "factual_consequence",
                              "counterfactual_replay")

    def test_no_control_or_experimental_language_in_arm_keys(self):
        for arm in study.ARMS:
            assert "control" not in arm
            assert "experimental" not in arm


class TestArmCapabilities:
    def test_only_the_third_arm_executes_a_counterfactual(self):
        assert not study.runs_counterfactual(study.AWARENESS_DEBRIEF)
        assert not study.runs_counterfactual(study.FACTUAL_CONSEQUENCE)
        assert study.runs_counterfactual(study.COUNTERFACTUAL_REPLAY)

    def test_the_first_arm_executes_no_consequence(self):
        assert not study.executes_consequence(study.AWARENESS_DEBRIEF)
        assert study.executes_consequence(study.FACTUAL_CONSEQUENCE)
        assert study.executes_consequence(study.COUNTERFACTUAL_REPLAY)

    def test_only_the_third_arm_reflects(self):
        assert not study.requires_reflection(study.AWARENESS_DEBRIEF)
        assert not study.requires_reflection(study.FACTUAL_CONSEQUENCE)
        assert study.requires_reflection(study.COUNTERFACTUAL_REPLAY)

    def test_unknown_arm_is_refused(self):
        with pytest.raises(UnknownArmError):
            study.require_arm("control")


class TestPhaseMachine:
    def test_every_arm_starts_enrolled_and_ends_retention_completed(self):
        for arm in study.ARMS:
            phases = study.arm_phases(arm)
            assert phases[0] == study.ENROLLED
            assert phases[-1] == study.RETENTION_COMPLETED

    def test_arm_a_has_no_technical_phases(self):
        phases = study.arm_phases(study.AWARENESS_DEBRIEF)
        assert study.FACTUAL_PREVIEW not in phases
        assert study.COUNTERFACTUAL_COMPLETED not in phases
        assert study.REFLECTION_COMPLETED not in phases

    def test_arm_b_previews_but_never_replays(self):
        phases = study.arm_phases(study.FACTUAL_CONSEQUENCE)
        assert study.FACTUAL_PREVIEW in phases
        assert study.COUNTERFACTUAL_COMPLETED not in phases
        assert study.REFLECTION_COMPLETED not in phases

    def test_arm_c_has_the_full_progression(self):
        phases = study.arm_phases(study.COUNTERFACTUAL_REPLAY)
        for phase in (study.FACTUAL_PREVIEW, study.COUNTERFACTUAL_COMPLETED,
                      study.REFLECTION_COMPLETED):
            assert phase in phases

    def test_only_the_immediate_successor_is_legal(self):
        arm = study.COUNTERFACTUAL_REPLAY
        assert study.check_transition(arm, study.ENROLLED,
                                      study.SOURCE_DECISION_RECORDED)
        with pytest.raises(PhaseTransitionError):
            study.check_transition(arm, study.ENROLLED,
                                   study.INTERVENTION_COMPLETED)

    def test_cannot_move_backwards(self):
        with pytest.raises(PhaseTransitionError):
            study.check_transition(study.AWARENESS_DEBRIEF,
                                   study.INTERVENTION_COMPLETED,
                                   study.ENROLLED)

    def test_a_phase_another_arm_has_is_unknown_to_this_one(self):
        with pytest.raises(UnknownPhaseError):
            study.phase_index(study.AWARENESS_DEBRIEF,
                              study.COUNTERFACTUAL_COMPLETED)

    def test_at_least_orders_within_an_arm(self):
        arm = study.FACTUAL_CONSEQUENCE
        assert study.at_least(arm, study.INTERVENTION_COMPLETED,
                              study.SOURCE_DECISION_RECORDED)
        assert not study.at_least(arm, study.ENROLLED, study.FACTUAL_PREVIEW)


class TestRetentionWindow:
    def test_window_is_seven_to_fourteen_days(self):
        assert study.RETENTION_OPEN_DAYS == 7
        assert study.RETENTION_CLOSE_DAYS == 14
        now = datetime(2026, 3, 1, 12, 0, 0)
        open_at, close_at = study.retention_window(now)
        assert open_at == now + timedelta(days=7)
        assert close_at == now + timedelta(days=14)

    def test_unscheduled_when_the_immediate_probe_is_unanswered(self):
        assert study.retention_window(None) == (None, None)
        assert study.retention_state(datetime(2026, 3, 1), None,
                                     None) == study.RETENTION_UNSCHEDULED

    def test_boundaries(self):
        now = datetime(2026, 3, 1, 12, 0, 0)
        open_at, close_at = study.retention_window(now)
        second = timedelta(seconds=1)
        assert study.retention_state(open_at - second, open_at,
                                     close_at) == study.RETENTION_PENDING
        # Inclusive at the opening instant: arriving exactly on time is not
        # turned away by a strict inequality.
        assert study.retention_state(open_at, open_at,
                                     close_at) == study.RETENTION_OPEN
        assert study.retention_state(close_at, open_at,
                                     close_at) == study.RETENTION_OPEN
        assert study.retention_state(close_at + second, open_at,
                                     close_at) == study.RETENTION_EXPIRED


class TestProbes:
    def test_immediate_probe_is_the_shipped_quishing_probe(self):
        """Reused, not copied: the same object the ordinary flow serves."""
        probe = study.probe_for_phase(study.IMMEDIATE_TRANSFER)
        assert probe is learning.probe_for_key("quishing_portal_qr")

    def test_retention_probe_is_study_only(self):
        """Unreachable from the normal R6 transfer routes."""
        assert study.RETENTION_PROBE_KEY not in learning.TRANSFER_PROBES
        with pytest.raises(learning.UnknownProbeError):
            learning.probe_for_key(study.RETENTION_PROBE_KEY)

    def test_retention_probe_shape(self):
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        assert probe.probe_key == "smishing_account_notice"
        assert probe.version == 1
        assert probe.source_scenario_key == learning.PHISHING
        assert probe.choice_ids == (
            "follow_message_and_sign_in", "inspect_message_details",
            "open_official_service", "report_suspicious_message")

    def test_retention_probe_qualities(self):
        expected = {
            "follow_message_and_sign_in": learning.RISKY,
            "inspect_message_details": learning.PARTIAL,
            "open_official_service": learning.PROTECTIVE,
            "report_suspicious_message": learning.PROTECTIVE,
        }
        for choice_id, quality in expected.items():
            assert study.classify(study.RETENTION_TRANSFER,
                                  choice_id).response_quality == quality

    def test_retention_probe_concepts(self):
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        assert set(probe.concept_tags) == {
            "independent_verification", "credential_exposure",
            "channel_switching"}

    def test_retention_probe_carries_no_destination(self):
        """No SMS, no URL, no host, no link, no form, no credential field."""
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        text = " ".join(probe.situation + (probe.prompt, probe.title,
                                           probe.principle)).lower()
        for token in ("http://", "https://", "www.", ".com", ".lab", ".net",
                      "href", "password", "sms:", "tel:"):
            assert token not in text

    def test_the_three_surfaces_differ(self):
        """Training email, QR notice and phone message are three surfaces."""
        immediate = study.probe_for_phase(study.IMMEDIATE_TRANSFER)
        retention = study.probe_for_phase(study.RETENTION_TRANSFER)
        assert immediate.probe_key != retention.probe_key
        assert set(immediate.choice_ids).isdisjoint(retention.choice_ids)

    def test_a_choice_from_the_other_probe_is_refused(self):
        with pytest.raises(learning.UnknownChoiceError):
            study.classify(study.RETENTION_TRANSFER, "scan_and_sign_in")
        with pytest.raises(learning.UnknownChoiceError):
            study.classify(study.IMMEDIATE_TRANSFER, "open_official_service")

    def test_unknown_phase_is_refused(self):
        with pytest.raises(UnknownStudyProbeError):
            study.probe_for_phase("far_transfer")

    def test_no_far_transfer_language_in_authored_content(self):
        """These are retention transfer probes, never "far transfer".

        The module docstring says so explicitly, so it is excluded here; what
        must be clean is every authored string a page could render, and every
        identifier the data model persists.
        """
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        rendered = " ".join(probe.situation
                            + (probe.prompt, probe.title, probe.principle))
        assert "far transfer" not in rendered.lower()
        for name in study.ASSESSMENT_PHASES + study.PHASES:
            assert "far" not in name


class TestDescriptiveOnly:
    def test_high_confidence_risky_uses_the_learning_threshold(self):
        threshold = learning.HIGH_CONFIDENCE_THRESHOLD
        assert study.high_confidence_risky(learning.RISKY, threshold)
        assert not study.high_confidence_risky(learning.RISKY, threshold - 1)
        assert not study.high_confidence_risky(learning.PROTECTIVE, 100)
        assert not study.high_confidence_risky(learning.RISKY, None)

    def test_missingness_is_represented_not_imputed(self):
        """No missingness state is a response quality."""
        for state in study.MISSINGNESS_STATES:
            assert state not in learning.RESPONSE_QUALITIES

    def test_no_statistics_are_computed_anywhere_in_the_package(self):
        import inspect
        banned = ("p_value", "pvalue", "significan", "effect_size",
                  "cohen", "ttest", "t_test", "chi2", "chisq")
        for module in (study.protocol, study.assignment, study.assessment,
                       study.continuity):
            source = inspect.getsource(module).lower()
            for token in banned:
                # The word may appear in prose explaining that it is absent;
                # it must never appear as an identifier.
                assert ("def %s" % token) not in source
                assert ("%s =" % token) not in source
