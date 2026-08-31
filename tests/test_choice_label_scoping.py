"""Choice labels resolve inside one scenario's vocabulary, never across.

A choice id is scenario-local. Two scenarios may legitimately name a choice the
same thing, so label resolution is keyed by ``scenario_key`` rather than
searching every shipped vocabulary in turn -- which would quietly turn choice
ids into globally unique identifiers and render the wrong label the first time
two scenarios collided.
"""

import pytest

from scenario_adapters import presentation
from scenario_adapters.phishing import (PHISHING_DECISION_ID,
                                        PHISHING_SCENARIO,
                                        PHISHING_SCENARIO_KEY)
from scenario_adapters.presentation import (CHOICE_LABEL_SOURCES,
                                            choice_labels_for,
                                            label_for_choice)
from scenario_adapters.ransomware import (RANSOMWARE_DECISION_ID,
                                          RANSOMWARE_SCENARIO,
                                          RANSOMWARE_SCENARIO_KEY)

SHARED_CHOICE_ID = "do_the_thing"


@pytest.fixture
def two_vocabularies(monkeypatch):
    """Two synthetic scenarios that deliberately share one choice id."""
    monkeypatch.setitem(CHOICE_LABEL_SOURCES, "scenario_alpha",
                        lambda: {SHARED_CHOICE_ID: "Alpha's version",
                                 "alpha_only": "Only in alpha"})
    monkeypatch.setitem(CHOICE_LABEL_SOURCES, "scenario_beta",
                        lambda: {SHARED_CHOICE_ID: "Beta's version",
                                 "beta_only": "Only in beta"})


# -- the shipped scenarios ---------------------------------------------------
def test_phishing_labels_resolve_under_the_phishing_scenario_key():
    decision = PHISHING_SCENARIO.decision(PHISHING_DECISION_ID)
    for choice in decision.choices:
        assert label_for_choice(PHISHING_SCENARIO_KEY,
                                choice.choice_id) == choice.label
    assert label_for_choice(PHISHING_SCENARIO_KEY,
                            "report_message") == "Report the message"


def test_ransomware_labels_resolve_under_the_ransomware_scenario_key():
    decision = RANSOMWARE_SCENARIO.decision(RANSOMWARE_DECISION_ID)
    for choice in decision.choices:
        assert label_for_choice(RANSOMWARE_SCENARIO_KEY,
                                choice.choice_id) == choice.label
    assert label_for_choice(
        RANSOMWARE_SCENARIO_KEY,
        "continue_working") == "Keep working and see if the problem stops"


def test_one_scenarios_choice_is_never_resolved_from_the_other():
    """The current ids do not collide -- so prove the *scoping*, not luck."""
    phishing_ids = PHISHING_SCENARIO.decision(PHISHING_DECISION_ID).choice_ids
    ransomware_ids = RANSOMWARE_SCENARIO.decision(
        RANSOMWARE_DECISION_ID).choice_ids
    for choice_id in phishing_ids:
        # Asked for under the wrong scenario key, it renders neutrally as the
        # id itself rather than borrowing the other scenario's vocabulary.
        assert label_for_choice(RANSOMWARE_SCENARIO_KEY, choice_id) == choice_id
    for choice_id in ransomware_ids:
        assert label_for_choice(PHISHING_SCENARIO_KEY, choice_id) == choice_id


# -- collision, unknown keys and unknown ids --------------------------------
def test_the_same_choice_id_resolves_differently_per_scenario(two_vocabularies):
    assert label_for_choice("scenario_alpha",
                            SHARED_CHOICE_ID) == "Alpha's version"
    assert label_for_choice("scenario_beta",
                            SHARED_CHOICE_ID) == "Beta's version"


def test_an_unknown_choice_is_not_resolved_from_another_vocabulary(
        two_vocabularies):
    assert label_for_choice("scenario_alpha", "beta_only") == "beta_only"
    assert label_for_choice("scenario_beta", "alpha_only") == "alpha_only"


@pytest.mark.parametrize("scenario_key", [
    "not_a_scenario", "", None, "phishing", "PHISHING_CREDENTIAL_COMPROMISE"])
def test_unknown_scenario_keys_fall_back_neutrally(scenario_key):
    assert choice_labels_for(scenario_key) == {}
    assert label_for_choice(scenario_key, "report_message") == "report_message"


@pytest.mark.parametrize("choice_id,expected", [
    ("no_such_choice", "no_such_choice"),
    ("", ""),
    (None, ""),
])
def test_unknown_choice_ids_fall_back_to_a_neutral_rendering(choice_id,
                                                             expected):
    assert label_for_choice(PHISHING_SCENARIO_KEY, choice_id) == expected


def test_choice_labels_for_returns_a_copy(two_vocabularies):
    """A caller mutating the result cannot corrupt a scenario's vocabulary."""
    labels = choice_labels_for("scenario_alpha")
    labels[SHARED_CHOICE_ID] = "tampered"
    assert label_for_choice("scenario_alpha",
                            SHARED_CHOICE_ID) == "Alpha's version"


def test_every_shipped_scenario_has_a_registered_vocabulary():
    for scenario in (PHISHING_SCENARIO, RANSOMWARE_SCENARIO):
        assert scenario.scenario_key in CHOICE_LABEL_SOURCES
        labels = choice_labels_for(scenario.scenario_key)
        for point in scenario.decision_points:
            for choice_id in point.choice_ids:
                assert choice_id in labels


def test_presentation_exposes_no_global_choice_lookup():
    """The old scenario-blind fallback must not come back."""
    assert not hasattr(presentation, "_LABEL_SOURCES")
    import inspect
    signature = inspect.signature(label_for_choice)
    assert list(signature.parameters) == ["scenario_key", "choice_id"]
