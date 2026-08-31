"""Application-level scenario definitions, consequence adapters and presentation.

This package is deliberately **outside** ``training/``.

``training/`` is the pure research runtime and must stay free of Flask,
SQLAlchemy, the ``sandbox`` package, Docker, HTTP and templates (see
``docs/training-runtime.md``). The concrete scenarios an application ships are
not part of that invariant: a phishing adapter legitimately wants to reuse the
application's synthetic-resource allow-list, and a presentation mapper exists
purely to render an application UI. Putting either under ``training/adapters``
would have broken the framework-independence the R1 milestone established, so
they live here instead.

What is here:

``phishing``      the ``phishing_credential_compromise`` scenario definition,
                  its deterministic consequence state, and the adapter that
                  enacts its fixed action vocabulary.
``ransomware``    the ``ransomware_incident_response`` scenario definition and
                  the adapter that enacts it against the real contained
                  sandbox through ``SandboxManager``.
``presentation``  an allow-listed, deterministic mapping from state keys and
                  state changes to learner-readable sentences. No LLM, no
                  generated prose, no raw JSON shown to a learner.
"""

from .phishing import (PHISHING_ACTIONS, PHISHING_BASELINE_STATE,
                       PHISHING_DECISION_ID, PHISHING_SCENARIO,
                       PHISHING_SCENARIO_KEY, PHISHING_SCENARIO_VERSION,
                       CREDENTIAL_CHOICE_ID, PhishingConsequenceAdapter,
                       choice_labels, phishing_choices)
from .ransomware import (IMPACT_PROGRESSION, INITIAL_IMPACT,
                         RANSOMWARE_ACTIONS, RANSOMWARE_CHOICE_IDS,
                         RANSOMWARE_DECISION_ID, RANSOMWARE_SCENARIO,
                         RANSOMWARE_SCENARIO_KEY, RANSOMWARE_SCENARIO_VERSION,
                         RansomwareConsequenceAdapter, ransomware_choices,
                         ransomware_choice_labels)
from .presentation import (CHOICE_LABEL_SOURCES, RANSOMWARE_VOCABULARY,
                           choice_labels_for, describe_difference,
                           describe_state, label_for_choice)

__all__ = [
    "PHISHING_ACTIONS", "PHISHING_BASELINE_STATE", "PHISHING_DECISION_ID",
    "PHISHING_SCENARIO", "PHISHING_SCENARIO_KEY", "PHISHING_SCENARIO_VERSION",
    "CREDENTIAL_CHOICE_ID", "PhishingConsequenceAdapter", "choice_labels",
    "phishing_choices", "describe_difference", "describe_state",
    "label_for_choice",
    "IMPACT_PROGRESSION", "INITIAL_IMPACT", "RANSOMWARE_ACTIONS",
    "RANSOMWARE_CHOICE_IDS", "RANSOMWARE_DECISION_ID", "RANSOMWARE_SCENARIO",
    "RANSOMWARE_SCENARIO_KEY", "RANSOMWARE_SCENARIO_VERSION",
    "RANSOMWARE_VOCABULARY", "RansomwareConsequenceAdapter",
    "ransomware_choices", "ransomware_choice_labels",
    "CHOICE_LABEL_SOURCES", "choice_labels_for",
]
