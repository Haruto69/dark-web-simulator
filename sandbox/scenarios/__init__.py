"""Controlled simulation scenarios."""

from .file_impact import SCENARIO_NAME, FileImpactScenario
from .phishing import (SCENARIO_NAME as PHISHING_SCENARIO_NAME, STAGES,
                       SYNTHETIC_RESOURCES, PhishingScenario, new_scenario_id,
                       stage_index)

__all__ = [
    "FileImpactScenario", "SCENARIO_NAME",
    "PhishingScenario", "PHISHING_SCENARIO_NAME", "STAGES",
    "SYNTHETIC_RESOURCES", "new_scenario_id", "stage_index",
]
