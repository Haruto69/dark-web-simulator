"""Immutable domain model for RewindSec training scenarios.

The safety boundary of this module: a scenario definition can name *what*
should happen, never *how*. A :class:`ConsequenceSpec` carries an opaque
``action_key`` -- a short symbolic token -- which only a trusted adapter may
resolve into real behaviour. Shell commands, import paths, callables, URLs and
filesystem paths are rejected at construction time, so a scenario definition can
never smuggle executable content through this layer.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .errors import ConfidenceValueError, ScenarioDefinitionError

# Identifiers and action keys: short, lowercase, symbolic. No slashes, dots,
# spaces, colons or shell metacharacters -- which alone rules out paths, URLs,
# dotted import paths and commands.
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# Defence in depth: even a key matching the pattern above is rejected if it
# reads like an execution attempt.
_FORBIDDEN_SUBSTRINGS = ("import", "eval", "exec", "subprocess", "system",
                         "popen", "lambda")

CONFIDENCE_MIN = 0
CONFIDENCE_MAX = 100


def validate_key(value, what):
    """Return ``value`` if it is a well-formed symbolic key."""
    if not isinstance(value, str):
        raise ScenarioDefinitionError(
            "{0} must be a string, got {1}".format(what, type(value).__name__))
    if not _KEY_RE.match(value):
        raise ScenarioDefinitionError(
            "{0} {1!r} is not a symbolic key (lowercase letters, digits and "
            "underscores only); paths, URLs, dotted import paths and commands "
            "are rejected by design".format(what, value))
    for bad in _FORBIDDEN_SUBSTRINGS:
        if bad in value:
            raise ScenarioDefinitionError(
                "{0} {1!r} contains {2!r}; consequence keys must be symbolic, "
                "not executable".format(what, value, bad))
    return value


def validate_confidence(value) -> Optional[int]:
    """Normalise an optional learner confidence reading.

    Accepts ``None`` (not asked, or not answered) or an ``int`` in 0..100.
    Rejects bools, floats (including NaN), numeric strings and out-of-range
    values, so a later analysis never has to guess what a reading meant.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfidenceValueError(
            "confidence must be an integer in {0}..{1} or None, got {2!r}"
            .format(CONFIDENCE_MIN, CONFIDENCE_MAX, value))
    if not CONFIDENCE_MIN <= value <= CONFIDENCE_MAX:
        raise ConfidenceValueError(
            "confidence {0} is outside {1}..{2}".format(
                value, CONFIDENCE_MIN, CONFIDENCE_MAX))
    return value


def validate_response_ms(value) -> Optional[int]:
    """Normalise an optional response time in whole milliseconds."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScenarioDefinitionError(
            "response time must be a non-negative integer number of "
            "milliseconds or None, got {0!r}".format(value))
    return value


def _require_text(value, what, max_length=200):
    if not isinstance(value, str) or not value.strip():
        raise ScenarioDefinitionError(
            "{0} must be a non-empty string".format(what))
    if len(value) > max_length:
        raise ScenarioDefinitionError(
            "{0} exceeds {1} characters".format(what, max_length))
    return value


@dataclass(frozen=True)
class ConsequenceSpec:
    """What a choice does, named symbolically.

    ``action_key`` is opaque to this package. The runtime checks it against the
    bound adapter's declared vocabulary before any branch runs; an unrecognised
    key fails closed rather than being interpreted.
    """

    action_key: str

    def __post_init__(self):
        validate_key(self.action_key, "consequence action key")


@dataclass(frozen=True)
class Choice:
    """One selectable option at a decision point."""

    choice_id: str
    label: str
    consequence: ConsequenceSpec
    description: str = ""

    def __post_init__(self):
        validate_key(self.choice_id, "choice id")
        _require_text(self.label, "choice label")
        if not isinstance(self.consequence, ConsequenceSpec):
            raise ScenarioDefinitionError(
                "choice {0!r} must carry a ConsequenceSpec, got {1}; raw "
                "commands, callables and URLs are not accepted".format(
                    self.choice_id, type(self.consequence).__name__))

    @property
    def action_key(self) -> str:
        return self.consequence.action_key


@dataclass(frozen=True)
class DecisionPoint:
    """A moment where the learner must choose, and the options available."""

    decision_id: str
    prompt_key: str
    choices: Tuple[Choice, ...]

    def __post_init__(self):
        validate_key(self.decision_id, "decision id")
        validate_key(self.prompt_key, "prompt key")
        object.__setattr__(self, "choices", tuple(self.choices))
        if len(self.choices) < 2:
            raise ScenarioDefinitionError(
                "decision {0!r} needs at least two choices to support a "
                "counterfactual comparison".format(self.decision_id))
        seen = set()
        for choice in self.choices:
            if not isinstance(choice, Choice):
                raise ScenarioDefinitionError(
                    "decision {0!r} contains a non-Choice entry".format(
                        self.decision_id))
            if choice.choice_id in seen:
                raise ScenarioDefinitionError(
                    "decision {0!r} has duplicate choice id {1!r}".format(
                        self.decision_id, choice.choice_id))
            seen.add(choice.choice_id)

    def choice(self, choice_id: str) -> Choice:
        for candidate in self.choices:
            if candidate.choice_id == choice_id:
                return candidate
        raise ScenarioDefinitionError(
            "decision {0!r} has no choice {1!r}".format(
                self.decision_id, choice_id))

    @property
    def choice_ids(self) -> Tuple[str, ...]:
        return tuple(choice.choice_id for choice in self.choices)

    @property
    def action_keys(self) -> Tuple[str, ...]:
        return tuple(sorted({choice.action_key for choice in self.choices}))


@dataclass(frozen=True)
class ScenarioDefinition:
    """A versioned training scenario: identity, tags and its decision points.

    ``version`` is part of the scenario's identity. Results captured under one
    version are never silently comparable with results from another.
    """

    scenario_key: str
    version: int
    title: str
    decision_points: Tuple[DecisionPoint, ...]
    competency_tags: Tuple[str, ...] = field(default=())

    def __post_init__(self):
        validate_key(self.scenario_key, "scenario key")
        if (isinstance(self.version, bool) or not isinstance(self.version, int)
                or self.version < 1):
            raise ScenarioDefinitionError(
                "scenario version must be a positive integer, got {0!r}"
                .format(self.version))
        _require_text(self.title, "scenario title")
        object.__setattr__(self, "decision_points", tuple(self.decision_points))
        object.__setattr__(self, "competency_tags",
                           tuple(sorted(set(self.competency_tags))))
        for tag in self.competency_tags:
            validate_key(tag, "competency tag")
        if not self.decision_points:
            raise ScenarioDefinitionError(
                "scenario {0!r} has no decision points".format(
                    self.scenario_key))
        seen = set()
        for point in self.decision_points:
            if not isinstance(point, DecisionPoint):
                raise ScenarioDefinitionError(
                    "scenario {0!r} contains a non-DecisionPoint entry".format(
                        self.scenario_key))
            if point.decision_id in seen:
                raise ScenarioDefinitionError(
                    "scenario {0!r} has duplicate decision id {1!r}".format(
                        self.scenario_key, point.decision_id))
            seen.add(point.decision_id)

    def decision(self, decision_id: str) -> DecisionPoint:
        for point in self.decision_points:
            if point.decision_id == decision_id:
                return point
        raise ScenarioDefinitionError(
            "scenario {0!r} has no decision {1!r}".format(
                self.scenario_key, decision_id))

    @property
    def identity(self) -> str:
        """``key@version`` -- the correlatable identity of this definition."""
        return "{0}@{1}".format(self.scenario_key, self.version)

    @property
    def action_keys(self) -> Tuple[str, ...]:
        keys = set()
        for point in self.decision_points:
            keys.update(point.action_keys)
        return tuple(sorted(keys))
