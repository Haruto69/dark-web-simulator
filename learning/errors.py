"""Exceptions raised by the pure RewindSec learning domain.

Deliberately separate from ``training.errors``. That package's exceptions
describe a *technical* counterfactual execution failing; these describe an
authored pedagogical definition being asked for something it does not define.
The two layers never share an exception hierarchy, because a malformed learning
lookup must never be mistaken for a failed experiment.
"""


class LearningError(Exception):
    """Base class for every error raised by the learning domain."""


class UnknownScenarioError(LearningError):
    """No authored learning definitions exist for this scenario key."""


class UnknownChoiceError(LearningError):
    """A choice id is not classified *within the scenario it was given with*.

    There is deliberately no cross-scenario fallback: a choice id means
    something only in the scenario that authored it.
    """


class UnknownExplanationError(LearningError):
    """A structured-explanation id is not offered by this scenario's prompt."""


class UnknownProbeError(LearningError):
    """No authored transfer probe exists for this probe key."""


class LearningConfidenceError(LearningError):
    """A confidence reading was not an integer in the closed range 0..100."""
