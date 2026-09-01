"""Exceptions raised by the pure RewindSec study domain.

Separate from ``training.errors`` and ``learning.errors`` for the same reason
those two are separate from each other: a study-protocol violation -- a phase
skipped, a retention window missed, an unconfigured allocation secret -- is not
a failed experiment and not a malformed pedagogical lookup, and the three must
never be caught by one ``except``.
"""


class StudyError(Exception):
    """Base class for every error raised by the study domain."""


class StudyConfigurationError(StudyError):
    """Research mode is enabled but a required setting is absent.

    Raised rather than defaulted. An allocation secret that silently fell back
    to a per-process random value would make the allocation sequence
    irreproducible, and irreproducible allocation cannot be audited.
    """


class UnknownArmError(StudyError):
    """An arm key is not one of the three the protocol defines."""


class UnknownPhaseError(StudyError):
    """A phase key is not part of this arm's authored progression."""


class PhaseTransitionError(StudyError):
    """A phase transition this arm's protocol does not permit."""


class RetentionWindowError(StudyError):
    """The retention probe was reached outside its authored window."""


class UnknownStudyProbeError(StudyError):
    """No authored probe exists for this study phase."""
