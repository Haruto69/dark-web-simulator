"""Closed vocabularies for the simulation domain.

Kept in one module because these are the vocabularies a caller outside the
domain (persistence adapter, a future REST layer) needs to agree on, and a
single import site keeps them from drifting into inconsistent spellings.
"""

from enum import Enum

from rewindsec.domain.errors import InvalidIdentityError

__all__ = [
    "Focus",
    "Mode",
    "SessionStatus",
    "ActionClass",
    "coerce_enum",
]


class Focus(Enum):
    """Training focus selected at session start. Architecture Spec v1.1 S3."""

    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    MFA = "mfa"
    BEC = "bec"
    MIXED = "mixed"


class Mode(Enum):
    """Training mode selected at session start. Architecture Spec v1.1 S3-4.

    Deliberately just these three -- there is no Easy/Medium/Hard axis here.
    """

    PRACTICE = "practice"
    SIMULATION = "simulation"
    ASSESSMENT = "assessment"


class SessionStatus(Enum):
    """Lifecycle state of a :class:`~rewindsec.domain.session.SimulationSession`.

    ``ACTIVE`` is the only state a mutating domain operation may run from.
    ``COMPLETED`` and ``ABANDONED`` are both terminal: the architecture
    requires no automatic rewind, and a terminal session's factual history
    stays exactly what it was.
    """

    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class ActionClass(Enum):
    """Observational vs consequential, per Architecture Spec v1.1 S8."""

    OBSERVATIONAL = "observational"
    CONSEQUENTIAL = "consequential"


def coerce_enum(value, enum_cls, what):
    """Accept either an enum member or its serialised string value.

    Every domain aggregate stores enums as their ``.value`` string in captured
    state, so restoring has to accept the string form; accepting the member
    too means a caller building a fresh object never has to remember which
    form is expected where.
    """
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            pass
    raise InvalidIdentityError(
        "%s must be one of %s, got %r"
        % (what, ", ".join(member.value for member in enum_cls), value))
