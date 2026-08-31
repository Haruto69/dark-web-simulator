"""Exceptions raised by the RewindSec training runtime.

Deliberately separate from ``sandbox.errors``: this subsystem is
framework-independent and must not import Flask, SQLAlchemy or the sandbox
package. ``sandbox.errors.BaselineMismatchError`` is a *different* concept (a
synthetic file no longer holding baseline content); the rewind-baseline failure
in this package is :class:`BaselineVerificationError`.
"""


class TrainingError(Exception):
    """Base class for every error raised by the training runtime."""


class ScenarioDefinitionError(TrainingError):
    """A scenario, decision point, choice or consequence is malformed."""


class UnknownActionError(TrainingError):
    """A consequence action key is not offered by the bound adapter.

    Raised *before* anything is applied, so an unresolvable action can never
    reach an environment.
    """


class ConfidenceValueError(TrainingError):
    """A confidence reading was not an integer in the closed range 0..100."""


class SnapshotError(TrainingError):
    """A state mapping could not be canonicalised into a snapshot."""


class BaselineVerificationError(TrainingError):
    """The rewound environment did not match the recorded baseline.

    The research invariant of RewindSec: the counterfactual branch runs only
    from a baseline whose canonical fingerprint equals the one captured before
    the factual branch. When it does not, the runtime fails closed and the
    alternative consequence is never applied.
    """

    def __init__(self, expected_digest, observed_digest, message=None):
        self.expected_digest = expected_digest
        self.observed_digest = observed_digest
        super().__init__(message or (
            "rewound baseline does not match the captured baseline "
            "(expected {0}, observed {1}); the counterfactual branch was not "
            "executed".format(expected_digest, observed_digest)))


class AdapterProtocolError(TrainingError):
    """A consequence adapter violated the adapter contract."""
