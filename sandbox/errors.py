"""Exception hierarchy for the conference sandbox subsystem."""


class SandboxError(Exception):
    """Base class for all sandbox failures."""


class SandboxNotFoundError(SandboxError):
    """No sandbox exists for the requested id."""


class SandboxNotReadyError(SandboxError):
    """A scenario was requested but no usable sandbox is running."""


class UnsafePathError(SandboxError):
    """A requested target escaped or violated the workspace policy."""


class BaselineMismatchError(SandboxError):
    """A target is an allow-listed name but no longer holds baseline content.

    The second of the two gates in ``sandbox/impact_core.py``. Raised *instead*
    of touching the file, so the emulator can only ever discard bytes it can
    prove the simulator itself wrote.
    """


class BackendUnavailableError(SandboxError):
    """The selected backend cannot operate (e.g. Docker not installed)."""


class SandboxCommandError(SandboxError):
    """A backend command failed or timed out."""


class ScenarioStateError(SandboxError):
    """A scenario stage was requested out of order or without consent."""
