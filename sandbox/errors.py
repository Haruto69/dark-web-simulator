"""Exception hierarchy for the conference sandbox subsystem."""


class SandboxError(Exception):
    """Base class for all sandbox failures."""


class SandboxNotFoundError(SandboxError):
    """No sandbox exists for the requested id."""


class SandboxNotReadyError(SandboxError):
    """A scenario was requested but no usable sandbox is running."""


class UnsafePathError(SandboxError):
    """A requested target escaped or violated the workspace policy."""


class BackendUnavailableError(SandboxError):
    """The selected backend cannot operate (e.g. Docker not installed)."""


class SandboxCommandError(SandboxError):
    """A backend command failed or timed out."""
