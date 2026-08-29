"""Backend interface for disposable sandbox environments."""

import re

from ..errors import SandboxError

SANDBOX_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,30}$")


def validate_sandbox_id(sandbox_id):
    """Reject anything that could become a shell/argument injection vector."""
    if not isinstance(sandbox_id, str) or not SANDBOX_ID_RE.match(sandbox_id):
        raise SandboxError("invalid sandbox id: %r" % (sandbox_id,))
    return sandbox_id


class SandboxBackend:
    """Abstract disposable-sandbox backend.

    Implementations own *how* a workspace is isolated; they never decide *what*
    the scenario does. Scenario logic lives in ``sandbox/scenarios``.
    """

    name = "abstract"
    #: Human-readable statement of the isolation this backend actually provides.
    isolation_summary = ""

    def is_available(self):
        raise NotImplementedError

    def create(self, sandbox_id):
        raise NotImplementedError

    def status(self, sandbox_id):
        raise NotImplementedError

    def reset(self, sandbox_id):
        raise NotImplementedError

    def destroy(self, sandbox_id):
        raise NotImplementedError

    def run_impact(self, sandbox_id, targets):
        raise NotImplementedError

    def workspace_state(self, sandbox_id):
        raise NotImplementedError
