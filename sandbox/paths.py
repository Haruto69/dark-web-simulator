"""Path policy for the file-impact simulation.

The policy is intentionally far stricter than "stay inside the workspace":
the simulator only ever acts on a *fixed allow-list of synthetic filenames*.
There is no user-supplied filesystem root, no recursion, and no directory
traversal surface, because directories are never walked at all.
"""

import os
import posixpath

from .dataset import BASELINE_FILENAMES
from .errors import UnsafePathError

# Canonical workspace path *inside* the sandbox. Not configurable by request
# data; it is a constant of the simulation environment.
SANDBOX_WORKSPACE = "/workspace"

# Suffix appended by the demo file-impact emulator.
IMPACT_SUFFIX = ".demo_locked"


def normalise_target(target, allowed_names=BASELINE_FILENAMES):
    """Validate ``target`` and return the bare synthetic filename.

    Accepts either ``finance_report.txt`` or ``/workspace/finance_report.txt``.
    Raises :class:`UnsafePathError` for anything else -- traversal sequences,
    absolute paths outside the workspace, nested directories, NUL bytes, or
    names that are not part of the fixed synthetic dataset.
    """
    if not isinstance(target, str) or not target.strip():
        raise UnsafePathError("target must be a non-empty string")

    candidate = target.strip()

    if "\x00" in candidate:
        raise UnsafePathError("target contains a NUL byte")

    # Reject Windows-style separators and drive letters outright; the sandbox
    # workspace is POSIX and host paths must never be expressible here.
    if "\\" in candidate or ":" in candidate:
        raise UnsafePathError("target must not contain '\\' or ':': %r" % target)

    if candidate.startswith(SANDBOX_WORKSPACE + "/"):
        candidate = candidate[len(SANDBOX_WORKSPACE) + 1:]
    elif candidate.startswith("/"):
        raise UnsafePathError("absolute paths outside %s are rejected: %r"
                              % (SANDBOX_WORKSPACE, target))

    if ".." in candidate.split("/"):
        raise UnsafePathError("path traversal is rejected: %r" % target)

    if "/" in candidate:
        raise UnsafePathError("nested paths are rejected: %r" % target)

    # Defence in depth: even after the checks above, confirm the joined path
    # normalises back into the workspace.
    resolved = posixpath.normpath(posixpath.join(SANDBOX_WORKSPACE, candidate))
    if posixpath.dirname(resolved) != SANDBOX_WORKSPACE:
        raise UnsafePathError("resolved path escapes the workspace: %r" % target)

    if candidate not in allowed_names:
        raise UnsafePathError(
            "%r is not part of the fixed synthetic dataset" % target)

    return candidate


def sandbox_path(filename):
    """Absolute POSIX path of a validated filename inside the sandbox."""
    return posixpath.join(SANDBOX_WORKSPACE, filename)


def resolve_in_directory(root, filename):
    """Resolve ``filename`` under host directory ``root``, refusing escapes.

    Used by the local backend, which operates on a real host directory that the
    project owns. ``filename`` must already have passed :func:`normalise_target`.
    """
    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, filename))
    if full != root_real and not full.startswith(root_real + os.sep):
        raise UnsafePathError("resolved path escapes the workspace root")
    return full
