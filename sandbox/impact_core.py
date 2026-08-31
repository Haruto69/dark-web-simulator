"""Demo file-impact emulator -- SIMULATION CODE, NOT MALWARE.

What this does: for each file of the fixed synthetic dataset, replaces its
contents with a short fixed placeholder record and renames it, so that
``finance_report.txt`` becomes ``finance_report.txt.demo_locked`` holding::

    DWS-DEMO-STATE
    original_filename=finance_report.txt
    original_sha256=<the known baseline digest>
    simulation_only=true

That is the entire "impact": the synthetic plaintext is gone from the
workspace, replaced by a constant that depends on nothing but the filename.
There is no reverse operation, and none is needed -- ``reset`` destroys and
recreates the sandbox and re-seeds the verified baseline.

TWO GATES, BOTH MANDATORY
-------------------------
A file is transformed only when **both** hold:

  1. its name is exactly one of :data:`BASELINE_FILENAMES`, and
  2. its current sha256 is exactly the matching :data:`BASELINE_DIGESTS` entry.

The second gate is what makes this code non-generalisable. Even inside the
sandbox, and even under a name from the allow-list, a file whose bytes are not
the known synthetic content is refused untouched. There is no input that turns
this into a tool for damaging real data: the only bytes it will ever discard
are bytes it can prove the simulator itself wrote.

What this deliberately does NOT do, and must never be extended to do:
  * no cryptography of any kind (no keys, no ciphers, no ransom keying)
  * no decryption, recovery or unlock path -- reset is the only restoration
  * no directory walking, recursion, globbing or enumeration to find targets
  * no user-supplied filesystem roots, absolute paths or nested paths
  * no symlink following
  * no propagation, persistence, privilege escalation, or evasion
  * no network access, host mounts or Docker socket access of any kind

It is run either inside a disposable container or against a
project-controlled scratch directory. See ``sandbox/paths.py`` for the policy.
"""

import hashlib
import os

from .dataset import BASELINE_DIGESTS, BASELINE_FILENAMES
from .errors import BaselineMismatchError, SandboxError, UnsafePathError
from .paths import IMPACT_SUFFIX, normalise_target, resolve_in_directory

#: First line of the placeholder record written over an impacted file.
DEMO_STATE_MAGIC = "DWS-DEMO-STATE"

#: Suffix of the temporary file used to stage a placeholder before it atomically
#: replaces the original. Never left behind, on success or on failure.
STAGING_SUFFIX = ".demo_staging"

#: Refusal reason for gate two. Describes policy, never content.
REJECT_NOT_BASELINE_CONTENT = (
    "content does not match the known synthetic baseline; refused")


def demo_state_text(filename):
    """The exact placeholder record written over ``filename``.

    Depends only on the filename, and only for names in the fixed dataset, so
    the impacted representation is as reproducible as the baseline itself. It
    carries no byte of the original file -- only its name and the *already
    public* baseline digest declared in ``sandbox/dataset.py``.
    """
    if filename not in BASELINE_DIGESTS:
        raise UnsafePathError("%r is not part of the fixed synthetic dataset"
                              % (filename,))
    return ("%s\n"
            "original_filename=%s\n"
            "original_sha256=%s\n"
            "simulation_only=true\n"
            % (DEMO_STATE_MAGIC, filename, BASELINE_DIGESTS[filename]))


def demo_state_bytes(filename):
    return demo_state_text(filename).encode("utf-8")


def is_demo_state(data):
    """True if ``data`` is the placeholder record for some baseline filename."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
    return any(data == demo_state_text(name) for name in BASELINE_FILENAMES)


def _digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _read_exact(path):
    """Read a regular file, refusing to follow a symlink.

    ``resolve_in_directory`` already refuses a link resolving outside the
    workspace; this refuses the link itself, so a link to a *sibling* synthetic
    file cannot make one target stand in for another.
    """
    if os.path.islink(path):
        raise UnsafePathError("symlinks are never followed: %r"
                              % os.path.basename(path))
    with open(path, "rb") as handle:
        return handle.read()


def _write_demo_state(workspace_root, name, destination):
    """Stage the placeholder, fsync it, verify it, then atomically install it.

    Nothing is removed until a complete, verified placeholder is already on
    disk under its final name, so an interrupted or failed call can never leave
    a truncated, empty or half-written file where a result is expected.
    """
    staging = resolve_in_directory(workspace_root, name + STAGING_SUFFIX)
    payload = demo_state_bytes(name)
    try:
        with open(staging, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if _read_exact(staging) != payload:
            raise SandboxError(
                "staged demo state for %s failed verification" % name)
        os.replace(staging, destination)
    except OSError as exc:
        raise SandboxError("could not write demo state for %s: %s"
                           % (name, exc.strerror)) from exc
    finally:
        if os.path.exists(staging):
            try:
                os.remove(staging)
            except OSError:
                pass


def impact_one(workspace_root, target):
    """Apply the demo impact to a single validated synthetic file.

    Returns a result dict. Raises :class:`UnsafePathError` if the target is not
    an allow-listed synthetic filename, or :class:`BaselineMismatchError` if it
    is one but no longer holds the known synthetic content.
    """
    name = normalise_target(target)
    source = resolve_in_directory(workspace_root, name)
    destination = resolve_in_directory(workspace_root, name + IMPACT_SUFFIX)

    if os.path.islink(source):
        raise UnsafePathError("symlinks are never followed: %r" % name)

    if not os.path.isfile(source):
        if os.path.isfile(destination):
            return {
                "target": name,
                "status": "already_impacted",
                "new_name": name + IMPACT_SUFFIX,
                "detail": "already replaced by demo state as %s"
                          % (name + IMPACT_SUFFIX),
            }
        return {
            "target": name,
            "status": "missing",
            "new_name": None,
            "detail": "baseline file not present in workspace",
        }

    # Gate two: the bytes on disk must be the known synthetic baseline. An
    # edited, replaced or foreign file is refused and left exactly as it is.
    original = _read_exact(source)
    digest = _digest_bytes(original)
    if digest != BASELINE_DIGESTS[name]:
        raise BaselineMismatchError("%s: %s" % (name, REJECT_NOT_BASELINE_CONTENT))

    _write_demo_state(workspace_root, name, destination)
    try:
        os.remove(source)
    except OSError as exc:
        raise SandboxError("could not remove %s after impact: %s"
                           % (name, exc.strerror)) from exc

    return {
        "target": name,
        "status": "impacted",
        "new_name": name + IMPACT_SUFFIX,
        "content_sha256_16": digest[:16],
        "detail": "contents replaced with fixed demo state and renamed to %s"
                  % (name + IMPACT_SUFFIX),
    }


def run_file_impact(workspace_root, targets=None):
    """Apply the demo impact across ``targets`` (defaults to the whole dataset).

    Unknown or unsafe targets, and allow-listed names whose content is not the
    known synthetic baseline, are reported as ``rejected`` results rather than
    aborting the run, so the instructor can demonstrate the guard rail. A real
    write failure is *not* swallowed: it propagates as a :class:`SandboxError`
    so the scenario reports failure rather than a false success.
    """
    selected = list(targets) if targets else list(BASELINE_FILENAMES)
    results = []
    for target in selected:
        try:
            results.append(impact_one(workspace_root, target))
        except (UnsafePathError, BaselineMismatchError) as exc:
            results.append({
                "target": str(target)[:120],
                "status": "rejected",
                "detail": str(exc),
            })
    return results


def workspace_state(workspace_root):
    """Report the current state of each baseline filename.

    Only the fixed dataset names are inspected; the directory is never walked
    for arbitrary content.
    """
    state = []
    for name in BASELINE_FILENAMES:
        original = os.path.join(workspace_root, name)
        impacted = os.path.join(workspace_root, name + IMPACT_SUFFIX)
        if os.path.isfile(impacted):
            status = "impacted"
            present_as = name + IMPACT_SUFFIX
        elif os.path.isfile(original):
            status = "baseline"
            present_as = name
        else:
            status = "missing"
            present_as = None
        state.append({"name": name, "status": status, "present_as": present_as})
    return state
