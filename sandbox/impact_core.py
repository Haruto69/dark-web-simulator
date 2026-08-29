"""Demo file-impact emulator -- SIMULATION CODE, NOT MALWARE.

What this does: renames a file from the fixed synthetic dataset so that
``finance_report.txt`` becomes ``finance_report.txt.demo_locked``. That is the
entire "impact". File *contents are never altered*, so the operation is
trivially and losslessly reversible by renaming back.

What this deliberately does NOT do, and must never be extended to do:
  * no cryptography of any kind (no keys, no ciphers, no ransom keying)
  * no directory walking or recursion -- only an explicit allow-list of names
  * no user-supplied filesystem roots
  * no propagation, persistence, privilege escalation, or evasion
  * no network access of any kind

It is run either inside a disposable container or against a
project-controlled scratch directory. See ``sandbox/paths.py`` for the policy.
"""

import hashlib
import os

from .dataset import BASELINE_FILENAMES
from .errors import UnsafePathError
from .paths import IMPACT_SUFFIX, normalise_target, resolve_in_directory


def _digest(path):
    """Short content digest, used only for reset/reproducibility checks."""
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()[:16]


def impact_one(workspace_root, target):
    """Apply the demo impact to a single validated synthetic file.

    Returns a result dict. Raises :class:`UnsafePathError` if the target is not
    an allow-listed synthetic filename.
    """
    name = normalise_target(target)
    source = resolve_in_directory(workspace_root, name)
    destination = resolve_in_directory(workspace_root, name + IMPACT_SUFFIX)

    if not os.path.isfile(source):
        if os.path.isfile(destination):
            return {
                "target": name,
                "status": "already_impacted",
                "new_name": name + IMPACT_SUFFIX,
                "detail": "already renamed to %s" % (name + IMPACT_SUFFIX),
            }
        return {
            "target": name,
            "status": "missing",
            "new_name": None,
            "detail": "baseline file not present in workspace",
        }

    digest = _digest(source)
    os.replace(source, destination)
    return {
        "target": name,
        "status": "impacted",
        "new_name": name + IMPACT_SUFFIX,
        "content_sha256_16": digest,
        "detail": "renamed to %s (contents unchanged)" % (name + IMPACT_SUFFIX),
    }


def restore_one(workspace_root, target):
    """Undo the demo impact for a single synthetic file."""
    name = normalise_target(target)
    impacted = resolve_in_directory(workspace_root, name + IMPACT_SUFFIX)
    original = resolve_in_directory(workspace_root, name)

    if not os.path.isfile(impacted):
        return {"target": name, "status": "not_impacted", "detail": "nothing to restore"}

    os.replace(impacted, original)
    return {
        "target": name,
        "status": "restored",
        "detail": "renamed back to %s" % name,
    }


def run_file_impact(workspace_root, targets=None):
    """Apply the demo impact across ``targets`` (defaults to the whole dataset).

    Unknown or unsafe targets are reported as ``rejected`` results rather than
    aborting the run, so the instructor can demonstrate the guard rail.
    """
    selected = list(targets) if targets else list(BASELINE_FILENAMES)
    results = []
    for target in selected:
        try:
            results.append(impact_one(workspace_root, target))
        except UnsafePathError as exc:
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
