"""Fixed synthetic dataset for the sandbox workspace.

SIMULATION DATA ONLY. Every value here is invented for teaching purposes.
It contains no real personal, financial or client information.

This module is the single source of truth for the baseline: it is used by the
Docker image build (to bake /opt/simulator/baseline) and by the local backend
(to seed a project-controlled workspace directory).
"""

import hashlib
import os

from .errors import SandboxError

WORKSPACE_DIRNAME = "workspace"

# Ordered so that seeding is deterministic and reproducible across runs.
SYNTHETIC_FILES = {
    "employee_records.csv": (
        "employee_id,name,department,role\n"
        "E-1001,Synthetic Person A,Operations,Analyst\n"
        "E-1002,Synthetic Person B,Finance,Controller\n"
        "E-1003,Synthetic Person C,Engineering,Developer\n"
        "E-1004,Synthetic Person D,Support,Technician\n"
        "# SIMULATED DATA - not real employees\n"
    ),
    "finance_report.txt": (
        "QUARTERLY FINANCE REPORT (SIMULATED)\n"
        "===================================\n"
        "Revenue.......... 1,240,000 (fictional)\n"
        "Operating cost...   860,000 (fictional)\n"
        "Net.............    380,000 (fictional)\n"
        "\n"
        "This document is synthetic teaching material.\n"
    ),
    "project_notes.txt": (
        "PROJECT NOTES (SIMULATED)\n"
        "-------------------------\n"
        "- Milestone 1: sandbox foundation\n"
        "- Milestone 2: credential-reuse scenario\n"
        "- All content in this workspace is fabricated for a lab exercise.\n"
    ),
    "client_database.csv": (
        "client_id,client_name,region,status\n"
        "C-2001,Example Client One,North,active\n"
        "C-2002,Example Client Two,South,active\n"
        "C-2003,Example Client Three,East,dormant\n"
        "# SIMULATED DATA - not real clients\n"
    ),
    "thesis_draft.txt": (
        "DRAFT: Container-Isolated Multi-Stage Cybersecurity Simulation\n"
        "==============================================================\n"
        "Abstract (placeholder). This file exists so that learners can observe\n"
        "a file-impact event against a document they would consider valuable.\n"
        "It is synthetic placeholder text.\n"
    ),
}

BASELINE_FILENAMES = tuple(SYNTHETIC_FILES.keys())


def baseline_bytes(filename):
    """Exact on-disk bytes of one baseline file."""
    return SYNTHETIC_FILES[filename].encode("utf-8")


#: sha256 of every baseline file, computed from this module alone. Both sides of
#: the Docker boundary derive it independently, so a seeded workspace can be
#: proven byte-identical to the baseline without shipping content over the wire.
BASELINE_DIGESTS = {
    name: hashlib.sha256(baseline_bytes(name)).hexdigest()
    for name in BASELINE_FILENAMES
}


def workspace_digests(workspace_path):
    """sha256 of each baseline filename present in ``workspace_path``.

    A missing or unreadable file maps to ``None`` rather than raising, so the
    caller can report exactly which part of the baseline is absent.
    """
    digests = {}
    for filename in BASELINE_FILENAMES:
        target = os.path.join(workspace_path, filename)
        try:
            with open(target, "rb") as handle:
                digests[filename] = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            digests[filename] = None
    return digests


def verify_workspace(workspace_path):
    """Raise :class:`SandboxError` unless the workspace holds the exact baseline."""
    digests = workspace_digests(workspace_path)
    mismatched = sorted(name for name in BASELINE_FILENAMES
                        if digests[name] != BASELINE_DIGESTS[name])
    if mismatched:
        raise SandboxError(
            "workspace baseline verification failed for: %s" % ", ".join(mismatched))
    return digests


def seed_workspace(workspace_path):
    """Write the fixed synthetic dataset into ``workspace_path``.

    Every file is written, flushed and fsync'd, then read back and verified
    against :data:`BASELINE_DIGESTS` before this function returns. Seeding is
    therefore synchronous and self-checking: a caller that sees this return
    normally knows the workspace holds the complete, byte-identical baseline,
    never a zero-byte or partially written file.

    Returns the list of filenames written, in deterministic order.
    Raises :class:`SandboxError` if verification fails.
    """
    os.makedirs(workspace_path, exist_ok=True)
    for filename in BASELINE_FILENAMES:
        target = os.path.join(workspace_path, filename)
        with open(target, "wb") as handle:
            handle.write(baseline_bytes(filename))
            handle.flush()
            os.fsync(handle.fileno())
    verify_workspace(workspace_path)
    return list(BASELINE_FILENAMES)
