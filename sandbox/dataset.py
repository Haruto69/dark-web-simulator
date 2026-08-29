"""Fixed synthetic dataset for the sandbox workspace.

SIMULATION DATA ONLY. Every value here is invented for teaching purposes.
It contains no real personal, financial or client information.

This module is the single source of truth for the baseline: it is used by the
Docker image build (to bake /opt/simulator/baseline) and by the local backend
(to seed a project-controlled workspace directory).
"""

import os

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


def seed_workspace(workspace_path):
    """Write the fixed synthetic dataset into ``workspace_path``.

    Returns the list of filenames written, in deterministic order.
    """
    os.makedirs(workspace_path, exist_ok=True)
    for filename in BASELINE_FILENAMES:
        target = os.path.join(workspace_path, filename)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(SYNTHETIC_FILES[filename])
    return list(BASELINE_FILENAMES)
