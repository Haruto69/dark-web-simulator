"""In-container entry point for the demo file-impact emulator.

SIMULATION CODE. Runs only inside the disposable sandbox container, prints a
JSON result array on stdout, and takes no filesystem root from its caller --
the workspace is the fixed constant ``/workspace``.

Usage (invoked by the host via ``docker exec``, never by a user):
    python -m sandbox.tools.impact_tool state
    python -m sandbox.tools.impact_tool impact -- finance_report.txt ...
"""

import argparse
import json
import sys

from .. import impact_core
from ..paths import SANDBOX_WORKSPACE


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sandbox file-impact emulator (simulation)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("state")
    impact = sub.add_parser("impact")
    impact.add_argument("targets", nargs="*")
    restore = sub.add_parser("restore")
    restore.add_argument("targets", nargs="*")

    args = parser.parse_args(argv)

    if args.command == "state":
        payload = impact_core.workspace_state(SANDBOX_WORKSPACE)
    elif args.command == "impact":
        payload = impact_core.run_file_impact(SANDBOX_WORKSPACE, args.targets)
    else:
        payload = [impact_core.restore_one(SANDBOX_WORKSPACE, t)
                   for t in args.targets]

    json.dump(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
