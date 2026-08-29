"""Seed the fixed synthetic dataset into the container workspace.

Runs once at container start. The dataset is generated from ``sandbox/dataset.py``
so every freshly created container has a byte-identical baseline.
"""

import json
import sys

from ..dataset import seed_workspace
from ..paths import SANDBOX_WORKSPACE


def main():
    written = seed_workspace(SANDBOX_WORKSPACE)
    json.dump({"workspace": SANDBOX_WORKSPACE, "files": written}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
