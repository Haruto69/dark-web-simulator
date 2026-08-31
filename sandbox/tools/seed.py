"""Seed the fixed synthetic dataset into the container workspace.

Invoked synchronously by the host through ``docker exec`` as the last step of
:meth:`DockerBackend.create`, never from the image ``CMD``. Seeding must be
complete *before* create() returns, so it cannot run asynchronously alongside
container start-up.

The dataset is generated from ``sandbox/dataset.py``, verified by read-back,
and its digests are reported on stdout so the host can independently confirm
that the workspace is byte-identical to the baseline.
"""

import json
import sys

from ..dataset import seed_workspace, workspace_digests
from ..errors import SandboxError
from ..paths import SANDBOX_WORKSPACE


def main():
    try:
        written = seed_workspace(SANDBOX_WORKSPACE)
    except (SandboxError, OSError) as exc:
        sys.stderr.write("seed failed: %s\n" % exc)
        return 1
    json.dump({"workspace": SANDBOX_WORKSPACE, "files": written,
               "digests": workspace_digests(SANDBOX_WORKSPACE)}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
