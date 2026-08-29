import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from sandbox import EventCollector, SandboxManager
from sandbox.backends.local import LocalBackend


@pytest.fixture
def collector():
    return EventCollector()


@pytest.fixture
def manager(tmp_path, collector):
    """A manager on the local backend, rooted in pytest's temp directory.

    Nothing outside tmp_path is ever touched, so tests cannot damage the
    developer machine.
    """
    return SandboxManager(LocalBackend(str(tmp_path / "sandboxes")),
                          recorder=collector)
