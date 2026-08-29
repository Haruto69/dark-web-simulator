"""A. File-impact path validation."""

import pytest

from sandbox.dataset import BASELINE_FILENAMES
from sandbox.errors import UnsafePathError
from sandbox.paths import SANDBOX_WORKSPACE, normalise_target

REJECTED = [
    "../etc/passwd",
    "../../workspace/finance_report.txt",
    "/workspace/../etc/passwd",
    "/etc/passwd",
    "/workspace/sub/finance_report.txt",
    "sub/finance_report.txt",
    "C:\\Windows\\System32\\config\\SAM",
    "..\\finance_report.txt",
    "finance_report.txt\x00.png",
    "",
    "   ",
    None,
    123,
    "unknown_file.txt",
    "finance_report.txt.demo_locked",  # not a baseline name
]


@pytest.mark.parametrize("bad", REJECTED)
def test_unsafe_targets_are_rejected(bad):
    with pytest.raises(UnsafePathError):
        normalise_target(bad)


@pytest.mark.parametrize("name", BASELINE_FILENAMES)
def test_bare_and_absolute_workspace_names_are_accepted(name):
    assert normalise_target(name) == name
    assert normalise_target("%s/%s" % (SANDBOX_WORKSPACE, name)) == name


def test_allow_list_is_the_fixed_dataset():
    # There is no way to widen the allow-list from request data.
    with pytest.raises(UnsafePathError):
        normalise_target("finance_report.txt", allowed_names=("other.txt",))
