"""Cross-process determinism under varying ``PYTHONHASHSEED``.

A session's ids and random draws are derived by SHA-256, never by ``hash()``
or dict/set iteration order, precisely so they do not depend on the per-
process hash salt. This test proves it by running the same scenario in two
subprocesses with different ``PYTHONHASHSEED`` values and asserting the
captured state is byte-for-byte identical. Kept to a handful of operations so
it stays fast.
"""

import ast
import subprocess
import sys

import pytest

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent

_SCRIPT = """
import json
import sys
sys.path.insert(0, %r)
from rewindsec.domain.enums import ActionClass, Focus, Mode
from rewindsec.domain.session import SimulationSession

session = SimulationSession.create("s1", "learner-1", Focus.RANSOMWARE,
                                   Mode.ASSESSMENT, root_seed=555)
ev = session.record_immediate_event("file.encrypted_marker", payload={"n": 1})
session.schedule_event("ransom.note_displayed", delay_ms=200)
session.advance_time(200)
act = session.record_action("inspect.open_file", ActionClass.OBSERVATIONAL,
                            target=ev.event_id)
session.introduce_fact("backup_location", "org", "s3://backups", "runbook",
                       introduced_by_event_id=ev.event_id)
session.observe_fact("backup_location", act.action_id)
draw = session.rng.stream("timing").random()
state = session.capture_state()
print(json.dumps({"state": state, "draw": draw}, sort_keys=True))
""" % str(REPO_ROOT)


def _run_with_hashseed(hashseed):
    import os
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = str(hashseed)
    completed = subprocess.run([sys.executable, "-c", _SCRIPT],
                               capture_output=True, text=True,
                               cwd=str(REPO_ROOT), env=env, timeout=60)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


@pytest.mark.parametrize("hashseed_pair", [(0, 1), (1, 42), (0, 999)])
def test_identical_scenario_produces_identical_state_under_different_hashseeds(
        hashseed_pair):
    seed_a, seed_b = hashseed_pair
    output_a = _run_with_hashseed(seed_a)
    output_b = _run_with_hashseed(seed_b)
    assert output_a == output_b
