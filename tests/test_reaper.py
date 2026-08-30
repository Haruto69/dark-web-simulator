"""Milestone 3, section 5: stale sandbox reaping.

The central safety property under test is negative: the reaper must never touch
anything this application did not create.
"""

import os
import time

import pytest

from sandbox import EventType, SandboxError, SandboxManager
from sandbox.backends.local import LocalBackend, MARKER_FILENAME
from sandbox.dataset import WORKSPACE_DIRNAME


@pytest.fixture
def reaper_manager(tmp_path, collector):
    return SandboxManager(LocalBackend(str(tmp_path / "roots")),
                          recorder=collector, default_sandbox_id=None)


# -- inventory ---------------------------------------------------------------

def test_created_sandboxes_carry_a_creation_timestamp(reaper_manager):
    before = time.time()
    info = reaper_manager.create("sess-aaaa")
    assert before <= info["created_at"] <= time.time()
    assert reaper_manager.status("sess-aaaa")["created_at"] == info["created_at"]


def test_absent_sandbox_reports_no_timestamp(reaper_manager):
    assert reaper_manager.status("sess-nope")["created_at"] is None


def test_metadata_lists_only_owned_sandboxes(reaper_manager, tmp_path):
    reaper_manager.create("sess-aaaa")
    root = tmp_path / "roots"

    # A directory a user dropped in by hand: valid name, seeded-looking, but
    # with no ownership marker.
    foreign = root / "sess-bbbb" / WORKSPACE_DIRNAME
    foreign.mkdir(parents=True)
    (foreign / "finance_report.txt").write_text("not ours", encoding="utf-8")

    ids = reaper_manager.list_sandboxes()
    assert ids == ["sess-aaaa"]
    assert "sess-bbbb" not in ids


def test_a_directory_with_an_invalid_name_is_ignored(reaper_manager, tmp_path):
    reaper_manager.create("sess-aaaa")
    stray = tmp_path / "roots" / "NOT A VALID ID"
    (stray / WORKSPACE_DIRNAME).mkdir(parents=True)
    assert reaper_manager.list_sandboxes() == ["sess-aaaa"]


def test_a_corrupted_marker_makes_a_sandbox_unowned(reaper_manager, tmp_path):
    reaper_manager.create("sess-aaaa")
    marker = tmp_path / "roots" / "sess-aaaa" / MARKER_FILENAME
    marker.write_text("{ not json", encoding="utf-8")
    assert reaper_manager.list_sandboxes() == []


def test_a_marker_naming_another_sandbox_is_rejected(reaper_manager, tmp_path):
    reaper_manager.create("sess-aaaa")
    marker = tmp_path / "roots" / "sess-aaaa" / MARKER_FILENAME
    marker.write_text('{"magic": "dark-web-sandbox", "sandbox_id": "sess-zzzz",'
                      ' "created_at": 1.0}', encoding="utf-8")
    assert reaper_manager.list_sandboxes() == []


# -- selection ---------------------------------------------------------------

def test_stale_selection_respects_max_age(reaper_manager):
    reaper_manager.create("sess-aaaa")
    now = time.time()
    assert reaper_manager.stale_sandboxes(3600, now=now) == []
    stale = reaper_manager.stale_sandboxes(0, now=now)
    assert [sandbox_id for sandbox_id, _ in stale] == ["sess-aaaa"]


def test_selection_is_deterministic_and_sorted(reaper_manager):
    for name in ("sess-cccc", "sess-aaaa", "sess-bbbb"):
        reaper_manager.create(name)
    now = time.time() + 10
    first = reaper_manager.stale_sandboxes(0, now=now)
    second = reaper_manager.stale_sandboxes(0, now=now)
    assert first == second
    assert [i for i, _ in first] == ["sess-aaaa", "sess-bbbb", "sess-cccc"]


def test_unknown_creation_time_is_never_selected(reaper_manager, monkeypatch):
    reaper_manager.create("sess-aaaa")
    monkeypatch.setattr(reaper_manager.backend, "sandbox_metadata",
                        lambda: [{"sandbox_id": "sess-aaaa",
                                  "created_at": None, "state": "running"}])
    assert reaper_manager.stale_sandboxes(0) == []
    assert reaper_manager.reap_stale(0) == []
    assert reaper_manager.status("sess-aaaa")["ready"] is True


@pytest.mark.parametrize("bad", [-1, "soon", None])
def test_a_bad_max_age_is_refused(reaper_manager, bad):
    with pytest.raises(SandboxError):
        reaper_manager.stale_sandboxes(bad)


# -- reaping -----------------------------------------------------------------

def test_reap_removes_only_stale_sandboxes(reaper_manager):
    old = reaper_manager.create("sess-old0")
    time.sleep(0.05)
    reaper_manager.create("sess-new0")

    cutoff = old["created_at"] + 0.02
    reaped = reaper_manager.reap_stale(0.01, now=cutoff + 0.01)

    assert [r["sandbox_id"] for r in reaped] == ["sess-old0"]
    assert reaper_manager.status("sess-old0")["ready"] is False
    assert reaper_manager.status("sess-new0")["ready"] is True


def test_dry_run_reports_without_destroying(reaper_manager):
    reaper_manager.create("sess-aaaa")
    planned = reaper_manager.reap_stale(0, dry_run=True)
    assert planned and planned[0]["destroyed"] is False
    assert reaper_manager.status("sess-aaaa")["ready"] is True


def test_reaping_emits_telemetry(reaper_manager, collector):
    reaper_manager.create("sess-aaaa")
    collector.events.clear()
    reaper_manager.reap_stale(0, session_id="instructor-1")

    types = collector.types()
    assert types == [EventType.SANDBOX_REAP_SCAN, EventType.SANDBOX_REAPED]
    reaped = collector.events[-1]
    assert reaped["target"] == "sess-aaaa"
    assert reaped["session_id"] == "instructor-1"
    assert "stale sandbox destroyed" in reaped["details"]


def test_a_scan_with_no_candidates_still_records_the_scan(reaper_manager, collector):
    collector.events.clear()
    assert reaper_manager.reap_stale(3600) == []
    assert collector.types() == [EventType.SANDBOX_REAP_SCAN]


def test_reaping_never_touches_an_unowned_directory(reaper_manager, tmp_path):
    root = tmp_path / "roots"
    root.mkdir(parents=True, exist_ok=True)
    foreign = root / "sess-bbbb" / WORKSPACE_DIRNAME
    foreign.mkdir(parents=True)
    keeper = foreign / "important.txt"
    keeper.write_text("must survive", encoding="utf-8")

    reaper_manager.create("sess-aaaa")
    reaper_manager.reap_stale(0)

    assert keeper.exists(), "an unowned directory must never be reaped"
    assert keeper.read_text(encoding="utf-8") == "must survive"
    assert not os.path.isdir(root / "sess-aaaa")


def test_reap_is_idempotent(reaper_manager):
    reaper_manager.create("sess-aaaa")
    assert len(reaper_manager.reap_stale(0)) == 1
    assert reaper_manager.reap_stale(0) == []


# -- HTTP surface ------------------------------------------------------------

def test_reap_route_requires_instructor_and_csrf(client):
    from conftest import csrf_for
    assert client.post("/sandbox/reap",
                       headers={"Accept": "application/json"}).status_code == 400
    assert client.post("/sandbox/reap",
                       headers={"Accept": "application/json",
                                "X-CSRF-Token": csrf_for(client)}).status_code == 403


def test_reap_route_refuses_a_dangerously_small_max_age(instructor):
    from conftest import csrf_for
    response = instructor.post("/sandbox/reap",
                               headers={"Accept": "application/json",
                                        "X-CSRF-Token": csrf_for(instructor)},
                               data={"max_age": "0"})
    assert response.status_code == 400
    assert "at least" in response.get_json()["error"]


def test_reap_route_refuses_a_non_numeric_max_age(instructor):
    from conftest import csrf_for
    response = instructor.post("/sandbox/reap",
                               headers={"Accept": "application/json",
                                        "X-CSRF-Token": csrf_for(instructor)},
                               data={"max_age": "soon"})
    assert response.status_code == 400


def test_reap_route_leaves_a_fresh_sandbox_alone(instructor):
    from conftest import csrf_for
    instructor.post("/sandbox/create",
                    headers={"Accept": "application/json",
                             "X-CSRF-Token": csrf_for(instructor)})
    response = instructor.post("/sandbox/reap",
                               headers={"Accept": "application/json",
                                        "X-CSRF-Token": csrf_for(instructor)},
                               data={"max_age": "3600"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["count"] == 0
    assert instructor.get("/sandbox/status").get_json()["sandbox"]["ready"] is True


def test_sessions_listing_exposes_age(instructor):
    from conftest import csrf_for
    instructor.post("/sandbox/create",
                    headers={"Accept": "application/json",
                             "X-CSRF-Token": csrf_for(instructor)})
    body = instructor.get("/sandbox/sessions").get_json()
    assert body["count"] >= 1
    for row in body["sandboxes"]:
        assert row["created_at"] is not None
        assert row["age_seconds"] >= 0
