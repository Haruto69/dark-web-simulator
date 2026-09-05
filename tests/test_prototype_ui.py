"""Guardrails for the RewindSec 2.0 UI prototype.

These tests do not try to prove that the prototype looks good -- that is what
the manual product gate is for, and a unit test asserting visual quality would
be theatre. What they hold are the properties a reviewer cannot check by
looking, and that would be expensive to discover late:

* every screen renders;
* every destination in the fixture content is inert;
* the organisation and the people in it are fictional;
* no hostile event announces itself on the learner-visible surface;
* Assessment mode suppresses in-attempt coaching and the safer-alternative
  screen;
* the prototype cannot change server state, because it has no way to;
* the mock layer stays isolated from v1 and from the deterministic core;
* the v1 surfaces still work.
"""

import ast
import io
import json
import os
import pathlib
import re

import pytest

from rewindsec.prototype import fixtures
from rewindsec.prototype import scenario_fixtures as scen
from rewindsec.prototype import trainer_fixtures as trainer
from rewindsec.prototype import world_fixtures as world

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTOTYPE_PKG = REPO_ROOT / "rewindsec" / "prototype"
PROTOTYPE_TEMPLATES = REPO_ROOT / "templates" / "prototype"
PROTOTYPE_STATIC = REPO_ROOT / "static" / "prototype"


# ===========================================================================
# Routes
# ===========================================================================

LEARNER_ROUTES = [
    "/prototype/",
    "/prototype/start",
    "/prototype/workstation",
    "/prototype/results",
]

TRAINER_ROUTES = [
    "/prototype/trainer",
    "/prototype/trainer/students",
    "/prototype/trainer/students/stu-aarti-venkatesh",
    "/prototype/trainer/groups",
    "/prototype/trainer/groups/grp-ops-a",
    "/prototype/trainer/assessments",
]


@pytest.mark.parametrize("path", LEARNER_ROUTES)
def test_learner_prototype_routes_render(client, path):
    response = client.get(path)
    assert response.status_code == 200, path
    assert b"prototype/base.css" in response.data, path


@pytest.mark.parametrize("path", TRAINER_ROUTES)
def test_trainer_prototype_routes_render(client, path):
    response = client.get(path)
    assert response.status_code == 200, path
    assert b"prototype/trainer.css" in response.data, path


def test_workstation_renders_a_shell_the_client_fills_from_the_server(client):
    """The workstation must not ship the world inside the HTML.

    If the fixture content were inlined into the template, the front end would
    be reading its truth from the page rather than from the server, and the
    eventual backend wiring would be a rewrite rather than a swap.
    """
    body = client.get("/prototype/workstation").data.decode()
    assert "pw-workarea" in body
    assert "prototype/workstation.js" in body
    # No message content of any kind is rendered server-side into the shell.
    assert "Salary structure revision" not in body
    assert "northbridge-payroll.example" not in body


def test_unknown_student_and_group_404(client):
    assert client.get("/prototype/trainer/students/nobody").status_code == 404
    assert client.get("/prototype/trainer/groups/nothing").status_code == 404


def test_world_endpoint_returns_the_whole_fixture_document(client):
    payload = client.get("/prototype/api/world").get_json()
    for key in ("organization", "learner", "mail", "files", "directory",
                "conversations", "mfa_prompts", "browser", "chains",
                "safer_alternatives", "score_dimensions", "modes",
                "timelines", "decisions", "safety"):
        assert key in payload, key
    assert payload["prototype"]["kind"].startswith("fixture-backed")


def test_prototype_exposes_no_state_changing_method(flask_app):
    """A GET-only surface, so there is nothing to persist and nothing to forge.

    The application's CSRF gate only covers unsafe methods; a prototype route
    that accepted one would need to justify itself, and none does.
    """
    rules = [r for r in flask_app.url_map.iter_rules()
             if r.rule.startswith("/prototype")]
    assert rules
    for rule in rules:
        unsafe = rule.methods & {"POST", "PUT", "PATCH", "DELETE"}
        assert unsafe == set(), "%s allows %s" % (rule.rule, sorted(unsafe))


# ===========================================================================
# Assessment assignment provenance (architecture §27)
# ===========================================================================

PROVENANCE = "/prototype/api/assignment-provenance"


def test_duplicate_assignment_reports_its_original_source(client):
    """Devika receives the Q3 check through Operations — Cohort A."""
    response = client.get(
        PROVENANCE + "?assessment_id=as-q3-judgement"
        "&student_id=stu-devika-raghavan")
    body = response.get_json()
    assert response.status_code == 200
    assert body["duplicate"] is True
    assert len(body["existing_sources"]) == 1
    source = body["existing_sources"][0]
    assert source["source"] == "group"
    assert source["group_name"] == "Operations — Cohort A"
    assert source["created"]
    assert source["created_by"]


def test_a_student_without_the_assessment_is_not_a_duplicate(client):
    body = client.get(
        PROVENANCE + "?assessment_id=as-attachment-handling"
        "&student_id=stu-aarti-venkatesh").get_json()
    assert body["duplicate"] is False
    assert body["existing_sources"] == []


def test_provenance_lookup_validates_its_arguments(client):
    assert client.get(PROVENANCE).status_code == 400
    assert client.get(
        PROVENANCE + "?assessment_id=nope&student_id=stu-aarti-venkatesh"
    ).status_code == 404
    assert client.get(
        PROVENANCE + "?assessment_id=as-q3-judgement&student_id=nobody"
    ).status_code == 404


def test_group_and_direct_assignments_stay_separate_on_a_record():
    """Aarti holds "Payment authorisation" twice, by two different routes."""
    detail = fixtures.student_detail("stu-aarti-venkatesh")
    payments = [a for a in detail["assignments"]
                if a["assessment"]["id"] == "as-payments"]
    assert len(payments) == 2
    assert {a["source"] for a in payments} == {"group", "direct"}
    # Each row says where it came from, rather than being merged into one.
    assert len({a["origin_label"] for a in payments}) == 2


def test_an_assessment_is_defined_by_scored_interactions_not_event_count():
    for assessment in trainer.ASSESSMENTS:
        assert isinstance(assessment["required_interactions"], int)
        assert assessment["required_interactions"] >= 1
        assert "event_count" not in assessment
        assert "events" not in assessment


# ===========================================================================
# Safety: inert destinations, synthetic identities, nothing executable
# ===========================================================================

def test_every_referenced_destination_is_non_resolving():
    """No live external URL anywhere in the fixture content.

    Reserved TLDs only. A training corpus that points at a real host is a
    liability whether or not the host is currently hostile.
    """
    offenders = [host for host in fixtures.referenced_hosts()
                 if not host.endswith(fixtures.INERT_SUFFIXES)]
    assert offenders == [], offenders


def test_safety_report_agrees_with_the_content():
    report = fixtures.safety_report()
    assert report["destinations_are_inert"] is True
    assert report["collects_credentials"] is False
    assert report["executes_attachments"] is False
    assert report["writes_real_files"] is False
    assert report["uses_docker"] is False
    assert report["makes_external_requests"] is False
    assert report["uses_external_dataset"] is False
    assert report["referenced_hosts"]


def test_no_fixture_string_contains_an_absolute_external_url():
    """Nothing anywhere in the document may be an http(s) URL off the
    reserved domains -- not in a body, a note, a chain or a debrief string."""
    document = json.dumps(fixtures.learner_snapshot())
    for match in re.findall(r"https?://([A-Za-z0-9.\-]+)", document):
        host = match.split("/")[0].lower()
        assert host.endswith(fixtures.INERT_SUFFIXES), host


def test_the_organisation_and_its_people_are_fictional():
    assert world.ORGANIZATION["name"] == "Northbridge Systems"
    assert world.ORGANIZATION["domain"].endswith(".example")
    assert world.LEARNER["email"].endswith("@northbridge.example")
    for contact in world.DIRECTORY:
        assert contact["email"].endswith(fixtures.INERT_SUFFIXES), contact["id"]
    for student in trainer.STUDENTS:
        # Minimal identity only: a display name, a reference, a cohort.
        assert set(student) <= {"id", "name", "ref", "cohort", "initials",
                                "status"}, student["id"]


def test_no_attachment_is_an_executable_type():
    """Attachment names are strings in a fixture; even so, none of them
    pretends to be something a learner could be encouraged to run."""
    banned = (".exe", ".msi", ".dll", ".bat", ".ps1", ".scr", ".jar", ".com",
              ".cmd", ".vbs", ".js")
    for message in world.MAIL + scen.CONSEQUENCE_MAIL:
        for attachment in message["surface"].get("attachments", []):
            lowered = attachment["name"].lower()
            assert not lowered.endswith(banned), attachment["name"]


def test_no_prototype_file_is_an_executable_fixture():
    for base in (PROTOTYPE_TEMPLATES, PROTOTYPE_STATIC, PROTOTYPE_PKG):
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            assert path.suffix.lower() not in (
                ".exe", ".msi", ".dll", ".bat", ".ps1", ".scr", ".jar"), path


def test_the_signin_page_never_reads_or_stores_a_password():
    """The one place a password field exists, and what the code does with it.

    The submit handler must clear the field and must never read its value.
    This is asserted on the source because it is the kind of thing a later
    convenience edit ("let's remember what they typed") would quietly undo.
    """
    source = (PROTOTYPE_STATIC / "workstation.js").read_text(encoding="utf-8")
    handler = source.split("function handleSubmit(", 1)[1]
    handler = handler.split("\n  // ====", 1)[0]
    assert "passwordField.value = ''" in handler
    # Nothing reads the field's value anywhere in the file.
    assert "pw-signin-pass').value" not in source
    assert 'pw-signin-pass").value' not in source
    # And nothing is ever sent anywhere from the sign-in path.
    assert "fetch(" not in handler


# ===========================================================================
# The learner-visible surface carries no threat vocabulary
# ===========================================================================

def test_no_hostile_content_is_labelled_on_the_workstation_surface():
    """A hostile message has to read like work.

    The moment the workstation says "phishing" next to a message, the exercise
    stops being a decision under uncertainty and becomes a reading test.
    """
    violations = fixtures.surface_violations()
    assert violations == [], "\n".join(
        "%s -> %r (matched %r)" % (where, text[:90], word)
        for where, text, word in violations)


def test_the_check_would_actually_catch_a_label():
    """Guards the guard. Without this, a broken matcher passes silently."""
    assert fixtures._FORBIDDEN_SURFACE_RE.search("URGENT: phishing attempt")
    assert fixtures._FORBIDDEN_SURFACE_RE.search("Ransomware alert")
    assert fixtures._FORBIDDEN_SURFACE_RE.search("BEC training")
    # ...and would not fire on ordinary workplace English.
    assert not fixtures._FORBIDDEN_SURFACE_RE.search(
        "Please find the attachment, because the invoice is due.")


def test_ground_truth_lives_outside_the_surface():
    """Family and disposition are recorded, but never in a surface field."""
    hostile = [m for m in world.MAIL + scen.CONSEQUENCE_MAIL
               if m["analysis"]["disposition"] == "hostile"]
    assert len(hostile) >= 4
    families = {m["analysis"]["family"] for m in hostile}
    assert {"phishing", "ransomware", "bec"} <= families
    for message in hostile:
        assert "analysis" not in message["surface"]
        assert "disposition" not in message["surface"]


def test_both_legitimate_and_hostile_mfa_prompts_exist():
    """"Deny everything" has to be visibly wrong, so a genuine prompt has to
    be reachable."""
    dispositions = {p["analysis"]["disposition"] for p in world.MFA_PROMPTS}
    assert dispositions == {"legitimate", "hostile"}
    legitimate = [p for p in world.MFA_PROMPTS
                  if p["analysis"]["disposition"] == "legitimate"]
    assert legitimate[0]["analysis"]["denying_costs"] is True


def test_legitimate_mail_includes_suspicious_looking_but_genuine_traffic():
    """Otherwise the learner passes by keyword rather than by judgement."""
    subjects = " ".join(m["surface"]["subject"].lower()
                        for m in world.MAIL
                        if m["analysis"]["disposition"] == "legitimate")
    for cue in ("password", "payslip", "invoice", "maintenance"):
        assert cue in subjects, cue


# ===========================================================================
# Mode semantics
# ===========================================================================

def mode(mode_id):
    for entry in scen.MODES:
        if entry["id"] == mode_id:
            return entry
    raise AssertionError(mode_id)


def test_assessment_suppresses_coaching_and_the_safer_alternative_screen():
    flags = mode("assessment")["flags"]
    assert flags["safer_alternative"] is False
    assert flags["coaching"] is False
    assert flags["explicit_confirmation"] is False
    assert flags["score_visible_during_attempt"] is False
    assert flags["investigation_hints"] is False
    assert flags["retry_visible"] is False


def test_practice_and_simulation_differ_in_the_ways_the_architecture_says():
    practice = mode("practice")["flags"]
    simulation = mode("simulation")["flags"]
    # Practice confirms good decisions explicitly; Simulation does not.
    assert practice["explicit_confirmation"] is True
    assert simulation["explicit_confirmation"] is False
    # Both show the provisional comparison; neither shows a live score.
    assert practice["safer_alternative"] is True
    assert simulation["safer_alternative"] is True
    assert practice["score_visible_during_attempt"] is False
    assert simulation["score_visible_during_attempt"] is False
    # Practice resolves consequences sooner.
    assert practice["consequence_delay_scale"] < simulation["consequence_delay_scale"]


def test_no_mode_shows_a_score_during_the_attempt():
    for entry in scen.MODES:
        assert entry["flags"]["score_visible_during_attempt"] is False


def test_cadence_matches_the_mode_semantics():
    assert scen.CADENCE["practice"]["style"] == "paced"
    assert scen.CADENCE["simulation"]["style"] == "timed"
    assert scen.CADENCE["assessment"]["style"] == "timed"
    # Assessment is the compressed one: events can pile up.
    assert (scen.CADENCE["assessment"]["base_ms"]
            < scen.CADENCE["simulation"]["base_ms"])


def test_there_is_no_easy_medium_hard_selector_anywhere():
    """Architecture §3: the learner picks focus and mode. Difficulty is
    derived, and must not appear as a control on any prototype screen."""
    for path in list(PROTOTYPE_TEMPLATES.rglob("*.html")):
        source = path.read_text(encoding="utf-8").lower()
        for banned in ("easy", "medium", "hard"):
            assert 'value="%s"' % banned not in source, (path.name, banned)
    ids = {option["id"] for option in scen.FOCUS_OPTIONS}
    assert ids == {"phishing", "ransomware", "mfa", "bec", "mixed"}


# ===========================================================================
# Fixture integrity
# ===========================================================================

def test_the_snapshot_is_json_serialisable():
    json.dumps(fixtures.learner_snapshot())
    json.dumps(fixtures.trainer_snapshot()["students"])


def test_every_chain_settles_on_a_step_it_actually_contains():
    for chain_id, chain in scen.CONSEQUENCE_CHAINS.items():
        ids = [step["id"] for step in chain["steps"]]
        assert chain["settles_after"] in ids, chain_id
        for step in chain["steps"]:
            assert step["cause"] == "decision" or step["cause"] in ids, step["id"]


def test_every_decision_points_at_a_chain_that_exists():
    for decision_id, decision in scen.DECISIONS.items():
        if decision["chain"] is not None:
            assert decision["chain"] in scen.CONSEQUENCE_CHAINS, decision_id


def test_every_safer_alternative_names_a_real_decision():
    for decision_id in scen.SAFER_ALTERNATIVES:
        assert decision_id in scen.DECISIONS, decision_id


def test_every_timeline_entry_names_content_that_exists():
    mail_ids = {m["id"] for m in world.MAIL + scen.CONSEQUENCE_MAIL}
    prompt_ids = {p["id"] for p in world.MFA_PROMPTS}
    for focus, timeline in scen.TIMELINES.items():
        assert timeline, focus
        for entry in timeline:
            if entry["type"] == "mail":
                assert entry["ref"] in mail_ids, (focus, entry["ref"])
            elif entry["type"] == "mfa":
                assert entry["ref"] in prompt_ids, (focus, entry["ref"])
            else:
                raise AssertionError(entry["type"])


def test_every_focus_has_a_timeline_and_the_focused_family_leads_it():
    for option in scen.FOCUS_OPTIONS:
        assert option["id"] in scen.TIMELINES, option["id"]
    mail_by_id = {m["id"]: m for m in world.MAIL + scen.CONSEQUENCE_MAIL}
    prompts = {p["id"]: p for p in world.MFA_PROMPTS}

    for focus in ("phishing", "ransomware", "mfa", "bec"):
        families = []
        for entry in scen.TIMELINES[focus]:
            record = (mail_by_id if entry["type"] == "mail" else prompts)[entry["ref"]]
            if record["analysis"]["disposition"] == "hostile":
                families.append(record["analysis"]["family"])
        assert families, focus
        # The chosen family leads: it is the first hostile event to arrive.
        assert families[0] == focus, (focus, families)


def test_every_chain_effect_uses_a_vocabulary_the_front_end_understands():
    known = {"notification", "mail", "mail_rule", "file_state", "message",
             "mfa_prompt", "auth_activity", "task", "incident"}
    file_ids = {f["id"] for location in world.FILE_TREE
                for f in location["files"]}
    mail_ids = {m["id"] for m in world.MAIL + scen.CONSEQUENCE_MAIL}
    conversation_ids = {c["id"] for c in world.CONVERSATIONS}
    task_ids = {t["id"] for t in scen.TASKS}

    for chain in scen.CONSEQUENCE_CHAINS.values():
        for step in chain["steps"]:
            for effect in step["effects"]:
                assert effect["type"] in known, effect["type"]
                if effect["type"] == "file_state":
                    assert effect["file_id"] in file_ids, effect
                elif effect["type"] == "mail":
                    assert effect["mail_id"] in mail_ids, effect
                elif effect["type"] == "message":
                    assert effect["conversation_id"] in conversation_ids, effect
                elif effect["type"] == "task":
                    assert effect["task_id"] in task_ids, effect


def test_the_six_architecture_dimensions_are_present_and_weighted():
    ids = [d["id"] for d in scen.SCORE_DIMENSIONS]
    assert ids == ["security_judgment", "evidence_use",
                   "verification_discipline", "incident_response",
                   "operational_accuracy", "recovery_quality"]
    assert set(scen.DEMO_WEIGHTS) == set(ids)
    assert abs(sum(scen.DEMO_WEIGHTS.values()) - 1.0) < 1e-9


def test_hostile_events_carry_an_evidence_model():
    """Architecture §15.1: a scored interaction defines what was available,
    where it was, and what action counts as having observed it."""
    hostile = [m for m in world.MAIL if m["analysis"]["disposition"] == "hostile"]
    assert hostile
    for message in hostile:
        evidence = message["analysis"]["evidence"]
        assert evidence, message["id"]
        for item in evidence:
            assert item["id"] and item["label"] and item["where"]
            assert ":" in item["action"] or item["action"].isidentifier()


def test_a_verification_path_exists_for_every_family_that_needs_one():
    """The Directory replaces a "Verify Sender" button, so the records that
    make independent verification possible have to be there."""
    callbacks = {c["id"] for c in world.DIRECTORY if c.get("callback")}
    assert "dir-calderwood" in callbacks       # BEC / vendor account change
    assert "dir-priya-menon" in callbacks      # payroll credential lure
    assert "dir-daniel-okonkwo" in callbacks   # unexpected approval request
    verifiable = {c["id"] for c in world.CONVERSATIONS
                  if c.get("verification_reply")}
    assert {"conv-arjun-rao", "conv-priya-menon"} <= verifiable


def test_over_suspicion_and_incomplete_work_have_authored_consequences():
    """Reporting or denying everything must have a visible cost, or the
    exercise teaches the wrong strategy."""
    assert scen.DECISIONS["d-report-legitimate"]["class"] == "over_suspicious"
    assert scen.DECISIONS["d-mfa-deny-legit"]["class"] == "over_suspicious"
    assert "d-report-legitimate" in scen.SAFER_ALTERNATIVES
    assert "d-mfa-deny-legit" in scen.SAFER_ALTERNATIVES
    # A genuine task that stays undone if it is ignored.
    headcount = [t for t in scen.TASKS if t["id"] == "task-headcount"][0]
    assert headcount["state"] == "outstanding"
    assert headcount["source"] == "m-headcount"


# ===========================================================================
# The provisional safer-alternative screen (architecture §12)
# ===========================================================================

def strip_comments(source):
    """Remove /* */ and // comments.

    The scans below are about what a learner can read, not about what the
    source says about itself -- a comment that names a banned phrase in order
    to ban it must not trip the check that enforces it.
    """
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    return re.sub(r"^\s*//.*$", " ", source, flags=re.M)


def test_the_comparison_never_uses_rewind_language():
    """It is not a rewind and must not read like one, in any surface it owns."""
    sources = [
        strip_comments((PROTOTYPE_STATIC / "comparison.js").read_text(encoding="utf-8")),
        strip_comments((PROTOTYPE_STATIC / "comparison.css").read_text(encoding="utf-8")),
    ]
    for entry in scen.SAFER_ALTERNATIVES.values():
        sources.append(json.dumps(entry))

    banned = ("rewinding", "rewound", "baseline restored", "restoring",
              "try again", "correct answer", "incorrect answer",
              "well done", "points")
    for source in sources:
        lowered = source.lower()
        for phrase in banned:
            assert phrase not in lowered, phrase


def test_the_comparison_is_removable_without_touching_the_workstation():
    """Its call site is guarded, so deleting the feature is a deletion, not a
    refactor. If this ever stops being true, removing a feature the
    architecture has not frozen becomes expensive."""
    workstation = (PROTOTYPE_STATIC / "workstation.js").read_text(encoding="utf-8")
    assert "if (!window.RewindSecComparison) { done(); return; }" in workstation
    # Exactly one place reaches for it, plus the guard.
    assert workstation.count("window.RewindSecComparison") == 2


def test_every_safer_alternative_states_that_the_world_did_not_change_back():
    for decision_id, entry in scen.SAFER_ALTERNATIVES.items():
        assert entry["still_true"], decision_id
        for key in ("heading", "what_you_did", "what_followed",
                    "safer_process", "likely_outcome"):
            assert entry[key], (decision_id, key)


# ===========================================================================
# Isolation from v1 and from the deterministic core
# ===========================================================================

def _imports(path):
    tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def prototype_modules():
    return sorted(p for p in PROTOTYPE_PKG.rglob("*.py")
                  if "__pycache__" not in p.parts)


@pytest.mark.parametrize("path", prototype_modules(),
                         ids=lambda p: pathlib.Path(p).name)
def test_the_prototype_does_not_import_the_deterministic_core(path):
    """The core's guarantees are not exercised here and must not appear to be.

    A prototype screenshot must never be readable as evidence about seeded
    replay, so the mock layer keeps its hands off the module that provides it.
    """
    for name in _imports(path):
        assert not name.startswith("rewindsec.core"), (path.name, name)


@pytest.mark.parametrize("path", prototype_modules(),
                         ids=lambda p: pathlib.Path(p).name)
def test_the_prototype_does_not_import_v1_code(path):
    v1 = {"study", "study_service", "study_routes", "learning",
          "learning_service", "learning_routes", "scenario_adapters",
          "evaluation", "training", "training_service", "training_routes",
          "sandbox", "telemetry_ledger"}
    for name in _imports(path):
        assert name.split(".")[0] not in v1, (path.name, name)


def test_the_prototype_touches_no_database_sandbox_or_docker():
    """No persistence, no containers, no subprocesses, no filesystem writes.

    Checked on imports and attribute access rather than on raw text, so a
    module may honestly *say* ``"uses_docker": False`` without tripping the
    rule that makes the statement true.
    """
    banned_imports = {"docker", "subprocess", "shutil", "sqlalchemy",
                      "flask_sqlalchemy", "sqlite3", "socket"}
    banned_calls = ("db.session", "os.remove", "os.unlink", "os.system",
                    "open(")
    for path in prototype_modules():
        forbidden = {name.split(".")[0] for name in _imports(path)} & banned_imports
        assert not forbidden, (path.name, sorted(forbidden))

        source = strip_python_comments(path)
        for banned in banned_calls:
            assert banned not in source, (path.name, banned)


def strip_python_comments(path):
    """Source with docstrings and ``#`` comments removed."""
    text = io.open(path, encoding="utf-8").read()
    tree = ast.parse(text, filename=str(path))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    for doc in docstrings:
        text = text.replace(doc, " ")
    return re.sub(r"^\s*#.*$", " ", text, flags=re.M)


def test_prototype_assets_live_only_under_the_prototype_directories():
    assert PROTOTYPE_TEMPLATES.is_dir()
    assert PROTOTYPE_STATIC.is_dir()
    # No v1 template pulls in a prototype asset, so removing the prototype
    # cannot break a v1 page.
    for path in (REPO_ROOT / "templates").glob("*.html"):
        source = path.read_text(encoding="utf-8")
        assert "prototype/" not in source, path.name


def test_the_prototype_does_not_reuse_the_v1_stylesheet(client):
    """Separate visual layers, so polishing one cannot regress the other."""
    body = client.get("/prototype/workstation").data.decode()
    assert "rewindsec.css" not in body


# ===========================================================================
# The v1 surfaces still work
# ===========================================================================

V1_ROUTES = [
    "/", "/training", "/training/phishing", "/training/ransomware",
    "/training/mfa", "/training/bec", "/resources", "/instructor/login",
]


@pytest.mark.parametrize("path", V1_ROUTES)
def test_v1_routes_still_render_with_the_v1_stylesheet(client, path):
    response = client.get(path)
    if response.status_code != 200:
        response = client.get(path, follow_redirects=True)
    assert response.status_code == 200, path
    assert b"rewindsec.css" in response.data, path


def test_the_v1_landing_page_is_unchanged_by_the_prototype(client):
    body = client.get("/").data.decode()
    assert "Deterministic counterfactual" in body
    assert "/prototype" not in body


def test_the_deterministic_core_modules_were_not_touched():
    """The four modules this batch was told not to rewrite are still there and
    still pure. The detailed rules are enforced by
    tests/test_rewindsec2_core_boundaries.py; this is the coarse check that
    they still exist to be enforced."""
    core = REPO_ROOT / "rewindsec" / "core"
    for name in ("rng.py", "simtime.py", "events.py", "scheduler.py"):
        assert (core / name).is_file(), name


# ===========================================================================
# Accessibility affordances that are cheap to lose
# ===========================================================================

@pytest.mark.parametrize("path", LEARNER_ROUTES + TRAINER_ROUTES)
def test_every_prototype_page_has_a_skip_link_that_lands_somewhere(client, path):
    """A skip link pointing at an element that does not exist is worse than
    no skip link: it looks like the page is accessible and is not."""
    body = client.get(path).data.decode()
    match = re.search(r'class="pw-skip" href="#([A-Za-z0-9_\-]+)"', body)
    assert match, path
    assert 'id="%s"' % match.group(1) in body, (path, match.group(1))
    assert "<main" in body, path


def test_reduced_motion_is_honoured():
    css = (PROTOTYPE_STATIC / "base.css").read_text(encoding="utf-8")
    assert "prefers-reduced-motion: reduce" in css
    assert "animation-duration: .01ms !important" in css


def test_dialogs_declare_themselves_as_dialogs():
    workstation = (PROTOTYPE_TEMPLATES / "workstation.html").read_text(
        encoding="utf-8")
    assert workstation.count('role="dialog"') >= 2
    assert workstation.count('aria-modal="true"') >= 2
    comparison = (PROTOTYPE_STATIC / "comparison.js").read_text(encoding="utf-8")
    assert 'role="dialog"' in comparison
    assert 'aria-modal="true"' in comparison


def test_the_prototype_developer_panel_is_labelled_as_tooling():
    panel = (PROTOTYPE_TEMPLATES / "_dev_panel.html").read_text(encoding="utf-8")
    assert "NOT a learner feature" in panel
    assert "Prototype tooling" in panel
    # It can be hidden, so it cannot contaminate a screenshot.
    assert "pw-dev-hide" in panel
    script = (PROTOTYPE_STATIC / "dev-panel.js").read_text(encoding="utf-8")
    assert "dev" in script and "'0'" in script


def test_no_prototype_asset_is_fetched_from_a_third_party():
    """Local assets and system fonts only. Nothing is loaded from a CDN, and
    no font or icon set of unclear provenance is pulled in."""
    for path in list(PROTOTYPE_TEMPLATES.rglob("*.html")) \
            + list(PROTOTYPE_STATIC.rglob("*")):
        if path.is_dir():
            continue
        source = path.read_text(encoding="utf-8")
        for banned in ("//cdn", "//fonts.googleapis", "//unpkg",
                       "//cdnjs", "@import url(http"):
            assert banned not in source, (path.name, banned)


# ===========================================================================
# Learner integrity controls
#
# Clipboard restriction and screenshot deterrence, applied to learner surfaces
# only. These tests hold three things a reviewer cannot see by looking: that
# the scope is decided by the server rather than by a template, that Notes is
# the one documented exception, and that the control reads nothing and keeps
# nothing.
# ===========================================================================

from rewindsec.prototype import routes as prototype_routes  # noqa: E402

INTEGRITY_JS = PROTOTYPE_STATIC / "integrity.js"
INTEGRITY_CSS = PROTOTYPE_STATIC / "integrity.css"

#: Surfaces a learner sits in front of. Deliberately not "/prototype/": that
#: page is the reviewer's entry point, a description of the prototype rather
#: than part of a session.
LEARNER_INTEGRITY_ROUTES = [
    "/prototype/start",
    "/prototype/workstation",
    "/prototype/results",
]


@pytest.mark.parametrize("path", LEARNER_INTEGRITY_ROUTES)
def test_learner_surfaces_load_the_integrity_controller(client, path):
    body = client.get(path).data.decode()
    assert 'data-integrity="learner"' in body, path
    assert "prototype/integrity.js" in body, path
    assert "prototype/integrity.css" in body, path


def test_the_prototype_home_page_is_not_a_learner_surface(client):
    """Documentation about the prototype, not a session surface.

    Restricting the clipboard on the page that explains the prototype would be
    friction with no integrity argument behind it.
    """
    body = client.get("/prototype/").data.decode()
    assert 'data-integrity="none"' in body
    assert "prototype/integrity.js" not in body


@pytest.mark.parametrize("path", TRAINER_ROUTES)
def test_trainer_surfaces_carry_no_learner_clipboard_restriction(client, path):
    body = client.get(path).data.decode()
    assert 'data-integrity="none"' in body, path
    assert "prototype/integrity.js" not in body, path
    assert "prototype/integrity.css" not in body, path
    # And no screenshot messaging is present to be triggered.
    assert "Screenshots are disabled" not in body, path


def test_the_learner_scope_is_decided_by_the_server(flask_app):
    """One list, in Python, rather than a marker each template must remember."""
    assert prototype_routes.LEARNER_ENDPOINTS == frozenset({
        "prototype.entry",
        "prototype.workstation",
        "prototype.results",
    })
    for endpoint in prototype_routes.LEARNER_ENDPOINTS:
        assert endpoint in flask_app.view_functions, endpoint
    for endpoint in flask_app.view_functions:
        if endpoint.startswith("prototype.trainer"):
            assert endpoint not in prototype_routes.LEARNER_ENDPOINTS


# -- browser capture policy -------------------------------------------------

@pytest.mark.parametrize("path", LEARNER_INTEGRITY_ROUTES)
def test_learner_responses_declare_the_display_capture_policy(client, path):
    """The page cannot start a display capture of its own.

    This says nothing about the operating system's screenshot tools, and the
    interface does not claim otherwise.
    """
    response = client.get(path)
    assert response.headers.get("Permissions-Policy") == "display-capture=()"


@pytest.mark.parametrize(
    "path", TRAINER_ROUTES + ["/prototype/", "/prototype/api/world"])
def test_non_learner_prototype_responses_keep_their_original_headers(
        client, path):
    assert "Permissions-Policy" not in client.get(path).headers, path


def test_the_capture_policy_does_not_reach_the_v1_application(client):
    """Scoped to the prototype blueprint, so v1 responses are untouched."""
    for path in ("/", "/health"):
        response = client.get(path)
        assert "Permissions-Policy" not in response.headers, path


# -- clipboard --------------------------------------------------------------

def integrity_source():
    return strip_comments(INTEGRITY_JS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("event_name", ["copy", "cut", "paste"])
def test_each_clipboard_event_is_cancelled(event_name):
    source = integrity_source()
    assert "'%s'" % event_name in source, event_name
    # All three go through one handler, which cancels before anything else.
    assert "['copy', 'cut', 'paste'].forEach" in source
    body = source.split("function blockClipboard", 1)[1]
    handler = body.split("\n  }", 1)[0]
    assert "event.preventDefault();" in handler
    assert "event.stopPropagation();" in handler


def test_the_clipboard_exception_is_one_explicit_marker():
    source = integrity_source()
    assert "var ALLOW = '[data-clipboard=\"allow\"]';" in source
    # Every decision goes through the same predicate, so there is one rule
    # rather than a per-field opinion.
    assert source.count("function permitted(") == 1
    assert source.count("permitted(") >= 4


def test_the_event_target_decides_not_whatever_happens_to_be_focused():
    """A caret parked in Notes must not authorise a copy taken from Mail.

    The predicate reads the element the event was raised on first, and only
    falls back to the focused element when the event arrived on the document
    or the body with no useful target of its own.
    """
    source = integrity_source()
    predicate = source.split("function permitted(", 1)[1].split("\n  }", 1)[0]
    target_at = predicate.index("target.closest(ALLOW)")
    focus_at = predicate.index("focused.closest(ALLOW)")
    assert target_at < focus_at
    assert "target !== document.body" in predicate


def test_notes_is_the_only_learner_application_that_allows_the_clipboard():
    """The marker is applied to the Notes window and nowhere else."""
    workstation = strip_comments(
        (PROTOTYPE_STATIC / "workstation.js").read_text(encoding="utf-8"))
    markers = re.findall(r".*data-clipboard.*", workstation)
    assert len(markers) == 1, markers
    assert "appId === 'notes'" in markers[0]
    assert "'allow'" in markers[0]


def test_the_developer_panel_is_exempt_from_the_learner_restriction():
    panel = (PROTOTYPE_TEMPLATES / "_dev_panel.html").read_text(
        encoding="utf-8")
    assert 'data-clipboard="allow"' in panel


def test_the_blocked_clipboard_notice_is_restrained_and_points_at_notes():
    source = integrity_source()
    assert "Copy and paste are disabled in the training " in source
    assert "Use Notes if you need to keep information." in source
    # A status message, not an alert, and not an error page.
    assert "'role', 'status'" in source
    assert "'aria-live', 'polite'" in source
    for punitive in ("violation", "cheat", "warning issued", "reported to",
                     "not allowed to"):
        assert punitive not in source.lower(), punitive


def test_ordinary_typing_is_not_intercepted():
    """Only Ctrl/Cmd with one of three keys is ever cancelled."""
    source = integrity_source()
    assert "if (!(event.ctrlKey || event.metaKey) || event.altKey) { return; }" \
        in source
    assert "if (key !== 'c' && key !== 'x' && key !== 'v') { return; }" in source
    # Nothing listens to the events that carry ordinary text entry.
    for banned in ("'keypress'", "'beforeinput'", "'input'", "'textInput'",
                   "'compositionstart'"):
        assert banned not in source, banned


def test_selection_and_the_context_menu_are_not_disabled_wholesale():
    """Event-level blocking, which keeps the rest of the page usable.

    Turning off selection or the context menu would take away reading,
    screen-reader interaction and the browser's own navigation for no extra
    integrity.
    """
    source = integrity_source()
    assert "'contextmenu'" not in source
    css = strip_comments(INTEGRITY_CSS.read_text(encoding="utf-8"))
    assert "user-select" not in css
    assert "pointer-events: none" not in css


def test_keyboard_navigation_and_focus_handling_are_left_alone():
    source = integrity_source()
    # No blanket cancellation: every preventDefault sits behind a guard that
    # has already returned for anything else.
    assert "event.preventDefault()" in source
    assert "tabindex" not in source


# -- screenshot deterrence --------------------------------------------------

def test_printscreen_detection_is_wired_on_learner_surfaces():
    source = integrity_source()
    assert "'PrintScreen'" in source
    assert "document.addEventListener('keydown', onPrintScreen, true);" in source
    assert "document.addEventListener('keyup', onPrintScreen, true);" in source


def test_the_screenshot_notice_is_accessible_and_dismissible():
    source = integrity_source()
    assert 'role="dialog"' in source
    assert 'aria-modal="true"' in source
    assert 'aria-labelledby="pw-int-title"' in source
    # Dismissible by pointer and by keyboard, with focus restored afterwards.
    assert "dismissBtn.addEventListener('click', closeModal);" in source
    assert "event.key === 'Escape'" in source
    assert "returnFocus = document.activeElement;" in source
    assert "returnFocus.focus();" in source


def test_the_screenshot_notice_states_the_integrity_reason():
    source = integrity_source()
    assert "Screenshots are disabled during RewindSec training" in source
    assert "assessed on what they did in the workspace" in source


def test_the_screenshot_notice_claims_no_technical_prevention():
    """The one claim the product must not make."""
    source = integrity_source()
    assert "cannot detect or block every capture method" in source
    # Split across a string concatenation in the source.
    assert "not a technical " in source and "guarantee." in source
    for overclaim in ("cannot be captured", "prevents all", "impossible to",
                      "blocks all screenshots", "fully prevented"):
        assert overclaim not in source.lower(), overclaim


# -- privacy ----------------------------------------------------------------

def test_no_clipboard_content_is_read_stored_or_transmitted():
    source = integrity_source()
    for banned in ("clipboardData", "getData(", "setData(",
                   "navigator.clipboard", "readText", "writeText",
                   "execCommand"):
        assert banned not in source, banned


def test_the_integrity_controller_keeps_nothing_and_sends_nothing():
    """No keylogging, no accumulation, no network call, no persistence."""
    source = integrity_source()
    for banned in ("localStorage", "sessionStorage", "indexedDB",
                   "document.cookie", "fetch(", "XMLHttpRequest",
                   "sendBeacon", "WebSocket", ".push(", "JSON.stringify"):
        assert banned not in source, banned


def test_integrity_telemetry_is_not_built_in_this_prototype():
    """The production event names may be described, never emitted."""
    source = integrity_source()
    for name in ("clipboard_copy_blocked", "clipboard_cut_blocked",
                 "clipboard_paste_blocked", "screenshot_attempt_detected"):
        # They appear in the file's own documentation as future work. They
        # must not appear in code -- and the previous test already establishes
        # that this file has no way to send or store anything at all.
        assert name not in source, name


# -- mode semantics ---------------------------------------------------------

def test_the_integrity_controls_are_the_same_in_every_mode():
    """Practice, Simulation and Assessment share one workstation contract.

    Assessment is where the argument is strongest, but a clipboard that
    behaved differently between modes would make the workspace unpredictable.
    """
    source = integrity_source().lower()
    for mode_word in ("practice", "simulation", "assessment", "s.flags",
                      "world.modes"):
        assert mode_word not in source, mode_word


def test_assessment_still_suppresses_the_safer_alternative_screen():
    """Existing behaviour, re-asserted because this batch touched the
    workstation renderer."""
    assessment = [m for m in scen.MODES if m["id"] == "assessment"][0]
    assert assessment["flags"]["safer_alternative"] is False
    assert assessment["flags"]["coaching"] is False
    workstation = (PROTOTYPE_STATIC / "workstation.js").read_text(
        encoding="utf-8")
    assert "if (!S.flags.safer_alternative) { done(); return; }" in workstation


# -- isolation --------------------------------------------------------------

def test_the_integrity_controls_touch_nothing_outside_the_prototype():
    for path in (REPO_ROOT / "templates").glob("*.html"):
        source = path.read_text(encoding="utf-8")
        assert "integrity" not in source, path.name
    for path in (REPO_ROOT / "static").glob("*.css"):
        assert "pw-int-" not in path.read_text(encoding="utf-8"), path.name
