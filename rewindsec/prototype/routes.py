"""Flask routes for the RewindSec 2.0 UI prototype.

Every route here is a ``GET``. That is deliberate rather than incidental: the
prototype has no server-side state to change, so it needs no state-changing
method, and giving it one would create the impression that something is being
persisted. The application's global CSRF gate only applies to unsafe methods
(see ``security.init_csrf``), so this blueprint adds no exemption of any kind.

The blueprint is mounted under one prefix and owns one template directory and
one static directory. Deleting this package, ``templates/prototype/``,
``static/prototype/`` and the ``register_blueprint`` call in ``app.py`` removes
the entire mock layer with nothing left behind.

Nothing here touches the database, the sandbox, the telemetry ledger, the
deterministic core, or any v1 module.
"""

from flask import Blueprint, abort, jsonify, render_template, request

from rewindsec.prototype import fixtures

#: Endpoints a learner actually sits in front of during a session.
#:
#: The learner integrity controls (clipboard restriction, screenshot notice,
#: display-capture policy) are attached from here rather than from a template,
#: so the scope is one list in one place and a new screen has to be added to it
#: deliberately. The trainer console and the fixture API are not on it, and
#: neither is ``/prototype/`` itself: that page is the reviewer's entry point
#: to the prototype -- a description of the thing, not the thing -- and
#: restricting the clipboard on documentation would be pure friction.
LEARNER_ENDPOINTS = frozenset({
    "prototype.entry",
    "prototype.workstation",
    "prototype.results",
})


def create_prototype_blueprint():
    """Build the ``/prototype`` blueprint.

    A factory rather than a module-level object so the application decides
    when -- and whether -- the prototype exists at all.
    """
    bp = Blueprint("prototype", __name__, url_prefix="/prototype")

    # -- shared template context ------------------------------------------

    @bp.context_processor
    def _prototype_context():
        """Values every prototype template needs.

        ``prototype_banner`` is rendered on every screen. A reviewer must
        never be able to mistake one of these pages for implemented product.
        """
        return {
            "prototype_banner": (
                "UI prototype — fixture data. No simulation engine, scoring "
                "engine or persistence is running behind these screens."),
            "org": fixtures.world.ORGANIZATION,
            "learner": fixtures.world.LEARNER,
            "integrity_scope": (
                "learner" if request.endpoint in LEARNER_ENDPOINTS else "none"),
        }

    # -- learner integrity controls ---------------------------------------

    @bp.after_request
    def _learner_capture_policy(response):
        """Refuse display capture initiated by a learner page itself.

        ``display-capture=()`` stops this document from calling
        ``getDisplayMedia`` -- so nothing in the workstation can quietly record
        the screen, and a script injected into it could not either. It does
        *not* stop the operating system's own screenshot tools, and it is not
        claimed to.

        Registered on the blueprint, so it reaches prototype responses only.
        Restricting it further to the learner endpoints keeps the trainer
        console and the v1 application on exactly the headers they had.
        """
        if request.endpoint in LEARNER_ENDPOINTS:
            response.headers["Permissions-Policy"] = "display-capture=()"
        return response

    # -- learner surfaces --------------------------------------------------

    @bp.route("/")
    def index():
        """Entry point for the manual product review."""
        return render_template(
            "prototype/index.html",
            safety=fixtures.safety_report())

    @bp.route("/start")
    def entry():
        """Focus and mode selection. No Easy/Medium/Hard control exists."""
        return render_template(
            "prototype/entry.html",
            focus_options=fixtures.scen.FOCUS_OPTIONS,
            modes=fixtures.scen.MODES,
            cadence=fixtures.scen.CADENCE)

    @bp.route("/workstation")
    def workstation():
        """The synthetic workstation shell.

        Renders an empty shell; the world arrives from ``/prototype/api/world``
        and is drawn by ``static/prototype/workstation.js``. That is the same
        shape the production client will have -- ask the server what the world
        is, then render it -- with a fixture document standing in for the
        simulation.
        """
        return render_template("prototype/workstation.html")

    @bp.route("/results")
    def results():
        """Learner debrief.

        The page is rendered from the run state the workstation left in
        ``sessionStorage``. Opened directly, it falls back to a representative
        fixture session so the screen is always reviewable.
        """
        return render_template(
            "prototype/results.html",
            dimensions=fixtures.scen.SCORE_DIMENSIONS)

    # -- trainer surfaces --------------------------------------------------

    @bp.route("/trainer")
    def trainer_dashboard():
        snapshot = fixtures.trainer_snapshot()
        sessions = sorted(snapshot["sessions"], key=lambda s: s["started"],
                          reverse=True)
        return render_template(
            "prototype/trainer_dashboard.html",
            snapshot=snapshot, sessions=sessions,
            active="dashboard")

    @bp.route("/trainer/students")
    def trainer_students():
        snapshot = fixtures.trainer_snapshot()
        rows = []
        for student in snapshot["students"]:
            detail = fixtures.student_detail(student["id"])
            completed = [s for s in detail["sessions"]
                         if s["status"] == "complete"]
            latest = completed[-1] if completed else None
            rows.append({
                "student": student,
                "groups": detail["groups"],
                "sessions": detail["sessions"],
                "assignments": detail["assignments"],
                "latest": latest,
            })
        return render_template(
            "prototype/trainer_students.html",
            snapshot=snapshot, rows=rows, active="students")

    @bp.route("/trainer/students/<student_id>")
    def trainer_student(student_id):
        detail = fixtures.student_detail(student_id)
        if detail is None:
            abort(404)
        return render_template(
            "prototype/trainer_student.html",
            snapshot=fixtures.trainer_snapshot(), detail=detail,
            active="students")

    @bp.route("/trainer/groups")
    def trainer_groups():
        snapshot = fixtures.trainer_snapshot()
        rows = [fixtures.group_detail(group["id"])
                for group in snapshot["groups"]]
        return render_template(
            "prototype/trainer_groups.html",
            snapshot=snapshot, rows=rows, active="groups")

    @bp.route("/trainer/groups/<group_id>")
    def trainer_group(group_id):
        detail = fixtures.group_detail(group_id)
        if detail is None:
            abort(404)
        return render_template(
            "prototype/trainer_group.html",
            snapshot=fixtures.trainer_snapshot(), detail=detail,
            active="groups")

    @bp.route("/trainer/assessments")
    def trainer_assessments():
        snapshot = fixtures.trainer_snapshot()
        rows = []
        for assessment in snapshot["assessments"]:
            groups = []
            students = []
            for row in snapshot["assignments"]:
                if row["assessment_id"] != assessment["id"]:
                    continue
                if row["source"] == "group":
                    group = snapshot["index"]["groups_by_id"].get(
                        row["group_id"])
                    if group:
                        groups.append(group)
                else:
                    student = snapshot["index"]["students_by_id"].get(
                        row["student_id"])
                    if student:
                        students.append(student)
            rows.append({"assessment": assessment, "groups": groups,
                         "students": students})
        return render_template(
            "prototype/trainer_assessments.html",
            snapshot=snapshot, rows=rows, active="assessments")

    # -- fixture API -------------------------------------------------------

    @bp.route("/api/world")
    def api_world():
        """The whole synthetic world as one document.

        This endpoint is the seam. Production replaces the *contents* with
        real simulation state and adds an event stream beside it; the client
        contract -- the server says what the world is -- does not change.
        """
        return jsonify(fixtures.learner_snapshot())

    @bp.route("/api/assignment-provenance")
    def api_assignment_provenance():
        """Where a student already receives an assessment from, if anywhere.

        Read-only lookup behind the duplicate-assignment warning in
        architecture §27. It answers "where did this come from", not "is it
        already assigned", because the trainer cannot decide anything useful
        from a boolean.
        """
        assessment_id = request.args.get("assessment_id", "")
        student_id = request.args.get("student_id", "")
        if not assessment_id or not student_id:
            return jsonify({"ok": False,
                            "error": "assessment_id and student_id required"}), 400

        snapshot = fixtures.trainer_snapshot()
        if assessment_id not in snapshot["index"]["assessments_by_id"]:
            return jsonify({"ok": False, "error": "unknown assessment"}), 404
        if student_id not in snapshot["index"]["students_by_id"]:
            return jsonify({"ok": False, "error": "unknown student"}), 404

        sources = fixtures.existing_assignment_sources(assessment_id,
                                                       student_id)
        student = snapshot["index"]["students_by_id"][student_id]
        assessment = snapshot["index"]["assessments_by_id"][assessment_id]
        return jsonify({
            "ok": True,
            "student": {"id": student["id"], "name": student["name"]},
            "assessment": {"id": assessment["id"], "name": assessment["name"]},
            "existing_sources": sources,
            "duplicate": bool(sources),
        })

    return bp
