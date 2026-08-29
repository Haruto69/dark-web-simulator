"""Instructor-facing Flask blueprint for the conference sandbox.

Kept out of ``app.py`` so that no Docker or subprocess logic lives in route
handlers: everything here delegates to :class:`sandbox.SandboxManager` and the
scenario classes.

Milestone 2 changes:

* **Session isolation.** There is no shared ``primary`` sandbox any more. Every
  route acts on the sandbox derived from the caller's own Flask session id
  (:func:`sandbox.sandbox_id_for_session`). A learner cannot name another
  learner's sandbox, because ids are never accepted from request data.
* **Real authentication.** ``/sandbox/*`` is gated by
  :func:`security.require_instructor` (session flag set by the instructor
  login), not by an optional shared token.
* **Aggregation.** Instructors get ``/sandbox/sessions`` and can inspect any
  session's telemetry; learners get nothing here at all.
* CSRF is enforced application-wide by :func:`security.init_csrf`.
"""

from flask import (Blueprint, current_app, flash, jsonify, redirect, request,
                   session, url_for)

from sandbox import (EventType, FileImpactScenario, SandboxError,
                     SandboxManager, SandboxNotReadyError,
                     sandbox_id_for_session)
from sandbox.dataset import BASELINE_FILENAMES
from security import is_instructor, require_instructor, wants_json


def make_recorder(db, SecurityEvent):
    """Return a callable that persists telemetry dicts into SecurityEvent."""
    def recorder(event):
        row = SecurityEvent(
            scenario_id=event.get("scenario_id"),
            session_id=event.get("session_id"),
            event_type=event["event_type"],
            timestamp=event["timestamp"],
            source=event.get("source"),
            target=(event.get("target") or None),
            details=(event.get("details") or None),
        )
        db.session.add(row)
        db.session.commit()
        return event
    return recorder


def ensure_manager(app, db, SecurityEvent, local_root):
    """One SandboxManager per Flask app, always wired to the DB recorder.

    ``default_sandbox_id=None`` is deliberate: any caller that forgets to pass
    a session-scoped id gets a ``SandboxError`` instead of quietly sharing one
    workspace across learners.
    """
    manager = getattr(app, "_sandbox_manager", None)
    if manager is None:
        manager = SandboxManager.autodetect(
            local_root, recorder=make_recorder(db, SecurityEvent),
            default_sandbox_id=None)
        app._sandbox_manager = manager
    return manager



def session_sandbox_id():
    """The sandbox id for the *current* session. Never request-controlled."""
    return sandbox_id_for_session(session["session_id"])


def create_sandbox_blueprint(db, SecurityEvent, local_root):
    bp = Blueprint("sandbox_ctl", __name__, url_prefix="/sandbox")

    def get_manager():
        return ensure_manager(current_app, db, SecurityEvent, local_root)

    def sid():
        return session.get("session_id")

    def respond(payload, status=200, message=None, category="info"):
        if wants_json():
            return jsonify(payload), status
        if message:
            flash(message, category)
        return redirect(url_for("dashboard"))

    # -- lifecycle ---------------------------------------------------------
    @bp.post("/create")
    @require_instructor
    def create():
        manager = get_manager()
        try:
            info = manager.create(session_sandbox_id(), session_id=sid())
        except SandboxError as exc:
            return respond({"ok": False, "error": str(exc)}, 500,
                           "Sandbox creation failed: %s" % exc, "danger")
        return respond({"ok": True, "sandbox": info},
                       message="Sandbox created (backend: %s)." % info["backend"],
                       category="success")

    @bp.post("/reset")
    @require_instructor
    def reset():
        manager = get_manager()
        try:
            info = manager.reset(session_sandbox_id(), session_id=sid())
        except SandboxError as exc:
            return respond({"ok": False, "error": str(exc)}, 500,
                           "Sandbox reset failed: %s" % exc, "danger")
        return respond({"ok": True, "sandbox": info},
                       message="Sandbox reset to synthetic baseline.",
                       category="success")

    @bp.post("/destroy")
    @require_instructor
    def destroy():
        manager = get_manager()
        info = manager.destroy(session_sandbox_id(), session_id=sid())
        return respond({"ok": True, "sandbox": info},
                       message="Sandbox destroyed.", category="info")

    # -- scenario ----------------------------------------------------------
    @bp.post("/scenario/file-impact")
    @require_instructor
    def file_impact():
        manager = get_manager()
        scenario = FileImpactScenario(manager)
        targets = request.form.getlist("targets") or None
        if targets is None and request.is_json:
            targets = (request.get_json(silent=True) or {}).get("targets")
        try:
            result = scenario.run(sandbox_id=session_sandbox_id(),
                                  session_id=sid(), targets=targets)
        except SandboxNotReadyError as exc:
            return respond({"ok": False, "error": str(exc)}, 409,
                           "No sandbox running - create one first.", "warning")
        except SandboxError as exc:
            return respond({"ok": False, "error": str(exc)}, 500,
                           "Scenario failed: %s" % exc, "danger")
        return respond({"ok": True, "result": result},
                       message="File-impact scenario complete (%d file(s) impacted)."
                               % result["impacted"],
                       category="success")

    # -- read-only views (instructor-only: they describe lab state) --------
    @bp.get("/status")
    @require_instructor
    def status():
        manager = get_manager()
        info = manager.status(session_sandbox_id())
        files = manager.workspace_state(session_sandbox_id()) if info["ready"] else []
        return jsonify({
            "ok": True,
            "sandbox": info,
            "files": files,
            "dataset": list(BASELINE_FILENAMES),
            "instructor_auth": True,
        })

    @bp.get("/sessions")
    @require_instructor
    def sessions():
        """Aggregate view: one row per sandbox the backend currently owns."""
        manager = get_manager()
        rows = []
        for sandbox_id in manager.list_sandboxes():
            info = manager.status(sandbox_id)
            rows.append({"sandbox_id": sandbox_id, "state": info.get("state"),
                         "ready": info.get("ready")})
        return jsonify({"ok": True, "count": len(rows), "sandboxes": rows})

    @bp.get("/events")
    @require_instructor
    def events():
        """Ordered telemetry. Instructors may filter by scenario or session.

        Ordering is ``(timestamp, id)``, which is total and stable: ``id`` is a
        monotonic autoincrement, so equal timestamps still resolve to insertion
        order.
        """
        query = SecurityEvent.query
        scenario_id = request.args.get("scenario_id")
        if scenario_id:
            query = query.filter(SecurityEvent.scenario_id == scenario_id)
        session_filter = request.args.get("session_id")
        if session_filter:
            query = query.filter(SecurityEvent.session_id == session_filter)
        limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
        rows = (query.order_by(SecurityEvent.timestamp.asc(),
                               SecurityEvent.id.asc()).limit(limit).all())
        return jsonify({"ok": True, "count": len(rows),
                        "events": [r.to_dict() for r in rows]})

    bp.event_types = EventType
    return bp


def sandbox_dashboard_context(app, db, SecurityEvent, local_root):
    """Build the template context for the dashboard's sandbox panel.

    Only ever called from the instructor-gated dashboard view.
    """
    manager = ensure_manager(app, db, SecurityEvent, local_root)
    sandbox_id = session_sandbox_id()
    info = manager.status(sandbox_id)
    files = []
    if info["ready"]:
        try:
            files = manager.workspace_state(sandbox_id)
        except SandboxError:
            files = []
    recent = (SecurityEvent.query
              .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
              .limit(30).all())
    return {
        "sandbox_info": info,
        "sandbox_files": files,
        "sandbox_events": list(reversed(recent)),
        "sandbox_auth_enabled": is_instructor(),
        "sandbox_all_ids": manager.list_sandboxes(),
    }
