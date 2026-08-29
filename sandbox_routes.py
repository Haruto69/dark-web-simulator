"""Instructor-facing Flask blueprint for the conference sandbox.

Kept out of ``app.py`` so that no Docker or subprocess logic lives in route
handlers: everything here delegates to :class:`sandbox.SandboxManager` and
:class:`sandbox.FileImpactScenario`.

Instructor separation: all sandbox control lives under the ``/sandbox`` prefix
and is gated by :func:`require_instructor`. Set ``SANDBOX_INSTRUCTOR_TOKEN`` in
the environment to require a shared token (sent as ``X-Instructor-Token`` or the
``token`` form field). When it is unset the routes stay open for local lab use
and the dashboard shows an explicit "unauthenticated" warning.
"""

import os
from functools import wraps

from flask import (Blueprint, current_app, flash, jsonify, redirect, request,
                   session, url_for)

from sandbox import (EventType, FileImpactScenario, SandboxError,
                     SandboxManager, SandboxNotReadyError)
from sandbox.dataset import BASELINE_FILENAMES


def instructor_token():
    return os.environ.get("SANDBOX_INSTRUCTOR_TOKEN", "").strip()


def require_instructor(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = instructor_token()
        if expected:
            supplied = (request.headers.get("X-Instructor-Token")
                        or request.form.get("token")
                        or request.args.get("token") or "")
            if supplied != expected:
                return jsonify({"ok": False, "error": "instructor token required"}), 403
        return view(*args, **kwargs)
    return wrapper


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
    """One SandboxManager per Flask app, always wired to the DB recorder."""
    manager = getattr(app, "_sandbox_manager", None)
    if manager is None:
        manager = SandboxManager.autodetect(
            local_root, recorder=make_recorder(db, SecurityEvent))
        app._sandbox_manager = manager
    return manager


def create_sandbox_blueprint(db, SecurityEvent, local_root):
    bp = Blueprint("sandbox_ctl", __name__, url_prefix="/sandbox")

    def get_manager():
        return ensure_manager(current_app, db, SecurityEvent, local_root)

    def sid():
        return session.get("session_id")

    def wants_json():
        return (request.accept_mimetypes.best == "application/json"
                or request.args.get("format") == "json"
                or request.is_json)

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
            info = manager.create(session_id=sid())
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
            info = manager.reset(session_id=sid())
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
        info = manager.destroy(session_id=sid())
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
            result = scenario.run(session_id=sid(), targets=targets)
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

    # -- read-only views ---------------------------------------------------
    @bp.get("/status")
    def status():
        manager = get_manager()
        info = manager.status()
        files = manager.workspace_state() if info["ready"] else []
        return jsonify({
            "ok": True,
            "sandbox": info,
            "files": files,
            "dataset": list(BASELINE_FILENAMES),
            "instructor_auth": bool(instructor_token()),
        })

    @bp.get("/events")
    def events():
        query = SecurityEvent.query
        scenario_id = request.args.get("scenario_id")
        if scenario_id:
            query = query.filter(SecurityEvent.scenario_id == scenario_id)
        limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
        rows = (query.order_by(SecurityEvent.timestamp.asc(),
                               SecurityEvent.id.asc()).limit(limit).all())
        return jsonify({"ok": True, "count": len(rows),
                        "events": [r.to_dict() for r in rows]})

    bp.event_types = EventType
    return bp


def sandbox_dashboard_context(app, db, SecurityEvent, local_root):
    """Build the template context for the dashboard's sandbox panel."""
    manager = ensure_manager(app, db, SecurityEvent, local_root)
    info = manager.status()
    files = []
    if info["ready"]:
        try:
            files = manager.workspace_state()
        except SandboxError:
            files = []
    recent = (SecurityEvent.query
              .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
              .limit(20).all())
    return {
        "sandbox_info": info,
        "sandbox_files": files,
        "sandbox_events": list(reversed(recent)),
        "sandbox_auth_enabled": bool(instructor_token()),
    }
