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

import os
import time

from flask import (Blueprint, current_app, flash, jsonify, redirect, request,
                   session, url_for)

from sandbox import (EventType, FileImpactScenario, SandboxError,
                     SandboxManager, SandboxNotReadyError,
                     sandbox_id_for_session)
from sandbox.backends.docker import DockerBackend
from sandbox.backends.local import LocalBackend
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.sanitize import sanitized_failure
from security import is_instructor, require_instructor, wants_json

#: Default staleness threshold for ``POST /sandbox/reap`` (2 hours), and a
#: floor beneath which the route refuses to operate so a mistyped value cannot
#: wipe every sandbox in an active class.
DEFAULT_MAX_AGE_SECONDS = 7200
MIN_REAP_AGE_SECONDS = 60


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

    ``SANDBOX_BACKEND`` selects the backend: ``auto`` (default, prefer Docker),
    ``docker`` (fail rather than silently degrade) or ``local``. Being able to
    pin the backend matters for honest measurement -- and lets the HTTP test
    suite exercise routing without creating containers.
    """
    manager = getattr(app, "_sandbox_manager", None)
    if manager is not None:
        return manager

    recorder = make_recorder(db, SecurityEvent)
    choice = (os.environ.get("SANDBOX_BACKEND", "auto") or "auto").strip().lower()
    if choice == "local":
        manager = SandboxManager(LocalBackend(local_root), recorder=recorder,
                                 default_sandbox_id=None)
    elif choice == "docker":
        backend = DockerBackend()
        if not backend.is_available():
            raise SandboxError(
                "SANDBOX_BACKEND=docker was requested but Docker is "
                "unavailable; refusing to fall back to the local backend")
        manager = SandboxManager(backend, recorder=recorder,
                                 default_sandbox_id=None)
    else:
        manager = SandboxManager.autodetect(
            local_root, recorder=recorder, default_sandbox_id=None)

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

    def fail(exc, status, context, category="danger"):
        """Turn a backend exception into a *sanitised* response.

        Milestone 4.1: these handlers used to return ``str(exc)``, which can
        carry Docker daemon internals, a subprocess argv, container stderr or
        a host path straight into an instructor-visible JSON body. The caller
        now gets a stable generic message plus a correlation reference; the
        scrubbed diagnostic goes to the application log only.
        """
        reference, message, _detail = sanitized_failure(
            exc, logger=current_app.logger, context=context)
        return respond({"ok": False, "error": message, "error_ref": reference,
                        "context": context}, status,
                       "%s (reference %s)" % (context, reference), category)

    # -- lifecycle ---------------------------------------------------------
    @bp.post("/create")
    @require_instructor
    def create():
        manager = get_manager()
        try:
            info = manager.create(session_sandbox_id(), session_id=sid())
        except SandboxError as exc:
            return fail(exc, 500, "sandbox creation failed")
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
            return fail(exc, 500, "sandbox reset failed")
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
            return fail(exc, 409, "no sandbox running - create one first",
                        "warning")
        except SandboxError as exc:
            return fail(exc, 500, "scenario failed")
        return respond({"ok": True, "result": result},
                       message="File-impact scenario complete (%d file(s) impacted)."
                               % result["impacted"],
                       category="success")

    @bp.post("/reap")
    @require_instructor
    def reap():
        """Destroy stale sandboxes belonging to this application.

        ``max_age`` is bounded and numeric; ``dry_run`` reports the selection
        without destroying anything. The reaper only ever considers sandboxes
        carrying this application's ownership marker -- an unrelated container
        or directory on the same host is never enumerated, let alone removed.
        """
        manager = get_manager()
        default_age = current_app.config.get("SANDBOX_MAX_AGE_SECONDS",
                                             DEFAULT_MAX_AGE_SECONDS)
        supplied = request.form.get("max_age")
        if supplied is None and request.is_json:
            supplied = (request.get_json(silent=True) or {}).get("max_age")
        try:
            max_age = float(default_age if supplied in (None, "") else supplied)
        except (TypeError, ValueError):
            return respond({"ok": False, "error": "max_age must be a number"}, 400,
                           "Invalid max_age.", "danger")
        if max_age < MIN_REAP_AGE_SECONDS:
            return respond({"ok": False,
                            "error": "max_age must be at least %d seconds"
                                     % MIN_REAP_AGE_SECONDS}, 400,
                           "max_age is too small.", "danger")
        dry_run = str(request.form.get("dry_run", "")).lower() in ("1", "true", "yes")
        try:
            reaped = manager.reap_stale(max_age, session_id=sid(), dry_run=dry_run)
        except SandboxError as exc:
            return fail(exc, 500, "reap failed")
        return respond({"ok": True, "max_age": max_age, "dry_run": dry_run,
                        "count": len(reaped), "reaped": reaped},
                       message="Reaped %d stale sandbox(es)." % len(reaped),
                       category="info")

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
        now = time.time()
        rows = []
        for row in manager.sandbox_metadata():
            created = row.get("created_at")
            rows.append({"sandbox_id": row["sandbox_id"],
                         "state": row.get("state"),
                         "created_at": created,
                         "age_seconds": (now - created) if created else None})
        return jsonify({"ok": True, "count": len(rows), "sandboxes": rows,
                        "backend": manager.backend.name})

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
