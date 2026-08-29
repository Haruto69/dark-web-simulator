"""Lightweight session security for the simulator: CSRF + instructor auth.

Deliberately small. This is an academic sandbox, not a SaaS product, so there
is no OAuth, no user table and no role model -- just:

  * a per-session CSRF token enforced on *every* state-changing request, and
  * a single instructor role, established by a password held in the
    environment and remembered only as a boolean session flag.

Nothing here stores a password. ``INSTRUCTOR_PASSWORD`` is read from the
environment on each comparison and compared with :func:`hmac.compare_digest`.
"""

import hmac
import os
import secrets
from functools import wraps

from flask import (current_app, jsonify, redirect, render_template, request,
                   session, url_for)

# -- CSRF --------------------------------------------------------------------

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def csrf_token():
    """Return (creating on first use) this session's CSRF token."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _submitted_csrf_token():
    token = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER)
    if not token and request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            token = payload.get(CSRF_FIELD)
    return token or ""


def csrf_is_valid():
    expected = session.get(CSRF_SESSION_KEY) or ""
    supplied = _submitted_csrf_token()
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected, supplied)


def wants_json():
    return (request.accept_mimetypes.best == "application/json"
            or request.args.get("format") == "json"
            or request.is_json)


def init_csrf(app):
    """Enforce CSRF on all unsafe methods and expose ``csrf_token()`` to Jinja.

    Enforcement is global rather than per-route so a newly added POST handler
    is protected by default instead of by remembering a decorator.
    """
    app.config.setdefault("CSRF_ENABLED", True)

    @app.before_request
    def _enforce_csrf():
        if request.method in SAFE_METHODS:
            return None
        if not current_app.config.get("CSRF_ENABLED", True):
            return None
        if csrf_is_valid():
            return None
        if wants_json():
            return jsonify({"ok": False, "error": "csrf token missing or invalid"}), 400
        return ("CSRF token missing or invalid. Reload the page and try again.",
                400, {"Content-Type": "text/plain; charset=utf-8"})

    app.jinja_env.globals["csrf_token"] = csrf_token
    return app


# -- Instructor authentication ----------------------------------------------

INSTRUCTOR_SESSION_KEY = "is_instructor"


def instructor_password():
    """The configured instructor password, or ``""`` when unset.

    When unset, instructor login is impossible and every instructor-only route
    stays closed. Failing closed is the point: an unconfigured deployment must
    not expose the dashboard or the sandbox controls.
    """
    return os.environ.get("INSTRUCTOR_PASSWORD", "")


def instructor_auth_configured():
    return bool(instructor_password())


def check_instructor_password(supplied):
    expected = instructor_password()
    if not expected or not isinstance(supplied, str) or not supplied:
        return False
    return hmac.compare_digest(expected, supplied)


def login_instructor():
    session[INSTRUCTOR_SESSION_KEY] = True


def logout_instructor():
    session.pop(INSTRUCTOR_SESSION_KEY, None)


def is_instructor():
    return bool(session.get(INSTRUCTOR_SESSION_KEY))


def require_instructor(view):
    """Gate a view behind the instructor session flag."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if is_instructor():
            return view(*args, **kwargs)
        if wants_json():
            return jsonify({"ok": False, "error": "instructor authentication required"}), 403
        return redirect(url_for("instructor_login", next=request.path))
    return wrapper


def safe_next(target, fallback="/dashboard"):
    """Return ``target`` only if it is a same-origin, relative path.

    Blocks open redirects: anything with a scheme, a host, a backslash or a
    protocol-relative ``//`` prefix falls back to the dashboard.
    """
    if not isinstance(target, str) or not target.startswith("/"):
        return fallback
    if target.startswith("//") or "\\" in target:
        return fallback
    return target


def render_instructor_login(error=None, status=200, next_path=None):
    return render_template("instructor_login.html",
                           error=error,
                           configured=instructor_auth_configured(),
                           next_path=next_path or ""), status
