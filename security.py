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
import time
import uuid
from collections import OrderedDict
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


def rotate_csrf_token():
    """Discard the current token and mint a new one.

    Called on privilege change so a token observed before authentication is
    worthless afterwards.
    """
    session.pop(CSRF_SESSION_KEY, None)
    return csrf_token()


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


# -- login throttling --------------------------------------------------------
#
# A deliberately small, bounded, in-memory limiter. Documented limitations:
#
#   * Process-local. Multiple workers each keep their own counters, so the
#     effective limit scales with worker count. This prototype runs one
#     process; a multi-worker deployment would need shared state.
#   * Lost on restart. Restarting the app clears all lockouts.
#   * Keyed by remote address. Learners behind one NAT share a bucket, so a
#     classroom on one public IP can lock itself out of the instructor login.
#   * Not a defence against a distributed attacker; it raises the cost of
#     online guessing on a lab network, nothing more.
#
# This is adequate for an academic sandbox and is not claimed to be more.

#: Hard cap on tracked keys, so the limiter cannot become a memory-growth
#: vector under a flood of spoofed source addresses.
THROTTLE_MAX_KEYS = 512

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_SECONDS = 300


class LoginThrottle:
    """Bounded fixed-window failure counter with a lockout period."""

    def __init__(self, max_attempts=DEFAULT_MAX_ATTEMPTS,
                 lockout_seconds=DEFAULT_LOCKOUT_SECONDS,
                 max_keys=THROTTLE_MAX_KEYS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.max_keys = max_keys
        #: key -> {"failures": int, "window_start": float, "locked_until": float}
        self._buckets = OrderedDict()

    def _now(self):
        return time.time()

    def _bucket(self, key, now):
        bucket = self._buckets.get(key)
        if bucket is None or now - bucket["window_start"] > self.lockout_seconds:
            bucket = {"failures": 0, "window_start": now, "locked_until": 0.0}
            self._buckets[key] = bucket
        self._buckets.move_to_end(key)
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)
        return bucket

    def retry_after(self, key, now=None):
        """Seconds remaining in a lockout, or 0 when the key may try again."""
        now = self._now() if now is None else now
        bucket = self._buckets.get(key)
        if not bucket:
            return 0
        remaining = bucket["locked_until"] - now
        return int(remaining) + 1 if remaining > 0 else 0

    def is_locked(self, key, now=None):
        return self.retry_after(key, now=now) > 0

    def record_failure(self, key, now=None):
        """Count a failed attempt; returns the lockout seconds (0 if none)."""
        now = self._now() if now is None else now
        bucket = self._bucket(key, now)
        bucket["failures"] += 1
        if bucket["failures"] >= self.max_attempts:
            bucket["locked_until"] = now + self.lockout_seconds
        return self.retry_after(key, now=now)

    def record_success(self, key):
        """Clear a key's history after a successful authentication."""
        self._buckets.pop(key, None)

    def reset(self):
        self._buckets.clear()


#: Module-level limiter shared by the login view.
login_throttle = LoginThrottle(
    max_attempts=int(os.environ.get("INSTRUCTOR_MAX_ATTEMPTS",
                                    DEFAULT_MAX_ATTEMPTS)),
    lockout_seconds=int(os.environ.get("INSTRUCTOR_LOCKOUT_SECONDS",
                                       DEFAULT_LOCKOUT_SECONDS)))


def throttle_key():
    """Bucket key for the current request: the remote address."""
    return (request.remote_addr or "unknown")[:64]


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


#: Session keys carried across the privilege change. ``session_id`` is a
#: *correlation* identifier, not an authenticator: it names the instructor's
#: own sandbox and ties their telemetry together. Preserving it keeps their
#: workspace continuous across login while everything that could authenticate
#: or authorise anything is discarded and re-minted.
PRESERVED_ON_LOGIN = ("session_id",)


def login_instructor():
    """Establish the instructor session, rotating all session state first.

    Session-fixation defence: the entire Flask session is cleared, a fresh
    ``session_id`` is issued when none needs preserving, and a **new CSRF
    token** is minted. Any session contents an attacker managed to fix before
    authentication -- including a CSRF token they had observed -- are gone by
    the time the instructor flag is set.
    """
    preserved = {key: session[key] for key in PRESERVED_ON_LOGIN
                 if key in session}
    session.clear()
    session.update(preserved)
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())
    rotate_csrf_token()
    session[INSTRUCTOR_SESSION_KEY] = True
    session.modified = True


def logout_instructor():
    """Drop the instructor flag and every other session value.

    Clearing wholesale (rather than popping one key) means a signed-out cookie
    carries no CSRF token and no scenario state that could be replayed.
    """
    session.clear()
    session.modified = True


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
