"""Synthetic sandbox-only identities.

These identities exist *only* inside the simulator:

  * the domain is ``lab.local``, a reserved-style name that resolves nowhere
    and corresponds to no real service;
  * the passwords are **derived**, not stored -- there is no credential table,
    so there is nothing to leak or dump;
  * derivation is keyed by the learner's session id, so the identity issued to
    session A does not authenticate in session B;
  * validation is a pure local HMAC comparison. No socket is opened, no
    external authentication service is contacted, ever.

The simulator validates a *submitted* password against a derived one and then
discards the submitted value. Nothing in this module writes a password to a
log, a database row, a template or an API response other than the learner's
own briefing page, where the sandbox issues the identity in the first place.
"""

import hashlib
import hmac

#: Deliberately non-routable, non-branded lab domain. Never use a realistic
#: real-world domain here -- learners must not be trained to type credentials
#: into anything that resembles a live service.
LAB_DOMAIN = "lab.local"

DEFAULT_IDENTITY_COUNT = 2


class SyntheticIdentityStore:
    """Derives (never persists) the sandbox identities for a session."""

    def __init__(self, secret, domain=LAB_DOMAIN, count=DEFAULT_IDENTITY_COUNT):
        if not secret:
            raise ValueError("a non-empty derivation secret is required")
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self.domain = domain
        self.count = count

    # -- derivation --------------------------------------------------------
    def usernames(self):
        return tuple("employee%02d@%s" % (n, self.domain)
                     for n in range(1, self.count + 1))

    def _password(self, session_id, username):
        message = ("%s\x00%s" % (session_id, username)).encode("utf-8")
        digest = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        # Short, typeable and obviously synthetic.
        return "lab-%s" % digest[:10]

    def identities(self, session_id):
        """Issue this session's identities.

        Returned to the learner's own briefing page only. The instructor
        dashboard never sees passwords.
        """
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        return [{"username": name, "password": self._password(session_id, name)}
                for name in self.usernames()]

    # -- validation --------------------------------------------------------
    def validate(self, session_id, username, password):
        """Return ``(valid, reason)``. ``password`` is never retained.

        ``reason`` is a coarse, non-echoing label ('ok', 'unknown_identity',
        'credential_mismatch') so that telemetry can record *why* without ever
        recording *what* was typed.
        """
        if not isinstance(session_id, str) or not session_id.strip():
            return False, "no_session"
        username = (username or "").strip().lower()
        if username not in self.usernames():
            return False, "unknown_identity"
        expected = self._password(session_id, username)
        if not isinstance(password, str):
            return False, "credential_mismatch"
        if not hmac.compare_digest(expected, password.strip()):
            return False, "credential_mismatch"
        return True, "ok"
