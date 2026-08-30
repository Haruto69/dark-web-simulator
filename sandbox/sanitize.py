"""Sanitised error reporting for instructor-facing responses and telemetry.

An exception raised deep in a backend can carry host-specific detail: a
Docker daemon socket path, a subprocess argv, a chunk of container stderr, a
Windows profile directory. None of that belongs in an HTTP response or in the
SecurityEvent table, which instructors export and share.

The contract here is deliberately blunt:

  * callers get a **stable generic message** plus a short correlation
    reference (``error_reference``) they can quote,
  * telemetry stores the exception's *class name* and that same reference --
    never the exception's message,
  * the sanitised message is what goes to the application log, so an operator
    with host access can still diagnose the failure.

Nothing here tries to be a clever redactor of a message that is allowed
through: the safe messages are the ones we wrote ourselves, and even those are
scrubbed before logging.
"""

import re
import secrets

#: What every instructor-facing failure says. Stable, so it cannot leak
#: anything by varying with the underlying cause.
GENERIC_ERROR = "the operation failed; see the instructor log for reference %s"

#: Patterns scrubbed even from the *internal* diagnostic string, so a stray
#: host path or argv never reaches the log file either.
_SCRUBBERS = (
    # Windows drive-letter paths, e.g. C:\Users\someone\project
    (re.compile(r"[A-Za-z]:\[^\s'\"]*"), "<path>"),
    # UNC paths
    (re.compile(r"\\[^\s'\"]+"), "<path>"),
    # POSIX absolute paths, except the constant sandbox workspace
    (re.compile(r"(?<!\w)/(?!workspace(?:/|\b))[^\s'\"]*"), "<path>"),
    # Anything that looks like a command line we ran
    (re.compile(r"(?i)\b(docker|podman|subprocess|argv|cmd)\b[^\n]*"), "<command>"),
    # Traceback framing, in case an exception message embeds one
    (re.compile(r"(?is)traceback \(most recent call last\):.*"), "<traceback>"),
    (re.compile(r'(?im)^\s*file "[^"]*", line \d+.*$'), "<traceback>"),
)

#: Hard cap on the internal diagnostic string.
MAX_DIAGNOSTIC = 200


def error_reference():
    """Return a fresh, opaque correlation id for one failure."""
    return "err-" + secrets.token_hex(4)


def scrub(text):
    """Return ``text`` with host paths and command lines replaced."""
    if not isinstance(text, str):
        text = str(text)
    for pattern, replacement in _SCRUBBERS:
        text = pattern.sub(replacement, text)
    # Collapse newlines so multi-line stderr cannot smuggle structure through.
    text = " ".join(text.split())
    return text[:MAX_DIAGNOSTIC]


def public_message(reference):
    """The stable message shown to a user or instructor."""
    return GENERIC_ERROR % reference


def telemetry_detail(exc, reference):
    """What SCENARIO_FAILED (and friends) may record about ``exc``.

    The exception *class* is ours and is safe; the *message* is not, and is
    never included.
    """
    return "%s (ref=%s)" % (type(exc).__name__, reference)


def internal_diagnostic(exc):
    """Scrubbed one-line description for the application log."""
    return "%s: %s" % (type(exc).__name__, scrub(str(exc)))


def sanitized_failure(exc, logger=None, context=None):
    """Handle ``exc`` once: log it internally, return the public parts.

    Returns ``(reference, public_message, telemetry_detail)``.
    """
    reference = error_reference()
    if logger is not None:
        logger.error("sandbox failure ref=%s%s: %s", reference,
                     (" context=%s" % scrub(context)) if context else "",
                     internal_diagnostic(exc))
    return reference, public_message(reference), telemetry_detail(exc, reference)
