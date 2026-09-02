"""Deterministic seeded randomness with independent named streams.

A RewindSec 2.0 simulation owns exactly one :class:`SeededRandom`. Every value
the simulation invents -- which message arrives, which persona sends it, how
long a consequence is delayed, which distractors are present -- is drawn from
it, and from nothing else. ``secrets``, ``uuid``, the global ``random``
functions and the wall clock are all forbidden in the deterministic core
precisely so that this module is the only door randomness can come through.

Why named streams
-----------------
A single shared generator makes a simulation reproducible but *fragile*: the
day someone adds one extra draw to mail generation, every later timing and
persona value shifts, and every stored session stops replaying. Streams are
therefore derived independently::

    stream_seed = SHA-256(f"{_DERIVATION_LABEL}|{root_seed}|{stream_name}")

so adding, removing or consuming a stream cannot perturb any other stream.
The derivation uses SHA-256 rather than ``hash()`` because CPython salts
``hash()`` per process, which would make a stored session replay differently
on the next run -- the exact failure this module exists to prevent.

Materialisation and restore contract
------------------------------------
* Streams are **materialised lazily**: a stream exists only once
  :meth:`SeededRandom.stream` has been asked for it. An unmaterialised stream
  is indistinguishable from a materialised-but-unconsumed one, because both
  derive from the same root seed.
* :meth:`SeededRandom.capture_state` serialises **only materialised streams**.
* :meth:`SeededRandom.restore_state` **replaces** the stream table: after a
  restore, exactly the streams named in the payload exist, positioned exactly
  where they were. Streams materialised after the captured moment are dropped,
  which is correct -- at the captured moment they had not been used.
* Asking for a stream the restored payload did not contain derives it freshly
  from the root seed, i.e. unconsumed. Correct for the same reason.

That contract is what makes a checkpoint restore reproduce the recorded event
stream instead of rerolling it.
"""

import hashlib
import json
import math
import random

__all__ = [
    "SeededRandom",
    "RandomStream",
    "RngError",
    "InvalidSeedError",
    "InvalidStreamNameError",
    "InvalidRngStateError",
    "dumps_state",
    "MAX_ROOT_SEED",
    "STATE_VERSION",
    "STREAM_DISTRACTORS",
    "STREAM_MAIL_GENERATION",
    "STREAM_PERSONA",
    "STREAM_TIMING",
]

#: Bumped only when the serialised shape changes incompatibly. Restoring a
#: payload from a different version fails loudly rather than being guessed at.
STATE_VERSION = 1

#: Domain-separation label folded into every stream derivation. Changing it
#: changes every stream for every seed, so it is versioned deliberately and
#: must never be edited casually: stored sessions would stop replaying.
_DERIVATION_LABEL = "rewindsec2/rng/v1"

#: Root seeds are unsigned 64-bit integers. The bound is not a cryptographic
#: statement -- it keeps a seed short enough to quote in a bug report, print in
#: a debrief and round-trip exactly through JSON.
MAX_ROOT_SEED = 2 ** 64 - 1

#: JSON numbers survive a round-trip through every reasonable consumer only up
#: to 2**53-1. Generator states are lists of 32-bit words so they are always
#: safe; this bound guards the draw counters.
_MAX_JSON_SAFE_INT = 2 ** 53 - 1

_MAX_STREAM_NAME_LENGTH = 64

#: Stream names the simulation is expected to use early. They are constants for
#: discoverability and consistent spelling across modules; the class does not
#: restrict callers to this list.
STREAM_MAIL_GENERATION = "mail_generation"
STREAM_TIMING = "timing"
STREAM_DISTRACTORS = "distractors"
STREAM_PERSONA = "persona"


class RngError(Exception):
    """Base class for every failure raised by this module."""


class InvalidSeedError(RngError, ValueError):
    """The root seed is not a usable, reproducible seed."""


class InvalidStreamNameError(RngError, ValueError):
    """The stream name would not derive stably across machines."""


class InvalidRngStateError(RngError, ValueError):
    """A captured-state payload is malformed, foreign or unrestorable."""


# -- validation --------------------------------------------------------------

def _validate_root_seed(seed):
    """Return *seed* if it is a legitimate root seed, else raise.

    ``bool`` is rejected explicitly even though it is a subclass of ``int``:
    ``SeededRandom(True)`` is always a mistake, and silently accepting it as
    seed 1 would hide it.
    """
    if isinstance(seed, bool):
        raise InvalidSeedError(
            "root seed must be an int, not a bool; got %r" % (seed,))
    if not isinstance(seed, int):
        raise InvalidSeedError(
            "root seed must be an int, got %s" % type(seed).__name__)
    if not 0 <= seed <= MAX_ROOT_SEED:
        raise InvalidSeedError(
            "root seed must be in [0, %d], got %d" % (MAX_ROOT_SEED, seed))
    return seed


def _validate_stream_name(name):
    """Return *name* if it derives stably, else raise.

    The charset is restricted to ``[a-z][a-z0-9_]*``. Unicode names would
    derive differently depending on normalisation form, and case-only variants
    ("timing" vs "Timing") would silently become two independent streams that a
    reader would read as one.
    """
    if not isinstance(name, str):
        raise InvalidStreamNameError(
            "stream name must be a str, got %s" % type(name).__name__)
    if not name:
        raise InvalidStreamNameError("stream name must not be empty")
    if len(name) > _MAX_STREAM_NAME_LENGTH:
        raise InvalidStreamNameError(
            "stream name must be at most %d characters, got %d"
            % (_MAX_STREAM_NAME_LENGTH, len(name)))
    for index, char in enumerate(name):
        if char == "_" and index > 0:
            continue
        if not char.isascii():
            raise InvalidStreamNameError(
                "stream name must be ASCII: %r" % (name,))
        if char.isdigit() and index > 0:
            continue
        if not (char.isalpha() and char.islower()):
            raise InvalidStreamNameError(
                "stream name must match [a-z][a-z0-9_]*: %r" % (name,))
    return name


def _derive_stream_seed(root_seed, stream_name):
    """Derive one stream's seed from the root seed and the stream name.

    SHA-256 over an unambiguous, delimiter-separated byte string. The
    delimiters matter: without them ("ab", "c") and ("a", "bc") would collide,
    silently coupling two streams that must stay independent.
    """
    material = "%s|%d|%s" % (_DERIVATION_LABEL, root_seed, stream_name)
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


# -- generator state encoding ------------------------------------------------

def _encode_generator_state(generator):
    """Encode ``random.Random.getstate()`` into a JSON-safe mapping.

    ``getstate()`` returns ``(version, tuple_of_ints, gauss_next)``. JSON has
    no tuples, so the shape is written out explicitly rather than pickled --
    ``pickle`` is not an option for state that has to be readable, auditable
    and diffable.
    """
    version, internal, gauss_next = generator.getstate()
    return {
        "version": version,
        "internal": list(internal),
        "gauss_next": gauss_next,
    }


def _decode_generator_state(payload, where):
    """Return a ``setstate``-shaped tuple from *payload*, or raise."""
    if not isinstance(payload, dict):
        raise InvalidRngStateError(
            "%s: generator state must be an object, got %s"
            % (where, type(payload).__name__))
    missing = {"version", "internal", "gauss_next"} - set(payload)
    if missing:
        raise InvalidRngStateError(
            "%s: generator state is missing %s"
            % (where, ", ".join(sorted(missing))))

    version = payload["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise InvalidRngStateError(
            "%s: generator state version must be an int" % where)

    internal = payload["internal"]
    if not isinstance(internal, list):
        raise InvalidRngStateError(
            "%s: generator internal state must be a list, got %s"
            % (where, type(internal).__name__))
    for value in internal:
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidRngStateError(
                "%s: generator internal state must contain only ints" % where)

    gauss_next = payload["gauss_next"]
    if gauss_next is not None:
        if isinstance(gauss_next, bool) or not isinstance(gauss_next, (int, float)):
            raise InvalidRngStateError(
                "%s: gauss_next must be null or a number" % where)
        if not math.isfinite(gauss_next):
            raise InvalidRngStateError("%s: gauss_next must be finite" % where)

    return (version, tuple(internal), gauss_next)


# -- streams -----------------------------------------------------------------

class RandomStream:
    """One independently-derived, explicitly-seeded PRNG stream.

    The underlying :class:`random.Random` is deliberately private. Handing it
    out would let a caller call ``getrandbits`` or ``seed`` directly, and the
    draw counter -- and with it the ability to notice divergence -- would
    quietly stop meaning anything. Only the operations the simulation actually
    needs are exposed; add more here, consciously, when a real caller appears.
    """

    __slots__ = ("_name", "_generator", "_draws")

    def __init__(self, name, generator, draws=0):
        self._name = name
        self._generator = generator
        self._draws = draws

    @property
    def name(self):
        return self._name

    @property
    def draws(self):
        """How many draw calls this stream has served.

        This counts *API calls*, not underlying entropy: :meth:`shuffled`
        consumes a variable number of words but counts as one draw. It is
        diagnostic only -- the generator state, not this number, is what
        restores a stream -- and exists so a divergence between two supposedly
        identical runs can be localised to a stream and a call index.
        """
        return self._draws

    def __repr__(self):
        return "RandomStream(name=%r, draws=%d)" % (self._name, self._draws)

    # -- draws ---------------------------------------------------------------
    # Each of these increments the counter only after the underlying call has
    # succeeded, so a rejected argument does not leave the counter drifted away
    # from the generator's real position.

    def random(self):
        """A float in [0.0, 1.0)."""
        value = self._generator.random()
        self._draws += 1
        return value

    def randint(self, a, b):
        """An int in [a, b], both inclusive."""
        value = self._generator.randint(a, b)
        self._draws += 1
        return value

    def randrange(self, start, stop=None, step=1):
        """An int drawn from ``range(start, stop, step)``."""
        if stop is None:
            value = self._generator.randrange(start)
        else:
            value = self._generator.randrange(start, stop, step)
        self._draws += 1
        return value

    def choice(self, seq):
        """One element of a non-empty sequence."""
        value = self._generator.choice(seq)
        self._draws += 1
        return value

    def shuffled(self, seq):
        """A new shuffled ``list`` built from *seq*.

        Named ``shuffled`` rather than ``shuffle`` because, unlike
        :func:`random.shuffle`, it does not mutate its argument. Returning a
        new list keeps callers from aliasing authored content: shuffling a
        module-level list of personas in place would corrupt every later
        session in the process.
        """
        items = list(seq)
        self._generator.shuffle(items)
        self._draws += 1
        return items


# -- the session-level owner -------------------------------------------------

class SeededRandom:
    """The one randomness owner of a simulation session.

    Construct it with the session's root seed, take named streams from it, and
    capture/restore its whole state alongside the rest of the session. Nothing
    else in the deterministic core may produce a random value.
    """

    __slots__ = ("_root_seed", "_streams")

    def __init__(self, root_seed):
        self._root_seed = _validate_root_seed(root_seed)
        self._streams = {}

    @property
    def root_seed(self):
        return self._root_seed

    @property
    def stream_names(self):
        """The materialised stream names, sorted.

        Sorted rather than insertion-ordered so two runs that materialise the
        same streams in a different order still compare and serialise
        identically.
        """
        return tuple(sorted(self._streams))

    def __repr__(self):
        return "SeededRandom(root_seed=%d, streams=%r)" % (
            self._root_seed, list(self.stream_names))

    # -- streams -------------------------------------------------------------

    def stream(self, name):
        """Return the named stream, materialising it on first use.

        Deriving a stream is a pure function of ``(root_seed, name)``, so the
        first call after a fresh construction and the first call after a
        restore that did not mention the stream produce exactly the same
        unconsumed stream.
        """
        name = _validate_stream_name(name)
        existing = self._streams.get(name)
        if existing is not None:
            return existing
        generator = random.Random(_derive_stream_seed(self._root_seed, name))
        stream = RandomStream(name, generator)
        self._streams[name] = stream
        return stream

    def has_stream(self, name):
        """Whether the named stream has been materialised yet."""
        return _validate_stream_name(name) in self._streams

    # -- state ---------------------------------------------------------------

    def capture_state(self):
        """Return a canonical, JSON-safe snapshot of every materialised stream.

        The result contains only ``dict``, ``list``, ``str``, ``int``,
        ``float`` and ``None``, so it survives ``json.dumps``/``json.loads``
        unchanged and can be fed straight to a canonical-JSON digest without
        special-casing.
        """
        streams = {}
        for name in sorted(self._streams):
            stream = self._streams[name]
            streams[name] = {
                "draws": stream.draws,
                "generator": _encode_generator_state(stream._generator),
            }
        return {
            "version": STATE_VERSION,
            "root_seed": self._root_seed,
            "streams": streams,
        }

    def restore_state(self, state):
        """Restore this instance to a previously captured state.

        The payload's root seed must match this instance's. A mismatch is
        always a bug -- a session restoring another session's randomness -- and
        silently accepting it would produce a replay that diverges for a reason
        no digest comparison could explain.

        Restoration is atomic: the new stream table is built and validated in
        full before anything is assigned, so a rejected payload leaves the
        instance exactly as it was.
        """
        streams = self._streams_from_state(state, expected_root_seed=self._root_seed)
        self._streams = streams

    @classmethod
    def from_state(cls, state):
        """Build a new instance from a captured state, seed included.

        Used when a session is loaded from persistence and there is no existing
        instance to restore into.
        """
        root_seed = cls._root_seed_from_state(state)
        instance = cls(root_seed)
        instance._streams = cls._streams_from_state(
            state, expected_root_seed=root_seed)
        return instance

    # -- state validation ----------------------------------------------------

    @staticmethod
    def _root_seed_from_state(state):
        if not isinstance(state, dict):
            raise InvalidRngStateError(
                "rng state must be an object, got %s" % type(state).__name__)
        missing = {"version", "root_seed", "streams"} - set(state)
        if missing:
            raise InvalidRngStateError(
                "rng state is missing %s" % ", ".join(sorted(missing)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidRngStateError("rng state version must be an int")
        if version != STATE_VERSION:
            raise InvalidRngStateError(
                "unsupported rng state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return _validate_root_seed(state["root_seed"])
        except InvalidSeedError as exc:
            raise InvalidRngStateError("rng state root_seed: %s" % exc) from exc

    @classmethod
    def _streams_from_state(cls, state, expected_root_seed):
        root_seed = cls._root_seed_from_state(state)
        if root_seed != expected_root_seed:
            raise InvalidRngStateError(
                "rng state belongs to root seed %d, not %d"
                % (root_seed, expected_root_seed))

        raw_streams = state["streams"]
        if not isinstance(raw_streams, dict):
            raise InvalidRngStateError(
                "rng state streams must be an object, got %s"
                % type(raw_streams).__name__)

        restored = {}
        for name in sorted(raw_streams):
            try:
                _validate_stream_name(name)
            except InvalidStreamNameError as exc:
                raise InvalidRngStateError(
                    "rng state stream name: %s" % exc) from exc

            entry = raw_streams[name]
            if not isinstance(entry, dict):
                raise InvalidRngStateError(
                    "rng state stream %r must be an object, got %s"
                    % (name, type(entry).__name__))
            missing = {"draws", "generator"} - set(entry)
            if missing:
                raise InvalidRngStateError(
                    "rng state stream %r is missing %s"
                    % (name, ", ".join(sorted(missing))))

            draws = entry["draws"]
            if isinstance(draws, bool) or not isinstance(draws, int):
                raise InvalidRngStateError(
                    "rng state stream %r draws must be an int" % name)
            if not 0 <= draws <= _MAX_JSON_SAFE_INT:
                raise InvalidRngStateError(
                    "rng state stream %r draws out of range: %d" % (name, draws))

            setstate_arg = _decode_generator_state(
                entry["generator"], "rng state stream %r" % name)
            generator = random.Random(_derive_stream_seed(root_seed, name))
            try:
                generator.setstate(setstate_arg)
            except (ValueError, TypeError, OverflowError) as exc:
                raise InvalidRngStateError(
                    "rng state stream %r is unrestorable: %s" % (name, exc)) from exc

            restored[name] = RandomStream(name, generator, draws=draws)
        return restored


def dumps_state(state):
    """Serialise a captured state to canonical JSON.

    A convenience so callers do not each pick their own ``json.dumps``
    arguments: equal states must produce equal text, or state digests stop
    meaning anything.
    """
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
