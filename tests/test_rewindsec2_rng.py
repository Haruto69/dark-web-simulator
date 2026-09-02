"""The deterministic RNG foundation.

Every test here defends one property of the replay contract. The failure mode
they exist for is silent: a simulation that replays and *looks* right but
rerolled, producing a counterfactual comparison against a factual run that
never happened.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rewindsec.core.rng import (MAX_ROOT_SEED, STATE_VERSION,
                                InvalidRngStateError, InvalidSeedError,
                                InvalidStreamNameError, RandomStream,
                                SeededRandom, dumps_state)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def draws(stream, count=5):
    """A short, comparable sequence of floats from *stream*."""
    return [stream.random() for _ in range(count)]


# -- reproducibility ---------------------------------------------------------

def test_same_seed_same_stream_same_operations_are_identical():
    first = SeededRandom(4242).stream("timing")
    second = SeededRandom(4242).stream("timing")
    assert draws(first) == draws(second)


def test_same_seed_reproduces_every_exposed_operation():
    """Not just random(): each wrapper must be reproducible too."""
    def script(rng):
        stream = rng.stream("mail_generation")
        return [
            stream.random(),
            stream.randint(1, 100),
            stream.randrange(10),
            stream.randrange(5, 500, 5),
            stream.choice("abcdefghij"),
            stream.shuffled(list(range(12))),
        ]

    assert script(SeededRandom(99)) == script(SeededRandom(99))


def test_different_seeds_produce_different_sequences():
    a = draws(SeededRandom(1).stream("timing"), 8)
    b = draws(SeededRandom(2).stream("timing"), 8)
    assert a != b


def test_different_stream_names_are_independently_derived():
    rng = SeededRandom(777)
    assert draws(rng.stream("timing"), 8) != draws(rng.stream("persona"), 8)


def test_neighbouring_seeds_do_not_produce_neighbouring_streams():
    """Seed 1 stream 'a' must not equal seed 2 stream 'a' shifted, etc.

    A naive derivation such as ``root_seed + hash(name)`` would let adjacent
    seeds and adjacent names collide. SHA-256 over a delimited string does not,
    and this pins that.
    """
    seen = set()
    for seed in range(6):
        for name in ("timing", "persona", "distractors"):
            key = tuple(draws(SeededRandom(seed).stream(name), 4))
            assert key not in seen, "stream collision at seed=%d name=%s" % (seed, name)
            seen.add(key)


def test_delimiters_prevent_seed_and_name_confusion():
    """Concatenation-style collisions are ruled out.

    Without delimiters in the derivation material, seed 11 + name "x" and seed
    1 + name "1x" could hash identically.
    """
    assert (draws(SeededRandom(11).stream("x"), 4)
            != draws(SeededRandom(1).stream("x"), 4))


# -- stream independence -----------------------------------------------------

def test_consuming_one_stream_does_not_alter_another():
    rng = SeededRandom(31337)
    untouched_first = draws(rng.stream("persona"), 3)

    other = SeededRandom(31337)
    for _ in range(500):
        other.stream("timing").random()
    untouched_second = draws(other.stream("persona"), 3)

    assert untouched_first == untouched_second


def test_creating_a_new_stream_does_not_perturb_an_existing_one():
    """The single most important long-term property.

    Adding a stream later (a new content generator, say) must not shift any
    stored session's existing streams, or every saved session stops replaying
    the day the feature lands.
    """
    baseline = SeededRandom(2024)
    timing = baseline.stream("timing")
    before = draws(timing, 3)

    withnew = SeededRandom(2024)
    withnew.stream("timing")
    withnew.stream("a_stream_added_much_later")
    withnew.stream("and_another_one")
    after = draws(withnew.stream("timing"), 3)

    assert before == after


def test_stream_returns_the_same_object_on_repeat_access():
    rng = SeededRandom(5)
    assert rng.stream("timing") is rng.stream("timing")


def test_streams_are_materialised_lazily():
    rng = SeededRandom(5)
    assert rng.stream_names == ()
    assert rng.has_stream("timing") is False
    rng.stream("timing")
    assert rng.stream_names == ("timing",)
    assert rng.has_stream("timing") is True


def test_stream_names_are_sorted_not_insertion_ordered():
    rng = SeededRandom(5)
    rng.stream("zebra")
    rng.stream("alpha")
    assert rng.stream_names == ("alpha", "zebra")


# -- capture and restore -----------------------------------------------------

def test_capture_consume_restore_reproduces_the_same_values():
    """The core replay guarantee."""
    rng = SeededRandom(8080)
    stream = rng.stream("mail_generation")
    stream.random()

    captured = rng.capture_state()
    expected = draws(stream, 6)

    rng.restore_state(captured)
    assert draws(rng.stream("mail_generation"), 6) == expected


def test_restore_reproduces_every_materialised_stream():
    rng = SeededRandom(1234)
    for name in ("timing", "persona", "distractors"):
        rng.stream(name).random()

    captured = rng.capture_state()
    expected = {name: draws(rng.stream(name), 4)
                for name in ("timing", "persona", "distractors")}

    rng.restore_state(captured)
    for name, values in expected.items():
        assert draws(rng.stream(name), 4) == values, name


def test_restore_drops_streams_materialised_after_the_capture():
    """A stream that did not exist at the captured moment must not survive it."""
    rng = SeededRandom(64)
    rng.stream("timing").random()
    captured = rng.capture_state()

    rng.stream("distractors").random()
    assert "distractors" in rng.stream_names

    rng.restore_state(captured)
    assert rng.stream_names == ("timing",)


def test_stream_unknown_to_a_restored_state_derives_unconsumed():
    """Requesting an unseen stream after restore gives a pristine stream.

    Correct by the contract: at the captured moment that stream had not been
    used, so it must behave exactly like a freshly derived one.
    """
    rng = SeededRandom(64)
    rng.stream("timing").random()
    captured = rng.capture_state()
    rng.restore_state(captured)

    after_restore = draws(rng.stream("persona"), 4)
    pristine = draws(SeededRandom(64).stream("persona"), 4)
    assert after_restore == pristine


def test_capture_does_not_consume_or_mutate():
    """Capturing state must never change it, or checkpoints are meaningless."""
    rng = SeededRandom(11)
    stream = rng.stream("timing")
    expected = draws(SeededRandom(11).stream("timing"), 4)
    for _ in range(4):
        rng.capture_state()
    assert draws(stream, 4) == expected


def test_repeated_capture_is_stable():
    rng = SeededRandom(11)
    rng.stream("timing").random()
    assert rng.capture_state() == rng.capture_state()


def test_from_state_rebuilds_a_new_instance_including_the_seed():
    rng = SeededRandom(555)
    rng.stream("timing").random()
    captured = rng.capture_state()
    expected = draws(rng.stream("timing"), 4)

    rebuilt = SeededRandom.from_state(captured)
    assert rebuilt.root_seed == 555
    assert draws(rebuilt.stream("timing"), 4) == expected


def test_restore_rejects_a_state_from_a_different_seed():
    """A session must not restore another session's randomness."""
    foreign = SeededRandom(1)
    foreign.stream("timing").random()
    with pytest.raises(InvalidRngStateError) as info:
        SeededRandom(2).restore_state(foreign.capture_state())
    assert "root seed" in str(info.value)


def test_failed_restore_leaves_the_instance_untouched():
    """Restoration is atomic."""
    rng = SeededRandom(77)
    stream = rng.stream("timing")
    stream.random()
    good = rng.capture_state()
    expected = draws(SeededRandom(77).stream("timing"), 4)[1:]

    broken = json.loads(json.dumps(good))
    broken["streams"]["timing"]["generator"]["internal"] = ["not-an-int"]
    with pytest.raises(InvalidRngStateError):
        rng.restore_state(broken)

    assert rng.stream_names == ("timing",)
    assert draws(rng.stream("timing"), 3) == expected


# -- serialization -----------------------------------------------------------

def test_state_round_trips_through_plain_json():
    rng = SeededRandom(2468)
    rng.stream("timing").random()
    rng.stream("persona").shuffled(range(9))

    captured = rng.capture_state()
    revived = json.loads(json.dumps(captured))
    assert revived == captured

    expected = draws(rng.stream("timing"), 4)
    rng.restore_state(revived)
    assert draws(rng.stream("timing"), 4) == expected


def test_captured_state_contains_only_json_primitives():
    rng = SeededRandom(13)
    rng.stream("timing").random()

    def check(node, path="state"):
        if isinstance(node, dict):
            for key, value in node.items():
                assert isinstance(key, str), path
                check(value, "%s.%s" % (path, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                check(value, "%s[%d]" % (path, index))
        else:
            assert node is None or isinstance(node, (str, int, float)), path
            assert not isinstance(node, tuple), path

    check(rng.capture_state())


def test_canonical_dump_is_stable_and_sorted():
    rng = SeededRandom(13)
    rng.stream("zebra").random()
    rng.stream("alpha").random()
    text = dumps_state(rng.capture_state())
    assert text.index('"alpha"') < text.index('"zebra"')
    assert dumps_state(rng.capture_state()) == text


def test_state_declares_its_version():
    assert SeededRandom(1).capture_state()["version"] == STATE_VERSION


# -- rejected input ----------------------------------------------------------

@pytest.mark.parametrize("seed", [
    "1234", 12.5, 12.0, None, b"1234", [1], object(),
])
def test_unsupported_root_seed_types_are_rejected(seed):
    with pytest.raises(InvalidSeedError):
        SeededRandom(seed)


def test_bool_root_seed_is_rejected_despite_being_an_int():
    """``SeededRandom(True)`` is always a mistake, so it must not become seed 1."""
    with pytest.raises(InvalidSeedError):
        SeededRandom(True)


@pytest.mark.parametrize("seed", [-1, MAX_ROOT_SEED + 1])
def test_out_of_range_root_seeds_are_rejected(seed):
    with pytest.raises(InvalidSeedError):
        SeededRandom(seed)


@pytest.mark.parametrize("seed", [0, 1, MAX_ROOT_SEED])
def test_boundary_root_seeds_are_accepted(seed):
    assert SeededRandom(seed).root_seed == seed


@pytest.mark.parametrize("name", [
    "", "Timing", "TIMING", "_leading", "9leading", "has space", "has-dash",
    "has.dot", "unicodé", "x" * 65, None, 5, b"timing",
])
def test_unsupported_stream_names_are_rejected(name):
    with pytest.raises(InvalidStreamNameError):
        SeededRandom(1).stream(name)


@pytest.mark.parametrize("name", ["a", "timing", "mail_generation", "s3", "x" * 64])
def test_valid_stream_names_are_accepted(name):
    assert SeededRandom(1).stream(name).name == name


@pytest.mark.parametrize("mutate", [
    lambda s: "not a dict",
    lambda s: {},
    lambda s: {k: v for k, v in s.items() if k != "streams"},
    lambda s: {k: v for k, v in s.items() if k != "root_seed"},
    lambda s: {k: v for k, v in s.items() if k != "version"},
    lambda s: dict(s, version=STATE_VERSION + 1),
    lambda s: dict(s, version="1"),
    lambda s: dict(s, root_seed=-5),
    lambda s: dict(s, streams=[]),
    lambda s: dict(s, streams={"timing": "not a dict"}),
    lambda s: dict(s, streams={"Bad Name": s["streams"]["timing"]}),
    lambda s: dict(s, streams={"timing": {"draws": 0}}),
    lambda s: dict(s, streams={"timing": dict(s["streams"]["timing"], draws=-1)}),
    lambda s: dict(s, streams={"timing": dict(s["streams"]["timing"], draws=1.5)}),
    lambda s: dict(s, streams={"timing": dict(s["streams"]["timing"], draws=True)}),
    lambda s: dict(s, streams={"timing": dict(s["streams"]["timing"],
                                             generator="not a dict")}),
    lambda s: dict(s, streams={"timing": dict(s["streams"]["timing"],
                                             generator={"version": 3})}),
])
def test_malformed_restore_state_is_rejected(mutate):
    rng = SeededRandom(9)
    rng.stream("timing").random()
    good = json.loads(json.dumps(rng.capture_state()))
    with pytest.raises(InvalidRngStateError):
        SeededRandom(9).restore_state(mutate(good))


@pytest.mark.parametrize("bad_generator", [
    {"version": 3, "internal": "nope", "gauss_next": None},
    {"version": 3, "internal": [1, 2, 3], "gauss_next": None},          # wrong length
    {"version": 3, "internal": [1.5] * 625, "gauss_next": None},
    {"version": 999, "internal": [0] * 625, "gauss_next": None},        # wrong MT version
    {"version": 3, "internal": [0] * 625, "gauss_next": float("nan")},
    {"version": 3, "internal": [0] * 625, "gauss_next": "0.5"},
])
def test_malformed_generator_state_is_rejected(bad_generator):
    rng = SeededRandom(9)
    rng.stream("timing").random()
    state = rng.capture_state()
    state["streams"]["timing"]["generator"] = bad_generator
    with pytest.raises(InvalidRngStateError):
        SeededRandom(9).restore_state(state)


# -- draw counters -----------------------------------------------------------

def test_draw_counter_starts_at_zero_and_counts_calls():
    stream = SeededRandom(3).stream("timing")
    assert stream.draws == 0
    stream.random()
    stream.randint(1, 3)
    stream.randrange(4)
    stream.choice("abc")
    stream.shuffled([1, 2, 3])
    assert stream.draws == 5


def test_draw_counter_survives_capture_and_restore():
    rng = SeededRandom(3)
    stream = rng.stream("timing")
    for _ in range(7):
        stream.random()
    captured = rng.capture_state()
    assert captured["streams"]["timing"]["draws"] == 7

    stream.random()
    assert stream.draws == 8

    rng.restore_state(captured)
    assert rng.stream("timing").draws == 7


def test_draw_counter_does_not_advance_on_a_rejected_call():
    """A failed draw must not drift the counter away from the real position."""
    stream = SeededRandom(3).stream("timing")
    stream.random()
    with pytest.raises((ValueError, IndexError, TypeError)):
        stream.choice([])
    assert stream.draws == 1


def test_draw_counters_are_per_stream():
    rng = SeededRandom(3)
    rng.stream("timing").random()
    rng.stream("timing").random()
    rng.stream("persona").random()
    assert rng.stream("timing").draws == 2
    assert rng.stream("persona").draws == 1


# -- encapsulation -----------------------------------------------------------

def test_stream_does_not_expose_the_underlying_generator_publicly():
    """Bypassing the wrapper would silently stop the draw counter meaning anything."""
    stream = SeededRandom(1).stream("timing")
    public = {name for name in dir(stream) if not name.startswith("_")}
    assert public == {"name", "draws", "random", "randint", "randrange",
                      "choice", "shuffled"}
    assert not hasattr(stream, "seed")
    assert not hasattr(stream, "getrandbits")
    assert not hasattr(stream, "getstate")


def test_shuffled_does_not_mutate_its_argument():
    """Shuffling authored content in place would corrupt later sessions."""
    original = list(range(20))
    copy = list(original)
    result = SeededRandom(1).stream("timing").shuffled(original)
    assert original == copy
    assert sorted(result) == copy
    assert isinstance(result, list)


def test_slots_prevent_stray_attributes():
    """Simulation state must live in captured state, not on the RNG object."""
    rng = SeededRandom(1)
    with pytest.raises(AttributeError):
        rng.extra_state = "would never be captured or restored"


# -- cross-process determinism -----------------------------------------------

_SUBPROCESS_SCRIPT = """
import json, sys
sys.path.insert(0, %(root)r)
from rewindsec.core.rng import SeededRandom, dumps_state

rng = SeededRandom(20260903)
out = {}
for name in ("mail_generation", "timing", "distractors", "persona"):
    stream = rng.stream(name)
    out[name] = [stream.random() for _ in range(5)]
    out[name + ":int"] = [stream.randint(0, 10 ** 6) for _ in range(3)]
    out[name + ":shuffled"] = stream.shuffled(list(range(10)))
print(json.dumps({"draws": out, "state": dumps_state(rng.capture_state())},
                 sort_keys=True))
"""


def _run_rng_subprocess(hash_seed):
    """Run the reference script in a fresh interpreter with a given hash seed."""
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = hash_seed
    env.pop("PYTHONSTARTUP", None)
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_SCRIPT % {"root": str(REPO_ROOT)}],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT), timeout=120)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_rng_is_deterministic_across_separate_processes():
    """Two fresh interpreters with different hash seeds must agree exactly.

    This is the test that catches accidental reliance on ``hash()`` -- which
    CPython salts per process -- or on any other process-global state. An
    in-process test cannot catch either, because both are constant within one
    run.
    """
    first = _run_rng_subprocess("0")
    second = _run_rng_subprocess("12345")
    assert first == second

    parsed = json.loads(first)
    assert parsed["draws"]["timing"]
    assert parsed["state"]


def test_subprocess_result_matches_the_in_process_result():
    """The separate interpreter agrees with this one, not merely with itself."""
    rng = SeededRandom(20260903)
    expected = {}
    for name in ("mail_generation", "timing", "distractors", "persona"):
        stream = rng.stream(name)
        expected[name] = [stream.random() for _ in range(5)]
        expected[name + ":int"] = [stream.randint(0, 10 ** 6) for _ in range(3)]
        expected[name + ":shuffled"] = stream.shuffled(list(range(10)))

    produced = json.loads(_run_rng_subprocess("7"))
    assert produced["draws"] == expected
    assert produced["state"] == dumps_state(rng.capture_state())
