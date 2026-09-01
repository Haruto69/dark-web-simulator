"""Randomised allocation: balance, reproducibility, and the mandatory secret.

Pure tests over ``study.assignment``. The database side of allocation --
claiming a slot uniquely under concurrency -- is covered by
``tests/test_study_flow.py``.
"""

from collections import Counter

import pytest

import study
from study.errors import StudyConfigurationError

SECRET = "allocation-secret-for-tests"


class TestSecretIsMandatory:
    def test_missing_secret_fails_closed(self):
        """No default, no fallback, no Flask secret_key."""
        for absent in (None, "", 0):
            with pytest.raises(StudyConfigurationError):
                study.arm_for_slot(absent, 1)

    def test_error_names_the_environment_variable(self):
        with pytest.raises(StudyConfigurationError) as caught:
            study.require_secret("")
        assert "REWINDSEC_STUDY_ASSIGNMENT_SECRET" in str(caught.value)
        assert study.SECRET_ENV_VAR == "REWINDSEC_STUDY_ASSIGNMENT_SECRET"


class TestBlockBalance:
    def test_block_size_is_six(self):
        assert study.BLOCK_SIZE == 6
        assert study.PER_ARM_PER_BLOCK == 2

    def test_every_complete_block_is_two_of_each(self):
        """Ten full blocks, sixty participants, 2/2/2 in every one."""
        sequence = study.allocation_sequence(SECRET, 60)
        for index in range(10):
            block = sequence[index * 6:(index + 1) * 6]
            counts = Counter(block)
            assert counts[study.AWARENESS_DEBRIEF] == 2, index
            assert counts[study.FACTUAL_CONSEQUENCE] == 2, index
            assert counts[study.COUNTERFACTUAL_REPLAY] == 2, index

    def test_an_incomplete_final_block_still_allocates_normally(self):
        """A run that stops mid-block is not an error and is not stuck."""
        sequence = study.allocation_sequence(SECRET, 16)
        assert len(sequence) == 16
        assert all(arm in study.ARMS for arm in sequence)
        # The completed blocks are still exactly balanced; the partial one is
        # at worst two participants away from balance, which is the whole point
        # of blocking.
        assert Counter(sequence[:12]) == {arm: 4 for arm in study.ARMS}
        partial = Counter(sequence[12:])
        assert sum(partial.values()) == 4
        assert max(partial.values()) <= 2

    def test_blocks_are_permutations_not_a_fixed_order(self):
        """Balance must not be achieved by always issuing A, A, B, B, C, C."""
        blocks = {study.block_permutation(SECRET, i) for i in range(30)}
        assert len(blocks) > 5

    def test_slot_arithmetic(self):
        assert study.block_index(1) == 0
        assert study.block_index(6) == 0
        assert study.block_index(7) == 1
        assert study.block_position(1) == 0
        assert study.block_position(7) == 0
        with pytest.raises(StudyConfigurationError):
            study.block_index(0)


class TestReproducibility:
    def test_same_secret_same_slots_same_allocation(self):
        first = study.allocation_sequence(SECRET, 30)
        second = study.allocation_sequence(SECRET, 30)
        assert first == second

    def test_allocation_is_a_function_of_the_slot_alone(self):
        """Slot 13 is the same arm whether it is reached first or last."""
        whole = study.allocation_sequence(SECRET, 30)
        assert study.arm_for_slot(SECRET, 13) == whole[12]
        assert study.allocation_sequence(SECRET, 5, first_slot=13) == whole[12:17]

    def test_a_different_secret_changes_the_permutation(self):
        mine = [study.block_permutation(SECRET, i) for i in range(20)]
        theirs = [study.block_permutation("a-different-secret", i)
                  for i in range(20)]
        assert mine != theirs
        assert sum(1 for a, b in zip(mine, theirs) if a != b) >= 1

    def test_a_different_protocol_version_changes_the_permutation(self):
        """A second protocol allocates independently of the first."""
        one = [study.block_permutation(SECRET, i, protocol_version=1)
               for i in range(20)]
        two = [study.block_permutation(SECRET, i, protocol_version=2)
               for i in range(20)]
        assert one != two

    def test_the_secret_is_never_returned_or_embedded(self):
        """Nothing derived from the secret leaks it back."""
        secret = "a-very-distinctive-secret-value"
        rendered = repr(study.allocation_sequence(secret, 12))
        assert secret not in rendered
        for arm in study.allocation_sequence(secret, 12):
            assert arm in study.ARMS


class TestUnpredictability:
    def test_the_arms_already_issued_do_not_reveal_the_next(self):
        """Two secrets agreeing on a prefix need not agree on what follows.

        Not a formal unpredictability proof -- the guarantee comes from HMAC --
        but it does catch an implementation that ignored the key, which would
        make every deployment's sequence identical and therefore public.
        """
        a = study.allocation_sequence("secret-a", 60)
        b = study.allocation_sequence("secret-b", 60)
        assert a != b
