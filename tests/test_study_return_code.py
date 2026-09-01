"""Return-code continuity: entropy, storage, resumption and non-disclosure.

The return code is treated as a credential throughout: high entropy, stored
only as a keyed digest, never logged, never in a URL, never exported. It is also
deliberately derived from nothing -- not the participant id, not the session id
-- so that possessing one reveals nothing about the participant it belongs to.
"""

from datetime import timedelta

import pytest

import study
from tests.study_helpers import (COMPLETE, EXPORT, GATE, IMMEDIATE_DONE,
                                 RESUME, RETENTION, answer_immediate,
                                 answer_retention, attempts_of,
                                 complete_intervention, enroll, enrollment_of,
                                 enrollment_row, first_decision,
                                 intervention_of, participant_id_of, post,
                                 research_mode, return_code_from,
                                 run_participant, shift_window)


@pytest.fixture
def study_mode(flask_app):
    with research_mode(flask_app) as configured:
        yield configured


class TestGeneration:
    def test_the_code_is_high_entropy(self, study_mode, client):
        code = return_code_from(enroll(client))
        assert len(code) >= study.RETURN_CODE_LENGTH
        assert study.RETURN_CODE_BYTES * 8 >= 128
        assert study.looks_like_code(code)

    def test_codes_are_not_predictable_or_sequential(self, study_mode,
                                                     flask_app):
        codes = {return_code_from(enroll(flask_app.test_client()))
                 for _ in range(8)}
        assert len(codes) == 8
        assert not any(code.isdigit() for code in codes)

    def test_the_code_is_not_derived_from_the_participant_or_session(
            self, study_mode, flask_app, client):
        """Possessing a code must reveal nothing about who it belongs to."""
        code = return_code_from(enroll(client))
        participant = participant_id_of(client)
        with client.session_transaction() as sess:
            session_id = sess.get("session_id")
        assert participant not in code
        assert session_id not in code
        assert code not in participant
        # And the reverse: neither identifier appears inside the code in any
        # truncated form long enough to be a derivation.
        assert participant.replace("-", "")[:8] not in code
        assert session_id.replace("-", "")[:8] not in code


class TestStorage:
    def test_the_raw_code_is_absent_from_the_database(self, study_mode,
                                                      flask_app, client):
        code = return_code_from(enroll(client))
        row = enrollment_of(flask_app, client)
        stored = [str(value) for value in row.to_dict().values()]
        assert code not in stored
        assert row.return_code_digest
        assert row.return_code_digest != code

    def test_the_digest_is_keyed_by_the_study_secret(self, study_mode,
                                                     flask_app, client):
        code = return_code_from(enroll(client))
        row = enrollment_of(flask_app, client)
        secret = flask_app.config["STUDY_CONTINUITY_SECRET"]
        assert row.return_code_digest == study.code_digest(secret, code)
        # A different key produces a different digest, so a copy of the
        # database alone does not let a code be enumerated.
        assert row.return_code_digest != study.code_digest("other", code)

    def test_the_continuity_secret_is_independent_of_the_assignment_secret(
            self, flask_app, client):
        """Allocation and continuity are separate security domains.

        Changing the assignment secret alone must not change which digest a
        given code hashes to, and vice versa -- otherwise the two purposes
        would secretly share key material.
        """
        with research_mode(flask_app, secret="assignment-a",
                           continuity_secret="continuity-x"):
            code = return_code_from(enroll(client))
            row = enrollment_of(flask_app, client)
            digest_a = row.return_code_digest

        fresh = flask_app.test_client()
        with research_mode(flask_app, secret="assignment-b",
                           continuity_secret="continuity-x"):
            response = post(fresh, RESUME, RESUME, return_code=code)
            assert response.status_code in (302, 303)
            row = enrollment_row(flask_app, participant_id_of(fresh))
            assert row.return_code_digest == digest_a

    def test_the_code_is_not_written_to_the_session(self, study_mode, client):
        code = return_code_from(enroll(client))
        with client.session_transaction() as sess:
            rendered = repr(dict(sess))
        assert code not in rendered

    def test_the_code_is_shown_exactly_once(self, study_mode, client):
        code = return_code_from(enroll(client))
        for path in (GATE, "/study/training"):
            assert code.encode() not in client.get(path,
                                                   follow_redirects=True).data


class TestResume:
    def test_an_incorrect_code_is_refused(self, study_mode, flask_app, client,
                                          other_client):
        enroll(client)
        response = post(other_client, RESUME, RESUME,
                        return_code="A" * 32)
        assert response.status_code == 400
        assert participant_id_of(other_client) is None

    def test_a_malformed_code_is_refused_the_same_way(self, study_mode,
                                                      other_client):
        for candidate in ("", "short", "!" * 32, "x" * 500):
            response = post(other_client, RESUME, RESUME,
                            return_code=candidate)
            assert response.status_code == 400

    def test_a_valid_code_resumes_the_same_participant(self, study_mode,
                                                       flask_app, client):
        code = return_code_from(enroll(client))
        first_decision(client, "follow_link_and_sign_in", 90)
        participant = participant_id_of(client)
        row = enrollment_of(flask_app, client)

        fresh = flask_app.test_client()
        response = post(fresh, RESUME, RESUME, return_code=code)
        assert response.status_code in (302, 303)
        assert participant_id_of(fresh) == participant

        resumed = enrollment_row(flask_app, participant)
        assert resumed.arm_key == row.arm_key
        assert resumed.allocation_slot == row.allocation_slot

    def test_the_arm_and_prior_responses_are_preserved(self, study_mode,
                                                       flask_app, client):
        code = run_participant(flask_app, client)
        participant = participant_id_of(client)
        before = enrollment_of(flask_app, client)
        arm, phase = before.arm_key, before.phase
        item = intervention_of(flask_app, client)
        baseline = (item.factual_choice_id, item.factual_confidence)
        immediate = attempts_of(flask_app, client,
                                study.IMMEDIATE_TRANSFER)[0].choice_id

        fresh = flask_app.test_client()
        post(fresh, RESUME, RESUME, return_code=code)

        after = enrollment_row(flask_app, participant)
        assert after.arm_key == arm
        assert after.phase == phase
        again = intervention_of(flask_app, fresh)
        assert (again.factual_choice_id, again.factual_confidence) == baseline
        assert attempts_of(flask_app, fresh,
                           study.IMMEDIATE_TRANSFER)[0].choice_id == immediate

    def test_the_session_association_is_moved_not_duplicated(self, study_mode,
                                                             flask_app,
                                                             client):
        """After a resume the old browser no longer owns the enrollment."""
        code = return_code_from(enroll(client))
        first_decision(client)
        participant = participant_id_of(client)

        fresh = flask_app.test_client()
        post(fresh, RESUME, RESUME, return_code=code)

        assert enrollment_row(flask_app,
                              participant).session_id is not None
        # The original browser still holds the participant id in its cookie,
        # but the enrollment is now bound elsewhere, so it is refused.
        response = client.get("/study/intervention")
        assert response.status_code in (302, 303)
        assert "/study" in response.headers["Location"]

    def test_resuming_lands_the_participant_where_they_left_off(
            self, study_mode, flask_app, client):
        code = run_participant(flask_app, client)
        fresh = flask_app.test_client()
        response = post(fresh, RESUME, RESUME, return_code=code)
        assert response.headers["Location"].endswith("/study/retention")

    def test_a_resumed_participant_can_finish_the_retention_probe(
            self, study_mode, flask_app, client):
        """The whole point of the mechanism: coming back a week later."""
        code = run_participant(flask_app, client)
        participant = participant_id_of(client)
        shift_window(flask_app, client, -timedelta(days=10))

        fresh = flask_app.test_client()
        post(fresh, RESUME, RESUME, return_code=code)
        answer_retention(fresh, "open_official_service", 65)

        row = enrollment_row(flask_app, participant)
        assert row.phase == study.RETENTION_COMPLETED
        assert len(attempts_of(flask_app, fresh,
                               study.RETENTION_TRANSFER)) == 1

    def test_one_participant_cannot_derive_anothers_code(self, study_mode,
                                                         flask_app, client,
                                                         other_client):
        mine = return_code_from(enroll(client))
        theirs = return_code_from(enroll(other_client))
        assert mine != theirs
        # Nothing either participant can see contains the other's code.
        for path in (GATE, RESUME, "/study/training"):
            body = client.get(path, follow_redirects=True).data
            assert theirs.encode() not in body


    def test_resume_rebind_invalidates_previous_browser_session(
            self, study_mode, flask_app, client):
        """The old browser must lose authorization, not just its client-side
        session key -- the server-side ownership check has to do this.

        Client A enrolls and can act on the study. Client B then resumes with
        A's return code. After that, A can no longer read the enrollment or
        submit anything against it, even though A's cookie/session is
        untouched -- only the row's ``session_id`` changed.
        """
        a = client
        code = return_code_from(enroll(a))
        participant = participant_id_of(a)
        with a.session_transaction() as sess:
            a_session_id = sess.get("session_id")

        b = flask_app.test_client()
        resume_response = post(b, RESUME, RESUME, return_code=code)
        assert resume_response.status_code in (302, 303)
        assert participant_id_of(b) == participant

        row = enrollment_row(flask_app, participant)
        assert row.session_id != a_session_id
        with b.session_transaction() as sess:
            b_session_id = sess.get("session_id")
        assert row.session_id == b_session_id

        # B can continue the study.
        first_decision(b, "follow_link_and_sign_in", 90)
        row = enrollment_row(flask_app, participant)
        assert row.phase != study.ENROLLED

        # A can no longer read the enrollment: every phase-specific GET
        # redirects to the gate, and the gate itself renders unauthenticated
        # (no enrollment found, exactly as if A had never enrolled).
        for path in ("/study/training", "/study/intervention",
                    "/study/comparison", "/study/reflection",
                    "/study/immediate", RETENTION, COMPLETE):
            response = a.get(path)
            assert response.status_code in (302, 303)
            assert response.headers["Location"].rstrip("/").endswith("/study")
        assert a.get(GATE).status_code == 200

        # A cannot mutate anything either: source decision, transfer probe,
        # or retention probe. Read the row's state before each attempt and
        # confirm the attempt made no difference.
        before = enrollment_row(flask_app, participant).to_dict()

        rejected = post(a, "/study/training/decision", GATE,
                        choice_id="follow_link_and_sign_in", confidence="10")
        assert rejected.status_code in (302, 303)

        rejected = post(a, "/study/immediate", GATE,
                        choice_id="verify_via_official_portal",
                        confidence="10")
        assert rejected.status_code in (302, 303)

        rejected = post(a, RETENTION, GATE,
                        choice_id="open_official_service", confidence="10")
        assert rejected.status_code in (302, 303)

        after = enrollment_row(flask_app, participant).to_dict()
        assert before == after


class TestNonDisclosure:
    def test_the_code_is_never_in_a_query_string(self, study_mode, flask_app,
                                                  client):
        """Resume is POST-only, so a code cannot reach history or a Referer."""
        rules = [r for r in flask_app.url_map.iter_rules()
                 if r.rule == "/study/resume"]
        methods = set().union(*[r.methods for r in rules])
        assert "GET" in methods and "POST" in methods
        # The GET form has no code in it, and submitting by GET does nothing.
        assert b"return_code" in client.get(RESUME).data
        assert client.get(RESUME + "?return_code=" + "A" * 32).status_code == 200
        assert participant_id_of(client) is None

    def test_the_code_is_absent_from_the_export(self, study_mode, flask_app,
                                                 client, instructor):
        code = run_participant(flask_app, client)
        row = enrollment_of(flask_app, client)
        body = instructor.get(EXPORT).data.decode()
        assert code not in body
        assert row.return_code_digest not in body
        assert "return_code" not in body

    def test_the_code_is_not_echoed_back_on_a_failed_resume(self, study_mode,
                                                             other_client):
        candidate = "Zz9" + "K" * 29
        response = post(other_client, RESUME, RESUME, return_code=candidate)
        assert candidate.encode() not in response.data

    def test_the_code_is_not_logged(self, study_mode, flask_app, client,
                                    caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            code = run_participant(flask_app, client)
        assert code not in caplog.text
