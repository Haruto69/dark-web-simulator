"""Allocation integrity over HTTP, the instructor dashboard, and the export.

This file covers the properties that make the pilot's data defensible rather
than merely present: allocation is unique, balanced and immutable; the
dashboard describes without inferring; and the export carries the research
correlation identifier and nothing that could identify a browser or a person.
"""

import csv
import io
import re
from collections import Counter
from datetime import timedelta

import pytest

import study
from tests.study_helpers import (ADMIN, EXPORT, answer_immediate,
                                 answer_retention, attempts_of,
                                 complete_intervention, enroll, enrollment_of,
                                 first_decision, intervention_of, post,
                                 research_mode, shift_window)


@pytest.fixture
def study_mode(flask_app):
    with research_mode(flask_app) as configured:
        yield configured


def enrol_many(flask_app, count):
    """``count`` fresh browsers, each enrolled once."""
    clients = []
    for _ in range(count):
        browser = flask_app.test_client()
        enroll(browser)
        clients.append(browser)
    return clients


def rows_for(flask_app, clients):
    return [enrollment_of(flask_app, browser) for browser in clients]


def export_table(instructor):
    response = instructor.get(EXPORT)
    assert response.status_code == 200
    text = response.data.decode("utf-8")
    return text, list(csv.DictReader(io.StringIO(text)))


class TestAllocationIntegrity:
    def test_every_enrollment_has_exactly_one_valid_arm(self, study_mode,
                                                        flask_app):
        rows = rows_for(flask_app, enrol_many(flask_app, 7))
        for row in rows:
            assert row.arm_key in study.ARMS

    def test_allocation_slots_are_unique(self, study_mode, flask_app):
        import app as app_module
        enrol_many(flask_app, 6)
        with flask_app.app_context():
            slots = [row.allocation_slot
                     for row in app_module.StudyEnrollment.query.all()]
        assert len(slots) == len(set(slots))

    def test_participant_ids_are_unique(self, study_mode, flask_app):
        import app as app_module
        enrol_many(flask_app, 6)
        with flask_app.app_context():
            ids = [row.participant_id
                   for row in app_module.StudyEnrollment.query.all()]
        assert len(ids) == len(set(ids))

    def test_the_arm_matches_the_allocator_for_its_slot(self, study_mode,
                                                        flask_app):
        secret = flask_app.config["STUDY_ASSIGNMENT_SECRET"]
        for row in rows_for(flask_app, enrol_many(flask_app, 8)):
            assert row.arm_key == study.arm_for_slot(secret,
                                                     row.allocation_slot)

    def test_the_arm_never_changes(self, study_mode, flask_app, client):
        """Through the whole flow, including a retention response."""
        enroll(client)
        arm = enrollment_of(flask_app, client).arm_key
        first_decision(client, "follow_link_and_sign_in", 90)
        assert enrollment_of(flask_app, client).arm_key == arm
        complete_intervention(flask_app, client)
        assert enrollment_of(flask_app, client).arm_key == arm
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))
        answer_retention(client)
        assert enrollment_of(flask_app, client).arm_key == arm

    def test_an_instructor_has_no_route_that_edits_an_assignment(
            self, study_mode, flask_app):
        """Every study admin route is read-only."""
        admin_rules = [r for r in flask_app.url_map.iter_rules()
                       if r.rule.startswith("/study/admin")]
        assert admin_rules
        for rule in admin_rules:
            assert rule.methods & {"POST", "PUT", "PATCH", "DELETE"} == set()


class TestBlockBalance:
    def test_six_enrollments_span_blocks_that_stay_balanced(self, study_mode,
                                                            flask_app):
        """Every *complete* block of six is 2/2/2, wherever it starts.

        The suite shares one database, so these six enrollments do not
        necessarily begin at slot 1. The assertion is therefore made over the
        complete blocks the allocator defines, which is what balance actually
        means.
        """
        import app as app_module
        enrol_many(flask_app, 18)
        with flask_app.app_context():
            rows = (app_module.StudyEnrollment.query
                    .order_by(app_module.StudyEnrollment.allocation_slot.asc())
                    .all())
            by_slot = {row.allocation_slot: row.arm_key for row in rows}

        blocks = {}
        for slot, arm in by_slot.items():
            blocks.setdefault(study.block_index(slot), []).append(arm)

        complete = [arms for arms in blocks.values()
                    if len(arms) == study.BLOCK_SIZE]
        assert complete, "no complete block was allocated"
        for arms in complete:
            counts = Counter(arms)
            assert counts[study.AWARENESS_DEBRIEF] == 2
            assert counts[study.FACTUAL_CONSEQUENCE] == 2
            assert counts[study.COUNTERFACTUAL_REPLAY] == 2

    def test_an_incomplete_block_is_not_an_error(self, study_mode, flask_app):
        """Enrolling one more participant mid-block works normally."""
        browser = flask_app.test_client()
        assert enroll(browser).status_code == 200
        assert enrollment_of(flask_app, browser).arm_key in study.ARMS


class TestImmutableResearchData:
    def test_the_first_decision_never_changes(self, study_mode, flask_app,
                                              client):
        enroll(client)
        first_decision(client, "follow_link_and_sign_in", 90)
        for choice in ("report_message", "inspect_sender"):
            post(client, "/study/training/decision", "/study/intervention",
                 choice_id=choice, confidence="5")
        item = intervention_of(flask_app, client)
        assert item.factual_choice_id == "follow_link_and_sign_in"
        assert item.factual_confidence == 90

    def test_the_immediate_attempt_never_changes(self, study_mode, flask_app,
                                                 client):
        enroll(client)
        first_decision(client)
        complete_intervention(flask_app, client)
        answer_immediate(client, "verify_via_official_portal", 70)
        answer_immediate(client, "scan_and_sign_in", 5)
        rows = attempts_of(flask_app, client, study.IMMEDIATE_TRANSFER)
        assert len(rows) == 1
        assert rows[0].choice_id == "verify_via_official_portal"

    def test_the_retention_attempt_never_changes(self, study_mode, flask_app,
                                                 client):
        enroll(client)
        first_decision(client)
        complete_intervention(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))
        answer_retention(client, "open_official_service", 65)
        answer_retention(client, "follow_message_and_sign_in", 99)
        rows = attempts_of(flask_app, client, study.RETENTION_TRANSFER)
        assert len(rows) == 1
        assert rows[0].choice_id == "open_official_service"


class TestDashboard:
    def test_it_renders_descriptive_counts(self, study_mode, flask_app,
                                           client, instructor):
        enroll(client)
        first_decision(client, "follow_link_and_sign_in", 90)
        complete_intervention(flask_app, client)
        answer_immediate(client)
        body = instructor.get(ADMIN).data.decode()
        assert "Study operations" in body
        assert "Participant flow" in body
        assert study.PROTOCOL_KEY in body

    def test_no_raw_session_id_is_rendered(self, study_mode, flask_app, client,
                                           instructor):
        enroll(client)
        with client.session_transaction() as sess:
            session_id = sess["session_id"]
        assert session_id.encode() not in instructor.get(ADMIN).data

    def test_no_return_code_digest_is_rendered(self, study_mode, flask_app,
                                               client, instructor):
        enroll(client)
        digest = enrollment_of(flask_app, client).return_code_digest
        assert digest.encode() not in instructor.get(ADMIN).data

    def test_participants_appear_under_a_pseudonymous_label(self, study_mode,
                                                            flask_app, client,
                                                            instructor):
        enroll(client)
        row = enrollment_of(flask_app, client)
        body = instructor.get(ADMIN).data.decode()
        assert row.display_dict()["study_label"] in body
        assert body.count("P-") >= 1

    def test_no_statistical_significance_language(self, study_mode,
                                                  instructor):
        """No inferential claim is made, and the page says so.

        The disclaimer paragraph necessarily *names* the things it disclaims,
        so it is removed before the page is scanned; what must not appear
        anywhere else is a claim.
        """
        body = instructor.get(ADMIN).data.decode().lower()
        assert "no statistical test" in body
        assert "does not constitute ethics approval" in body
        disclaimed = re.sub(
            r"descriptive operational counts only\..*?registration\.", "",
            body, flags=re.S)
        assert "no statistical test" not in disclaimed
        for token in ("p-value", "p &lt;", "significan", "effect size",
                      "cohen", "confidence interval", "improved",
                      "outperform", "better than", "more effective"):
            assert token not in disclaimed

    def test_missing_retention_is_reported_as_missing(self, study_mode,
                                                      flask_app, client,
                                                      instructor):
        """An expired window is counted as expired, never as a risky answer."""
        enroll(client)
        first_decision(client)
        complete_intervention(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=20))
        with flask_app.app_context():
            import app as app_module
            report = app_module.study_service().dashboard()
        arm = enrollment_of(flask_app, client).arm_key
        assert report["retention_expired"][arm] >= 1
        assert sum(report["retention_quality"][arm].values()) == 0

    def test_the_dashboard_counts_only(self, study_mode, flask_app,
                                       instructor):
        with flask_app.app_context():
            import app as app_module
            report = app_module.study_service().dashboard()
        for key in ("assigned", "intervention_completed", "immediate_completed",
                    "retention_completed", "retention_expired"):
            assert all(isinstance(value, int)
                       for value in report[key].values())
        assert "p_value" not in report
        assert "effect_size" not in report


class TestExport:
    def test_header_matches_the_declared_columns(self, study_mode, flask_app,
                                                 instructor):
        text, _rows = export_table(instructor)
        with flask_app.app_context():
            import app as app_module
            expected = app_module.study_service().EXPORT_COLUMNS
        assert tuple(text.splitlines()[0].split(",")) == expected

    def test_one_row_per_enrollment(self, study_mode, flask_app, instructor):
        import app as app_module
        _text, rows = export_table(instructor)
        with flask_app.app_context():
            assert len(rows) == app_module.StudyEnrollment.query.count()

    def test_it_carries_the_research_identifier_and_the_arm(self, study_mode,
                                                            flask_app, client,
                                                            instructor):
        enroll(client)
        row = enrollment_of(flask_app, client)
        _text, rows = export_table(instructor)
        mine = [r for r in rows if r["participant_id"] == row.participant_id]
        assert len(mine) == 1
        assert mine[0]["arm_key"] == row.arm_key
        assert mine[0]["allocation_slot"] == str(row.allocation_slot)
        assert mine[0]["protocol_key"] == study.PROTOCOL_KEY

    def test_it_carries_no_session_id(self, study_mode, flask_app, client,
                                      instructor):
        enroll(client)
        with client.session_transaction() as sess:
            session_id = sess["session_id"]
        text, rows = export_table(instructor)
        assert "session_id" not in rows[0]
        assert session_id not in text

    def test_it_carries_no_return_code_data_or_access_code(self, study_mode,
                                                           flask_app, client,
                                                           instructor):
        from tests.study_helpers import STUDY_ACCESS_CODE
        enroll(client)
        digest = enrollment_of(flask_app, client).return_code_digest
        text, rows = export_table(instructor)
        assert digest not in text
        assert STUDY_ACCESS_CODE not in text
        for column in rows[0]:
            assert "return_code" not in column
            assert "access_code" not in column

    def test_missing_measurements_are_empty_not_zero(self, study_mode,
                                                     flask_app, client,
                                                     instructor):
        enroll(client)
        row = enrollment_of(flask_app, client)
        _text, rows = export_table(instructor)
        mine = [r for r in rows if r["participant_id"] == row.participant_id][0]
        for column in ("baseline_response_quality", "immediate_choice_id",
                       "retention_response_quality", "retention_confidence"):
            assert mine[column] == ""

    def test_a_completed_participant_exports_every_measurement(
            self, study_mode, flask_app, client, instructor):
        enroll(client)
        first_decision(client, "follow_link_and_sign_in", 90)
        complete_intervention(flask_app, client)
        answer_immediate(client, "verify_via_official_portal", 70)
        shift_window(flask_app, client, -timedelta(days=10))
        answer_retention(client, "open_official_service", 65)

        row = enrollment_of(flask_app, client)
        _text, rows = export_table(instructor)
        mine = [r for r in rows if r["participant_id"] == row.participant_id][0]
        assert mine["baseline_choice_id"] == "follow_link_and_sign_in"
        assert mine["baseline_response_quality"] == "RISKY"
        assert mine["baseline_confidence"] == "90"
        assert mine["intervention_completed"] == "true"
        assert mine["immediate_probe_key"] == "quishing_portal_qr"
        assert mine["immediate_response_quality"] == "PROTECTIVE"
        assert mine["retention_probe_key"] == "smishing_account_notice"
        assert mine["retention_response_quality"] == "PROTECTIVE"
        assert mine["retention_open_at"] and mine["retention_close_at"]
        assert mine["retention_completed_at"]

    def test_arm_c_exports_its_pair_evidence(self, study_mode, flask_app,
                                             client, instructor):
        from tests.test_study_flow import force_arm
        enroll(client)
        force_arm(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client, "follow_link_and_sign_in", 90)
        complete_intervention(flask_app, client)

        row = enrollment_of(flask_app, client)
        _text, rows = export_table(instructor)
        mine = [r for r in rows if r["participant_id"] == row.participant_id][0]
        assert mine["training_execution_id"]
        assert mine["pair_id"]
        assert mine["baseline_verified"] == "true"
        assert mine["reflection_selected_preferred"] == "true"

    def test_arms_a_and_b_export_no_pair_evidence(self, study_mode, flask_app,
                                                  client, instructor):
        from tests.test_study_flow import force_arm
        for arm in (study.AWARENESS_DEBRIEF, study.FACTUAL_CONSEQUENCE):
            browser = flask_app.test_client()
            enroll(browser)
            force_arm(flask_app, browser, arm)
            first_decision(browser)
            complete_intervention(flask_app, browser)
            row = enrollment_of(flask_app, browser)
            _text, rows = export_table(instructor)
            mine = [r for r in rows
                    if r["participant_id"] == row.participant_id][0]
            assert mine["training_execution_id"] == ""
            assert mine["pair_id"] == ""
            assert mine["baseline_verified"] == ""
            assert mine["reflection_selected_preferred"] == ""

    def test_csv_escaping_is_correct(self, study_mode, flask_app, instructor):
        """Every field round-trips through a real CSV reader.

        Nothing in this export is learner-authored, so there is no attacker-
        controlled comma to escape -- but the file is written by ``csv`` rather
        than by string concatenation precisely so that stays true by
        construction rather than by luck.
        """
        text, rows = export_table(instructor)
        with flask_app.app_context():
            import app as app_module
            columns = app_module.study_service().EXPORT_COLUMNS
        for row in rows:
            assert set(row) == set(columns)
        assert text.endswith("\n")

    def test_it_is_served_as_a_csv_attachment(self, study_mode, instructor):
        response = instructor.get(EXPORT)
        assert response.mimetype == "text/csv"
        assert "attachment" in response.headers["Content-Disposition"]

    def test_no_statistical_columns_exist(self, study_mode, flask_app,
                                          instructor):
        with flask_app.app_context():
            import app as app_module
            columns = app_module.study_service().EXPORT_COLUMNS
        for column in columns:
            for token in ("p_value", "significance", "effect", "improvement",
                          "score"):
                assert token not in column
