"""Trainer-side fixture records for the RewindSec 2.0 UI prototype.

Fictional people, fictional cohorts, fictional results. Identity data is kept
to the minimum a trainer console needs: a display name, a reference and a
cohort. No address, no date of birth, no contact detail, nothing that would be
personal data if these people existed.

Every number on the trainer screens is demonstration data. None of it was
measured, and none of it may be cited.

Architecture boundaries represented here:

* §25 -- the trainer sees records, results and analytics. There is no control
  anywhere in these screens for the organisation profile, threat-family
  probabilities, event sequencing, learner difficulty or a learner's
  self-directed focus.
* §26 -- an assessment is defined by *required scored interactions*, never by
  a raw event count.
* §27 -- an assignment records where it came from. A learner who already
  receives an assessment through a group keeps that provenance separately from
  a later direct assignment; the two are never merged.
"""

TRAINER = {
    "name": "Dr. Halima Yusuf",
    "role": "Programme Lead",
    "organization": "Northbridge Systems — Learning & Development",
}

STUDENTS = [
    {"id": "stu-aarti-venkatesh", "name": "Aarti Venkatesh", "ref": "NB-4471",
     "cohort": "Operations", "initials": "AV", "status": "active"},
    {"id": "stu-devika-raghavan", "name": "Devika Raghavan", "ref": "NB-4488",
     "cohort": "Operations", "initials": "DR", "status": "active"},
    {"id": "stu-samuel-adeyemi", "name": "Samuel Adeyemi", "ref": "NB-4502",
     "cohort": "Operations", "initials": "SA", "status": "active"},
    {"id": "stu-marta-kowalczyk", "name": "Marta Kowalczyk", "ref": "NB-4517",
     "cohort": "Finance", "initials": "MK", "status": "active"},
    {"id": "stu-jonah-eriksen", "name": "Jonah Eriksen", "ref": "NB-4523",
     "cohort": "Finance", "initials": "JE", "status": "active"},
    {"id": "stu-nadia-belkacem", "name": "Nadia Belkacem", "ref": "NB-4530",
     "cohort": "Technology", "initials": "NB", "status": "active"},
    {"id": "stu-hector-salas", "name": "Hector Salas", "ref": "NB-4541",
     "cohort": "Technology", "initials": "HS", "status": "onboarding"},
    {"id": "stu-yuki-tanaka", "name": "Yuki Tanaka", "ref": "NB-4556",
     "cohort": "Operations", "initials": "YT", "status": "active"},
]

GROUPS = [
    {
        "id": "grp-ops-a",
        "name": "Operations — Cohort A",
        "created": "4 August 2026",
        "members": ["stu-aarti-venkatesh", "stu-devika-raghavan",
                    "stu-samuel-adeyemi", "stu-yuki-tanaka"],
    },
    {
        # Aarti is in this group *and* holds "Payment authorisation" directly
        # (asg-4). That pairing is deliberate: it gives the student record a
        # standing example of the two provenances architecture §27 requires
        # to stay separate, without a trainer having to reproduce the
        # duplicate-assignment flow first.
        "id": "grp-finance-payments",
        "name": "Finance — payment handlers",
        "created": "17 June 2026",
        "members": ["stu-marta-kowalczyk", "stu-jonah-eriksen",
                    "stu-devika-raghavan", "stu-aarti-venkatesh"],
    },
    {
        "id": "grp-new-starters",
        "name": "New starters — Q3 intake",
        "created": "1 September 2026",
        "members": ["stu-hector-salas", "stu-nadia-belkacem",
                    "stu-yuki-tanaka"],
    },
]

ASSESSMENTS = [
    {
        "id": "as-q3-judgement",
        "name": "Q3 judgement check",
        "focus": "mixed",
        "required_interactions": 6,
        "window": "8 – 26 September 2026",
        "status": "open",
        "note": "Six scored interactions. Benign traffic between them varies "
                "by attempt and is not counted.",
    },
    {
        "id": "as-payments",
        "name": "Payment authorisation",
        "focus": "bec",
        "required_interactions": 4,
        "window": "1 – 30 September 2026",
        "status": "open",
        "note": "Finance-facing. Weighted toward payment and authority "
                "requests.",
    },
    {
        "id": "as-attachment-handling",
        "name": "Attachment handling",
        "focus": "ransomware",
        "required_interactions": 5,
        "window": "15 September – 3 October 2026",
        "status": "scheduled",
        "note": "Opens after the September attachment briefing.",
    },
    {
        "id": "as-baseline-august",
        "name": "August baseline",
        "focus": "mixed",
        "required_interactions": 5,
        "window": "4 – 22 August 2026",
        "status": "closed",
        "note": "Closed. Retained for comparison only.",
    },
]

#: Assignment provenance (architecture §27). ``source`` is "group" or
#: "direct"; a learner may hold both for the same assessment and the two rows
#: stay distinct.
ASSIGNMENTS = [
    {"id": "asg-1", "assessment_id": "as-q3-judgement", "source": "group",
     "group_id": "grp-ops-a", "student_id": None,
     "created": "8 September 2026", "created_by": "Dr. Halima Yusuf"},
    {"id": "asg-2", "assessment_id": "as-payments", "source": "group",
     "group_id": "grp-finance-payments", "student_id": None,
     "created": "1 September 2026", "created_by": "Dr. Halima Yusuf"},
    {"id": "asg-3", "assessment_id": "as-attachment-handling",
     "source": "group", "group_id": "grp-new-starters", "student_id": None,
     "created": "2 September 2026", "created_by": "Dr. Halima Yusuf"},
    {"id": "asg-4", "assessment_id": "as-payments", "source": "direct",
     "group_id": None, "student_id": "stu-aarti-venkatesh",
     "created": "3 September 2026", "created_by": "Dr. Halima Yusuf"},
    {"id": "asg-5", "assessment_id": "as-baseline-august", "source": "group",
     "group_id": "grp-ops-a", "student_id": None,
     "created": "4 August 2026", "created_by": "Dr. Halima Yusuf"},
]

#: Session records. ``profile`` is the *derived* scaffolding profile the
#: trainer may view but never sets.
SESSIONS = [
    {"id": "ses-8801", "student_id": "stu-aarti-venkatesh", "focus": "mixed",
     "mode": "simulation", "profile": "Standard scaffolding · v0",
     "started": "4 Sep 2026 09:02", "duration": "24 min", "status": "complete",
     "score": 62, "assessment_id": None,
     "highlights": ["Credential submitted on a look-alike payroll page",
                    "Reported the second look-alike message"]},
    {"id": "ses-8814", "student_id": "stu-aarti-venkatesh", "focus": "phishing",
     "mode": "practice", "profile": "High scaffolding · v0",
     "started": "5 Sep 2026 11:40", "duration": "18 min", "status": "complete",
     "score": 74, "assessment_id": None,
     "highlights": ["Checked payroll on a known channel before acting"]},
    {"id": "ses-8822", "student_id": "stu-devika-raghavan", "focus": "bec",
     "mode": "assessment", "profile": "Minimal scaffolding · v0",
     "started": "5 Sep 2026 14:05", "duration": "21 min", "status": "complete",
     "score": 81, "assessment_id": "as-payments",
     "highlights": ["Called the supplier number of record",
                    "Left one benign request unanswered"]},
    {"id": "ses-8830", "student_id": "stu-samuel-adeyemi", "focus": "mixed",
     "mode": "simulation", "profile": "Standard scaffolding · v0",
     "started": "5 Sep 2026 15:22", "duration": "12 min",
     "status": "abandoned", "score": None, "assessment_id": None,
     "highlights": ["Left before the first consequence chain settled"]},
    {"id": "ses-8841", "student_id": "stu-marta-kowalczyk", "focus": "bec",
     "mode": "assessment", "profile": "Minimal scaffolding · v0",
     "started": "6 Sep 2026 09:15", "duration": "26 min", "status": "complete",
     "score": 69, "assessment_id": "as-payments",
     "highlights": ["Replied to the requester to confirm the account change"]},
    {"id": "ses-8849", "student_id": "stu-jonah-eriksen", "focus": "bec",
     "mode": "practice", "profile": "High scaffolding · v0",
     "started": "6 Sep 2026 10:02", "duration": "31 min", "status": "complete",
     "score": 58, "assessment_id": None,
     "highlights": ["Payment released without an independent check",
                    "Contained well once Finance queried it"]},
    {"id": "ses-8853", "student_id": "stu-nadia-belkacem",
     "focus": "ransomware", "mode": "simulation",
     "profile": "Standard scaffolding · v0",
     "started": "6 Sep 2026 13:44", "duration": "22 min", "status": "complete",
     "score": 88, "assessment_id": None,
     "highlights": ["Attachment left unopened", "Reported within 90 seconds"]},
    {"id": "ses-8860", "student_id": "stu-yuki-tanaka", "focus": "mfa",
     "mode": "practice", "profile": "High scaffolding · v0",
     "started": "6 Sep 2026 16:10", "duration": "15 min", "status": "complete",
     "score": 47, "assessment_id": None,
     "highlights": ["Denied a genuine sign-in, then approved an unexpected "
                    "one"]},
    {"id": "ses-8871", "student_id": "stu-devika-raghavan", "focus": "mixed",
     "mode": "simulation", "profile": "Standard scaffolding · v0",
     "started": "7 Sep 2026 09:31", "duration": "27 min", "status": "complete",
     "score": 77, "assessment_id": None,
     "highlights": ["Directory used before acting on two requests"]},
    {"id": "ses-8884", "student_id": "stu-hector-salas", "focus": "phishing",
     "mode": "practice", "profile": "High scaffolding · v0",
     "started": "7 Sep 2026 11:18", "duration": "9 min", "status": "in_progress",
     "score": None, "assessment_id": None,
     "highlights": ["In progress"]},
    {"id": "ses-8890", "student_id": "stu-samuel-adeyemi", "focus": "mfa",
     "mode": "simulation", "profile": "Standard scaffolding · v0",
     "started": "7 Sep 2026 14:47", "duration": "19 min", "status": "complete",
     "score": 71, "assessment_id": None,
     "highlights": ["Approved own sign-in, denied the unexpected one"]},
    {"id": "ses-8902", "student_id": "stu-yuki-tanaka", "focus": "mixed",
     "mode": "assessment", "profile": "Minimal scaffolding · v0",
     "started": "8 Sep 2026 10:05", "duration": "23 min", "status": "complete",
     "score": 64, "assessment_id": "as-q3-judgement",
     "highlights": ["Two of six scored interactions handled without "
                    "investigation"]},
]

#: Aggregate cards on the dashboard. Demonstration values.
DASHBOARD_METRICS = [
    {"id": "students", "label": "Students", "value": "8",
     "sub": "3 cohorts"},
    {"id": "sessions_week", "label": "Sessions this week", "value": "12",
     "sub": "10 complete · 1 in progress · 1 abandoned"},
    {"id": "assessments_open", "label": "Assessments open", "value": "2",
     "sub": "1 scheduled · 1 closed"},
    {"id": "attempts_outstanding", "label": "Attempts outstanding",
     "value": "5", "sub": "across 2 open assessments"},
]

#: Extensible metric rows (architecture §24): versioned records rather than
#: columns hardwired onto the session model.
COHORT_METRICS = [
    {"id": "relevant_evidence_use", "label": "Relevant evidence inspected",
     "value": "54%", "note": "Share of decision-relevant items that were "
                             "actually opened before the decision.",
     "version": "demo-metric-v0"},
    {"id": "false_positive_rate", "label": "Legitimate mail reported",
     "value": "18%", "note": "Genuine messages reported as suspicious.",
     "version": "demo-metric-v0"},
    {"id": "credential_submissions", "label": "Credential submissions",
     "value": "3 of 12 sessions", "note": "Sign-in completed on a look-alike "
                                          "destination.",
     "version": "demo-metric-v0"},
    {"id": "known_channel_verification", "label": "Known-channel verification",
     "value": "41%", "note": "Requests checked on a channel the request did "
                             "not supply.",
     "version": "demo-metric-v0"},
    {"id": "unsafe_attachment_opens", "label": "Unsafe attachments opened",
     "value": "2 of 12 sessions", "note": "Macro-bearing attachment opened "
                                          "from mail.",
     "version": "demo-metric-v0"},
    {"id": "containment_quality", "label": "Contained at first symptom",
     "value": "50%", "note": "Of sessions where a file incident started.",
     "version": "demo-metric-v0"},
]
