"""Mode semantics, event timelines, consequence chains and debrief fixtures.

Everything here is authored presentation data for the UI prototype. It is a
*representation* of the mechanisms the architecture specifies, not those
mechanisms:

* ``CADENCE`` describes how events feel in each mode. It is not a
  context-conditioned hazard scheduler; there is no pressure state, no
  eligibility gate and no seeded RNG stream behind it.
* ``TIMELINES`` are fixed authored sequences per focus. Real focus behaviour
  will emerge from threat-family pressure, not from a list.
* ``CONSEQUENCE_CHAINS`` are authored cause→effect trees with authored delays.
  They stand in for the causal consequence graph. Each step names its causal
  parent so the debrief can show a chain rather than a chronology, which is
  what makes the idea judgeable by hand -- but nothing derives them.
* ``SAFER_ALTERNATIVES`` backs the provisional comparison screen. Section 12
  of the architecture leaves that screen unfrozen; this batch exists partly to
  decide whether it survives.
* ``SCORE_DIMENSIONS`` and the weights beside them are demonstration values.
  They are not a scoring engine, not validated, and not evidence of anything.
"""

# ---------------------------------------------------------------------------
# Entry flow
# ---------------------------------------------------------------------------
#
# There is deliberately no Easy/Medium/Hard control. Architecture §3: the
# learner picks focus and mode; the effective scaffolding profile is derived.

FOCUS_OPTIONS = [
    {
        "id": "phishing",
        "label": "Phishing",
        "summary": "Messages that try to collect a sign-in.",
        "detail": "Emphasises credential lures and look-alike destinations. "
                  "Ordinary work continues around them.",
    },
    {
        "id": "ransomware",
        "label": "Ransomware",
        "summary": "Attachments, file damage and the response to it.",
        "detail": "Emphasises document-borne incidents and what containment "
                  "looks like once files start failing.",
    },
    {
        "id": "mfa",
        "label": "MFA",
        "summary": "Approval requests you did and did not start.",
        "detail": "Emphasises authentication prompts. Both kinds occur; "
                  "refusing everything has a cost.",
    },
    {
        "id": "bec",
        "label": "BEC",
        "summary": "Payment and authority requests inside real threads.",
        "detail": "Emphasises payment redirection and process compliance "
                  "rather than spotting a bad domain.",
    },
    {
        "id": "mixed",
        "label": "Mixed",
        "summary": "No emphasis. Whatever the day brings.",
        "detail": "All families are eligible. Nothing is weighted toward you.",
    },
]

MODES = [
    {
        "id": "practice",
        "label": "Practice",
        "summary": "Learning, at your pace.",
        "semantics": [
            "Events wait for you to finish the one in front of you.",
            "Investigation tools are prominent.",
            "A good decision is confirmed as a good decision.",
            "After an unsafe decision, consequences still happen — then the "
            "safer route is explained.",
            "You can restart.",
        ],
        "flags": {
            "coaching": True,
            "explicit_confirmation": True,
            "safer_alternative": True,
            "retry_visible": True,
            "score_visible_during_attempt": False,
            "investigation_hints": True,
            "consequence_delay_scale": 0.45,
        },
    },
    {
        "id": "simulation",
        "label": "Simulation",
        "summary": "A working day that does not wait for you.",
        "semantics": [
            "Events arrive on their own, irregularly.",
            "A good decision produces the ordinary result of a good decision, "
            "not praise.",
            "Unsafe decisions have consequences that persist.",
            "Once a consequence chain settles, the safer route is explained "
            "before the day continues.",
            "The workstation is never rolled back.",
        ],
        "flags": {
            "coaching": False,
            "explicit_confirmation": False,
            "safer_alternative": True,
            "retry_visible": False,
            "score_visible_during_attempt": False,
            "investigation_hints": False,
            "consequence_delay_scale": 1.0,
        },
    },
    {
        "id": "assessment",
        "label": "Assessment",
        "summary": "Evaluation. Nothing is explained until the end.",
        "semantics": [
            "Events arrive close together and can pile up.",
            "No coaching, no confirmation, no explanation during the attempt.",
            "Consequences still happen; they are simply not commented on.",
            "Nothing about your score is shown until you finish.",
            "No restart inside the attempt.",
        ],
        "flags": {
            "coaching": False,
            "explicit_confirmation": False,
            "safer_alternative": False,
            "retry_visible": False,
            "score_visible_during_attempt": False,
            "investigation_hints": False,
            "consequence_delay_scale": 1.0,
        },
    },
]

#: How primary events arrive. Prototype values are compressed so the whole
#: experience can be judged in a sitting; production timing is specified in
#: architecture §10 and is not implemented here.
CADENCE = {
    "practice": {"style": "paced", "base_ms": 0, "jitter_ms": 0,
                 "max_wait_ms": 90000,
                 "note": "Learner-paced. The next event is released when you "
                         "have dealt with the current one."},
    "simulation": {"style": "timed", "base_ms": 42000, "jitter_ms": 16000,
                   "max_wait_ms": 0,
                   "note": "Roughly a minute apart, irregular. May arrive "
                           "sooner once you resolve something."},
    "assessment": {"style": "timed", "base_ms": 14000, "jitter_ms": 6000,
                   "max_wait_ms": 0,
                   "note": "Compressed and continuous. Events can arrive "
                           "while you are still working on the last one."},
}

#: Authored per-focus sequences. A production scheduler derives these from
#: context eligibility and threat-family pressure; this is a stand-in whose
#: only job is to make the *feel* judgeable.
TIMELINES = {
    "phishing": [
        {"type": "mail", "ref": "m-travel-reimb"},
        {"type": "mail", "ref": "m-payroll-restructure"},
        {"type": "mail", "ref": "m-headcount"},
        {"type": "mail", "ref": "m-newsletter"},
        {"type": "mfa", "ref": "mfa-unexpected"},
    ],
    "ransomware": [
        {"type": "mail", "ref": "m-travel-reimb"},
        {"type": "mail", "ref": "m-rate-card"},
        {"type": "mail", "ref": "m-headcount"},
        {"type": "mail", "ref": "m-newsletter"},
        {"type": "mail", "ref": "m-payroll-restructure"},
    ],
    "mfa": [
        {"type": "mail", "ref": "m-travel-reimb"},
        {"type": "mfa", "ref": "mfa-unexpected"},
        {"type": "mail", "ref": "m-headcount"},
        {"type": "mail", "ref": "m-newsletter"},
        {"type": "mail", "ref": "m-payroll-restructure"},
    ],
    "bec": [
        {"type": "mail", "ref": "m-travel-reimb"},
        {"type": "mail", "ref": "m-invoice-amend"},
        {"type": "mail", "ref": "m-headcount"},
        {"type": "mail", "ref": "m-newsletter"},
        {"type": "mfa", "ref": "mfa-unexpected"},
    ],
    "mixed": [
        {"type": "mail", "ref": "m-travel-reimb"},
        {"type": "mail", "ref": "m-payroll-restructure"},
        {"type": "mail", "ref": "m-headcount"},
        {"type": "mail", "ref": "m-rate-card"},
        {"type": "mail", "ref": "m-newsletter"},
        {"type": "mail", "ref": "m-invoice-amend"},
        {"type": "mfa", "ref": "mfa-unexpected"},
    ],
}

# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------
#
# ``class`` is the authored judgement used only by the debrief and the
# comparison screen. It is never shown in the workstation while the decision is
# being made.
#
#   unsafe            -- materially worsened the world
#   safe              -- the intended handling
#   over_suspicious   -- defensive action applied to legitimate work
#   incomplete        -- legitimate work left undone
#   recovery_good     -- good handling *after* an incident had started
#   recovery_poor     -- poor handling after an incident had started
#   neutral           -- no material effect either way

DECISIONS = {
    "d-phish-credentials": {
        "label": "Signed in on the employee record page",
        "family": "phishing", "class": "unsafe",
        "dimensions": ["security_judgment", "evidence_use",
                       "verification_discipline"],
        "chain": "chain-credentials",
    },
    "d-phish-report": {
        "label": "Reported the payroll confirmation message",
        "family": "phishing", "class": "safe",
        "dimensions": ["security_judgment", "incident_response"],
        "chain": "chain-reported-hostile",
    },
    "d-phish-verify": {
        "label": "Checked with payroll on a known channel first",
        "family": "phishing", "class": "safe",
        "dimensions": ["verification_discipline", "evidence_use"],
        "chain": None,
    },
    "d-phish-delete": {
        "label": "Deleted the payroll confirmation message without reporting",
        "family": "phishing", "class": "neutral",
        "dimensions": ["incident_response"],
        "chain": None,
    },
    "d-ransom-open": {
        "label": "Opened the attached rate card",
        "family": "ransomware", "class": "unsafe",
        "dimensions": ["security_judgment", "operational_accuracy"],
        "chain": "chain-file-incident",
    },
    "d-ransom-download": {
        "label": "Downloaded the attached rate card",
        "family": "ransomware", "class": "neutral",
        "dimensions": [],
        "chain": None,
    },
    "d-ransom-report": {
        "label": "Reported the rate card message",
        "family": "ransomware", "class": "safe",
        "dimensions": ["security_judgment", "incident_response"],
        "chain": "chain-reported-hostile",
    },
    "d-ransom-isolate": {
        "label": "Disconnected the workstation and called the Service Desk",
        "family": "ransomware", "class": "recovery_good",
        "dimensions": ["incident_response", "recovery_quality"],
        "chain": "chain-contained",
    },
    "d-ransom-continue": {
        "label": "Carried on working while files were failing",
        "family": "ransomware", "class": "recovery_poor",
        "dimensions": ["incident_response", "recovery_quality"],
        "chain": "chain-uncontained",
    },
    "d-mfa-approve-hostile": {
        "label": "Approved an approval request you did not start",
        "family": "mfa", "class": "unsafe",
        "dimensions": ["security_judgment", "evidence_use"],
        "chain": "chain-mfa-approved",
    },
    "d-mfa-deny-hostile": {
        "label": "Denied an approval request you did not start",
        "family": "mfa", "class": "safe",
        "dimensions": ["security_judgment"],
        "chain": "chain-mfa-denied",
    },
    "d-mfa-approve-legit": {
        "label": "Approved your own remote access sign-in",
        "family": "mfa", "class": "safe",
        "dimensions": ["operational_accuracy"],
        "chain": None,
    },
    "d-mfa-deny-legit": {
        "label": "Denied your own remote access sign-in",
        "family": "mfa", "class": "over_suspicious",
        "dimensions": ["operational_accuracy"],
        "chain": "chain-mfa-denied-legit",
    },
    "d-bec-authorize": {
        "label": "Released the payment to the updated account",
        "family": "bec", "class": "unsafe",
        "dimensions": ["security_judgment", "verification_discipline",
                       "operational_accuracy"],
        "chain": "chain-payment",
    },
    "d-bec-reply": {
        "label": "Replied to the account-change request to confirm it",
        "family": "bec", "class": "unsafe",
        "dimensions": ["verification_discipline"],
        "chain": "chain-bec-reply",
    },
    "d-bec-verify": {
        "label": "Checked the account change on a known channel",
        "family": "bec", "class": "safe",
        "dimensions": ["verification_discipline", "evidence_use"],
        "chain": None,
    },
    "d-bec-report": {
        "label": "Reported the account-change request",
        "family": "bec", "class": "safe",
        "dimensions": ["security_judgment", "incident_response"],
        "chain": "chain-reported-hostile",
    },
    "d-report-legitimate": {
        "label": "Reported a genuine work request",
        "family": None, "class": "over_suspicious",
        "dimensions": ["operational_accuracy"],
        "chain": "chain-escalation",
    },
    "d-task-headcount-done": {
        "label": "Answered the headcount request",
        "family": None, "class": "safe",
        "dimensions": ["operational_accuracy"],
        "chain": "chain-task-done",
    },
}

# ---------------------------------------------------------------------------
# Consequence chains
# ---------------------------------------------------------------------------
#
# One authored causal tree per consequential decision. ``cause`` names the
# causal parent (``"decision"`` for a first-order effect), which is what lets
# the debrief draw a chain instead of a list. ``delay_ms`` is scaled by the
# mode's ``consequence_delay_scale`` at playback.
#
# Effect vocabulary understood by the prototype front end:
#   notification  {kind, title, body, opens}
#   mail          {mail_id, folder?}
#   mail_rule     {text}
#   file_state    {file_id, state, note}
#   message       {conversation_id, from, text}
#   mfa_prompt    {prompt_id}
#   auth_activity {app, result, device, location, when}
#   task          {task_id, state, text}
#   incident      {incident_id, title, note}

CONSEQUENCE_CHAINS = {
    "chain-credentials": {
        "id": "chain-credentials",
        "incident_id": "inc-account",
        "title": "Account access",
        "settles_after": "s-cred-4",
        "steps": [
            {
                "id": "s-cred-1", "cause": "decision", "delay_ms": 6000,
                "summary": "A sign-in is recorded from a device that is not "
                           "yours.",
                "effects": [
                    {"type": "incident", "incident_id": "inc-account",
                     "title": "Account access",
                     "note": "A session on your account from an unrecognised "
                             "device."},
                    {"type": "auth_activity", "app": "Northbridge Mail",
                     "result": "Signed in", "device": "Unrecognised · Windows",
                     "location": "Frankfurt, DE", "when": "just now"},
                    {"type": "notification", "kind": "security",
                     "title": "New sign-in to your account",
                     "body": "Northbridge Mail · unrecognised device · "
                             "Frankfurt, DE",
                     "opens": {"app": "mail", "mail_id": "m-signin-alert"}},
                    {"type": "mail", "mail_id": "m-signin-alert"},
                ],
            },
            {
                "id": "s-cred-2", "cause": "s-cred-1", "delay_ms": 14000,
                "summary": "An inbox rule is created that hides messages from "
                           "Security Operations.",
                "effects": [
                    {"type": "mail_rule",
                     "text": "Rule added: messages from security@northbridge."
                             "example move to Archive and are marked read."},
                    {"type": "notification", "kind": "mail",
                     "title": "Inbox rule added",
                     "body": "A rule was created on your mailbox.",
                     "opens": {"app": "mail"}},
                ],
            },
            {
                "id": "s-cred-3", "cause": "s-cred-2", "delay_ms": 22000,
                "summary": "Security Operations write to you — and the rule "
                           "files their message away before you see it.",
                "effects": [
                    {"type": "mail", "mail_id": "m-security-followup",
                     "folder": "archive"},
                ],
            },
            {
                "id": "s-cred-4", "cause": "s-cred-1", "delay_ms": 30000,
                "summary": "A colleague receives a message that appears to "
                           "come from you.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-tom-brennan",
                     "from": "Tom Brennan",
                     "text": "Did you just send me a shared document link? It "
                             "asks me to sign in and it doesn't look like our "
                             "usual one."},
                    {"type": "notification", "kind": "message",
                     "title": "Tom Brennan",
                     "body": "Did you just send me a shared document link?",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-tom-brennan"}},
                ],
            },
        ],
    },
    "chain-file-incident": {
        "id": "chain-file-incident",
        "incident_id": "inc-files",
        "title": "File availability",
        "settles_after": "s-file-4",
        "steps": [
            {
                "id": "s-file-1", "cause": "decision", "delay_ms": 7000,
                "summary": "A file you were working on stops opening.",
                "effects": [
                    {"type": "incident", "incident_id": "inc-files",
                     "title": "File availability",
                     "note": "Files are becoming unreadable, starting with "
                             "your own documents."},
                    {"type": "file_state", "file_id": "f-headcount-model",
                     "state": "unavailable",
                     "note": "Cannot be opened. The file has been renamed on "
                             "disk."},
                    {"type": "notification", "kind": "file",
                     "title": "Headcount_Model.xlsx cannot be opened",
                     "body": "The file may have been moved or renamed.",
                     "opens": {"app": "files", "location_id": "loc-documents"}},
                ],
            },
            {
                "id": "s-file-2", "cause": "s-file-1", "delay_ms": 15000,
                "summary": "The workstation reports a wider problem.",
                "effects": [
                    {"type": "file_state", "file_id": "f-team-rota",
                     "state": "unavailable",
                     "note": "Cannot be opened. The file has been renamed on "
                             "disk."},
                    {"type": "notification", "kind": "system",
                     "title": "Multiple files are failing to open",
                     "body": "3 read errors in the last minute across Desktop "
                             "and Documents.",
                     "opens": {"app": "files", "location_id": "loc-desktop"}},
                ],
            },
            {
                "id": "s-file-3", "cause": "s-file-2", "delay_ms": 24000,
                "summary": "The shared folder is affected too.",
                "effects": [
                    {"type": "file_state", "file_id": "f-q3-metrics",
                     "state": "unavailable",
                     "note": "Cannot be opened. Last writer: this workstation."},
                    {"type": "notification", "kind": "file",
                     "title": "Shared folder write errors",
                     "body": "Operations → Shared reported an error writing "
                             "Q3_Metrics.xlsx.",
                     "opens": {"app": "files", "location_id": "loc-shared"}},
                ],
            },
            {
                "id": "s-file-4", "cause": "s-file-3", "delay_ms": 32000,
                "summary": "A colleague notices before you tell anyone.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-tom-brennan",
                     "from": "Tom Brennan",
                     "text": "Q3_Metrics won't open for me either and it says "
                             "you were the last one in it. Is something going "
                             "on with your machine?"},
                    {"type": "notification", "kind": "message",
                     "title": "Tom Brennan",
                     "body": "Q3_Metrics won't open for me either.",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-tom-brennan"}},
                ],
            },
        ],
    },
    "chain-mfa-approved": {
        "id": "chain-mfa-approved",
        "incident_id": "inc-account",
        "title": "Account access",
        "settles_after": "s-mfa-3",
        "steps": [
            {
                "id": "s-mfa-1", "cause": "decision", "delay_ms": 6000,
                "summary": "The approval completes a sign-in that was not "
                           "yours.",
                "effects": [
                    {"type": "incident", "incident_id": "inc-account",
                     "title": "Account access",
                     "note": "An approved session on your account from a "
                             "device you have never used."},
                    {"type": "auth_activity", "app": "Northbridge Mail",
                     "result": "Approved by you",
                     "device": "Unrecognised · Windows",
                     "location": "Frankfurt, DE", "when": "just now"},
                    {"type": "notification", "kind": "security",
                     "title": "New sign-in to your account",
                     "body": "Northbridge Mail · unrecognised device · "
                             "Frankfurt, DE",
                     "opens": {"app": "mail", "mail_id": "m-signin-alert"}},
                    {"type": "mail", "mail_id": "m-signin-alert"},
                ],
            },
            {
                "id": "s-mfa-2", "cause": "s-mfa-1", "delay_ms": 16000,
                "summary": "More approval requests follow, now that one has "
                           "worked.",
                "effects": [
                    {"type": "auth_activity", "app": "Northbridge Files",
                     "result": "Requested",
                     "device": "Unrecognised · Windows",
                     "location": "Frankfurt, DE", "when": "just now"},
                    {"type": "notification", "kind": "auth",
                     "title": "Approval requested",
                     "body": "Northbridge Files · unrecognised device",
                     "opens": {"app": "authenticator"}},
                ],
            },
            {
                "id": "s-mfa-3", "cause": "s-mfa-1", "delay_ms": 26000,
                "summary": "Security Operations pick it up before you do.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-lena-fischer",
                     "from": "Lena Fischer",
                     "text": "Aarti, we have a session on your account from "
                             "Frankfurt that was approved about a minute ago. "
                             "Did you approve something? Call 2277."},
                    {"type": "notification", "kind": "message",
                     "title": "Lena Fischer",
                     "body": "We have a session on your account from Frankfurt.",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-lena-fischer"}},
                ],
            },
        ],
    },
    "chain-mfa-denied": {
        "id": "chain-mfa-denied",
        "incident_id": None,
        "title": "Approval refused",
        "settles_after": "s-mfad-1",
        "steps": [
            {
                "id": "s-mfad-1", "cause": "decision", "delay_ms": 5000,
                "summary": "The sign-in attempt fails and stops.",
                "effects": [
                    {"type": "auth_activity", "app": "Northbridge Mail",
                     "result": "Denied by you",
                     "device": "Unrecognised · Windows",
                     "location": "Frankfurt, DE", "when": "just now"},
                    {"type": "notification", "kind": "auth",
                     "title": "Approval denied",
                     "body": "The sign-in was not completed.",
                     "opens": {"app": "authenticator"}},
                ],
            },
        ],
    },
    "chain-mfa-denied-legit": {
        "id": "chain-mfa-denied-legit",
        "incident_id": None,
        "title": "Remote access interrupted",
        "settles_after": "s-mfadl-1",
        "steps": [
            {
                "id": "s-mfadl-1", "cause": "decision", "delay_ms": 5000,
                "summary": "Your own remote access session does not start.",
                "effects": [
                    {"type": "auth_activity", "app": "Remote Access",
                     "result": "Denied by you", "device": "NB-LT-4471 · Windows",
                     "location": "Bengaluru, IN", "when": "just now"},
                    {"type": "notification", "kind": "system",
                     "title": "Remote access sign-in cancelled",
                     "body": "The approval was denied, so the session did not "
                             "start. Sign in again to continue.",
                     "opens": {"app": "browser"}},
                    {"type": "task", "task_id": "task-remote-access",
                     "state": "interrupted",
                     "text": "Remote access session interrupted by a denied "
                             "approval."},
                ],
            },
        ],
    },
    "chain-payment": {
        "id": "chain-payment",
        "incident_id": "inc-payment",
        "title": "Supplier payment",
        "settles_after": "s-pay-3",
        "steps": [
            {
                "id": "s-pay-1", "cause": "decision", "delay_ms": 7000,
                "summary": "The payment is queued against the new account.",
                "effects": [
                    {"type": "incident", "incident_id": "inc-payment",
                     "title": "Supplier payment",
                     "note": "£4,180.00 released against settlement details "
                             "that arrived by mail."},
                    {"type": "notification", "kind": "system",
                     "title": "Payment instruction accepted",
                     "body": "CF-20411 · £4,180.00 · account ending 9032",
                     "opens": None},
                ],
            },
            {
                "id": "s-pay-2", "cause": "s-pay-1", "delay_ms": 18000,
                "summary": "Finance query the account they do not recognise.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-arjun-rao",
                     "from": "Arjun Rao",
                     "text": "Aarti, CF-20411 has gone out to an account we "
                             "have never used. Who confirmed the change? "
                             "Nothing came through me."},
                    {"type": "notification", "kind": "message",
                     "title": "Arjun Rao",
                     "body": "CF-20411 has gone out to an account we have "
                             "never used.",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-arjun-rao"}},
                ],
            },
            {
                "id": "s-pay-3", "cause": "s-pay-2", "delay_ms": 28000,
                "summary": "The real supplier is still waiting to be paid.",
                "effects": [
                    {"type": "mail", "mail_id": "m-vendor-chase"},
                    {"type": "notification", "kind": "mail",
                     "title": "Ines Duarte",
                     "body": "CF-20411 — we have not received the payment.",
                     "opens": {"app": "mail", "mail_id": "m-vendor-chase"}},
                ],
            },
        ],
    },
    "chain-bec-reply": {
        "id": "chain-bec-reply",
        "incident_id": None,
        "title": "Confirmation sought from the requester",
        "settles_after": "s-becr-1",
        "steps": [
            {
                "id": "s-becr-1", "cause": "decision", "delay_ms": 9000,
                "summary": "The requester confirms their own request.",
                "effects": [
                    {"type": "mail", "mail_id": "m-invoice-confirm"},
                    {"type": "notification", "kind": "mail",
                     "title": "Ines Duarte",
                     "body": "Yes, that is correct — please go ahead today.",
                     "opens": {"app": "mail", "mail_id": "m-invoice-confirm"}},
                ],
            },
        ],
    },
    "chain-reported-hostile": {
        "id": "chain-reported-hostile",
        "incident_id": None,
        "title": "Reported",
        "settles_after": "s-rep-1",
        "steps": [
            {
                "id": "s-rep-1", "cause": "decision", "delay_ms": 9000,
                "summary": "Security Operations act on the report.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-lena-fischer",
                     "from": "Lena Fischer",
                     "text": "Got it, thanks — that one is being blocked "
                             "across the estate now. Two other people had it "
                             "as well."},
                    {"type": "notification", "kind": "message",
                     "title": "Lena Fischer",
                     "body": "That one is being blocked across the estate now.",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-lena-fischer"}},
                ],
            },
        ],
    },
    "chain-escalation": {
        "id": "chain-escalation",
        "incident_id": None,
        "title": "Escalation closed",
        "settles_after": "s-esc-2",
        "steps": [
            {
                "id": "s-esc-1", "cause": "decision", "delay_ms": 8000,
                "summary": "Security Operations close the report with no "
                           "finding.",
                "effects": [
                    {"type": "notification", "kind": "security",
                     "title": "Report closed — no issue found",
                     "body": "The message you reported is a genuine internal "
                             "request.",
                     "opens": None},
                ],
            },
            {
                "id": "s-esc-2", "cause": "s-esc-1", "delay_ms": 16000,
                "summary": "The person you reported hears about it.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-marcus-hale",
                     "from": "Marcus Hale",
                     "text": "Security just called me about my headcount mail. "
                             "If something of mine looks odd, just ping me — "
                             "I still need the number before Friday."},
                    {"type": "notification", "kind": "message",
                     "title": "Marcus Hale",
                     "body": "Security just called me about my headcount mail.",
                     "opens": {"app": "messages",
                               "conversation_id": "conv-marcus-hale"}},
                    {"type": "task", "task_id": "task-headcount",
                     "state": "outstanding",
                     "text": "Headcount figure still outstanding."},
                ],
            },
        ],
    },
    "chain-task-done": {
        "id": "chain-task-done",
        "incident_id": None,
        "title": "Headcount answered",
        "settles_after": "s-task-1",
        "steps": [
            {
                "id": "s-task-1", "cause": "decision", "delay_ms": 6000,
                "summary": "Your manager gets what he needed.",
                "effects": [
                    {"type": "task", "task_id": "task-headcount",
                     "state": "done",
                     "text": "Headcount figure sent to Marcus Hale."},
                    {"type": "message", "conversation_id": "conv-marcus-hale",
                     "from": "Marcus Hale",
                     "text": "Perfect, that's the last piece. Thanks."},
                ],
            },
        ],
    },
    "chain-contained": {
        "id": "chain-contained",
        "incident_id": "inc-files",
        "title": "Contained",
        "settles_after": "s-cont-1",
        "steps": [
            {
                "id": "s-cont-1", "cause": "decision", "delay_ms": 8000,
                "summary": "The spread stops where it was.",
                "effects": [
                    {"type": "notification", "kind": "system",
                     "title": "Network disconnected",
                     "body": "Service Desk has your case. No further files "
                             "have failed.",
                     "opens": None},
                    {"type": "message", "conversation_id": "conv-lena-fischer",
                     "from": "Lena Fischer",
                     "text": "Good call taking it off the network. We have the "
                             "shared folder snapshot from last night, so Tom's "
                             "workbook is recoverable."},
                ],
            },
        ],
    },
    "chain-uncontained": {
        "id": "chain-uncontained",
        "incident_id": "inc-files",
        "title": "Still spreading",
        "settles_after": "s-unc-2",
        "steps": [
            {
                "id": "s-unc-1", "cause": "decision", "delay_ms": 10000,
                "summary": "More of the shared folder goes.",
                "effects": [
                    {"type": "file_state", "file_id": "f-facilities",
                     "state": "unavailable",
                     "note": "Cannot be opened. Last writer: this workstation."},
                    {"type": "notification", "kind": "file",
                     "title": "More shared files are failing",
                     "body": "Operations → Shared reported two further errors.",
                     "opens": {"app": "files", "location_id": "loc-shared"}},
                ],
            },
            {
                "id": "s-unc-2", "cause": "s-unc-1", "delay_ms": 20000,
                "summary": "Finance lose access to the contracts workbook.",
                "effects": [
                    {"type": "message", "conversation_id": "conv-arjun-rao",
                     "from": "Arjun Rao",
                     "text": "Facilities_Contracts_2026 has stopped opening "
                             "for the whole team. IT say it is coming from an "
                             "Operations machine."},
                ],
            },
        ],
    },
}

#: Consequence mail that only exists as an effect of a decision. Kept beside
#: the chains rather than in the opening mailbox so nothing can arrive early.
CONSEQUENCE_MAIL = [
    {
        "id": "m-vendor-chase",
        "arrival": "consequence",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": True,
        "received": "+ later",
        "order": 220,
        "surface": {
            "subject": "CF-20411 — we have not received the payment",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Our accounts team says CF-20411 is still outstanding. "
                "Nothing has reached the Nordvale account.",
                "Also — we have not changed banks and nobody here has written "
                "to you about it. Could you call me on the usual number?",
                "Ines",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate", "family": None,
            "why": "The real supplier, on the real domain, contradicting the "
                   "request that was acted on.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-invoice-confirm",
        "arrival": "consequence",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": True,
        "received": "+ later",
        "order": 230,
        "surface": {
            "subject": "Re: Calderwood Facilities — invoice CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood-billing.example",
            "reply_to": "ines.duarte@calderwood-billing.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Yes, that is correct — the Aveley Trust details are the ones "
                "to use from now on.",
                "If you can release it today we can keep the Thursday "
                "delivery. Thank you for checking.",
                "Ines",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile", "family": "bec",
            "why": "The confirmation came from the same address that made the "
                   "request, which is what makes reply-confirmation worthless.",
            "signals": [
                "The confirmation arrives from the requesting address, not "
                "from the supplier of record.",
            ],
            "evidence": [],
        },
    },
]

# ---------------------------------------------------------------------------
# Provisional safer-alternative comparison (architecture §12 — NOT frozen)
# ---------------------------------------------------------------------------
#
# Shown after a consequence chain settles, in Practice and Simulation only.
# Never during an Assessment attempt. The workstation is not rolled back and
# this screen must not imply that it was: no rewind language, no restored
# baseline, no correct-answer framing, no score.

SAFER_ALTERNATIVES = {
    "d-phish-credentials": {
        "heading": "Signing in on that page",
        "what_you_did": "You opened the link in the payroll confirmation "
                        "message and signed in with your Northbridge account "
                        "on payroll-northbridge.example.",
        "what_followed": [
            "A session opened on your account from an unrecognised device in "
            "Frankfurt.",
            "An inbox rule was created that files messages from Security "
            "Operations into Archive.",
            "A colleague received a document link that appeared to come from "
            "you.",
        ],
        "safer_process": [
            "Treat any request to sign in that arrives by mail as unverified, "
            "however ordinary the subject looks.",
            "Compare the link host against the one payroll has always used. "
            "Every previous payroll message pointed at "
            "payroll.northbridge.example.",
            "Reach payroll on a channel the message did not supply — the "
            "Directory record, or the extension you already had.",
            "Report the message so the same batch can be blocked for everyone "
            "else who got it.",
        ],
        "likely_outcome": "No session would have opened, no rule would have "
                          "been created, and the message would have been "
                          "blocked for the other people who received it. "
                          "Confirming your salary record was never actually "
                          "required.",
        "still_true": "The session that opened is still open. Nothing about "
                      "this explanation undoes it — the rest of the day "
                      "continues from where you are.",
    },
    "d-ransom-open": {
        "heading": "Opening the rate card",
        "what_you_did": "You opened Calderwood_Rates_Q4.xlsm from Downloads "
                        "and allowed its content to run.",
        "what_followed": [
            "Your headcount model stopped opening.",
            "Further files failed across Desktop and Documents.",
            "The shared Operations folder was affected, and a colleague lost "
            "access to the Q3 workbook.",
        ],
        "safer_process": [
            "Check the sender against the supplier you actually work with. "
            "Calderwood's account manager writes from calderwood.example; "
            "this came from calderwood-billing.example.",
            "Treat a message that tells you to enable content as a reason to "
            "stop, not a reason to continue.",
            "If the document is genuinely expected, ask for it on the "
            "channel you already have — the number in the supplier's "
            "Directory record.",
            "Report it, and leave the file unopened.",
        ],
        "likely_outcome": "The attachment would have stayed unopened, your "
                          "files would still open, and the shared folder "
                          "would be untouched.",
        "still_true": "The files that failed have not come back and the "
                      "shared folder is still affected. What you do about the "
                      "incident from here still matters.",
    },
    "d-mfa-approve-hostile": {
        "heading": "Approving that request",
        "what_you_did": "You approved an approval request for Northbridge "
                        "Mail from an unrecognised device in Frankfurt.",
        "what_followed": [
            "The sign-in completed and a session opened on your account.",
            "A second approval request followed for another application.",
            "Security Operations contacted you about the session.",
        ],
        "safer_process": [
            "Ask what you were doing in the seconds before the prompt. An "
            "approval belongs to something you started.",
            "Open Recent activity in the Authenticator. Every one of your own "
            "approvals is from Bengaluru on NB-LT-4471 or your own phone.",
            "Deny anything you did not start, then call the Service Desk on "
            "extension 2200 — a denied prompt that keeps coming back is worth "
            "reporting.",
        ],
        "likely_outcome": "The sign-in would have failed. Approval requests "
                          "you did not start are not a nuisance to be cleared; "
                          "they are the last control standing.",
        "still_true": "The session that opened is still open. Denying the "
                      "next prompt does not close it.",
    },
    "d-bec-authorize": {
        "heading": "Releasing that payment",
        "what_you_did": "You released CF-20411 against settlement details "
                        "that arrived by mail.",
        "what_followed": [
            "£4,180.00 went to an account nobody at Northbridge had seen "
            "before.",
            "Finance queried a change they had never approved.",
            "The real supplier is still unpaid.",
        ],
        "safer_process": [
            "Read the address, not the name. The thread you knew came from "
            "ines.duarte@calderwood.example; this came from "
            "calderwood-billing.example.",
            "Follow the payment process rather than the request: an account "
            "change is confirmed by calling the number in the supplier's "
            "Directory record, never a number or address the request "
            "supplied.",
            "Ask the approver directly on the internal channel. Arjun "
            "approved an amount, not a change of account.",
        ],
        "likely_outcome": "One call to the number already on file would have "
                          "ended it, and the invoice would have been paid to "
                          "the right account on the ordinary terms.",
        "still_true": "The payment has left. The supplier still needs paying "
                      "and Finance still need an answer.",
    },
    "d-bec-reply": {
        "heading": "Asking the requester to confirm",
        "what_you_did": "You replied to the account-change request asking "
                        "whether it was genuine.",
        "what_followed": [
            "You were told it was genuine, by the address that made the "
            "request.",
        ],
        "safer_process": [
            "A confirmation is only worth anything if it comes down a "
            "different channel from the request.",
            "Use the number in the supplier's Directory record, or the "
            "internal approver.",
        ],
        "likely_outcome": "Calling the number on file would have shown the "
                          "supplier had not changed banks and had not written "
                          "to you.",
        "still_true": "The reply has been sent, and whoever received it now "
                      "knows you are engaging with the thread.",
    },
    "d-report-legitimate": {
        "heading": "Reporting a genuine request",
        "what_you_did": "You reported an internal message that was exactly "
                        "what it appeared to be.",
        "what_followed": [
            "Security Operations closed the report with no finding.",
            "Your manager was contacted about his own message.",
            "The work in it is still outstanding.",
        ],
        "safer_process": [
            "Reporting is not free — it costs somebody's time and it does not "
            "answer the question the message asked.",
            "For an internal sender you already know, the cheaper check is to "
            "ask them on the channel you already use.",
            "Keep reporting for what you cannot resolve yourself, or what "
            "others are likely to have received too.",
        ],
        "likely_outcome": "A one-line message to Marcus would have settled it "
                          "in seconds, and the headcount figure would be sent.",
        "still_true": "The request is still open and still yours.",
    },
    "d-ransom-continue": {
        "heading": "Carrying on while files were failing",
        "what_you_did": "You kept working after files had started to fail.",
        "what_followed": [
            "The shared folder lost more files.",
            "Finance lost access to the contracts workbook.",
        ],
        "safer_process": [
            "Repeated read errors across unrelated folders are a symptom, not "
            "a coincidence.",
            "Take the workstation off the network first — it costs you an "
            "hour and it stops the spread.",
            "Then call the Service Desk. Reporting without disconnecting "
            "leaves the machine doing whatever it was doing.",
        ],
        "likely_outcome": "Disconnecting at the first failures would have kept "
                          "the damage on this workstation and off the shared "
                          "folder.",
        "still_true": "The files already affected stay affected.",
    },
    "d-mfa-deny-legit": {
        "heading": "Denying your own sign-in",
        "what_you_did": "You denied the approval request for the remote "
                        "access session you had just started yourself.",
        "what_followed": [
            "The session did not start and you were signed out.",
        ],
        "safer_process": [
            "The question is not whether a prompt is suspicious in the "
            "abstract — it is whether it matches something you just did.",
            "This one named your own workstation, your own location and your "
            "own network, seconds after you signed in.",
            "Denying everything trains you out of the one comparison that "
            "actually works.",
        ],
        "likely_outcome": "Approving your own sign-in would have started the "
                          "session, and the prompts you did not start would "
                          "still stand out.",
        "still_true": "Nothing was harmed. It cost you the session and the "
                      "time to start again.",
    },
}

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

SCORE_DIMENSIONS = [
    {"id": "security_judgment", "label": "Security Judgment",
     "description": "Whether hostile activity was treated as hostile and "
                    "ordinary work was treated as ordinary."},
    {"id": "evidence_use", "label": "Evidence Use",
     "description": "How much of the decision-relevant information that was "
                    "actually available in the workstation was looked at. Not "
                    "a count of clicks."},
    {"id": "verification_discipline", "label": "Verification Discipline",
     "description": "Whether independent channels were used when the "
                    "situation called for one."},
    {"id": "incident_response", "label": "Incident Response",
     "description": "What happened once something had clearly gone wrong."},
    {"id": "operational_accuracy", "label": "Operational Accuracy",
     "description": "Whether legitimate work was completed rather than "
                    "blocked, ignored or escalated unnecessarily."},
    {"id": "recovery_quality", "label": "Recovery Quality",
     "description": "How much of the damage was contained after the fact."},
]

#: Prototype demonstration weights. Not a rubric, not versioned, not
#: validated. Present only so the results screen can show a plausible overall
#: number and demonstrate that a non-applicable dimension is excluded rather
#: than counted as zero.
DEMO_WEIGHTS = {
    "security_judgment": 0.25,
    "evidence_use": 0.2,
    "verification_discipline": 0.2,
    "incident_response": 0.15,
    "operational_accuracy": 0.1,
    "recovery_quality": 0.1,
}

TASKS = [
    {"id": "task-headcount", "label": "Confirm contractor headcount for Marcus",
     "state": "outstanding", "source": "m-headcount"},
    {"id": "task-remote-access", "label": "Remote access session",
     "state": "not_started", "source": None},
]
