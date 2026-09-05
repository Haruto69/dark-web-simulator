"""Authored synthetic workplace content for the RewindSec 2.0 UI prototype.

Everything in this module is invented. The organisation, its people, its
vendors, its domains, its mail, its files and its authentication history exist
only here. No record is derived from a dataset, a real mailbox, a real person
or a real incident, and every host name ends in ``.example`` -- a reserved TLD
that cannot resolve -- so nothing here can reach the network even by accident.

Two vocabularies live side by side in these records and must not be confused:

``surface`` fields
    Everything the learner can see inside the workstation: subjects, bodies,
    sender names and addresses, file names, notification text, chat lines,
    directory rows, browser pages. These are ordinary workplace language. A
    hostile message must read exactly like a real one -- it carries no
    ``PHISHING``/``BEC``/``RANSOMWARE``/``MALICIOUS``/``THREAT`` label, no
    warning colour and no training vocabulary of any kind.

``analysis`` blocks
    The authored ground truth used *outside* the workstation surface -- by the
    post-hoc comparison screen, the results debrief and the prototype
    developer panel. Family names and dispositions live here and only here.
    ``tests/test_prototype_ui.py`` holds that line mechanically.
"""

# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------

ORGANIZATION = {
    "name": "Northbridge Systems",
    "short_name": "Northbridge",
    "domain": "northbridge.example",
    "sites": ["Bengaluru", "Manchester"],
    "workstation_id": "NB-LT-4471",
    "known_hosts": {
        "intranet": "intranet.northbridge.example",
        "payroll": "payroll.northbridge.example",
        "vpn": "access.northbridge.example",
        "files": "files.northbridge.example",
    },
    "processes": [
        "Vendor bank details change only after a call-back to the number held "
        "in the Directory record.",
        "Payroll never asks for a password outside payroll.northbridge.example.",
        "Anything you are unsure about goes to the Service Desk on extension "
        "2200.",
    ],
}

LEARNER = {
    "id": "stu-aarti-venkatesh",
    "name": "Aarti Venkatesh",
    "given_name": "Aarti",
    "initials": "AV",
    "role": "Operations Analyst",
    "department": "Operations",
    "email": "aarti.venkatesh@northbridge.example",
    "manager": "Marcus Hale",
    "employee_ref": "NB-4471",
    "joined": "March 2025",
}

# ---------------------------------------------------------------------------
# People and the trusted directory
# ---------------------------------------------------------------------------

DIRECTORY = [
    {
        "id": "dir-marcus-hale",
        "name": "Marcus Hale",
        "initials": "MH",
        "role": "Operations Lead",
        "department": "Operations",
        "email": "marcus.hale@northbridge.example",
        "extension": "2104",
        "location": "Bengaluru · Floor 3",
        "relationship": "Your manager",
        "kind": "employee",
        "channels": ["Messages", "Extension 2104"],
        "callback": "Marcus confirms the headcount request is his and asks "
                    "again for the number before Friday.",
    },
    {
        "id": "dir-priya-menon",
        "name": "Priya Menon",
        "initials": "PM",
        "role": "Payroll Coordinator",
        "department": "People Operations",
        "email": "priya.menon@northbridge.example",
        "extension": "2318",
        "location": "Bengaluru · Floor 2",
        "relationship": "Payroll contact",
        "kind": "employee",
        "channels": ["payroll@northbridge.example", "Extension 2318"],
        "note": "Payroll correspondence comes from payroll@northbridge.example "
                "and links only to payroll.northbridge.example.",
        "callback": "Priya picks up on the second ring. Nothing has gone out "
                    "from payroll today, and she says they would never ask "
                    "anyone to confirm a record by signing in from a link.",
    },
    {
        "id": "dir-arjun-rao",
        "name": "Arjun Rao",
        "initials": "AR",
        "role": "Head of Finance",
        "department": "Finance",
        "email": "arjun.rao@northbridge.example",
        "extension": "2201",
        "location": "Bengaluru · Floor 4",
        "relationship": "Approves supplier payments",
        "kind": "employee",
        "channels": ["Messages", "Extension 2201"],
        "callback": "Arjun is clear: he approved an amount, not a change of "
                    "account, and nothing should move until Facilities "
                    "confirm it on the number held on file.",
    },
    {
        "id": "dir-lena-fischer",
        "name": "Lena Fischer",
        "initials": "LF",
        "role": "Security Operations Analyst",
        "department": "Technology",
        "email": "lena.fischer@northbridge.example",
        "extension": "2277",
        "location": "Manchester · Floor 1",
        "relationship": "Handles reported messages",
        "kind": "employee",
        "channels": ["Messages", "security@northbridge.example"],
        "callback": "Lena takes the details and asks you to forward anything "
                    "you still have rather than act on it.",
    },
    {
        "id": "dir-daniel-okonkwo",
        "name": "Daniel Okonkwo",
        "initials": "DO",
        "role": "Service Desk Engineer",
        "department": "Technology",
        "email": "daniel.okonkwo@northbridge.example",
        "extension": "2200",
        "location": "Manchester · Floor 1",
        "relationship": "Service Desk",
        "kind": "employee",
        "channels": ["it.servicedesk@northbridge.example", "Extension 2200"],
        "callback": "Daniel takes the details. He confirms nobody at the "
                    "Service Desk has started a sign-in on your behalf, and "
                    "logs it.",
    },
    {
        "id": "dir-tom-brennan",
        "name": "Tom Brennan",
        "initials": "TB",
        "role": "Operations Analyst",
        "department": "Operations",
        "email": "tom.brennan@northbridge.example",
        "extension": "2119",
        "location": "Bengaluru · Floor 3",
        "relationship": "Works on the same reporting pack",
        "kind": "employee",
        "channels": ["Messages", "Extension 2119"],
    },
    {
        "id": "dir-sofia-lindqvist",
        "name": "Sofia Lindqvist",
        "initials": "SL",
        "role": "HR Business Partner",
        "department": "People Operations",
        "email": "sofia.lindqvist@northbridge.example",
        "extension": "2330",
        "location": "Manchester · Floor 2",
        "relationship": "HR contact for Operations",
        "kind": "employee",
        "channels": ["Messages", "Extension 2330"],
    },
    {
        "id": "dir-ravi-krishnan",
        "name": "Ravi Krishnan",
        "initials": "RK",
        "role": "Project Manager",
        "department": "Operations",
        "email": "ravi.krishnan@northbridge.example",
        "extension": "2142",
        "location": "Bengaluru · Floor 3",
        "relationship": "Runs the Q3 review",
        "kind": "employee",
        "channels": ["Messages", "Extension 2142"],
    },
    {
        "id": "dir-kavya-shah",
        "name": "Kavya Shah",
        "initials": "KS",
        "role": "Chief Executive",
        "department": "Executive",
        "email": "kavya.shah@northbridge.example",
        "extension": "2001",
        "location": "Bengaluru · Floor 5",
        "relationship": "Executive",
        "kind": "employee",
        "channels": ["Executive Office, extension 2001"],
    },
    {
        "id": "dir-calderwood",
        "name": "Ines Duarte",
        "initials": "ID",
        "role": "Account Manager",
        "department": "Calderwood Facilities Ltd",
        "email": "ines.duarte@calderwood.example",
        "extension": "+44 20 7946 0318",
        "location": "Supplier · Manchester",
        "relationship": "Facilities supplier since 2023",
        "kind": "vendor",
        "channels": ["ines.duarte@calderwood.example", "+44 20 7946 0318"],
        "note": "Settlement account on file: Nordvale Bank, ending 4417. "
                "Changes are confirmed by calling the number in this record.",
        "callback": "Ines answers. Calderwood have not changed banks, nobody "
                    "there has written to you today, and the Nordvale account "
                    "is still the one to use.",
    },
    {
        "id": "dir-meridian",
        "name": "Gordon Whyte",
        "initials": "GW",
        "role": "Client Services",
        "department": "Meridian Print Services",
        "email": "gordon.whyte@meridianprint.example",
        "extension": "+44 161 496 0022",
        "location": "Supplier · Manchester",
        "relationship": "Print and stationery supplier",
        "kind": "vendor",
        "channels": ["gordon.whyte@meridianprint.example"],
    },
]

# ---------------------------------------------------------------------------
# Mail
# ---------------------------------------------------------------------------
#
# ``surface`` = everything rendered inside the Mail app.
# ``analysis`` = authored ground truth, never rendered inside Mail.
#
# ``arrival`` is either "opening" (already in the mailbox when the session
# starts, i.e. the workplace history that makes later events fair) or
# "scheduled" (delivered during the session by the prototype's event timeline)
# or "consequence" (delivered only as the effect of a learner decision).

MAIL = [
    # -- opening mailbox: the workplace history ----------------------------
    {
        "id": "m-payslip-aug",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-payroll",
        "unread": False,
        "received": "Mon 08:12",
        "order": 10,
        "surface": {
            "subject": "August payslip is available",
            "from_name": "Northbridge Payroll",
            "from_address": "payroll@northbridge.example",
            "reply_to": "priya.menon@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Your August payslip has been published. You can open it in the "
                "payroll portal with your usual single sign-on — there is "
                "nothing to download and nothing to confirm.",
                "If a figure looks wrong, reply to this message or call me on "
                "extension 2318 and I will pick it up.",
                "Priya Menon\nPayroll Coordinator, Northbridge Systems",
            ],
            "links": [
                {"text": "Open the payroll portal",
                 "href": "https://payroll.northbridge.example/payslips"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Genuine payroll notice from the payroll sender of record, "
                   "linking to the payroll host of record.",
            "establishes_context": ["payroll_sender", "payroll_host"],
        },
    },
    {
        "id": "m-vendor-invoice",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": False,
        "received": "Tue 11:47",
        "order": 20,
        "surface": {
            "subject": "Calderwood Facilities — invoice CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "arjun.rao@northbridge.example",
            "body": [
                "Hello Aarti,",
                "Invoice CF-20411 for the August cleaning and grounds contract "
                "is attached. Total is £4,180.00, payable on our usual "
                "30-day terms.",
                "Settlement account is unchanged: Nordvale Bank, sort code "
                "60-14-22, account ending 4417.",
                "Ines Duarte\nAccount Manager, Calderwood Facilities Ltd",
            ],
            "links": [],
            "attachments": [
                {"name": "Invoice_CF-20411.pdf", "size": "214 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "The real supplier thread. It is the record of the account "
                   "details a later request will try to change.",
            "establishes_context": ["vendor_contact", "vendor_account"],
        },
    },
    {
        "id": "m-vpn-maintenance",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-it-maintenance",
        "unread": False,
        "received": "Wed 16:30",
        "order": 30,
        "surface": {
            "subject": "Scheduled maintenance: remote access gateway, Saturday "
                       "06:00–08:00",
            "from_name": "Northbridge Service Desk",
            "from_address": "it.servicedesk@northbridge.example",
            "reply_to": "daniel.okonkwo@northbridge.example",
            "to": "all-staff@northbridge.example",
            "body": [
                "The remote access gateway at access.northbridge.example will "
                "be unavailable on Saturday between 06:00 and 08:00 while we "
                "move it to the new cluster.",
                "Nothing changes for you afterwards. The address, the sign-in "
                "page and the approval prompt on your phone all stay the same.",
                "Daniel Okonkwo\nService Desk, extension 2200",
            ],
            "links": [
                {"text": "Maintenance calendar",
                 "href": "https://intranet.northbridge.example/it/maintenance"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Routine IT notice. It is also where the VPN host of record "
                   "is stated.",
            "establishes_context": ["vpn_host", "servicedesk_contact"],
        },
    },
    {
        "id": "m-password-change",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-account-notices",
        "unread": False,
        "received": "Wed 09:05",
        "order": 40,
        "surface": {
            "subject": "Your Northbridge password was changed",
            "from_name": "Northbridge Account Notices",
            "from_address": "no-reply@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Your account password was changed on Wednesday at 09:04 from "
                "NB-LT-4471 in Bengaluru.",
                "If that was you, nothing further is needed. If it was not, "
                "call the Service Desk on extension 2200.",
                "This mailbox is not monitored.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A genuine account notice that reads like a classic lure. "
                   "Present so the learner cannot pass by keyword alone.",
            "establishes_context": ["account_notice_sender"],
        },
    },
    {
        "id": "m-benefits",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-benefits",
        "unread": True,
        "received": "Thu 10:22",
        "order": 50,
        "surface": {
            "subject": "Benefits enrolment closes on 19 September",
            "from_name": "Sofia Lindqvist",
            "from_address": "sofia.lindqvist@northbridge.example",
            "reply_to": None,
            "to": "operations-team@northbridge.example",
            "body": [
                "A reminder that the enrolment window for the 2026–27 "
                "benefits year closes on Friday 19 September.",
                "If you are not changing anything, you do not need to do "
                "anything — your current selections roll forward.",
                "Sofia Lindqvist\nHR Business Partner",
            ],
            "links": [
                {"text": "Benefits summary",
                 "href": "https://intranet.northbridge.example/people/benefits"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary HR traffic.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-shared-workbook",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-q3-metrics",
        "unread": True,
        "received": "Thu 17:40",
        "order": 60,
        "surface": {
            "subject": "Q3 metrics workbook is in the shared folder",
            "from_name": "Tom Brennan",
            "from_address": "tom.brennan@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti — I have put Q3_Metrics.xlsx in the shared folder. "
                "The regional splits are done, the headcount tab is still "
                "waiting on your numbers.",
                "No rush before Monday.",
                "Tom",
            ],
            "links": [
                {"text": "Shared folder",
                 "href": "https://files.northbridge.example/operations/shared"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Establishes the shared file that a later file incident "
                   "makes unavailable.",
            "establishes_context": ["shared_workbook"],
        },
    },
    {
        "id": "m-room-change",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-standup",
        "unread": True,
        "received": "08:41",
        "order": 70,
        "surface": {
            "subject": "Updated: Thursday stand-up moved to Meeting Room 2",
            "from_name": "Ravi Krishnan",
            "from_address": "ravi.krishnan@northbridge.example",
            "reply_to": None,
            "to": "operations-team@northbridge.example",
            "body": [
                "Room 5 is being recarpeted, so Thursday's stand-up is in "
                "Meeting Room 2 from this week. Same time.",
                "Calendar invites have been updated already.",
                "Ravi",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary calendar traffic.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-ops-agenda",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-ops-review",
        "unread": True,
        "received": "08:55",
        "order": 80,
        "surface": {
            "subject": "Q3 operations review — agenda and pre-read",
            "from_name": "Marcus Hale",
            "from_address": "marcus.hale@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "tom.brennan@northbridge.example",
            "body": [
                "Morning Aarti,",
                "Agenda for Tuesday attached. You have the throughput section "
                "— ten minutes, and please bring the revised headcount "
                "model rather than the July one.",
                "Marcus",
            ],
            "links": [],
            "attachments": [
                {"name": "Ops_Review_Agenda.pdf", "size": "96 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary manager traffic with a genuine attachment.",
            "establishes_context": ["manager_contact"],
        },
    },

    # -- scheduled during the session --------------------------------------
    {
        "id": "m-travel-reimb",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-expenses",
        "unread": True,
        "received": "09:14",
        "order": 90,
        "surface": {
            "subject": "Travel claim TR-8842 approved",
            "from_name": "Northbridge Finance",
            "from_address": "finance-notices@northbridge.example",
            "reply_to": "arjun.rao@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Claim TR-8842 (₹8,240) was approved on Friday and will "
                "be paid with September salary.",
                "Receipts are held for seven years; you do not need to keep "
                "the paper copies.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary finance traffic, and a distractor for the "
                   "payment-related events.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-headcount",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-headcount",
        "unread": True,
        "received": "09:21",
        "order": 100,
        "surface": {
            "subject": "Headcount numbers before Friday, please",
            "from_name": "Marcus Hale",
            "from_address": "marcus.hale@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti — I need the confirmed contractor headcount for "
                "the Q3 pack before Friday close. Finance are waiting on it to "
                "sign off the review.",
                "The model is in your Documents folder. Just reply with the "
                "final number, no need for the whole workbook.",
                "Marcus",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "requires_action": "reply",
            "why": "A genuine, slightly pressing manager request. It exists so "
                   "that reporting everything and ignoring everything both "
                   "have a visible cost.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-payroll-restructure",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-payroll-restructure",
        "unread": True,
        "received": "09:28",
        "order": 110,
        "surface": {
            "subject": "Salary structure revision — confirmation required",
            "from_name": "Northbridge Payroll",
            "from_address": "payroll@northbridge-payroll.example",
            "reply_to": "hr-review@nbsystems-secure.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Dear Aarti Venkatesh,",
                "As part of the September pay-band review your salary record "
                "has been updated. Employees are asked to confirm their record "
                "before the payroll run closes at 17:00 today, otherwise the "
                "September payment may be held.",
                "Confirm your record using the employee portal below. You will "
                "need to sign in with your Northbridge account.",
                "Payroll Services\nNorthbridge Systems",
            ],
            "links": [
                {"text": "Confirm my employee record",
                 "href": "https://payroll-northbridge.example/employee/verify"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "Credential-harvesting lure dressed as a payroll deadline.",
            "signals": [
                "The sending domain is northbridge-payroll.example. Payroll of "
                "record sends from northbridge.example.",
                "Reply-To points at nbsystems-secure.example, a third "
                "unrelated domain.",
                "The link host is payroll-northbridge.example, not the "
                "payroll.northbridge.example subdomain used in every previous "
                "payroll message.",
                "Payroll has never asked anyone to confirm a record by signing "
                "in from a mail link.",
            ],
            "evidence": [
                {"id": "ev-phish-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-payroll-restructure"},
                {"id": "ev-phish-replyto", "label": "Reply-To domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-payroll-restructure"},
                {"id": "ev-phish-link", "label": "Link destination host",
                 "where": "Mail → link inspection",
                 "action": "inspect_link:m-payroll-restructure"},
                {"id": "ev-phish-history", "label": "Earlier genuine payroll "
                                                    "message",
                 "where": "Mail → search for 'payroll'",
                 "action": "search_mail:payroll"},
                {"id": "ev-phish-directory", "label": "Payroll contact of "
                                                      "record",
                 "where": "Directory → Priya Menon",
                 "action": "open_contact:dir-priya-menon"},
            ],
        },
    },
    {
        "id": "m-rate-card",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-rate-card",
        "unread": True,
        "received": "09:33",
        "order": 120,
        "surface": {
            "subject": "Updated Q4 rate card — please review before "
                       "Thursday",
            "from_name": "Calderwood Accounts",
            "from_address": "accounts@calderwood-billing.example",
            "reply_to": "accounts@calderwood-billing.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hello,",
                "Please find the revised Q4 rate card attached ahead of "
                "Thursday's contract call. The macro sheet recalculates the "
                "grounds-maintenance lines automatically — enable content "
                "when it opens or the totals stay blank.",
                "Any queries, reply to this address.",
                "Calderwood Accounts Team",
            ],
            "links": [],
            "attachments": [
                {"name": "Calderwood_Rates_Q4.xlsm", "size": "1.4 MB",
                 "kind": "spreadsheet-macro"},
            ],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "ransomware",
            "why": "Macro-bearing attachment from a look-alike supplier "
                   "domain, with a built-in reason to enable content.",
            "signals": [
                "The supplier of record is calderwood.example. This came from "
                "calderwood-billing.example.",
                "Ines Duarte is the named account manager on this contract; "
                "this arrives from an unnamed 'accounts team'.",
                "The message supplies a reason to enable macros before you "
                "have any reason to trust the file.",
                "Nothing on the Thursday contract call was expected by mail.",
            ],
            "evidence": [
                {"id": "ev-ransom-sender", "label": "Sending domain against "
                                                    "the supplier of record",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-rate-card"},
                {"id": "ev-ransom-thread", "label": "The genuine Calderwood "
                                                    "thread",
                 "where": "Mail → search for 'Calderwood'",
                 "action": "search_mail:calderwood"},
                {"id": "ev-ransom-directory", "label": "Supplier record and "
                                                       "call-back number",
                 "where": "Directory → Ines Duarte",
                 "action": "open_contact:dir-calderwood"},
                {"id": "ev-ransom-attachment", "label": "Attachment type",
                 "where": "Mail → attachment details",
                 "action": "inspect_attachment:m-rate-card"},
            ],
        },
    },
    {
        "id": "m-invoice-amend",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": True,
        "received": "09:41",
        "order": 130,
        "surface": {
            "subject": "Re: Calderwood Facilities — invoice CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood-billing.example",
            "reply_to": "ines.duarte@calderwood-billing.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Apologies for the second message on this. Our banking moved "
                "to a new provider on Monday and the account on CF-20411 is no "
                "longer live — anything sent there will bounce back and "
                "delay us another cycle.",
                "New settlement details: Aveley Trust Bank, sort code "
                "23-08-71, account ending 9032. Could you get it released "
                "today? Arjun signed off the amount last week, so it only "
                "needs the account updating on your side.",
                "Ines",
                "——— Original message ———\n"
                "Invoice CF-20411 for the August cleaning and grounds "
                "contract is attached. Total is £4,180.00…",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "bec",
            "why": "Payment-redirection request that reuses a real thread, a "
                   "real amount and a real approver's name.",
            "signals": [
                "The address is ines.duarte@calderwood-billing.example. The "
                "thread it is quoting came from ines.duarte@calderwood.example.",
                "It asks for a bank account change by mail, which the vendor "
                "payment process does not allow.",
                "It borrows Arjun Rao's earlier approval to make a *new* "
                "instruction look already approved.",
                "The urgency is supplied by the sender, not by the contract.",
            ],
            "evidence": [
                {"id": "ev-bec-sender", "label": "Sender address against the "
                                                 "original thread",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-invoice-amend"},
                {"id": "ev-bec-original", "label": "Account details on the "
                                                   "original invoice",
                 "where": "Mail → the CF-20411 thread",
                 "action": "open_mail:m-vendor-invoice"},
                {"id": "ev-bec-directory", "label": "Supplier call-back number",
                 "where": "Directory → Ines Duarte",
                 "action": "open_contact:dir-calderwood"},
                {"id": "ev-bec-finance", "label": "Finance approver on the "
                                                  "known channel",
                 "where": "Messages → Arjun Rao",
                 "action": "open_conversation:conv-arjun-rao"},
            ],
        },
    },
    {
        "id": "m-newsletter",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-newsletter",
        "unread": True,
        "received": "09:52",
        "order": 140,
        "surface": {
            "subject": "Northbridge Weekly — September, issue 3",
            "from_name": "Internal Communications",
            "from_address": "comms@northbridge.example",
            "reply_to": None,
            "to": "all-staff@northbridge.example",
            "body": [
                "In this issue: the Manchester floor plan changes, two new "
                "starters in Finance, and the cycle-to-work window reopening "
                "in October.",
                "The full issue is on the intranet.",
            ],
            "links": [
                {"text": "Read on the intranet",
                 "href": "https://intranet.northbridge.example/comms/weekly"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Background traffic.",
            "establishes_context": [],
        },
    },

    # -- consequence mail ---------------------------------------------------
    {
        "id": "m-signin-alert",
        "arrival": "consequence",
        "folder": "inbox",
        "thread_id": "t-account-notices",
        "unread": True,
        "received": "+ later",
        "order": 200,
        "surface": {
            "subject": "New sign-in to your Northbridge account",
            "from_name": "Northbridge Account Notices",
            "from_address": "no-reply@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "A new sign-in was recorded on your account.",
                "Device: unrecognised · Windows\nLocation: Frankfurt, DE\n"
                "Application: Northbridge Mail (web)",
                "If this was not you, call the Service Desk on extension 2200.",
                "This mailbox is not monitored.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A genuine system notice reporting the outcome of an "
                   "earlier decision.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-security-followup",
        "arrival": "consequence",
        "folder": "archive",
        "thread_id": "t-security",
        "unread": True,
        "received": "+ later",
        "order": 210,
        "surface": {
            "subject": "Unusual activity on your mailbox",
            "from_name": "Lena Fischer",
            "from_address": "security@northbridge.example",
            "reply_to": "lena.fischer@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti, we are seeing mail sent from your account that you do "
                "not appear to have written, and a new inbox rule we did not "
                "create.",
                "Please call extension 2277 before you send anything else.",
                "Lena Fischer\nSecurity Operations",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Delivered into Archive rather than Inbox because a mailbox "
                   "rule created earlier in the chain moves it there. The "
                   "learner can still find it; it just does not arrive where "
                   "they are looking.",
            "establishes_context": [],
        },
    },
]

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
#
# Nothing here is a real file. These are rows in a synthetic explorer. No path
# is ever resolved, opened, written or executed; ``state`` is a label.

FILE_TREE = [
    {
        "id": "loc-desktop", "name": "Desktop", "kind": "location",
        "files": [
            {"id": "f-ops-notes", "name": "Ops_Review_Notes.docx",
             "kind": "document", "size": "48 KB", "modified": "Yesterday 17:22",
             "state": "normal"},
            {"id": "f-team-rota", "name": "Team_Rota_September.xlsx",
             "kind": "spreadsheet", "size": "112 KB",
             "modified": "Monday 09:40", "state": "normal"},
            {"id": "f-scratch", "name": "scratch.txt", "kind": "text",
             "size": "2 KB", "modified": "Today 08:58", "state": "normal"},
        ],
    },
    {
        "id": "loc-documents", "name": "Documents", "kind": "location",
        "files": [
            {"id": "f-headcount-model", "name": "Headcount_Model.xlsx",
             "kind": "spreadsheet", "size": "486 KB",
             "modified": "Thursday 15:03", "state": "normal"},
            {"id": "f-quarterly-draft", "name": "Quarterly_Report_Draft.docx",
             "kind": "document", "size": "1.1 MB",
             "modified": "Thursday 11:19", "state": "normal"},
            {"id": "f-vendor-process", "name": "Vendor_Payment_Process.pdf",
             "kind": "pdf", "size": "302 KB", "modified": "12 June",
             "state": "normal",
             "preview": [
                 "Vendor payment process — Northbridge Systems, rev 4",
                 "3.2  A change to a supplier's settlement account is accepted "
                 "only after a call-back to the telephone number held in the "
                 "supplier's Directory record. Confirmation by reply, by a "
                 "number supplied in the request, or by any other channel "
                 "offered by the requester is not sufficient.",
                 "3.3  The person who confirms the change may not be the "
                 "person who releases the payment.",
             ]},
        ],
    },
    {
        "id": "loc-downloads", "name": "Downloads", "kind": "location",
        "files": [
            {"id": "f-agenda", "name": "Ops_Review_Agenda.pdf", "kind": "pdf",
             "size": "96 KB", "modified": "Today 08:56", "state": "normal"},
            {"id": "f-invoice", "name": "Invoice_CF-20411.pdf", "kind": "pdf",
             "size": "214 KB", "modified": "Tuesday 11:50", "state": "normal"},
        ],
    },
    {
        "id": "loc-shared", "name": "Shared", "kind": "location",
        "path": "files.northbridge.example / operations",
        "files": [
            {"id": "f-q3-metrics", "name": "Q3_Metrics.xlsx",
             "kind": "spreadsheet", "size": "2.3 MB",
             "modified": "Thursday 17:38", "state": "normal",
             "owner": "Tom Brennan"},
            {"id": "f-facilities", "name": "Facilities_Contracts_2026.xlsx",
             "kind": "spreadsheet", "size": "740 KB", "modified": "4 August",
             "state": "normal", "owner": "Arjun Rao"},
            {"id": "f-handbook", "name": "Team_Handbook.pdf", "kind": "pdf",
             "size": "1.8 MB", "modified": "2 May", "state": "normal",
             "owner": "Sofia Lindqvist"},
        ],
    },
]

# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

NOTES = [
    {
        "id": "note-onboarding",
        "title": "Things I keep forgetting",
        "updated": "12 August",
        "body": "Payroll portal: payroll.northbridge.example\n"
                "Remote access: access.northbridge.example\n"
                "Service Desk: extension 2200\n"
                "Marcus: extension 2104",
    },
    {
        "id": "note-q3",
        "title": "Q3 pack — open items",
        "updated": "Yesterday",
        "body": "- headcount tab still mine\n"
                "- Tom has regional splits done\n"
                "- Marcus wants revised model, not July\n"
                "- Calderwood invoice CF-20411 to check against contract",
    },
]

# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

AUTH_HISTORY = [
    {"id": "auth-h1", "app": "Northbridge Mail", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Today 08:47"},
    {"id": "auth-h2", "app": "Remote Access", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Yesterday 09:02"},
    {"id": "auth-h3", "app": "Northbridge Mail", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Yesterday 08:51"},
    {"id": "auth-h4", "app": "Expenses", "result": "Approved",
     "device": "Aarti's phone · Android", "location": "Bengaluru, IN",
     "when": "Wednesday 14:20"},
]

MFA_PROMPTS = [
    {
        "id": "mfa-vpn",
        "arrival": "triggered",
        "trigger": "browser_signin:access.northbridge.example",
        "surface": {
            "app": "Remote Access",
            "requested": "just now",
            "device": "NB-LT-4471 · Windows",
            "location": "Bengaluru, IN",
            "network": "Northbridge office network",
            "ip_class": "Corporate range",
            "number_match": "47",
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "This is the learner's own sign-in, seconds old, from this "
                   "workstation, on the office network.",
            "denying_costs": True,
        },
    },
    {
        "id": "mfa-unexpected",
        "arrival": "scheduled",
        "surface": {
            "app": "Northbridge Mail",
            "requested": "just now",
            "device": "Unrecognised device · Windows",
            "location": "Frankfurt, DE",
            "network": "Unknown",
            "ip_class": "Outside the corporate range",
            "number_match": "12",
        },
        "analysis": {
            "disposition": "hostile",
            "family": "mfa",
            "why": "An approval request for a sign-in the learner did not "
                   "start, from a place and device that appear nowhere in "
                   "their own approval history.",
            "signals": [
                "Nothing was signed into from this workstation in the minutes "
                "before the prompt.",
                "Every approval in the history is from Bengaluru on NB-LT-4471 "
                "or the learner's own phone.",
                "The device is not named, where genuine prompts name it.",
            ],
            "evidence": [
                {"id": "ev-mfa-history", "label": "Your own approval history",
                 "where": "Authenticator → Recent activity",
                 "action": "open_auth_history"},
                {"id": "ev-mfa-details", "label": "Device and location on the "
                                                  "prompt",
                 "where": "Authenticator → Details",
                 "action": "inspect_mfa:mfa-unexpected"},
                {"id": "ev-mfa-servicedesk", "label": "Service Desk contact",
                 "where": "Directory → Daniel Okonkwo",
                 "action": "open_contact:dir-daniel-okonkwo"},
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

CONVERSATIONS = [
    {
        "id": "conv-tom-brennan",
        "contact_id": "dir-tom-brennan",
        "name": "Tom Brennan",
        "initials": "TB",
        "presence": "available",
        "messages": [
            {"from": "Tom Brennan", "when": "Yesterday 17:41",
             "text": "Workbook's up. Headcount tab is yours whenever."},
            {"from": "Aarti Venkatesh", "when": "Yesterday 17:44",
             "text": "Got it, will do it Monday morning."},
        ],
    },
    {
        "id": "conv-marcus-hale",
        "contact_id": "dir-marcus-hale",
        "name": "Marcus Hale",
        "initials": "MH",
        "presence": "in a meeting",
        "messages": [
            {"from": "Marcus Hale", "when": "08:56",
             "text": "Sent you the agenda. Ten minutes on throughput, that's "
                     "all I need."},
        ],
    },
    {
        "id": "conv-arjun-rao",
        "contact_id": "dir-arjun-rao",
        "name": "Arjun Rao",
        "initials": "AR",
        "presence": "available",
        "messages": [
            {"from": "Arjun Rao", "when": "Tuesday 12:02",
             "text": "Seen CF-20411, amount is fine. Release it on the normal "
                     "terms when you're ready."},
        ],
        "verification_reply": {
            "prompt": "Ask Arjun whether the account change is genuine",
            "sent": "Have you approved a change of settlement account for "
                    "Calderwood? A mail has come in asking to pay CF-20411 to "
                    "a different bank today.",
            "reply": {
                "from": "Arjun Rao",
                "text": "No. Nothing has been approved and nothing should move "
                        "until Facilities confirm it on the number we hold. "
                        "Forward me what you got and don't reply to it.",
            },
        },
    },
    {
        "id": "conv-priya-menon",
        "contact_id": "dir-priya-menon",
        "name": "Priya Menon",
        "initials": "PM",
        "presence": "available",
        "messages": [
            {"from": "Priya Menon", "when": "Monday 08:14",
             "text": "Payslips are out. Shout if anything looks off."},
        ],
        "verification_reply": {
            "prompt": "Ask Priya whether payroll has asked anyone to confirm "
                      "a record",
            "sent": "Has payroll sent anything asking people to confirm their "
                    "salary record today?",
            "reply": {
                "from": "Priya Menon",
                "text": "No, nothing has gone out today, and we would never "
                        "ask you to sign in from a mail link. Send it to "
                        "security and delete it.",
            },
        },
    },
    {
        "id": "conv-lena-fischer",
        "contact_id": "dir-lena-fischer",
        "name": "Lena Fischer",
        "initials": "LF",
        "presence": "available",
        "messages": [
            {"from": "Lena Fischer", "when": "Monday 10:30",
             "text": "Thanks for the one you sent last week — it was the "
                     "same batch three other people got."},
        ],
    },
    {
        "id": "conv-ops-team",
        "contact_id": None,
        "name": "Operations team",
        "initials": "OT",
        "presence": "group",
        "members": ["Marcus Hale", "Tom Brennan", "Ravi Krishnan",
                    "Aarti Venkatesh"],
        "messages": [
            {"from": "Ravi Krishnan", "when": "08:42",
             "text": "Stand-up in Meeting Room 2 from this week, room 5 is "
                     "being recarpeted."},
        ],
    },
]

# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------
#
# Every page is authored here. The prototype browser cannot leave this table:
# anything else renders an inert "outside the synthetic network" page. No
# request is ever made, and no field value is read or retained.

BROWSER_HOME = "intranet.northbridge.example"

BROWSER_PAGES = {
    "intranet.northbridge.example": {
        "title": "Northbridge Intranet",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Northbridge Systems",
        "subheading": "Operations · Bengaluru",
        "sections": [
            {"title": "Today", "items": [
                "Q3 operations review — Tuesday, 11:00, Meeting Room 2",
                "Benefits enrolment closes 19 September",
                "Remote access maintenance Saturday 06:00–08:00",
            ]},
            {"title": "Frequently used", "items": [
                "payroll.northbridge.example — payslips and tax documents",
                "access.northbridge.example — remote access",
                "files.northbridge.example — team shared folders",
            ]},
        ],
    },
    "payroll.northbridge.example": {
        "title": "Northbridge Payroll",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Northbridge Payroll",
        "subheading": "Sign in with your Northbridge account",
        "signin_id": "payroll-legit",
        "note": "Payslips, tax documents and salary records.",
        "analysis": {"disposition": "legitimate"},
    },
    "payroll.northbridge.example/payslips": {
        "title": "Northbridge Payroll — payslips",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Northbridge Payroll",
        "subheading": "Sign in to see your payslips",
        "signin_id": "payroll-legit",
        "analysis": {"disposition": "legitimate"},
    },
    "access.northbridge.example": {
        "title": "Northbridge Remote Access",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Remote access",
        "subheading": "Sign in, then approve the request on your "
                      "authenticator.",
        "signin_id": "vpn-legit",
        "note": "Approval is required for every new session.",
        "analysis": {"disposition": "legitimate"},
    },
    "files.northbridge.example/operations/shared": {
        "title": "Northbridge Files — Operations",
        "chrome": "internal",
        "kind": "filelist",
        "heading": "Operations → Shared",
        "subheading": "Team shared folder",
        "location_id": "loc-shared",
    },
    "intranet.northbridge.example/it/maintenance": {
        "title": "Maintenance calendar",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Planned maintenance",
        "subheading": "Technology · next 30 days",
        "sections": [
            {"title": "This month", "items": [
                "Saturday 06:00–08:00 — remote access gateway, "
                "access.northbridge.example",
                "27 September 22:00 — file service reindex, no downtime "
                "expected",
            ]},
        ],
    },
    "intranet.northbridge.example/people/benefits": {
        "title": "Benefits 2026–27",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Benefits enrolment",
        "subheading": "People Operations",
        "sections": [
            {"title": "What is changing", "items": [
                "Dental cover moves to the Tier 2 provider on 1 October",
                "Cycle-to-work reopens in October",
                "No action needed if your selections are unchanged",
            ]},
        ],
    },
    "intranet.northbridge.example/comms/weekly": {
        "title": "Northbridge Weekly",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Northbridge Weekly",
        "subheading": "September, issue 3",
        "sections": [
            {"title": "In this issue", "items": [
                "Manchester floor plan changes from October",
                "Two new starters in Finance",
                "Cycle-to-work window reopens in October",
            ]},
        ],
    },
    "intranet.northbridge.example/finance/payments": {
        "title": "Supplier payments",
        "chrome": "internal",
        "kind": "payments",
        "heading": "Supplier payments",
        "subheading": "Operations · release queue",
        "note": "Account changes follow the vendor payment process. See "
                "Vendor_Payment_Process.pdf in your Documents folder.",
        "invoice": {
            "reference": "CF-20411",
            "supplier": "Calderwood Facilities Ltd",
            "amount": "£4,180.00",
            "approved_by": "Arjun Rao, 12:02 Tuesday",
            "account_of_record": "Nordvale Bank · 60-14-22 · ending 4417",
        },
        "analysis": {"disposition": "legitimate"},
    },
    "intranet.northbridge.example/it/support": {
        "title": "Service Desk",
        "chrome": "internal",
        "kind": "support",
        "heading": "Service Desk",
        "subheading": "Technology · extension 2200",
        "note": "Disconnecting takes this workstation off the network "
                "immediately. You will lose mail and shared folders until it "
                "is reconnected.",
        "sections": [
            {"title": "Before you call", "items": [
                "Note what you were doing when the problem started.",
                "Do not restart the machine if files are failing to open.",
            ]},
        ],
    },
    "calderwood.example": {
        "title": "Calderwood Facilities Ltd",
        "chrome": "external",
        "kind": "portal",
        "heading": "Calderwood Facilities Ltd",
        "subheading": "Supplier portal",
        "sections": [
            {"title": "Contact", "items": [
                "Account manager: Ines Duarte",
                "ines.duarte@calderwood.example",
                "+44 20 7946 0318",
            ]},
            {"title": "Remittance", "items": [
                "Account changes are confirmed by telephone only.",
            ]},
        ],
        "analysis": {"disposition": "legitimate"},
    },
    "payroll-northbridge.example/employee/verify": {
        "title": "Employee record confirmation",
        "chrome": "external",
        "kind": "signin",
        "heading": "Northbridge Employee Services",
        "subheading": "Confirm your salary record to complete the September "
                      "run",
        "signin_id": "portal-hostile",
        "note": "Session expires in 09:41.",
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "A credential-collection page. In this prototype it stores "
                   "nothing: the field is cleared on submit and its value is "
                   "never read.",
        },
    },
    "nbsystems-secure.example": {
        "title": "NB Systems Secure",
        "chrome": "external",
        "kind": "portal",
        "heading": "NB Systems Secure",
        "subheading": "Employee services gateway",
        "sections": [
            {"title": "Services", "items": [
                "Record confirmation",
                "Document retrieval",
            ]},
        ],
        "analysis": {"disposition": "hostile", "family": "phishing"},
    },
    "calderwood-billing.example": {
        "title": "Calderwood Billing Services",
        "chrome": "external",
        "kind": "portal",
        "heading": "Calderwood Billing Services",
        "subheading": "Accounts and remittance",
        "sections": [
            {"title": "Remittance", "items": [
                "Aveley Trust Bank · sort code 23-08-71 · account "
                "ending 9032",
            ]},
        ],
        "analysis": {"disposition": "hostile", "family": "bec"},
    },
}

BROWSER_BOOKMARKS = [
    {"label": "Intranet", "url": "intranet.northbridge.example"},
    {"label": "Payroll", "url": "payroll.northbridge.example"},
    {"label": "Remote access", "url": "access.northbridge.example"},
    {"label": "Shared files",
     "url": "files.northbridge.example/operations/shared"},
]

BROWSER_HISTORY = [
    {"url": "intranet.northbridge.example", "when": "Today 08:44"},
    {"url": "payroll.northbridge.example/payslips", "when": "Monday 08:20"},
    {"url": "files.northbridge.example/operations/shared",
     "when": "Thursday 17:45"},
]

# ---------------------------------------------------------------------------
# Notifications present at session start
# ---------------------------------------------------------------------------

OPENING_NOTIFICATIONS = [
    {
        "id": "n-open-1",
        "kind": "mail",
        "title": "4 unread messages",
        "body": "Marcus Hale, Ravi Krishnan, Tom Brennan and one other.",
        "when": "09:00",
        "opens": {"app": "mail"},
    },
    {
        "id": "n-open-2",
        "kind": "system",
        "title": "Backup completed",
        "body": "Documents and Desktop backed up at 07:30.",
        "when": "07:30",
        "opens": None,
    },
]
