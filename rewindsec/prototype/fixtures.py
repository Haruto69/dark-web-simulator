"""Assembles the prototype fixture snapshot and the checks that keep it safe.

One function, :func:`learner_snapshot`, returns the whole synthetic world as a
single JSON-serialisable document. The prototype front end fetches it once and
renders from it. That is the seam that keeps the eventual backend wiring
plausible: today the document is authored data, later it is produced by the
real simulation, and the client's job -- render what the server says the world
is -- does not change.

The rest of this module is enforcement. :func:`surface_strings` enumerates
exactly the text the learner can read inside the workstation, and
:func:`referenced_hosts` enumerates every destination the prototype can name.
``tests/test_prototype_ui.py`` uses both, so "no live destination" and "no
threat label on the workstation surface" are properties the suite holds rather
than intentions the content happens to satisfy today.
"""

import re

from rewindsec.prototype import scenario_fixtures as scen
from rewindsec.prototype import trainer_fixtures as trainer
from rewindsec.prototype import world_fixtures as world

#: Reserved, non-resolving TLDs. Every destination named anywhere in the
#: prototype must sit under one of these. ``.example`` is reserved by RFC 2606
#: precisely so documentation and training material cannot accidentally point
#: at somebody's real service.
INERT_SUFFIXES = (".example", ".invalid", ".test", ".localhost")

#: Vocabulary that must never appear on the learner-visible workstation
#: surface. A hostile message that announces itself is not a training event,
#: it is a quiz question with extra steps.
#:
#: Whole-word patterns, because substring matching would flag "because" for
#: "bec" and "attachment" for "attach" and would then be deleted by the first
#: person it inconvenienced.
FORBIDDEN_SURFACE_PATTERNS = (
    r"phish\w*",
    r"ransomware",
    r"malware",
    r"malicious\w*",
    r"business email compromise",
    r"bec",
    r"mfa fatigue",
    r"threat\w*",
    r"attacker\w*",
    r"attack",
    r"attacks",
    r"spoof\w*",
    r"fraudulent",
    r"scam\w*",
    r"training module",
    r"simulation exercise",
    r"security awareness",
)

_FORBIDDEN_SURFACE_RE = re.compile(
    r"\b(?:%s)\b" % "|".join(FORBIDDEN_SURFACE_PATTERNS), re.IGNORECASE)

_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_BARE_HOST_RE = re.compile(r"\b([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)\b")


# ---------------------------------------------------------------------------
# Snapshot assembly
# ---------------------------------------------------------------------------

def _all_mail():
    return list(world.MAIL) + list(scen.CONSEQUENCE_MAIL)


def learner_snapshot():
    """The whole synthetic workplace, as one JSON-serialisable document.

    Includes the authored ``analysis`` blocks, because the comparison screen,
    the debrief and the prototype developer panel are all rendered from this
    same document. The workstation renderer never reads them; that separation
    is a property of the front end and is checked by the suite.
    """
    return {
        "prototype": {
            "name": "RewindSec 2.0 UI prototype",
            "kind": "fixture-backed presentation prototype",
            "warning": "Every value in this document is authored synthetic "
                       "fixture data. No simulation engine, scheduler, "
                       "context ledger, scoring engine or persistence layer "
                       "is running behind it.",
        },
        "organization": world.ORGANIZATION,
        "learner": world.LEARNER,
        "directory": world.DIRECTORY,
        "mail": _all_mail(),
        "files": world.FILE_TREE,
        "notes": world.NOTES,
        "auth_history": world.AUTH_HISTORY,
        "mfa_prompts": world.MFA_PROMPTS,
        "conversations": world.CONVERSATIONS,
        "browser": {
            "home": world.BROWSER_HOME,
            "pages": world.BROWSER_PAGES,
            "bookmarks": world.BROWSER_BOOKMARKS,
            "history": world.BROWSER_HISTORY,
        },
        "notifications": world.OPENING_NOTIFICATIONS,
        "focus_options": scen.FOCUS_OPTIONS,
        "modes": scen.MODES,
        "cadence": scen.CADENCE,
        "timelines": scen.TIMELINES,
        "decisions": scen.DECISIONS,
        "chains": scen.CONSEQUENCE_CHAINS,
        "safer_alternatives": scen.SAFER_ALTERNATIVES,
        "score_dimensions": scen.SCORE_DIMENSIONS,
        "demo_weights": scen.DEMO_WEIGHTS,
        "tasks": scen.TASKS,
        "safety": safety_report(),
    }


def trainer_snapshot():
    """Trainer-side records, resolved enough for the templates to render."""
    students_by_id = {s["id"]: s for s in trainer.STUDENTS}
    groups_by_id = {g["id"]: g for g in trainer.GROUPS}
    assessments_by_id = {a["id"]: a for a in trainer.ASSESSMENTS}

    return {
        "trainer": trainer.TRAINER,
        "students": trainer.STUDENTS,
        "groups": trainer.GROUPS,
        "assessments": trainer.ASSESSMENTS,
        "assignments": trainer.ASSIGNMENTS,
        "sessions": trainer.SESSIONS,
        "dashboard_metrics": trainer.DASHBOARD_METRICS,
        "cohort_metrics": trainer.COHORT_METRICS,
        "index": {
            "students_by_id": students_by_id,
            "groups_by_id": groups_by_id,
            "assessments_by_id": assessments_by_id,
        },
    }


def student_detail(student_id):
    """One student with their sessions, groups and resolved assignments."""
    snapshot = trainer_snapshot()
    student = snapshot["index"]["students_by_id"].get(student_id)
    if student is None:
        return None

    groups = [g for g in snapshot["groups"] if student_id in g["members"]]
    group_ids = {g["id"] for g in groups}

    assignments = []
    for row in snapshot["assignments"]:
        assessment = snapshot["index"]["assessments_by_id"].get(
            row["assessment_id"])
        if assessment is None:
            continue
        if row["source"] == "direct" and row["student_id"] == student_id:
            assignments.append({
                "assignment_id": row["id"],
                "assessment": assessment,
                "source": "direct",
                "origin_label": "Assigned directly",
                "created": row["created"],
                "created_by": row["created_by"],
            })
        elif row["source"] == "group" and row["group_id"] in group_ids:
            group = snapshot["index"]["groups_by_id"][row["group_id"]]
            assignments.append({
                "assignment_id": row["id"],
                "assessment": assessment,
                "source": "group",
                "origin_label": "Via group · %s" % group["name"],
                "created": row["created"],
                "created_by": row["created_by"],
            })

    sessions = [s for s in snapshot["sessions"]
                if s["student_id"] == student_id]

    return {
        "student": student,
        "groups": groups,
        "assignments": assignments,
        "sessions": sessions,
    }


def group_detail(group_id):
    """One group with its members and the assessments it carries."""
    snapshot = trainer_snapshot()
    group = snapshot["index"]["groups_by_id"].get(group_id)
    if group is None:
        return None

    members = [snapshot["index"]["students_by_id"][sid]
               for sid in group["members"]
               if sid in snapshot["index"]["students_by_id"]]

    assessments = []
    for row in snapshot["assignments"]:
        if row["source"] == "group" and row["group_id"] == group_id:
            assessment = snapshot["index"]["assessments_by_id"].get(
                row["assessment_id"])
            if assessment is not None:
                assessments.append({"assessment": assessment,
                                    "created": row["created"],
                                    "created_by": row["created_by"]})

    other_groups = []
    for other in snapshot["groups"]:
        if other["id"] == group_id:
            continue
        shared = [sid for sid in other["members"] if sid in group["members"]]
        if shared:
            other_groups.append({
                "group": other,
                "shared": [snapshot["index"]["students_by_id"][sid]["name"]
                           for sid in shared],
            })

    return {
        "group": group,
        "members": members,
        "assessments": assessments,
        "overlapping_groups": other_groups,
    }


def existing_assignment_sources(assessment_id, student_id):
    """Every route by which *student_id* already receives *assessment_id*.

    This is the data behind the duplicate-assignment warning in architecture
    §27. It returns a list rather than a boolean precisely because the answer
    "already assigned" is not useful on its own -- the trainer needs to know
    *where it came from* before deciding whether a second, separately
    provenanced assignment is what they want.
    """
    snapshot = trainer_snapshot()
    groups = {g["id"] for g in snapshot["groups"]
              if student_id in g["members"]}
    found = []
    for row in snapshot["assignments"]:
        if row["assessment_id"] != assessment_id:
            continue
        if row["source"] == "direct" and row["student_id"] == student_id:
            found.append({
                "source": "direct",
                "label": "Assigned directly to this student",
                "created": row["created"],
                "created_by": row["created_by"],
                "assignment_id": row["id"],
            })
        elif row["source"] == "group" and row["group_id"] in groups:
            group = snapshot["index"]["groups_by_id"][row["group_id"]]
            found.append({
                "source": "group",
                "label": "Via group · %s" % group["name"],
                "group_id": group["id"],
                "group_name": group["name"],
                "created": row["created"],
                "created_by": row["created_by"],
                "assignment_id": row["id"],
            })
    return found


# ---------------------------------------------------------------------------
# Safety enumeration
# ---------------------------------------------------------------------------

def referenced_hosts():
    """Every host name the prototype can display or navigate to.

    Collected from mail links, mail bodies, browser page keys, bookmarks,
    history, directory records and the organisation profile. A host that is
    not inert would be a live destination inside training content, which the
    research requirements forbid outright (R5) -- so this list is asserted
    against :data:`INERT_SUFFIXES` in the suite rather than eyeballed.
    """
    hosts = set()

    def add_from_text(text):
        if not isinstance(text, str):
            return
        for host in _HOST_RE.findall(text):
            hosts.add(host.split("/")[0].lower())
        for host in _BARE_HOST_RE.findall(text):
            lowered = host.lower()
            # Only treat it as a host if it ends in something that looks like
            # a TLD rather than a file extension or an abbreviation.
            if lowered.endswith(INERT_SUFFIXES) or lowered.endswith(
                    (".com", ".net", ".org", ".io", ".co", ".in", ".uk",
                     ".de", ".ru", ".cn", ".xyz", ".info", ".biz")):
                hosts.add(lowered)

    for message in _all_mail():
        surface = message["surface"]
        for link in surface.get("links", []):
            add_from_text(link.get("href", ""))
        for field in ("from_address", "reply_to", "to", "cc"):
            value = surface.get(field)
            if isinstance(value, str) and "@" in value:
                hosts.add(value.split("@")[-1].strip().lower())
        for paragraph in surface.get("body", []):
            add_from_text(paragraph)

    for url in world.BROWSER_PAGES:
        hosts.add(url.split("/")[0].lower())
    for bookmark in world.BROWSER_BOOKMARKS:
        hosts.add(bookmark["url"].split("/")[0].lower())
    for entry in world.BROWSER_HISTORY:
        hosts.add(entry["url"].split("/")[0].lower())

    for contact in world.DIRECTORY:
        email = contact.get("email") or ""
        if "@" in email:
            hosts.add(email.split("@")[-1].strip().lower())
        add_from_text(contact.get("note") or "")

    hosts.add(world.ORGANIZATION["domain"].lower())
    for host in world.ORGANIZATION["known_hosts"].values():
        hosts.add(host.lower())
    hosts.add(world.LEARNER["email"].split("@")[-1].lower())

    for location in world.FILE_TREE:
        add_from_text(location.get("path") or "")

    return sorted(hosts)


def surface_strings():
    """Every string the learner can read *inside the workstation*.

    Deliberately excludes ``analysis`` blocks, the comparison screen and the
    debrief: those are post-hoc pedagogy and are allowed to name a technique.
    What must stay clean is the workplace itself.

    Yields ``(location, text)`` pairs so a failure names the offending record.
    """
    for message in _all_mail():
        surface = message["surface"]
        where = "mail:%s" % message["id"]
        for field in ("subject", "from_name", "from_address", "reply_to",
                      "to", "cc"):
            value = surface.get(field)
            if isinstance(value, str):
                yield ("%s.%s" % (where, field), value)
        for index, paragraph in enumerate(surface.get("body", [])):
            yield ("%s.body[%d]" % (where, index), paragraph)
        for link in surface.get("links", []):
            yield ("%s.link" % where, link.get("text", ""))
            yield ("%s.link.href" % where, link.get("href", ""))
        for attachment in surface.get("attachments", []):
            yield ("%s.attachment" % where, attachment.get("name", ""))

    for location in world.FILE_TREE:
        yield ("files:%s" % location["id"], location["name"])
        for item in location["files"]:
            yield ("files:%s.%s" % (location["id"], item["id"]), item["name"])
            for line in item.get("preview", []):
                yield ("files:%s.%s.preview" % (location["id"], item["id"]),
                       line)

    for prompt in world.MFA_PROMPTS:
        for key, value in prompt["surface"].items():
            if isinstance(value, str):
                yield ("mfa:%s.%s" % (prompt["id"], key), value)

    for conversation in world.CONVERSATIONS:
        yield ("messages:%s.name" % conversation["id"], conversation["name"])
        for index, line in enumerate(conversation["messages"]):
            yield ("messages:%s[%d]" % (conversation["id"], index),
                   line["text"])
        verification = conversation.get("verification_reply")
        if verification:
            yield ("messages:%s.verify.prompt" % conversation["id"],
                   verification["prompt"])
            yield ("messages:%s.verify.sent" % conversation["id"],
                   verification["sent"])
            yield ("messages:%s.verify.reply" % conversation["id"],
                   verification["reply"]["text"])

    for contact in world.DIRECTORY:
        for field in ("name", "role", "department", "email", "relationship",
                      "note", "callback"):
            value = contact.get(field)
            if isinstance(value, str):
                yield ("directory:%s.%s" % (contact["id"], field), value)

    for url, page in world.BROWSER_PAGES.items():
        yield ("browser:%s.url" % url, url)
        for field in ("title", "heading", "subheading", "note"):
            value = page.get(field)
            if isinstance(value, str):
                yield ("browser:%s.%s" % (url, field), value)
        for key, value in (page.get("invoice") or {}).items():
            yield ("browser:%s.invoice.%s" % (url, key), value)
        for section in page.get("sections", []):
            yield ("browser:%s.section" % url, section["title"])
            for item in section["items"]:
                yield ("browser:%s.item" % url, item)

    for note in world.NOTES:
        yield ("notes:%s.title" % note["id"], note["title"])
        yield ("notes:%s.body" % note["id"], note["body"])

    for notification in world.OPENING_NOTIFICATIONS:
        yield ("notification:%s.title" % notification["id"],
               notification["title"])
        yield ("notification:%s.body" % notification["id"],
               notification["body"])

    for entry in world.AUTH_HISTORY:
        for field in ("app", "result", "device", "location", "when"):
            yield ("auth:%s.%s" % (entry["id"], field), entry[field])

    # Consequence effects also land on the workstation surface, so they are
    # held to the same rule.
    for chain in scen.CONSEQUENCE_CHAINS.values():
        for step in chain["steps"]:
            for effect in step["effects"]:
                where = "chain:%s.%s" % (chain["id"], step["id"])
                for field in ("title", "body", "text", "note", "device",
                              "location", "app", "result"):
                    value = effect.get(field)
                    if isinstance(value, str):
                        yield ("%s.%s" % (where, field), value)


def surface_violations():
    """Learner-visible strings that carry threat vocabulary.

    Returns ``(location, text, matched_word)`` triples. An empty result is the
    property the suite asserts: inside the workstation, a hostile event has to
    look like ordinary work.
    """
    found = []
    for where, text in surface_strings():
        if not isinstance(text, str):
            continue
        match = _FORBIDDEN_SURFACE_RE.search(text)
        if match:
            found.append((where, text, match.group(0)))
    return found


def safety_report():
    """A machine-checkable statement of what this prototype does and does not do.

    Rendered in the prototype's own developer panel and asserted in the suite,
    so the claims cannot drift away from the content.
    """
    hosts = referenced_hosts()
    return {
        "organization_is_fictional": True,
        "identities_are_fictional": True,
        "destinations_are_inert": all(h.endswith(INERT_SUFFIXES)
                                      for h in hosts),
        "referenced_hosts": hosts,
        "collects_credentials": False,
        "executes_attachments": False,
        "writes_real_files": False,
        "uses_docker": False,
        "makes_external_requests": False,
        "uses_external_dataset": False,
        "notes": [
            "Attachment names are strings in a fixture. No file of any kind "
            "is created, opened, downloaded or executed.",
            "The sign-in pages in the prototype browser never read the value "
            "of a password field, never serialise a form and never issue a "
            "request. The field is cleared on submit.",
            "File 'impact' is a label on a fixture row. Nothing on the host "
            "filesystem is touched.",
            "Every host name is under a reserved non-resolving TLD.",
        ],
    }
