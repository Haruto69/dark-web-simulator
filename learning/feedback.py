"""Authored learner-facing wording for the learning feedback page.

Every sentence a learner reads about their own decision comes from a fixed
table here. Nothing is generated, templated from their input, or produced by a
model, and the only variable ever interpolated is the confidence number they
themselves stated.

Wording rules, applied throughout
---------------------------------
*  **The response is described, never the person.** "This response suggests
   this concept may need reinforcement", not "you have a misconception". The
   internal signal ``misconception_candidate`` never reaches a page.
*  **No grade, no percentage, no mastery bar, no badge.** There is no global
   score in R6 and nothing here composes one.
*  **No shame language and no psychological labels.** A risky response is
   described as what it did in the exercise.
*  **Neutral about confidence.** High confidence with a risky response is
   worth noticing; it is not a character flaw, and the wording says so.
"""

from types import MappingProxyType

from . import assessment as A
from . import concepts as C
from .errors import UnknownScenarioError
from .quality import BEC, MFA, PARTIAL, PHISHING, PROTECTIVE, RANSOMWARE, RISKY

#: Short neutral name for each authored response quality.
QUALITY_LABELS = MappingProxyType({
    PROTECTIVE: "Protective response",
    PARTIAL: "Partial response",
    RISKY: "Risky response",
})

#: One-line description of what each quality means *in this exercise*.
QUALITY_SUMMARIES = MappingProxyType({
    PROTECTIVE: ("In this scenario, that response broke the chain of events "
                 "before the damaging step."),
    PARTIAL: ("In this scenario, that response helped, but it left the "
              "decisive risk in place."),
    RISKY: ("In this scenario, that response allowed the chain of events to "
            "continue."),
})

#: The authored confidence sentence for each quality/confidence interpretation.
#: One sentence each, describing the response and what to do with it.
CONFIDENCE_SENTENCES = MappingProxyType({
    A.CONFIDENT_PROTECTIVE: (
        "That was a protective response, and you were confident in it. Worth "
        "noticing what made the request recognisable, so it stays recognisable "
        "on a different surface."),
    A.FRAGILE_PROTECTIVE: (
        "That was a protective response, but your confidence was relatively "
        "low. The judgement was sound; the reasoning behind it is what is "
        "worth making explicit."),
    A.HIGH_CONFIDENCE_RISK: (
        "That was a high-confidence risky response in this scenario. That "
        "combination is the most useful thing this exercise can show you: the "
        "situation looked clear, and the outcome went the other way."),
    A.RECOGNIZED_UNCERTAINTY: (
        "That response allowed the chain of events to continue, and your "
        "confidence was already low. Recognising the uncertainty is the useful "
        "part; the next step is knowing which check resolves it."),
    A.PARTIAL_RESPONSE: (
        "That response addressed part of the situation. It is worth being "
        "precise about which part it left open."),
})

#: ``(scenario_key, concept_tag) -> one authored statement to carry forward``.
#:
#: Scenario-scoped like everything else in this package: ``incident_reporting``
#: is a shared concept, but what a learner should carry forward about it is
#: phrased for the situation they were actually in.
_CONCEPT_STATEMENTS = {
    (PHISHING, C.SENDER_VERIFICATION):
        "A display name is chosen by the sender. The address behind it, and "
        "the domain at the end of it, are what identify who actually wrote.",
    (PHISHING, C.INDEPENDENT_VERIFICATION):
        "Verify an urgent request through a route you already had -- a saved "
        "number, a bookmarked portal -- not one the request supplied.",
    (PHISHING, C.CREDENTIAL_EXPOSURE):
        "Credentials are the point of the exercise for an attacker. Once they "
        "are entered, everything after that happens without you.",

    (RANSOMWARE, C.ENDPOINT_ISOLATION):
        "Containment comes before investigation. Taking the machine off "
        "the network stops impact from spreading while everything else is "
        "worked out.",
    (RANSOMWARE, C.INCIDENT_REPORTING):
        "Reporting brings people who can help, but it does not by itself stop "
        "what is already running.",
    (RANSOMWARE, C.RECOVERY_SEQUENCE):
        "Recovery steps -- restarting, reopening, retrying -- belong after "
        "containment. Taken first, they can extend the impact instead of "
        "ending it.",

    (MFA, C.MFA_PROMPT_VERIFICATION):
        "An approval prompt is a decision, not a notification. Read what is "
        "being approved before answering it.",
    (MFA, C.UNEXPECTED_AUTHENTICATION):
        "A sign-in you did not start is someone else's sign-in. An unexpected "
        "prompt is a signal in itself, whatever the details say.",
    (MFA, C.INCIDENT_REPORTING):
        "Denying an unexpected prompt protects the account; reporting it is "
        "what lets anyone else find out the attempt happened.",

    (BEC, C.SECONDARY_CHANNEL_VERIFICATION):
        "Verification has to leave the channel the request arrived on. A "
        "reply to a compromised thread reaches whoever controls it.",
    (BEC, C.PAYMENT_CHANGE_VERIFICATION):
        "A change of bank details is the request worth checking, however "
        "ordinary the rest of the message looks.",
    (BEC, C.INCIDENT_ESCALATION):
        "Escalating a suspicious payment change costs a delay. Not escalating "
        "one costs the payment.",
}

CONCEPT_STATEMENTS = MappingProxyType(dict(_CONCEPT_STATEMENTS))

#: The neutral heading shown above the concepts a learner should carry forward,
#: chosen by the strength of the evidence signal. Never a diagnosis.
SIGNAL_HEADINGS = MappingProxyType({
    A.SUPPORTING_EVIDENCE: "Worth keeping hold of",
    A.FRAGILE_UNDERSTANDING: "Worth making explicit",
    A.PARTIAL_UNDERSTANDING: "Worth completing",
    A.NEEDS_REINFORCEMENT: "Worth reinforcing",
    A.MISCONCEPTION_CANDIDATE: "Worth reinforcing",
})

#: The one sentence that explains what an evidence signal is *for*, in learner
#: terms. Deliberately about the concept, never about the learner.
SIGNAL_NOTES = MappingProxyType({
    A.SUPPORTING_EVIDENCE:
        "This response supports these concepts.",
    A.FRAGILE_UNDERSTANDING:
        "This response suggests these concepts are in place but not yet "
        "settled.",
    A.PARTIAL_UNDERSTANDING:
        "This response suggests these concepts are partly in place.",
    A.NEEDS_REINFORCEMENT:
        "This response suggests these concepts may need reinforcement.",
    A.MISCONCEPTION_CANDIDATE:
        "This response suggests these concepts may need reinforcement.",
})

#: Where the learner goes after the feedback page. Purely presentational.
MAX_CARRY_FORWARD = 3


def quality_label(quality):
    return QUALITY_LABELS.get(quality, quality)


def quality_summary(quality):
    return QUALITY_SUMMARIES.get(quality, "")


def confidence_sentence(assessment):
    """The authored sentence for this assessment's confidence interpretation."""
    return CONFIDENCE_SENTENCES[assessment.confidence_interpretation]


def confidence_statement(assessment):
    """"You chose this response with N% confidence." -- or nothing.

    The only interpolated value on the whole page, and it is the learner's own
    stated number. When no confidence was recorded, there is no sentence rather
    than an invented one.
    """
    if assessment.confidence is None:
        return None
    return ("You chose this response with {0}% confidence."
            .format(assessment.confidence))


def concept_statement(scenario_key, concept_tag):
    """One authored statement, or ``None`` when nothing is authored for it."""
    return CONCEPT_STATEMENTS.get((scenario_key, concept_tag))


def carry_forward(scenario_key, concept_tags, limit=MAX_CARRY_FORWARD):
    """One to three authored concept statements, in authored tag order.

    Only the concepts the response actually gave evidence about, so the page
    never recites the whole scenario back at a learner who addressed one part
    of it.
    """
    if scenario_key not in {PHISHING, RANSOMWARE, MFA, BEC}:
        raise UnknownScenarioError(
            "no feedback wording for scenario {0!r}".format(scenario_key))
    statements = []
    for tag in concept_tags:
        text = concept_statement(scenario_key, tag)
        if text is not None:
            statements.append({"concept_tag": tag, "statement": text})
        if len(statements) >= limit:
            break
    return tuple(statements)


def signal_heading(evidence_signal):
    return SIGNAL_HEADINGS.get(evidence_signal, "Worth carrying forward")


def signal_note(evidence_signal):
    return SIGNAL_NOTES.get(evidence_signal, "")
