/* RewindSec 2.0 UI prototype — learner debrief.
 *
 * Reads the run the workstation left in sessionStorage and draws the six
 * architecture dimensions, the timeline, the evidence table and the causal
 * chains behind each consequence.
 *
 * The arithmetic below is a DEMONSTRATION. It exists so the screen can show
 * plausible numbers, show a non-applicable dimension being excluded rather
 * than counted as zero, and make the shape of an evidence-aware score
 * judgeable by eye. It is not the scoring engine, it is not versioned, it was
 * not validated against anything, and no figure it produces may be cited.
 *
 * Opened directly with no run in storage, the page falls back to a small
 * authored example so the screen is always reviewable.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'rewindsec.prototype.run';

  function qs(selector) { return document.querySelector(selector); }

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function clamp(value, low, high) {
    return Math.max(low, Math.min(high, Math.round(value)));
  }

  function titleCase(value) {
    return String(value || '').charAt(0).toUpperCase() + String(value || '').slice(1);
  }

  // -----------------------------------------------------------------------
  // Fallback example run
  // -----------------------------------------------------------------------

  function exampleRun() {
    return {
      example: true,
      focus: 'mixed',
      mode: 'simulation',
      assessmentId: null,
      endedAt: '09:41',
      durationMinutes: 41,
      timeline: [
        { at: '09:00', kind: 'event', label: 'Session started',
          detail: 'Simulation · mixed focus' },
        { at: '09:03', kind: 'action', label: 'Opened: Q3 operations review — agenda and pre-read',
          detail: 'From Marcus Hale' },
        { at: '09:09', kind: 'action', label: 'Opened: Salary structure revision — confirmation required',
          detail: 'From Northbridge Payroll' },
        { at: '09:10', kind: 'investigation', label: 'Checked where a link in a message goes' },
        { at: '09:12', kind: 'decision', label: 'Signed in on the employee record page',
          detail: 'Browser → payroll-northbridge.example/employee/verify' },
        { at: '09:14', kind: 'consequence',
          label: 'A sign-in is recorded from a device that is not yours.',
          detail: 'Account access',
          cause: 'Signed in on the employee record page' },
        { at: '09:18', kind: 'consequence',
          label: 'An inbox rule is created that hides messages from Security Operations.',
          detail: 'Account access',
          cause: 'A sign-in is recorded from a device that is not yours.' },
        { at: '09:24', kind: 'consequence',
          label: 'A colleague receives a message that appears to come from you.',
          detail: 'Account access',
          cause: 'A sign-in is recorded from a device that is not yours.' },
        { at: '09:31', kind: 'action', label: 'Reported: Re: Calderwood Facilities — invoice CF-20411',
          detail: 'Mail' },
        { at: '09:33', kind: 'decision', label: 'Reported the account-change request',
          detail: 'Mail' }
      ],
      decisions: [
        { id: 'd-phish-credentials',
          label: 'Signed in on the employee record page',
          klass: 'unsafe', at: '09:12',
          where: 'Browser → payroll-northbridge.example/employee/verify',
          inspectedBefore: 1, evidenceTotal: 5,
          evidence: [] },
        { id: 'd-bec-report', label: 'Reported the account-change request',
          klass: 'safe', at: '09:33', where: 'Mail',
          inspectedBefore: 2, evidenceTotal: 4, evidence: [] }
      ],
      chains: [
        { chainId: 'chain-credentials', decisionId: 'd-phish-credentials',
          title: 'Account access', incidentId: 'inc-account', startedAt: '09:12',
          steps: [
            { id: 's-cred-1', cause: 'decision', at: '09:14',
              summary: 'A sign-in is recorded from a device that is not yours.' },
            { id: 's-cred-2', cause: 's-cred-1', at: '09:18',
              summary: 'An inbox rule is created that hides messages from Security Operations.' },
            { id: 's-cred-3', cause: 's-cred-2', at: '09:21',
              summary: 'Security Operations write to you — and the rule files their message away before you see it.' },
            { id: 's-cred-4', cause: 's-cred-1', at: '09:24',
              summary: 'A colleague receives a message that appears to come from you.' }
          ] }
      ],
      incidents: { 'inc-account': { id: 'inc-account', title: 'Account access' } },
      tasks: {
        'task-headcount': { id: 'task-headcount', state: 'outstanding',
          label: 'Confirm contractor headcount for Marcus' },
        'task-remote-access': { id: 'task-remote-access', state: 'not_started',
          label: 'Remote access session' }
      },
      observed: ['open_mail:m-payroll-restructure',
                 'inspect_link:m-payroll-restructure',
                 'open_contact:dir-calderwood',
                 'call_contact:dir-calderwood'],
      hostileDelivered: ['m-payroll-restructure', 'm-invoice-amend'],
      hostilePrompts: 0,
      deletedHostile: 0,
      filesImpacted: 0,
      evidenceUniverse: [
        { id: 'ev-phish-sender', label: 'Sending domain',
          where: 'Mail → message header', observed: false },
        { id: 'ev-phish-replyto', label: 'Reply-To domain',
          where: 'Mail → message header', observed: false },
        { id: 'ev-phish-link', label: 'Link destination host',
          where: 'Mail → link inspection', observed: true },
        { id: 'ev-phish-history', label: 'Earlier genuine payroll message',
          where: "Mail → search for 'payroll'", observed: false },
        { id: 'ev-phish-directory', label: 'Payroll contact of record',
          where: 'Directory → Priya Menon', observed: false },
        { id: 'ev-bec-sender', label: 'Sender address against the original thread',
          where: 'Mail → message header', observed: false },
        { id: 'ev-bec-original', label: 'Account details on the original invoice',
          where: 'Mail → the CF-20411 thread', observed: false },
        { id: 'ev-bec-directory', label: 'Supplier call-back number',
          where: 'Directory → Ines Duarte', observed: true },
        { id: 'ev-bec-finance', label: 'Finance approver on the known channel',
          where: 'Messages → Arjun Rao', observed: false }
      ]
    };
  }

  function loadRun() {
    try {
      var raw = window.sessionStorage.getItem(STORAGE_KEY);
      if (raw) { return JSON.parse(raw); }
    } catch (err) { /* fall through to the example */ }
    return exampleRun();
  }

  // -----------------------------------------------------------------------
  // Demonstration scoring
  // -----------------------------------------------------------------------

  function score(run) {
    var decisions = run.decisions || [];
    var observed = run.observed || [];
    var evidence = run.evidenceUniverse || [];

    function ofClass(name) {
      return decisions.filter(function (d) { return d.klass === name; });
    }
    function has(id) {
      return decisions.some(function (d) { return d.id === id; });
    }

    var hostile = (run.hostileDelivered || []).length + (run.hostilePrompts || 0);
    var unsafe = ofClass('unsafe').length;
    var safe = ofClass('safe').length;
    var over = ofClass('over_suspicious').length;

    var out = {};

    // Security Judgment -----------------------------------------------------
    out.security_judgment = hostile === 0 ? null
      : clamp(100 * Math.min(safe, hostile) / hostile - 24 * unsafe - 12 * over, 0, 100);

    // Evidence Use — proportion of decision-relevant, available evidence that
    // was actually inspected. Not a count of clicks.
    out.evidence_use = evidence.length === 0 ? null
      : clamp(100 * evidence.filter(function (e) { return e.observed; }).length
              / evidence.length, 0, 100);

    // Verification Discipline ------------------------------------------------
    var verifiable = (run.hostileDelivered || []).filter(function (id) {
      return id === 'm-payroll-restructure' || id === 'm-invoice-amend';
    }).length + ((run.hostilePrompts || 0) > 0 ? 1 : 0);
    var verifications = observed.filter(function (key) {
      return key.indexOf('call_contact:') === 0
        || key.indexOf('verify_message:') === 0
        || key === 'open_auth_history';
    }).length;
    out.verification_discipline = verifiable === 0 ? null
      : clamp(100 * Math.min(verifications, verifiable) / verifiable
              - (has('d-bec-reply') ? 30 : 0), 0, 100);

    // Incident Response -------------------------------------------------------
    if (hostile === 0) {
      out.incident_response = null;
    } else {
      var reports = decisions.filter(function (d) {
        return /-report$/.test(d.id);
      }).length;
      var value = 100 * Math.min(reports, hostile) / hostile;
      if (has('d-ransom-isolate')) { value += 15; }
      if (has('d-ransom-continue')) { value -= 28; }
      value -= 8 * (run.deletedHostile || 0);
      out.incident_response = clamp(value, 0, 100);
    }

    // Operational Accuracy -----------------------------------------------------
    var tasks = run.tasks || {};
    var started = 0;
    var done = 0;
    Object.keys(tasks).forEach(function (id) {
      var task = tasks[id];
      if (task.state === 'not_started') { return; }
      started += 1;
      if (task.state === 'done') { done += 1; }
    });
    if (started === 0 && over === 0 && !has('d-mfa-deny-legit')) {
      out.operational_accuracy = null;
    } else {
      var accuracy = started === 0 ? 100 : (100 * done / started);
      accuracy -= 25 * over;
      accuracy -= 20 * decisions.filter(function (d) {
        return d.id === 'd-mfa-deny-legit';
      }).length;
      out.operational_accuracy = clamp(accuracy, 0, 100);
    }

    // Recovery Quality ----------------------------------------------------------
    var incidents = Object.keys(run.incidents || {});
    if (!incidents.length) {
      out.recovery_quality = null;
    } else {
      var recovery = 55;
      if (has('d-ransom-isolate')) { recovery = 86; }
      if (has('d-ransom-continue')) { recovery = 28; }
      if ((run.filesImpacted || 0) > 3) { recovery -= 10; }
      if (reportedAny(decisions)) { recovery += 8; }
      out.recovery_quality = clamp(recovery, 0, 100);
    }

    return out;
  }

  function reportedAny(decisions) {
    return decisions.some(function (d) { return /-report$/.test(d.id); });
  }

  function overallScore(scores, weights) {
    var total = 0;
    var weight = 0;
    Object.keys(scores).forEach(function (id) {
      if (scores[id] === null) { return; }
      var w = weights[id] || 0;
      total += scores[id] * w;
      weight += w;
    });
    if (weight === 0) { return null; }
    return Math.round(total / weight);
  }

  // -----------------------------------------------------------------------
  // Rendering
  // -----------------------------------------------------------------------

  function meterClass(value) {
    if (value < 55) { return 'is-low'; }
    if (value < 75) { return 'is-mid'; }
    return 'is-high';
  }

  function renderDimensions(world, scores) {
    qs('#pw-res-dims').innerHTML = world.score_dimensions.map(function (dim) {
      var value = scores[dim.id];
      var applicable = value !== null && value !== undefined;
      return '<div class="pw-dim">'
        + '<div class="pw-dim-top"><b>' + esc(dim.label) + '</b>'
        + (applicable
            ? '<span class="pw-dim-value">' + value + '</span>'
            : '<span class="pw-dim-value is-na">N/A</span>')
        + '</div>'
        + (applicable
            ? '<div class="pw-meter ' + meterClass(value) + '"><span style="width:'
              + value + '%"></span></div>'
            : '<div class="pw-meter"><span style="width:0"></span></div>')
        + '<p>' + esc(dim.description) + '</p>'
        + (applicable ? ''
            : '<p class="pw-xsmall pw-muted">Nothing in this session exercised '
              + 'it, so it is excluded from the overall figure rather than '
              + 'counted as zero.</p>')
        + '</div>';
    }).join('');
  }

  function renderTimeline(run) {
    var entries = run.timeline || [];
    if (!entries.length) {
      qs('#pw-res-timeline').innerHTML =
        '<li class="pw-tl"><span class="pw-tl-main pw-muted">Nothing recorded.</span></li>';
      return;
    }
    qs('#pw-res-timeline').innerHTML = entries.map(function (entry) {
      return '<li class="pw-tl is-' + esc(entry.kind) + '">'
        + '<span class="pw-tl-time">' + esc(entry.at) + '</span>'
        + '<span class="pw-tl-main"><b>' + esc(entry.label) + '</b>'
        + (entry.detail ? '<span>' + esc(entry.detail) + '</span>' : '')
        + (entry.cause
            ? '<span class="pw-tl-cause">caused by · ' + esc(entry.cause) + '</span>'
            : '')
        + '</span></li>';
    }).join('');
  }

  function renderEvidence(run) {
    var rows = run.evidenceUniverse || [];
    if (!rows.length) {
      qs('#pw-res-evidence').innerHTML =
        '<tr><td colspan="3" class="pw-muted">No decision-relevant evidence '
        + 'was in play in this session.</td></tr>';
      return;
    }
    qs('#pw-res-evidence').innerHTML = rows.map(function (item) {
      return '<tr><td>' + esc(item.label) + '</td>'
        + '<td class="pw-xsmall pw-muted">' + esc(item.where) + '</td>'
        + '<td>' + (item.observed
            ? '<span class="pw-chip is-good">Yes</span>'
            : '<span class="pw-chip">No</span>') + '</td></tr>';
    }).join('');
  }

  function renderChains(run, world) {
    var chains = run.chains || [];
    if (!chains.length) {
      qs('#pw-res-chains').innerHTML =
        '<div class="pw-card pw-empty"><h3>No consequence chains ran</h3>'
        + '<p>Nothing you did set off a chain of effects in this session.</p></div>';
      return;
    }

    qs('#pw-res-chains').innerHTML = chains.map(function (chain) {
      var decision = (world.decisions || {})[chain.decisionId] || {};
      var depths = {};

      var nodes = (chain.steps || []).map(function (step) {
        var depth = step.cause === 'decision' ? 0
          : Math.min(2, (depths[step.cause] === undefined ? 0 : depths[step.cause]) + 1);
        depths[step.id] = depth;
        return '<div class="pw-causal-node is-depth-' + depth
          + (depth === 0 ? ' is-root' : '') + '">'
          + esc(step.summary)
          + '<span>' + esc(step.at) + '</span></div>';
      }).join('');

      return '<div class="pw-causal">'
        + '<div class="pw-causal-head">'
        + '<b>' + esc(decision.label || chain.decisionId) + '</b>'
        + '<span>' + esc(chain.title) + ' · started ' + esc(chain.startedAt)
        + (chain.incidentId ? ' · incident ' + esc(chain.incidentId) : '')
        + '</span></div>'
        + '<div class="pw-causal-body">' + (nodes
            || '<p class="pw-small pw-muted">The chain had not reached its '
               + 'first effect when the session ended.</p>') + '</div>'
        + '</div>';
    }).join('');
  }

  function renderDecisions(run) {
    var decisions = run.decisions || [];
    if (!decisions.length) {
      qs('#pw-res-decisions').innerHTML =
        '<tr><td colspan="4" class="pw-muted">No consequential decision was '
        + 'recorded.</td></tr>';
      return;
    }
    qs('#pw-res-decisions').innerHTML = decisions.map(function (decision) {
      var chip = {
        unsafe: 'is-alert', safe: 'is-good', over_suspicious: 'is-caution',
        recovery_good: 'is-good', recovery_poor: 'is-caution',
        incomplete: 'is-caution', neutral: ''
      }[decision.klass] || '';
      var label = {
        unsafe: 'worsened the situation', safe: 'held up',
        over_suspicious: 'cost time elsewhere',
        recovery_good: 'contained it', recovery_poor: 'let it spread',
        neutral: 'no material effect'
      }[decision.klass] || decision.klass;

      return '<tr><td class="is-num">' + esc(decision.at) + '</td>'
        + '<td><b>' + esc(decision.label) + '</b>'
        + '<div class="pw-xsmall"><span class="pw-chip ' + chip + '">'
        + esc(label) + '</span></div></td>'
        + '<td class="pw-xsmall pw-muted">' + esc(decision.where || '—') + '</td>'
        + '<td class="is-num">'
        + (decision.evidenceTotal
            ? esc(decision.inspectedBefore) + ' of ' + esc(decision.evidenceTotal)
            : '<span class="pw-muted">—</span>')
        + '</td></tr>';
    }).join('');
  }

  function renderHero(run, overall) {
    qs('#pw-res-overall').textContent = overall === null ? '—' : overall;

    var outstanding = Object.keys(run.tasks || {}).map(function (id) {
      return run.tasks[id];
    }).filter(function (task) {
      return task.state === 'outstanding' || task.state === 'interrupted';
    });

    qs('#pw-res-sub').textContent = run.example
      ? 'An authored example session, shown because this page was opened '
        + 'directly rather than from a workstation run.'
      : 'You worked for ' + run.durationMinutes + ' simulated minutes and '
        + 'finished at ' + run.endedAt + '.';

    var chips = [
      '<span class="pw-chip is-plain">' + esc(titleCase(run.focus)) + ' focus</span>',
      '<span class="pw-chip is-plain">' + esc(titleCase(run.mode)) + '</span>',
      '<span class="pw-chip is-plain">'
        + (run.decisions || []).length + ' consequential decisions</span>'
    ];
    if (run.assessmentId) {
      chips.push('<span class="pw-chip is-caution">Assessment attempt</span>');
    }
    if (outstanding.length) {
      chips.push('<span class="pw-chip is-caution">' + outstanding.length
        + ' item' + (outstanding.length === 1 ? '' : 's') + ' left undone</span>');
    }
    if (run.filesImpacted) {
      chips.push('<span class="pw-chip is-alert">' + run.filesImpacted
        + ' files unusable</span>');
    }
    qs('#pw-res-meta').innerHTML = chips.join('');

    var retry = qs('#pw-res-retry');
    retry.href = '/prototype/workstation?focus=' + encodeURIComponent(run.focus)
      + '&mode=' + encodeURIComponent(run.mode)
      + (run.assessmentId ? '&assessment=' + encodeURIComponent(run.assessmentId) : '');

    if (run.mode === 'assessment') {
      var note = document.createElement('div');
      note.className = 'pw-note is-accent';
      note.style.marginTop = '1rem';
      note.textContent = 'Nothing was explained to you during the attempt. '
        + 'This page is the first feedback the attempt produced, which is what '
        + 'Assessment mode is for.';
      qs('#pw-res-meta').parentNode.appendChild(note);
    }
  }

  // -----------------------------------------------------------------------
  // Boot
  // -----------------------------------------------------------------------

  fetch('/prototype/api/world', { headers: { Accept: 'application/json' } })
    .then(function (response) { return response.json(); })
    .then(function (world) {
      var run = loadRun();
      var scores = score(run);
      var overall = overallScore(scores, world.demo_weights);

      renderHero(run, overall);
      renderDimensions(world, scores);
      renderTimeline(run);
      renderEvidence(run);
      renderChains(run, world);
      renderDecisions(run);
    })
    .catch(function (error) {
      if (window.console) { window.console.error(error); }
    });
}());
