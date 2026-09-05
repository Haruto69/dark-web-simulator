/* RewindSec 2.0 UI prototype — the synthetic workstation.
 *
 * WHAT THIS IS
 * ------------
 * A presentation prototype. It fetches one authored document from
 * /prototype/api/world and renders a workplace from it. Learner actions
 * mutate a client-side copy of that document and play back *server-authored*
 * consequence chains on a timer.
 *
 * WHAT THIS IS NOT
 * ----------------
 * It is not the simulation. There is no session, no world model, no context
 * ledger, no hazard scheduler, no evidence graph, no scoring engine and no
 * persistence. Nothing here should be read as evidence that any of those
 * work, and nothing here should be carried into the backend batches as an
 * implementation.
 *
 * THE SEAM
 * --------
 * Consequences are never invented in this file. Every effect comes from
 * `WORLD.chains`, which the server authored, keyed by the decision that
 * causes it, with its causal parent and its delay already stated. Production
 * replaces "fetch a document, then play its chains locally" with "subscribe
 * to the server's event stream"; the renderer's contract — draw what the
 * server says the world is — is unchanged. That is deliberate, because the
 * one design assumption this prototype must not bake in is that important
 * consequences can stay in client JavaScript.
 */
(function () {
  'use strict';

  // =========================================================================
  // Small helpers
  // =========================================================================

  function qs(selector, root) { return (root || document).querySelector(selector); }
  function qsa(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function icon(name, extra) {
    return '<svg aria-hidden="true"' + (extra ? ' ' + extra : '')
      + '><use href="#i-' + name + '"></use></svg>';
  }

  function clone(value) { return JSON.parse(JSON.stringify(value)); }

  function clamp(value, low, high) {
    return Math.max(low, Math.min(high, value));
  }

  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }

  // =========================================================================
  // Session state
  // =========================================================================

  var WORLD = null;   // the authored document from the server
  var S = null;       // this run's mutable copy plus what the learner has done
  var WIN = {};       // window geometry / open / focus state
  var APP = {};       // per-application view state, survives close and reopen
  var timers = [];

  var APPS = {
    mail: { label: 'Mail', icon: 'mail', w: 1020, h: 660 },
    browser: { label: 'Browser', icon: 'globe', w: 940, h: 640 },
    files: { label: 'Files', icon: 'folder', w: 880, h: 560 },
    messages: { label: 'Messages', icon: 'chat', w: 800, h: 560 },
    authenticator: { label: 'Authenticator', icon: 'shield', w: 700, h: 560 },
    directory: { label: 'Directory', icon: 'book', w: 800, h: 560 },
    notes: { label: 'Notes', icon: 'note', w: 720, h: 500 }
  };

  var FOLDERS = [
    { id: 'inbox', label: 'Inbox', icon: 'mail' },
    { id: 'archive', label: 'Archive', icon: 'folder' },
    { id: 'sent', label: 'Sent', icon: 'reply' },
    { id: 'reported', label: 'Reported', icon: 'flag' },
    { id: 'deleted', label: 'Deleted', icon: 'trash' }
  ];

  /* Which authored decision a report/reply/download maps to. Kept as data so
   * the mapping is inspectable rather than buried in branches. */
  var REPORT_DECISION = {
    'm-payroll-restructure': 'd-phish-report',
    'm-rate-card': 'd-ransom-report',
    'm-invoice-amend': 'd-bec-report',
    'm-invoice-confirm': 'd-bec-report'
  };
  var REPLY_DECISION = {
    'm-headcount': 'd-task-headcount-done',
    'm-invoice-amend': 'd-bec-reply'
  };

  function defaultAppState() {
    return {
      mail: {
        folder: 'inbox', selected: null, search: '', headers: false,
        linkShown: null, composing: null, draft: '', mobileDetail: false
      },
      browser: { tabs: [], active: 0 },
      files: { location: 'loc-desktop', selected: null, renaming: false },
      messages: { conversation: 'conv-tom-brennan', draft: '', mobileDetail: false },
      authenticator: { details: {}, historyOpen: false },
      directory: { search: '', selected: null, call: null, mobileDetail: false },
      notes: { selected: null }
    };
  }

  function modeFlags(modeId) {
    for (var i = 0; i < WORLD.modes.length; i += 1) {
      if (WORLD.modes[i].id === modeId) { return WORLD.modes[i].flags; }
    }
    return WORLD.modes[1].flags;
  }

  function modeLabel(modeId) {
    for (var i = 0; i < WORLD.modes.length; i += 1) {
      if (WORLD.modes[i].id === modeId) { return WORLD.modes[i].label; }
    }
    return modeId;
  }

  function buildState(focus, mode, assessmentId) {
    var mail = [];
    WORLD.mail.forEach(function (message) {
      var copy = clone(message);
      copy.delivered = copy.arrival === 'opening';
      copy.read = copy.arrival === 'opening' ? !copy.unread : false;
      copy.reported = false;
      copy.repliedAt = null;
      copy.forwarded = false;
      mail.push(copy);
    });

    var files = clone(WORLD.files);

    return {
      focus: focus,
      mode: mode,
      assessmentId: assessmentId || null,
      flags: modeFlags(mode),
      startedAt: Date.now(),
      paused: false,
      ended: false,
      fast: false,

      mail: mail,
      mailRule: null,
      files: files,
      notes: clone(WORLD.notes),
      conversations: clone(WORLD.conversations),
      authHistory: clone(WORLD.auth_history),
      prompts: [],                 // live MFA prompts
      notifications: WORLD.notifications.map(function (n) {
        var copy = clone(n);
        copy.unread = false;
        return copy;
      }),

      tasks: (function () {
        var out = {};
        WORLD.tasks.forEach(function (task) { out[task.id] = clone(task); });
        return out;
      }()),

      queue: (WORLD.timelines[focus] || WORLD.timelines.mixed).slice(),
      queueIndex: 0,
      awaitingResolution: null,

      timeline: [],
      decisions: [],
      observed: {},
      incidents: {},
      chains: [],                  // played chain records, for the debrief
      vpnConnected: false,
      networkDisconnected: false,
      deletedHostile: 0
    };
  }

  // =========================================================================
  // Simulated clock
  // =========================================================================
  //
  // Starts at 09:00 and runs twelve times faster than the wall clock, so a
  // twenty-minute review covers a plausible morning. The production clock is
  // a server-owned SimClock; this is a display device and nothing more.

  var CLOCK_START_MIN = 9 * 60;
  var CLOCK_RATE = 12;

  function simMinutes() {
    if (!S) { return CLOCK_START_MIN; }
    return CLOCK_START_MIN
      + Math.floor(((Date.now() - S.startedAt) * CLOCK_RATE) / 60000);
  }

  function nowLabel() {
    var total = simMinutes();
    var hh = Math.floor(total / 60) % 24;
    var mm = total % 60;
    return (hh < 10 ? '0' : '') + hh + ':' + (mm < 10 ? '0' : '') + mm;
  }

  // =========================================================================
  // Recording
  // =========================================================================

  function record(kind, label, detail, cause) {
    S.timeline.push({
      at: nowLabel(),
      minute: simMinutes(),
      kind: kind,
      label: label,
      detail: detail || '',
      cause: cause || null
    });
  }

  /* An observational action. Marks a piece of evidence as actually inspected,
   * which is the available-versus-observed distinction the Context Ledger
   * formalises. Here it is a flat map; there it is a first-class object. */
  function observe(actionKey, label) {
    if (!S.observed[actionKey]) {
      S.observed[actionKey] = { at: nowLabel(), minute: simMinutes() };
      if (label) { record('investigation', label); }
    }
  }

  function relevantEvidenceFor(messageId) {
    var message = findMail(messageId);
    if (!message || !message.analysis || !message.analysis.evidence) { return []; }
    return message.analysis.evidence;
  }

  function evidenceState(items) {
    return (items || []).map(function (item) {
      return {
        id: item.id,
        label: item.label,
        where: item.where,
        observed: !!S.observed[item.action]
      };
    });
  }

  // =========================================================================
  // Decisions and consequence chains
  // =========================================================================

  function decide(decisionId, context) {
    var definition = WORLD.decisions[decisionId];
    if (!definition) { return; }

    var evidence = evidenceState(context && context.evidence);
    var entry = {
      id: decisionId,
      label: definition.label,
      klass: definition['class'],
      family: definition.family,
      dimensions: definition.dimensions || [],
      at: nowLabel(),
      minute: simMinutes(),
      where: (context && context.where) || '',
      evidence: evidence,
      inspectedBefore: evidence.filter(function (e) { return e.observed; }).length,
      evidenceTotal: evidence.length
    };
    S.decisions.push(entry);
    record('decision', definition.label, entry.where);

    if (definition.chain) {
      playChain(definition.chain, decisionId);
    }

    // Practice confirms a good decision explicitly. Simulation gives the
    // ordinary result of a good decision and says nothing. Assessment says
    // nothing about anything.
    if (S.flags.explicit_confirmation
        && (entry.klass === 'safe' || entry.klass === 'recovery_good')) {
      APP.confirmation = {
        text: confirmationText(decisionId),
        at: Date.now()
      };
      setTimeout(function () {
        if (APP.confirmation && Date.now() - APP.confirmation.at > 11000) {
          APP.confirmation = null;
          render();
        }
      }, 12000);
    }

    render();
  }

  function confirmationText(decisionId) {
    var texts = {
      'd-phish-report': 'That was the right call. Reporting it means the same '
        + 'batch can be stopped for everyone else who received it.',
      'd-ransom-report': 'Good. The attachment stayed unopened and the sender '
        + 'is now on record.',
      'd-bec-report': 'Good. An account change that arrives by mail is exactly '
        + 'the thing to stop and check.',
      'd-phish-verify': 'That is the check that works — you asked on a channel '
        + 'the message did not supply.',
      'd-bec-verify': 'That is the check that works. The number came from your '
        + 'own records, not from the request.',
      'd-mfa-deny-hostile': 'Right call. An approval belongs to something you '
        + 'started.',
      'd-mfa-approve-legit': 'That one was yours — same workstation, same '
        + 'location, seconds after you signed in.',
      'd-ransom-isolate': 'Taking it off the network first is the part most '
        + 'people skip.',
      'd-task-headcount-done': 'Done — and it was a genuine request, which is '
        + 'the other half of the job.'
    };
    return texts[decisionId] || 'That was a reasonable way to handle it.';
  }

  function scaleDelay(ms) {
    var scale = S.flags.consequence_delay_scale || 1;
    if (S.fast) { scale = scale * 0.12; }
    return Math.max(400, Math.round(ms * scale));
  }

  function playChain(chainId, decisionId) {
    var chain = WORLD.chains[chainId];
    if (!chain) { return; }

    var record_ = {
      chainId: chainId,
      decisionId: decisionId,
      title: chain.title,
      incidentId: chain.incident_id,
      startedAt: nowLabel(),
      steps: []
    };
    S.chains.push(record_);

    chain.steps.forEach(function (step) {
      var handle = setTimeout(function () {
        if (S.ended) { return; }
        step.effects.forEach(function (effect) {
          applyEffect(effect, step, chain);
        });
        record_.steps.push({
          id: step.id,
          cause: step.cause,
          summary: step.summary,
          at: nowLabel()
        });
        record('consequence', step.summary,
               chain.title, step.cause === 'decision'
                 ? (WORLD.decisions[decisionId] || {}).label
                 : summaryOf(chain, step.cause));
        render();

        if (step.id === chain.settles_after) {
          onChainSettled(chainId, decisionId);
        }
      }, scaleDelay(step.delay_ms));
      timers.push(handle);
    });
  }

  function summaryOf(chain, stepId) {
    for (var i = 0; i < chain.steps.length; i += 1) {
      if (chain.steps[i].id === stepId) { return chain.steps[i].summary; }
    }
    return null;
  }

  function applyEffect(effect, step, chain) {
    switch (effect.type) {
    case 'notification':
      pushNotification({
        kind: effect.kind,
        title: effect.title,
        body: effect.body,
        opens: effect.opens || null
      });
      break;

    case 'mail':
      deliverMail(effect.mail_id, effect.folder || null, true);
      break;

    case 'mail_rule':
      S.mailRule = effect.text;
      break;

    case 'file_state':
      setFileState(effect.file_id, effect.state, effect.note);
      break;

    case 'message':
      appendMessage(effect.conversation_id, effect.from, effect.text);
      break;

    case 'mfa_prompt':
      addPrompt(effect.prompt_id);
      break;

    case 'auth_activity':
      S.authHistory.unshift({
        id: 'auth-' + Math.random().toString(36).slice(2, 8),
        app: effect.app, result: effect.result, device: effect.device,
        location: effect.location, when: effect.when === 'just now'
          ? nowLabel() : effect.when
      });
      break;

    case 'task':
      if (S.tasks[effect.task_id]) {
        S.tasks[effect.task_id].state = effect.state;
        S.tasks[effect.task_id].note = effect.text;
      }
      break;

    case 'incident':
      S.incidents[effect.incident_id] = {
        id: effect.incident_id,
        title: effect.title,
        note: effect.note,
        openedAt: nowLabel(),
        contained: false
      };
      break;

    default:
      break;
    }
  }

  /* When the last step of a chain lands, the world has settled. That is the
   * moment the provisional comparison is allowed to interrupt — never in the
   * middle of a chain, and never in an Assessment attempt. */
  function onChainSettled(chainId, decisionId) {
    if (chainId === 'chain-file-incident') {
      // The root cause comes first: opening the attachment is what started
      // this. Only after that is acknowledged does the *second* question --
      // what you did once files began failing -- become the live one.
      maybeShowComparison(decisionId, function () {
        if (S.incidents['inc-files'] && !S.incidents['inc-files'].contained
            && !alreadyDecided('d-ransom-continue')) {
          decide('d-ransom-continue', { where: 'Files' });
        }
      });
      return;
    }

    maybeShowComparison(decisionId);
  }

  /* ``after`` runs once the learner has moved on -- immediately when the
   * comparison is suppressed (Assessment), or on Continue when it is shown.
   * It must run either way, because what it does is record world state, not
   * pedagogy. */
  function maybeShowComparison(decisionId, after) {
    function done() {
      resumeDelivery();
      if (after) { after(); }
    }

    if (!S.flags.safer_alternative) { done(); return; }
    if (!window.RewindSecComparison) { done(); return; }

    var authored = WORLD.safer_alternatives[decisionId];
    if (!authored) { done(); return; }

    var decision = null;
    for (var i = S.decisions.length - 1; i >= 0; i -= 1) {
      if (S.decisions[i].id === decisionId) { decision = S.decisions[i]; break; }
    }

    S.paused = true;
    window.RewindSecComparison.show({
      heading: authored.heading,
      what_you_did: authored.what_you_did,
      what_followed: authored.what_followed,
      evidence: decision ? decision.evidence : [],
      safer_process: authored.safer_process,
      likely_outcome: authored.likely_outcome,
      still_true: authored.still_true
    }).then(function () {
      S.paused = false;
      render();
      done();
    });
  }

  // =========================================================================
  // World mutation helpers
  // =========================================================================

  function findMail(id) {
    for (var i = 0; i < S.mail.length; i += 1) {
      if (S.mail[i].id === id) { return S.mail[i]; }
    }
    return null;
  }

  function deliverMail(id, folder, silent) {
    var message = findMail(id);
    if (!message || message.delivered) { return; }
    message.delivered = true;
    message.unread = true;
    message.read = false;
    message.received = nowLabel();
    if (folder) { message.folder = folder; }

    // A mailbox rule created earlier in a chain files Security Operations
    // mail away before the learner sees it. The message is still findable —
    // it just does not arrive where they are looking.
    if (S.mailRule && message.surface.from_address === 'security@northbridge.example') {
      message.folder = 'archive';
    }

    record('event', 'Message received: ' + message.surface.subject,
           'From ' + message.surface.from_name);

    if (message.folder !== 'archive') {
      pushNotification({
        kind: 'mail',
        title: message.surface.from_name,
        body: message.surface.subject,
        opens: { app: 'mail', mail_id: message.id }
      });
    }
    if (!silent) { render(); }
  }

  function setFileState(fileId, state, note) {
    S.files.forEach(function (location) {
      location.files.forEach(function (file) {
        if (file.id === fileId) {
          file.state = state;
          file.note = note || '';
          if (state === 'unavailable' && file.name.indexOf('.demo_locked') < 0) {
            file.displayName = file.name + '.demo_locked';
          }
        }
      });
    });
  }

  function appendMessage(conversationId, from, text) {
    for (var i = 0; i < S.conversations.length; i += 1) {
      if (S.conversations[i].id === conversationId) {
        S.conversations[i].messages.push({
          from: from, when: nowLabel(), text: text
        });
        S.conversations[i].unread = true;
        return;
      }
    }
  }

  function addPrompt(promptId) {
    for (var i = 0; i < WORLD.mfa_prompts.length; i += 1) {
      if (WORLD.mfa_prompts[i].id === promptId) {
        var already = S.prompts.some(function (p) {
          return p.id === promptId && p.status === 'pending';
        });
        if (already) { return; }
        var prompt = clone(WORLD.mfa_prompts[i]);
        prompt.status = 'pending';
        prompt.arrivedAt = nowLabel();
        prompt.uid = promptId + '-' + S.prompts.length;
        S.prompts.unshift(prompt);
        record('event', 'Approval requested: ' + prompt.surface.app,
               prompt.surface.device + ' · ' + prompt.surface.location);
        pushNotification({
          kind: 'auth',
          title: 'Approval requested',
          body: prompt.surface.app + ' · ' + prompt.surface.location,
          opens: { app: 'authenticator' }
        });
        return;
      }
    }
  }

  var notifCounter = 0;

  function pushNotification(spec) {
    notifCounter += 1;
    var entry = {
      id: 'n-' + notifCounter,
      kind: spec.kind || 'system',
      title: spec.title,
      body: spec.body,
      when: nowLabel(),
      opens: spec.opens || null,
      unread: true
    };
    S.notifications.unshift(entry);
    showToast(entry);
  }

  // =========================================================================
  // Event delivery cadence
  // =========================================================================

  var deliveryTimer = null;

  function cadence() {
    return WORLD.cadence[S.mode] || WORLD.cadence.simulation;
  }

  function nextDelay() {
    var c = cadence();
    if (S.fast) { return 2500; }
    if (c.style === 'paced') { return 18000; }
    var jitter = Math.round((Math.random() * 2 - 1) * (c.jitter_ms || 0));
    return Math.max(4000, c.base_ms + jitter);
  }

  function scheduleNextDelivery(overrideMs) {
    if (deliveryTimer) { clearTimeout(deliveryTimer); }
    if (S.ended || S.queueIndex >= S.queue.length) { return; }
    var delay = overrideMs !== undefined ? overrideMs : nextDelay();
    deliveryTimer = setTimeout(function () {
      if (S.ended) { return; }
      if (S.paused) { scheduleNextDelivery(2500); return; }

      // Practice waits for the learner. Simulation and Assessment do not:
      // in Assessment, events are explicitly allowed to pile up.
      if (cadence().style === 'paced' && S.awaitingResolution) {
        var waited = Date.now() - S.awaitingResolution.since;
        if (waited < (cadence().max_wait_ms || 90000)) {
          scheduleNextDelivery(5000);
          return;
        }
      }
      deliverNext();
    }, delay);
    timers.push(deliveryTimer);
  }

  function resumeDelivery() { scheduleNextDelivery(); }

  function deliverNext() {
    if (S.queueIndex >= S.queue.length) { return; }
    var entry = S.queue[S.queueIndex];
    S.queueIndex += 1;

    if (entry.type === 'mail') {
      deliverMail(entry.ref, null, true);
      S.awaitingResolution = { ref: entry.ref, since: Date.now() };
    } else if (entry.type === 'mfa') {
      addPrompt(entry.ref);
      S.awaitingResolution = { ref: entry.ref, since: Date.now() };
    }

    render();
    scheduleNextDelivery();
  }

  function markResolved(ref) {
    if (S.awaitingResolution && S.awaitingResolution.ref === ref) {
      S.awaitingResolution = null;
      if (cadence().style === 'paced') { scheduleNextDelivery(7000); }
    }
  }

  // =========================================================================
  // Window management
  // =========================================================================

  var zCounter = 10;

  function areaSize() {
    var area = qs('#pw-workarea');
    return { w: area.clientWidth, h: area.clientHeight };
  }

  function canDrag() { return window.innerWidth >= 1024; }

  function openApp(appId, focusTarget) {
    if (!WIN[appId]) {
      var size = areaSize();
      var spec = APPS[appId];
      var n = Object.keys(WIN).length;
      var w = Math.min(spec.w, Math.max(320, size.w - 40));
      var h = Math.min(spec.h, Math.max(240, size.h - 40));
      // The first window opens centred, slightly above the optical middle;
      // each one after it steps down and right. Opening on the top-left
      // corner leaves a large empty desk to its lower right and reads as a
      // window that has not been placed so much as dropped.
      var step = 34;
      var baseX = Math.round((size.w - w) / 2);
      var baseY = Math.round((size.h - h) * 0.42);
      WIN[appId] = {
        open: true, minimized: false, maximized: size.w < 1100,
        x: clamp(baseX + (n % 5) * step, 12, Math.max(12, size.w - w - 12)),
        y: clamp(baseY + (n % 5) * step, 12, Math.max(12, size.h - h - 12)),
        w: w, h: h, z: (zCounter += 1)
      };
    } else {
      WIN[appId].open = true;
      WIN[appId].minimized = false;
      WIN[appId].z = (zCounter += 1);
    }
    if (focusTarget) { applyFocusTarget(appId, focusTarget); }
    render();
    var node = qs('[data-window="' + appId + '"] .pw-winbody');
    if (node) { node.setAttribute('tabindex', '-1'); node.focus(); }
  }

  /* Keep every open window inside the work area. Purely geometric: no window
   * is opened, closed, focused or re-ordered here. */
  function reflowWindows() {
    var size = areaSize();
    Object.keys(WIN).forEach(function (appId) {
      var win = WIN[appId];
      if (!win || !win.open || win.maximized) { return; }
      win.w = Math.min(win.w, Math.max(320, size.w - 24));
      win.h = Math.min(win.h, Math.max(220, size.h - 24));
      win.x = clamp(win.x, 12, Math.max(12, size.w - win.w - 12));
      win.y = clamp(win.y, 12, Math.max(12, size.h - win.h - 12));
    });
  }

  function applyFocusTarget(appId, target) {
    if (appId === 'mail' && target.mail_id) {
      var message = findMail(target.mail_id);
      if (message) {
        APP.mail.folder = message.folder;
        openMessage(target.mail_id, true);
      }
    } else if (appId === 'files' && target.location_id) {
      APP.files.location = target.location_id;
    } else if (appId === 'messages' && target.conversation_id) {
      APP.messages.conversation = target.conversation_id;
      APP.messages.mobileDetail = true;
      markConversationRead(target.conversation_id);
    } else if (appId === 'browser' && target.url) {
      browserNavigate(target.url);
    }
  }

  function closeApp(appId) {
    if (WIN[appId]) { WIN[appId].open = false; }
    render();
  }

  function minimiseApp(appId) {
    if (WIN[appId]) { WIN[appId].minimized = true; }
    render();
  }

  function focusApp(appId) {
    if (WIN[appId]) { WIN[appId].z = (zCounter += 1); render(); }
  }

  function topWindow() {
    var best = null;
    Object.keys(WIN).forEach(function (appId) {
      var w = WIN[appId];
      if (w.open && !w.minimized && (!best || w.z > WIN[best].z)) { best = appId; }
    });
    return best;
  }

  // =========================================================================
  // Rendering
  // =========================================================================

  var focusSnapshot = null;

  function captureFocus() {
    var active = document.activeElement;
    if (!active || !active.id) { focusSnapshot = null; return; }
    focusSnapshot = {
      id: active.id,
      start: typeof active.selectionStart === 'number' ? active.selectionStart : null,
      end: typeof active.selectionEnd === 'number' ? active.selectionEnd : null
    };
  }

  function restoreFocus() {
    if (!focusSnapshot) { return; }
    var node = document.getElementById(focusSnapshot.id);
    if (!node) { focusSnapshot = null; return; }
    node.focus();
    if (focusSnapshot.start !== null && node.setSelectionRange) {
      try { node.setSelectionRange(focusSnapshot.start, focusSnapshot.end); }
      catch (err) { /* not a text input any more */ }
    }
    focusSnapshot = null;
  }

  function render() {
    if (!S) { return; }
    captureFocus();
    renderTopBar();
    renderRail();
    renderDesk();
    renderWindows();
    renderNotifications();
    restoreFocus();
  }

  function focusLabel(focusId) {
    var found = null;
    (WORLD.focus_options || []).forEach(function (option) {
      if (option.id === focusId) { found = option.label; }
    });
    return found || (String(focusId).charAt(0).toUpperCase()
                     + String(focusId).slice(1));
  }

  function renderTopBar() {
    qs('#pw-clock').textContent = nowLabel();
    qs('#pw-mode-label').textContent = modeLabel(S.mode);
    // The authored label, not a title-cased id: capitalising the first letter
    // of "bec" and "mfa" turns two acronyms into "Bec" and "Mfa".
    qs('#pw-focus-chip').textContent = focusLabel(S.focus) + ' focus';
    qs('#pw-assessment-chip').hidden = !S.assessmentId;

    var unread = S.notifications.filter(function (n) { return n.unread; }).length;
    var badge = qs('#pw-notif-badge');
    badge.hidden = unread === 0;
    badge.textContent = unread > 9 ? '9+' : String(unread);
  }

  function renderRail() {
    var counts = {
      mail: S.mail.filter(function (m) {
        return m.delivered && m.unread && m.folder === 'inbox';
      }).length,
      messages: S.conversations.filter(function (c) { return c.unread; }).length,
      authenticator: S.prompts.filter(function (p) { return p.status === 'pending'; }).length,
      files: Object.keys(S.incidents).indexOf('inc-files') >= 0
        ? S.files.reduce(function (total, location) {
            return total + location.files.filter(function (f) {
              return f.state === 'unavailable';
            }).length;
          }, 0)
        : 0
    };

    var top = topWindow();
    qsa('.pw-applink').forEach(function (node) {
      var appId = node.getAttribute('data-app');
      var win = WIN[appId];
      node.classList.toggle('is-open', !!(win && win.open));
      node.classList.toggle('is-active', appId === top);
      node.setAttribute('aria-pressed', appId === top ? 'true' : 'false');

      var badge = node.querySelector('[data-count]');
      if (badge) {
        var value = counts[appId] || 0;
        badge.hidden = value === 0;
        badge.textContent = String(value);
      }
    });
  }

  function renderDesk() {
    var anyOpen = Object.keys(WIN).some(function (id) {
      return WIN[id].open && !WIN[id].minimized;
    });
    qs('#pw-desk').style.opacity = anyOpen ? '0' : '1';

    var outstanding = Object.keys(S.tasks).map(function (id) {
      return S.tasks[id];
    }).filter(function (task) {
      return task.state === 'outstanding' || task.state === 'interrupted';
    });

    var box = qs('#pw-desk-tasks');
    box.hidden = outstanding.length === 0;
    qs('#pw-desk-tasklist').innerHTML = outstanding.map(function (task) {
      return '<li>' + esc(task.note || task.label) + '</li>';
    }).join('');
  }

  function renderWindows() {
    var area = qs('#pw-workarea');
    var top = topWindow();

    Object.keys(APPS).forEach(function (appId) {
      var win = WIN[appId];
      var node = qs('[data-window="' + appId + '"]', area);

      if (!win || !win.open || win.minimized) {
        if (node) { dismissWindow(node, appId, win && win.minimized); }
        return;
      }

      if (!node) {
        node = document.createElement('section');
        node.className = 'pw-window';
        node.setAttribute('data-window', appId);
        node.setAttribute('role', 'region');
        node.setAttribute('aria-label', APPS[appId].label);
        // Notes is the one learner application where the clipboard works.
        // Marking the whole window rather than each field means the exception
        // cannot drift out of step with what Notes renders -- see
        // static/prototype/integrity.js.
        if (appId === 'notes') { node.setAttribute('data-clipboard', 'allow'); }
        node.innerHTML = windowChrome(appId);
        area.insertBefore(node, qs('#pw-notifpanel', area));
        bindWindow(node, appId);
      }

      node.style.zIndex = String(win.z);

      // Coming to the front is the one state change a window makes that a
      // learner needs to *see*, because it is how they know which
      // application their next keystroke goes to. It gets one short lift.
      // Only on a genuine change of focus -- `render` runs on every
      // background tick, and a window that was already at the front must
      // stay still.
      var isTop = (appId === top);
      if (isTop && !node.classList.contains('is-focused')) { raiseWindow(node); }
      node.classList.toggle('is-focused', isTop);
      node.classList.toggle('is-maximized', win.maximized);
      node.classList.toggle('is-draggable', canDrag() && !win.maximized);
      if (!win.maximized) {
        node.style.left = win.x + 'px';
        node.style.top = win.y + 'px';
        node.style.width = win.w + 'px';
        node.style.height = win.h + 'px';
      } else {
        node.style.left = node.style.top = node.style.width = node.style.height = '';
      }

      var sub = qs('.pw-winbar-sub', node);
      if (sub) { sub.textContent = windowSubtitle(appId); }

      // A background event must never wipe what the learner is typing into a
      // password field. The value of that field is deliberately not held in
      // state -- it is never read and never stored -- so the only way to keep
      // it intact across an unrelated re-render is to leave the window alone
      // while it has focus.
      var body = qs('.pw-winbody', node);
      if (holdsFocusedPassword(body)) { return; }

      // Compare before writing. A background consequence tick re-renders
      // every open window several times a session; without this the whole
      // body is rebuilt each time, which throws away scroll position and
      // restarts every CSS entrance animation inside it. With it, the
      // animations in workstation.css fire when a learner actually selects
      // something and stay still otherwise.
      var markup = renderApp(appId);
      if (body.innerHTML !== markup) { body.innerHTML = markup; }
    });
  }

  // A window leaving the desk plays its exit animation and is removed after
  // it. The node stops answering to `data-window` immediately, so a window
  // reopened during those few frames builds a fresh one rather than
  // resurrecting the one on its way out.
  //
  // Focus is moved out first, to the rail button for the same application:
  // that is where a keyboard user would expect to land after closing a
  // window, and it means no animating, about-to-be-removed subtree ever
  // holds the caret.
  function dismissWindow(node, appId, minimising) {
    if (!node.parentNode) { return; }
    node.removeAttribute('data-window');

    if (node.contains(document.activeElement)) {
      var railButton = qs('.pw-applink[data-app="' + appId + '"]');
      if (railButton) { railButton.focus(); }
      else if (document.activeElement.blur) { document.activeElement.blur(); }
    }

    if (prefersReducedMotion()) {
      node.parentNode.removeChild(node);
      return;
    }

    node.classList.add(minimising ? 'is-minimising' : 'is-closing');
    var handle = setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, 220);
    timers.push(handle);
  }

  // The lift a window plays on being brought forward. The class is stripped
  // again once the animation has run, so the next focus change can replay
  // it; under reduced motion it is never added at all, and the window simply
  // changes its rim and elevation like every other state in the product.
  function raiseWindow(node) {
    if (prefersReducedMotion()) { return; }
    node.classList.remove('is-raising');
    // Reading a layout property between the removal and the addition is what
    // forces the animation to start over rather than being treated as the
    // same, still-running one.
    void node.offsetWidth;
    node.classList.add('is-raising');
    var handle = setTimeout(function () {
      node.classList.remove('is-raising');
    }, 320);
    timers.push(handle);
  }

  function prefersReducedMotion() {
    return !!(window.matchMedia
              && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  function holdsFocusedPassword(node) {
    var active = document.activeElement;
    return !!(active && active.type === 'password' && node.contains(active));
  }

  function windowChrome(appId) {
    var spec = APPS[appId];
    return ''
      + '<header class="pw-winbar">'
      + '  <span class="pw-winbar-title">' + icon(spec.icon)
      + '    <span>' + esc(spec.label) + '</span>'
      + '    <span class="pw-winbar-sub"></span>'
      + '  </span>'
      + '  <span class="pw-winbar-actions">'
      + '    <button type="button" class="pw-winctl" data-win="minimise"'
      + '      aria-label="Minimise ' + esc(spec.label) + '">' + icon('minimise') + '</button>'
      + '    <button type="button" class="pw-winctl" data-win="maximise"'
      + '      aria-label="Maximise or restore ' + esc(spec.label) + '">' + icon('expand') + '</button>'
      + '    <button type="button" class="pw-winctl is-close" data-win="close"'
      + '      aria-label="Close ' + esc(spec.label) + '">' + icon('close') + '</button>'
      + '  </span>'
      + '</header>'
      + '<div class="pw-winbody"></div>';
  }

  function windowSubtitle(appId) {
    if (appId === 'mail') { return WORLD.learner.email; }
    if (appId === 'files') { return WORLD.organization.workstation_id; }
    if (appId === 'browser') {
      var tab = APP.browser.tabs[APP.browser.active];
      return tab ? tab.url : '';
    }
    if (appId === 'authenticator') { return WORLD.learner.name; }
    return '';
  }

  function renderApp(appId) {
    switch (appId) {
    case 'mail': return renderMail();
    case 'browser': return renderBrowser();
    case 'files': return renderFiles();
    case 'messages': return renderMessages();
    case 'authenticator': return renderAuthenticator();
    case 'directory': return renderDirectory();
    case 'notes': return renderNotes();
    default: return '';
    }
  }

  // =========================================================================
  // Mail
  // =========================================================================

  function visibleMail() {
    var state = APP.mail;
    var term = state.search.trim().toLowerCase();
    return S.mail.filter(function (message) {
      if (!message.delivered) { return false; }
      if (term) {
        var haystack = [
          message.surface.subject, message.surface.from_name,
          message.surface.from_address, (message.surface.body || []).join(' ')
        ].join(' ').toLowerCase();
        return haystack.indexOf(term) >= 0;
      }
      return message.folder === state.folder;
    }).sort(function (a, b) { return b.order - a.order; });
  }

  function renderMail() {
    var state = APP.mail;
    var messages = visibleMail();
    var selected = state.selected ? findMail(state.selected) : null;
    if (selected && !selected.delivered) { selected = null; }

    var folders = FOLDERS.map(function (folder) {
      var count = S.mail.filter(function (m) {
        return m.delivered && m.folder === folder.id && m.unread;
      }).length;
      var total = S.mail.filter(function (m) {
        return m.delivered && m.folder === folder.id;
      }).length;
      return '<button type="button" class="pw-navitem'
        + (state.folder === folder.id && !state.search ? ' is-active' : '') + '"'
        + ' data-mail-folder="' + folder.id + '">'
        + icon(folder.icon) + '<span>' + esc(folder.label) + '</span>'
        + '<span class="pw-navitem-count">' + (count || total || '') + '</span>'
        + '</button>';
    }).join('');

    var rows = messages.map(function (message) {
      var preview = (message.surface.body || [''])[0] || '';
      return '<button type="button" class="pw-msgrow'
        + (message.unread ? ' is-unread' : '')
        + (state.selected === message.id ? ' is-active' : '') + '"'
        + ' data-mail-open="' + message.id + '">'
        + '<span class="pw-msgrow-top">'
        + '<span class="pw-msgrow-from">' + esc(message.surface.from_name) + '</span>'
        + '<span class="pw-msgrow-time">' + esc(message.received) + '</span>'
        + '</span>'
        + '<span class="pw-msgrow-subject">' + esc(message.surface.subject) + '</span>'
        + '<span class="pw-msgrow-preview">' + esc(preview.slice(0, 92)) + '</span>'
        + (message.reported || message.repliedAt || (message.surface.attachments || []).length
            ? '<span class="pw-msgrow-flags">'
              + ((message.surface.attachments || []).length
                  ? '<span class="pw-chip">' + icon('paperclip', 'style="width:11px;height:11px"')
                    + ' attachment</span>' : '')
              + (message.reported ? '<span class="pw-chip is-caution">reported</span>' : '')
              + (message.repliedAt ? '<span class="pw-chip">replied</span>' : '')
              + '</span>'
            : '')
        + '</button>';
    }).join('');

    if (!rows) {
      rows = '<div class="pw-empty"><h3>Nothing here</h3><p>'
        + (state.search ? 'No message matches that search.' : 'This folder is empty.')
        + '</p></div>';
    }

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-sidepane">'
      + '    <div class="pw-pane-scroll"><div class="pw-nav">' + folders + '</div></div>'
      + '  </div>'
      + '  <div class="pw-pane pw-listpane">'
      + '    <div class="pw-pane-head">'
      + '      <label class="pw-search">' + icon('search')
      + '        <input type="search" id="pw-mail-search" placeholder="Search mail"'
      + '          aria-label="Search mail" value="' + esc(state.search) + '">'
      + '      </label>'
      + '    </div>'
      + (S.mailRule
          ? '<div class="pw-mailbanner">' + icon('info')
            + '<span>' + esc(S.mailRule) + '</span></div>'
          : '')
      + '    <div class="pw-pane-scroll">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (selected ? renderReader(selected)
                  : '<div class="pw-empty"><h3>No message selected</h3>'
                    + '<p>Choose something from the list.</p></div>')
      + '  </div>'
      + '</div>';
  }

  function renderReader(message) {
    var state = APP.mail;
    var surface = message.surface;
    var confirmation = APP.confirmation
      ? '<div class="pw-confirmstrip">' + icon('check')
        + '<span>' + esc(APP.confirmation.text) + '</span></div>'
      : '';

    var headers = state.headers
      ? '<div class="pw-reader-headers"><dl>'
        + '<dt>From</dt><dd>' + esc(surface.from_address) + '</dd>'
        + '<dt>Reply-To</dt><dd>'
        + esc(surface.reply_to || surface.from_address) + '</dd>'
        + '<dt>To</dt><dd>' + esc(surface.to) + '</dd>'
        + (surface.cc ? '<dt>Cc</dt><dd>' + esc(surface.cc) + '</dd>' : '')
        + '<dt>Received</dt><dd>' + esc(message.received) + '</dd>'
        + '</dl></div>'
      : '';

    var body = (surface.body || []).map(function (paragraph) {
      if (paragraph.indexOf('———') === 0) {
        return '<p class="pw-reader-quote">' + esc(paragraph) + '</p>';
      }
      return '<p>' + esc(paragraph) + '</p>';
    }).join('');

    var links = (surface.links || []).map(function (link, index) {
      var shown = state.linkShown === message.id + ':' + index;
      return '<p><button type="button" class="pw-maillink"'
        + ' data-mail-link="' + esc(link.href) + '">' + esc(link.text)
        + icon('external', 'style="width:12px;height:12px"') + '</button>'
        + ' <button type="button" class="pw-linkbtn" style="margin-left:.5rem"'
        + ' data-mail-inspect-link="' + message.id + ':' + index + '">'
        + (shown ? 'Hide destination' : 'Where does this go?') + '</button>'
        + (shown ? '<span class="pw-linkinfo">' + esc(link.href) + '</span>' : '')
        + '</p>';
    }).join('');

    var attachments = (surface.attachments || []).map(function (attachment, index) {
      var key = message.id + ':' + index;
      var shown = state.linkShown === 'att:' + key;
      return '<div class="pw-attach">' + icon(attachmentIcon(attachment.kind))
        + '<span class="pw-attach-main"><b>' + esc(attachment.name) + '</b>'
        + '<span>' + esc(attachment.size) + '</span>'
        + (shown
            ? '<span class="pw-linkinfo">Type: ' + esc(attachmentKindLabel(attachment.kind))
              + '<br>Sender: ' + esc(surface.from_address) + '</span>'
            : '')
        + '</span>'
        + '<span class="pw-attach-actions">'
        + '<button type="button" class="pw-btn is-sm" data-att-inspect="' + key + '">'
        + (shown ? 'Hide details' : 'Details') + '</button>'
        + '<button type="button" class="pw-btn is-sm" data-att-download="' + key + '">'
        + 'Download</button>'
        + '</span></div>';
    }).join('');

    var compose = state.composing === message.id
      ? '<div class="pw-compose">'
        + '<h4>Reply to ' + esc(surface.from_name) + '</h4>'
        + '<textarea id="pw-compose-body" aria-label="Reply text">'
        + esc(state.draft) + '</textarea>'
        + '<div class="pw-compose-actions">'
        + '<button type="button" class="pw-btn is-primary is-sm" data-mail-send="'
        + message.id + '">Send</button>'
        + '<button type="button" class="pw-btn is-sm" data-mail-cancel="1">Cancel</button>'
        + '</div></div>'
      : '';

    var hint = S.flags.investigation_hints
      ? '<div class="pw-note" style="margin:.75rem 0;font-size:.8rem">'
        + 'You can open the full header, check where a link actually goes, '
        + 'search older mail from the same sender, or look someone up in the '
        + 'Directory before you act.</div>'
      : '';

    return ''
      + '<div class="pw-pane-head">'
      + '  <button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-mail-back="1">'
      + icon('back') + ' Inbox</button>'
      // Reply is the ordinary thing to do with a message, so it carries the
      // toolbar's one emphasis. Nothing else in the row is ranked: Report
      // must never look more or less encouraged than Forward or Delete.
      + '  <button type="button" class="pw-btn is-sm is-primary" data-mail-reply="' + message.id + '">'
      + icon('reply', 'style="width:13px;height:13px"') + ' Reply</button>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-forward="' + message.id + '">Forward</button>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-report="' + message.id + '">'
      + icon('flag', 'style="width:13px;height:13px"') + ' Report</button>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-delete="' + message.id + '">'
      + icon('trash', 'style="width:13px;height:13px"') + ' Delete</button>'
      + '  <span class="pw-spacer"></span>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-headers="'
      + message.id + '" aria-pressed="' + (APP.mail.headers ? 'true' : 'false') + '">'
      + (APP.mail.headers ? 'Hide header' : 'Show header') + '</button>'
      + '</div>'
      + confirmation
      + '<div class="pw-pane-scroll"><div class="pw-reader">'
      + '  <h2 class="pw-reader-subject">' + esc(surface.subject) + '</h2>'
      + '  <div class="pw-reader-from">'
      + '    <span class="pw-avatar is-neutral" aria-hidden="true">'
      + esc(initialsOf(surface.from_name)) + '</span>'
      + '    <span class="pw-reader-from-main">'
      + '      <b>' + esc(surface.from_name) + '</b>'
      + '      <span>' + esc(surface.from_address) + '</span>'
      + '    </span>'
      + '  </div>'
      + headers
      + hint
      + '  <div class="pw-reader-body">' + body + links + '</div>'
      + attachments
      + '</div></div>'
      + compose;
  }

  function attachmentIcon(kind) {
    if (kind === 'pdf') { return 'pdf'; }
    if (kind === 'spreadsheet' || kind === 'spreadsheet-macro') { return 'sheet'; }
    return 'doc';
  }

  function attachmentKindLabel(kind) {
    if (kind === 'spreadsheet-macro') {
      return 'Spreadsheet containing macros (.xlsm)';
    }
    if (kind === 'spreadsheet') { return 'Spreadsheet (.xlsx)'; }
    if (kind === 'pdf') { return 'Portable document (.pdf)'; }
    return 'Document';
  }

  function initialsOf(name) {
    return String(name || '').split(/\s+/).slice(0, 2)
      .map(function (part) { return part.charAt(0); }).join('').toUpperCase();
  }

  function defaultReply(message) {
    if (message.id === 'm-headcount') {
      return 'Hi Marcus,\n\nConfirmed contractor headcount for Q3 is 41.\n\nAarti';
    }
    return '';
  }

  function openMessage(messageId, silent) {
    var message = findMail(messageId);
    if (!message) { return; }
    APP.mail.selected = messageId;
    APP.mail.headers = false;
    APP.mail.linkShown = null;
    APP.mail.composing = null;
    APP.mail.mobileDetail = true;
    if (message.unread) {
      message.unread = false;
      message.read = true;
      record('action', 'Opened: ' + message.surface.subject,
             'From ' + message.surface.from_name);
    }
    observe('open_mail:' + messageId);
    markResolved(messageId);
    if (!silent) { render(); }
  }

  // =========================================================================
  // Browser
  // =========================================================================

  function ensureTab() {
    if (!APP.browser.tabs.length) {
      APP.browser.tabs.push({
        url: WORLD.browser.home,
        history: [WORLD.browser.home],
        index: 0,
        signedIn: {},
        pending: null,
        accountOverride: null,
        urlDraft: null
      });
      APP.browser.active = 0;
    }
    return APP.browser.tabs[APP.browser.active];
  }

  function normaliseUrl(raw) {
    return String(raw || '').trim()
      .replace(/^https?:\/\//i, '')
      .replace(/\/+$/, '')
      .toLowerCase();
  }

  function browserNavigate(rawUrl) {
    var tab = ensureTab();
    var url = normaliseUrl(rawUrl);
    tab.history = tab.history.slice(0, tab.index + 1);
    tab.history.push(url);
    tab.index = tab.history.length - 1;
    tab.url = url;
    tab.urlDraft = null;
    observe('browser_visit:' + url);
    record('action', 'Opened ' + url, 'Browser');
    openApp('browser');
  }

  function renderBrowser() {
    var tab = ensureTab();
    var page = WORLD.browser.pages[tab.url];

    var tabs = APP.browser.tabs.map(function (entry, index) {
      var titled = WORLD.browser.pages[entry.url];
      return '<button type="button" class="pw-tab'
        + (index === APP.browser.active ? ' is-active' : '') + '"'
        + ' data-tab-select="' + index + '">'
        + '<span>' + esc(titled ? titled.title : entry.url) + '</span>'
        + (APP.browser.tabs.length > 1
            ? '<span class="pw-tab-close" data-tab-close="' + index + '"'
              + ' role="button" aria-label="Close tab">&times;</span>' : '')
        + '</button>';
    }).join('');

    var bookmarks = WORLD.browser.bookmarks.map(function (bookmark) {
      return '<button type="button" class="pw-bookmark" data-go="'
        + esc(bookmark.url) + '">' + esc(bookmark.label) + '</button>';
    }).join('')
      + '<button type="button" class="pw-bookmark" data-go="intranet.northbridge.example/finance/payments">Supplier payments</button>'
      + '<button type="button" class="pw-bookmark" data-go="intranet.northbridge.example/it/support">Service Desk</button>';

    var internal = page && page.chrome === 'internal';

    return ''
      + '<div class="pw-app pw-browser">'
      + '  <div class="pw-tabstrip">' + tabs
      + '    <button type="button" class="pw-tab" data-tab-new="1" aria-label="New tab">+</button>'
      + '  </div>'
      + '  <div class="pw-urlbar">'
      + '    <button type="button" class="pw-winctl" data-nav="back" aria-label="Back"'
      + (tab.index <= 0 ? ' disabled' : '') + '>' + icon('back') + '</button>'
      + '    <button type="button" class="pw-winctl" data-nav="forward" aria-label="Forward"'
      + (tab.index >= tab.history.length - 1 ? ' disabled' : '') + '>' + icon('forward') + '</button>'
      + '    <button type="button" class="pw-winctl" data-nav="reload" aria-label="Reload">'
      + icon('reload') + '</button>'
      + '    <span class="pw-urlfield">'
      + (internal ? icon('lock', 'class="is-internal"') : icon('unlock'))
      + '      <input type="text" id="pw-url-input" value="'
      + esc(tab.urlDraft === undefined || tab.urlDraft === null ? tab.url : tab.urlDraft) + '"'
      + '        aria-label="Address" spellcheck="false" autocomplete="off">'
      + '    </span>'
      + '  </div>'
      + '  <div class="pw-bookmarks">' + bookmarks + '</div>'
      + '  <div class="pw-viewport">' + renderPage(tab, page) + '</div>'
      + '</div>';
  }

  function renderPage(tab, page) {
    if (!page) {
      return '<div class="pw-blocked">' + icon('globe', 'style="width:28px;height:28px"')
        + '<h1>This address is not reachable</h1>'
        + '<p>This browser only reaches the synthetic ' + esc(WORLD.organization.name)
        + ' network used by the prototype. Nothing outside it can be loaded.</p></div>';
    }

    if (page.kind === 'signin') { return renderSignin(tab, page); }
    if (page.kind === 'filelist') { return renderBrowserFiles(page); }
    if (page.kind === 'payments') { return renderPayments(tab, page); }
    if (page.kind === 'support') { return renderSupport(page); }

    var sections = (page.sections || []).map(function (section) {
      return '<section class="pw-site-section"><h2>' + esc(section.title) + '</h2><ul>'
        + section.items.map(function (item) { return '<li>' + esc(item) + '</li>'; }).join('')
        + '</ul></section>';
    }).join('');

    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading || '') + '</p></div>'
      + sections + '</div>';
  }

  function renderSignin(tab, page) {
    var signedIn = tab.signedIn[tab.url];

    if (signedIn === 'pending') {
      return '<div class="pw-signin"><h1>' + esc(page.heading) + '</h1>'
        + '<p class="pw-signin-sub">Waiting for you to approve the request on '
        + 'your authenticator.</p>'
        + '<p class="pw-signin-note">Open the Authenticator to approve or deny '
        + 'it.</p></div>';
    }
    if (signedIn === 'done') {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Signed in as ' + esc(WORLD.learner.email) + '</p></div>'
        + '<section class="pw-site-section"><h2>Your record</h2><ul>'
        + '<li>August payslip — published 8 September</li>'
        + '<li>July payslip — published 8 August</li>'
        + '<li>Tax summary 2025–26</li></ul></section></div>';
    }
    if (signedIn === 'submitted') {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Your record has been confirmed. You can close this page.</p>'
        + '</div></div>';
    }
    if (signedIn === 'denied') {
      return '<div class="pw-signin"><h1>' + esc(page.heading) + '</h1>'
        + '<p class="pw-signin-sub">The sign-in was not completed. You can try '
        + 'again when you are ready.</p>'
        + '<button type="button" class="pw-btn is-block" data-signin-retry="1">'
        + 'Sign in again</button></div>';
    }

    return '<form class="pw-signin" data-signin="' + esc(page.signin_id) + '">'
      + '<h1>' + esc(page.heading) + '</h1>'
      + '<p class="pw-signin-sub">' + esc(page.subheading || '') + '</p>'
      + '<label class="pw-field"><span class="pw-label">Work email</span>'
      + '<input class="pw-input" type="email" id="pw-signin-user"'
      + ' value="' + esc(WORLD.learner.email) + '" autocomplete="off"></label>'
      + '<label class="pw-field"><span class="pw-label">Password</span>'
      + '<input class="pw-input" type="password" id="pw-signin-pass"'
      + ' autocomplete="off" data-synthetic-only="true"></label>'
      + '<button type="submit" class="pw-btn is-primary is-block">Sign in</button>'
      + (page.note ? '<p class="pw-signin-note">' + esc(page.note) + '</p>' : '')
      + '</form>';
  }

  function renderBrowserFiles(page) {
    var location = null;
    S.files.forEach(function (entry) {
      if (entry.id === page.location_id) { location = entry; }
    });
    if (!location) { return '<div class="pw-site"><p>Folder unavailable.</p></div>'; }

    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading || '') + '</p></div>'
      + '<section class="pw-site-section"><h2>Files</h2><ul>'
      + location.files.map(function (file) {
          return '<li>' + esc(file.displayName || file.name)
            + (file.owner ? ' <span class="pw-muted">· ' + esc(file.owner) + '</span>' : '')
            + (file.state === 'unavailable'
                ? ' <span class="pw-chip is-alert">will not open</span>' : '')
            + '</li>';
        }).join('')
      + '</ul></section></div>';
  }

  function renderPayments(tab, page) {
    var invoice = page.invoice;
    var released = tab.signedIn['payments-released'];
    var account = tab.accountOverride || invoice.account_of_record;

    if (released) {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Instruction accepted.</p></div>'
        + '<section class="pw-site-section"><h2>' + esc(invoice.reference) + '</h2><ul>'
        + '<li>' + esc(invoice.supplier) + ' — ' + esc(invoice.amount) + '</li>'
        + '<li>Released to ' + esc(released) + '</li>'
        + '<li>Released by ' + esc(WORLD.learner.name) + ' at ' + esc(nowLabel()) + '</li>'
        + '</ul></section></div>';
    }

    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading) + '</p></div>'
      + '<section class="pw-site-section"><h2>Awaiting release</h2>'
      + '<div class="pw-card" style="max-width:32rem">'
      + '<h3 style="margin-bottom:.4rem">' + esc(invoice.reference) + ' · '
      + esc(invoice.supplier) + '</h3>'
      + '<p class="pw-small pw-muted">Amount ' + esc(invoice.amount)
      + ' · approved by ' + esc(invoice.approved_by) + '</p>'
      + '<label class="pw-field" style="margin-top:.9rem">'
      + '<span class="pw-label">Settlement account</span>'
      + '<input class="pw-input" id="pw-pay-account" value="' + esc(account) + '"'
      + ' autocomplete="off"></label>'
      + '<div class="pw-row">'
      + '<button type="button" class="pw-btn is-primary" data-pay-release="1">'
      + 'Release payment</button>'
      + '<button type="button" class="pw-btn" data-pay-reset="1">Restore account of record</button>'
      + '</div>'
      + '<p class="pw-hint" style="margin-top:.7rem">' + esc(page.note) + '</p>'
      + '</div></section></div>';
  }

  function renderSupport(page) {
    var incident = S.incidents['inc-files'];
    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading) + '</p></div>'
      + (incident
          ? '<div class="pw-note is-caution" style="margin-bottom:1rem">'
            + esc(incident.note) + '</div>' : '')
      + '<section class="pw-site-section"><h2>Actions</h2>'
      + '<div class="pw-row">'
      + '<button type="button" class="pw-btn' + (S.networkDisconnected ? '' : ' is-primary')
      + '" data-support="isolate"' + (S.networkDisconnected ? ' disabled' : '') + '>'
      + (S.networkDisconnected ? 'Workstation is disconnected' : 'Disconnect this workstation from the network')
      + '</button>'
      + '<button type="button" class="pw-btn" data-support="raise">'
      + 'Raise an incident with the Service Desk</button>'
      + '</div>'
      + '<p class="pw-hint" style="margin-top:.7rem">' + esc(page.note) + '</p>'
      + '</section>'
      + ((page.sections || []).map(function (section) {
          return '<section class="pw-site-section"><h2>' + esc(section.title) + '</h2><ul>'
            + section.items.map(function (item) { return '<li>' + esc(item) + '</li>'; }).join('')
            + '</ul></section>';
        }).join(''))
      + '</div>';
  }

  // =========================================================================
  // Files
  // =========================================================================

  function findFile(fileId) {
    var found = null;
    S.files.forEach(function (location) {
      location.files.forEach(function (file) {
        if (file.id === fileId) { found = { file: file, location: location }; }
      });
    });
    return found;
  }

  function renderFiles() {
    var state = APP.files;
    var current = null;
    S.files.forEach(function (location) {
      if (location.id === state.location) { current = location; }
    });
    if (!current) { current = S.files[0]; state.location = current.id; }

    var nav = S.files.map(function (location) {
      var broken = location.files.filter(function (f) {
        return f.state === 'unavailable';
      }).length;
      return '<button type="button" class="pw-navitem'
        + (location.id === state.location ? ' is-active' : '') + '"'
        + ' data-file-location="' + location.id + '">'
        + icon('folder') + '<span>' + esc(location.name) + '</span>'
        + (broken ? '<span class="pw-navitem-count">' + broken + '</span>' : '')
        + '</button>';
    }).join('');

    var rows = current.files.map(function (file) {
      var unavailable = file.state === 'unavailable';
      return '<button type="button" class="pw-filerow'
        + (unavailable ? ' is-unavailable' : '')
        + (file.state === 'downloaded' ? ' is-new' : '')
        + (state.selected === file.id ? ' is-active' : '') + '"'
        + ' data-file-select="' + file.id + '">'
        + icon(unavailable ? 'filex' : fileIcon(file.kind))
        + '<span class="pw-filerow-name">' + esc(file.displayName || file.name) + '</span>'
        + '<span class="pw-filerow-meta is-optional">' + esc(file.size) + '</span>'
        + '<span class="pw-filerow-meta is-optional">' + esc(file.modified) + '</span>'
        + '<span class="pw-filerow-meta">'
        + (unavailable ? '<span class="pw-chip is-alert">error</span>'
           : file.state === 'downloaded' ? '<span class="pw-chip is-accent">new</span>' : '')
        + '</span>'
        + '</button>';
    }).join('');

    // A labelled column header, sharing one grid template with the rows. Two
    // right-aligned numeric columns with nothing at the top of them read as
    // stray figures rather than as size and date.
    var header = ''
      + '<div class="pw-filehead" aria-hidden="true">'
      + '<span></span><span>Name</span>'
      + '<span class="is-optional">Size</span>'
      + '<span class="is-optional">Modified</span>'
      + '<span></span></div>';

    if (!rows) {
      header = '';
      rows = '<div class="pw-empty"><h3>Empty folder</h3>'
        + '<p>Nothing has been saved here.</p></div>';
    }

    var selected = state.selected ? findFile(state.selected) : null;

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-sidepane">'
      + '    <div class="pw-pane-scroll"><div class="pw-nav">' + nav + '</div></div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head"><h3>' + esc(current.name) + '</h3>'
      + (current.path ? '<span class="pw-xsmall pw-muted">' + esc(current.path) + '</span>' : '')
      + '</div>'
      + (S.incidents['inc-files']
          ? '<div class="pw-mailbanner">' + icon('alert')
            + '<span>' + esc(S.incidents['inc-files'].note)
            + ' The Service Desk page in the Browser has the actions.</span></div>'
          : '')
      + header
      + '    <div class="pw-pane-scroll">' + rows + '</div>'
      + (selected ? renderFileInfo(selected) : '')
      + '  </div>'
      + '</div>';
  }

  function fileIcon(kind) {
    if (kind === 'pdf') { return 'pdf'; }
    if (kind === 'spreadsheet' || kind === 'spreadsheet-macro') { return 'sheet'; }
    if (kind === 'text') { return 'text'; }
    return 'doc';
  }

  function renderFileInfo(entry) {
    var file = entry.file;
    var unavailable = file.state === 'unavailable';
    return '<div class="pw-pane-foot" style="display:block">'
      + '<div class="pw-fileinfo" style="padding:0">'
      + '<div class="pw-row is-between"><b>' + esc(file.displayName || file.name) + '</b>'
      + '<span class="pw-row" style="gap:.35rem">'
      + '<button type="button" class="pw-btn is-sm" data-file-open="' + file.id + '">Open</button>'
      + '<button type="button" class="pw-btn is-sm" data-file-rename="' + file.id + '">Rename</button>'
      + '<button type="button" class="pw-btn is-sm is-alert" data-file-delete="' + file.id + '">Delete</button>'
      + '</span></div>'
      + (APP.files.renaming === file.id
          ? '<div class="pw-row" style="margin-top:.5rem">'
            + '<input class="pw-input" id="pw-file-rename" style="max-width:20rem" value="'
            + esc(file.name) + '" aria-label="New file name">'
            + '<button type="button" class="pw-btn is-sm is-primary" data-file-rename-save="'
            + file.id + '">Save</button></div>'
          : '')
      + '<dl>'
      + '<dt>Location</dt><dd>' + esc(entry.location.name) + '</dd>'
      + '<dt>Size</dt><dd>' + esc(file.size) + '</dd>'
      + '<dt>Modified</dt><dd>' + esc(file.modified) + '</dd>'
      + (file.owner ? '<dt>Owner</dt><dd>' + esc(file.owner) + '</dd>' : '')
      + (file.source ? '<dt>Source</dt><dd>' + esc(file.source) + '</dd>' : '')
      + '<dt>Status</dt><dd>'
      + (unavailable ? esc(file.note || 'Cannot be opened.') : 'Available')
      + '</dd>'
      + '</dl>'
      + (file.preview
          ? '<div class="pw-filepreview">'
            + file.preview.map(function (line) { return '<p>' + esc(line) + '</p>'; }).join('')
            + '</div>'
          : '')
      + '</div></div>';
  }

  // =========================================================================
  // Messages
  // =========================================================================

  function markConversationRead(conversationId) {
    S.conversations.forEach(function (conversation) {
      if (conversation.id === conversationId) { conversation.unread = false; }
    });
  }

  function renderMessages() {
    var state = APP.messages;
    var current = null;
    S.conversations.forEach(function (conversation) {
      if (conversation.id === state.conversation) { current = conversation; }
    });
    if (!current) { current = S.conversations[0]; state.conversation = current.id; }

    var list = S.conversations.map(function (conversation) {
      var last = conversation.messages[conversation.messages.length - 1];
      return '<button type="button" class="pw-convrow'
        + (conversation.id === state.conversation ? ' is-active' : '')
        + (conversation.unread ? ' is-unread' : '') + '"'
        + ' data-conv-open="' + conversation.id + '">'
        + '<span class="pw-avatar is-neutral" aria-hidden="true">'
        + esc(conversation.initials) + '</span>'
        + '<span class="pw-convrow-main"><b>' + esc(conversation.name) + '</b>'
        + '<span>' + esc(last ? last.text : '') + '</span></span>'
        + (conversation.unread ? '<span class="pw-dot is-accent"></span>' : '')
        + '</button>';
    }).join('');

    var bubbles = current.messages.map(function (line) {
      var mine = line.from === WORLD.learner.name;
      return '<div class="pw-bubble ' + (mine ? 'is-me' : 'is-them') + '">'
        + esc(line.text)
        + '<span class="pw-bubble-meta">' + esc(mine ? 'You' : line.from)
        + ' · ' + esc(line.when) + '</span></div>';
    }).join('');

    var verify = current.verification_reply
      ? '<button type="button" class="pw-btn is-sm" data-conv-verify="' + current.id + '">'
        + esc(current.verification_reply.prompt) + '</button>'
      : '';

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-listpane" style="width:250px">'
      + '    <div class="pw-pane-head"><h3>Conversations</h3></div>'
      + '    <div class="pw-pane-scroll">' + list + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head">'
      + '      <button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-conv-back="1">'
      + icon('back') + '</button>'
      + '      <h3>' + esc(current.name) + '</h3>'
      + '      <span class="pw-chip is-plain">' + esc(current.presence) + '</span>'
      + '      <span class="pw-spacer"></span>' + verify
      + '    </div>'
      + '    <div class="pw-pane-scroll"><div class="pw-thread">' + bubbles + '</div></div>'
      + '    <div class="pw-pane-foot">'
      + '      <input class="pw-input" id="pw-msg-input" placeholder="Write a message"'
      + '        aria-label="Message" value="' + esc(state.draft) + '" style="flex:1">'
      + '      <button type="button" class="pw-btn is-sm is-primary" data-msg-send="'
      + current.id + '">Send</button>'
      + '    </div>'
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Authenticator
  // =========================================================================

  function renderAuthenticator() {
    var pending = S.prompts.filter(function (p) { return p.status === 'pending'; });

    var prompts = pending.map(function (prompt) {
      var open = !!APP.authenticator.details[prompt.uid];
      var surface = prompt.surface;
      return '<div class="pw-authprompt">'
        + '<div class="pw-row" style="align-items:flex-start">'
        + '<div style="flex:1;min-width:0">'
        + '<h3>Approve sign-in to ' + esc(surface.app) + '?</h3>'
        + '<p class="pw-authsub">Requested ' + esc(prompt.arrivedAt) + '</p>'
        + '</div>'
        + '<span class="pw-authnum" aria-label="Number shown on the sign-in screen">'
        + esc(surface.number_match) + '</span>'
        + '</div>'
        + (open
            ? '<dl class="pw-authgrid">'
              + '<dt>Application</dt><dd>' + esc(surface.app) + '</dd>'
              + '<dt>Device</dt><dd>' + esc(surface.device) + '</dd>'
              + '<dt>Location</dt><dd>' + esc(surface.location) + '</dd>'
              + '<dt>Network</dt><dd>' + esc(surface.network) + '</dd>'
              + '<dt>Address</dt><dd>' + esc(surface.ip_class) + '</dd>'
              + '</dl>'
            : '')
        // Approve and Deny are drawn identically, and neither is emphasised.
        // A primary Approve is a nudge towards approving, and the whole
        // point of the prompt is that the context above it -- not the shape
        // of the buttons -- is what a learner should be reading.
        + '<div class="pw-authactions">'
        + '<button type="button" class="pw-btn is-sm" data-mfa-approve="'
        + prompt.uid + '">Approve</button>'
        + '<button type="button" class="pw-btn is-sm" data-mfa-deny="' + prompt.uid + '">Deny</button>'
        + '<button type="button" class="pw-btn is-sm is-quiet" data-mfa-details="'
        + prompt.uid + '" aria-expanded="' + (open ? 'true' : 'false') + '">'
        + (open ? 'Hide details' : 'Details') + '</button>'
        + '</div></div>';
    }).join('');

    if (!prompts) {
      prompts = '<div class="pw-empty"><h3>Nothing waiting</h3>'
        + '<p>Approval requests appear here when something asks to sign in as '
        + esc(WORLD.learner.name) + '.</p></div>';
    }

    var history = S.authHistory.map(function (entry) {
      return '<div class="pw-authrow">'
        + '<span class="pw-dot' + (String(entry.result).indexOf('Denied') === 0
            ? ' is-caution' : entry.result === 'Approved' ? ' is-good' : ' is-accent')
        + '" aria-hidden="true"></span>'
        + '<span class="pw-authrow-main"><b>' + esc(entry.app) + ' · ' + esc(entry.result) + '</b>'
        + '<span>' + esc(entry.device) + ' · ' + esc(entry.location) + '</span></span>'
        + '<span class="pw-authrow-when">' + esc(entry.when) + '</span>'
        + '</div>';
    }).join('');

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head"><h3>Waiting for you</h3>'
      + '<span class="pw-spacer"></span>'
      + '<span class="pw-chip is-plain">' + esc(WORLD.learner.email) + '</span></div>'
      + '    <div class="pw-pane-scroll">' + prompts
      + '      <div class="pw-pane-head" style="border-top:1px solid var(--p-line)">'
      + '        <h3>Recent activity</h3><span class="pw-spacer"></span>'
      + '        <button type="button" class="pw-btn is-sm is-quiet" data-auth-history="1">'
      + 'I checked this</button>'
      + '      </div>'
      + history
      + '    </div>'
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Directory
  // =========================================================================

  function renderDirectory() {
    var state = APP.directory;
    var term = state.search.trim().toLowerCase();
    var contacts = WORLD.directory.filter(function (contact) {
      if (!term) { return true; }
      return [contact.name, contact.role, contact.department, contact.email]
        .join(' ').toLowerCase().indexOf(term) >= 0;
    });

    var rows = contacts.map(function (contact) {
      return '<button type="button" class="pw-dirrow'
        + (state.selected === contact.id ? ' is-active' : '') + '"'
        + ' data-dir-open="' + contact.id + '">'
        + '<span class="pw-avatar is-neutral" aria-hidden="true">'
        + esc(contact.initials) + '</span>'
        + '<span class="pw-dirrow-main"><b>' + esc(contact.name) + '</b>'
        + '<span>' + esc(contact.role) + ' · ' + esc(contact.department) + '</span></span>'
        + (contact.kind === 'vendor' ? '<span class="pw-chip">supplier</span>' : '')
        + '</button>';
    }).join('') || '<div class="pw-empty"><h3>No match</h3></div>';

    var selected = null;
    WORLD.directory.forEach(function (contact) {
      if (contact.id === state.selected) { selected = contact; }
    });

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-listpane">'
      + '    <div class="pw-pane-head">'
      + '      <label class="pw-search">' + icon('search')
      + '        <input type="search" id="pw-dir-search" placeholder="Search people and suppliers"'
      + '          aria-label="Search the directory" value="' + esc(state.search) + '">'
      + '      </label>'
      + '    </div>'
      + '    <div class="pw-pane-scroll">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (selected ? renderContact(selected)
                  : '<div class="pw-empty"><h3>Directory</h3>'
                    + '<p>The organisation\'s own record of who people are and '
                    + 'how to reach them.</p></div>')
      + '  </div>'
      + '</div>';
  }

  function renderContact(contact) {
    var state = APP.directory;
    return '<div class="pw-pane-head">'
      + '<button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-dir-back="1">'
      + icon('back') + '</button>'
      + '<h3>' + esc(contact.name) + '</h3></div>'
      + '<div class="pw-pane-scroll"><div class="pw-contact">'
      + '<div class="pw-contact-head">'
      + '<span class="pw-avatar is-lg" aria-hidden="true">' + esc(contact.initials) + '</span>'
      + '<div><h3>' + esc(contact.name) + '</h3>'
      + '<p>' + esc(contact.role) + ' · ' + esc(contact.department) + '</p></div>'
      + '</div>'
      + '<dl>'
      + '<dt>Email</dt><dd>' + esc(contact.email) + '</dd>'
      + '<dt>Telephone</dt><dd>' + esc(contact.extension) + '</dd>'
      + '<dt>Location</dt><dd>' + esc(contact.location) + '</dd>'
      + '<dt>Relationship</dt><dd>' + esc(contact.relationship) + '</dd>'
      + '<dt>Known channels</dt><dd>' + esc((contact.channels || []).join(' · ')) + '</dd>'
      + '</dl>'
      + (contact.note ? '<div class="pw-note" style="margin-top:.9rem">'
          + esc(contact.note) + '</div>' : '')
      + (contact.callback
          ? '<div class="pw-row" style="margin-top:1rem">'
            + '<button type="button" class="pw-btn" data-dir-call="' + contact.id + '">'
            + 'Call ' + esc(contact.extension) + '</button></div>'
          : '')
      + (state.call && state.call.id === contact.id
          ? '<div class="pw-note is-accent" style="margin-top:.8rem">'
            + esc(state.call.text) + '</div>'
          : '')
      + '</div></div>';
  }

  // =========================================================================
  // Notes
  // =========================================================================

  function renderNotes() {
    var state = APP.notes;
    if (!state.selected && S.notes.length) { state.selected = S.notes[0].id; }
    var current = null;
    S.notes.forEach(function (note) {
      if (note.id === state.selected) { current = note; }
    });

    var rows = S.notes.map(function (note) {
      return '<button type="button" class="pw-noterow'
        + (note.id === state.selected ? ' is-active' : '') + '"'
        + ' data-note-open="' + note.id + '">'
        + '<b>' + esc(note.title || 'Untitled') + '</b>'
        + '<span>' + esc(note.updated) + '</span></button>';
    }).join('') || '<div class="pw-empty"><h3>No notes</h3></div>';

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-listpane" style="width:220px">'
      + '    <div class="pw-pane-head"><h3>Notes</h3><span class="pw-spacer"></span>'
      + '      <button type="button" class="pw-btn is-sm" data-note-new="1">New</button></div>'
      + '    <div class="pw-pane-scroll">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (current
          ? '<div class="pw-noteedit">'
            + '<input class="pw-notetitle" id="pw-note-title" value="'
            + esc(current.title) + '" aria-label="Note title">'
            + '<textarea id="pw-note-body" aria-label="Note text">' + esc(current.body)
            + '</textarea>'
            + '<div class="pw-pane-foot">'
            + '<span class="pw-xsmall pw-muted">Saved automatically</span>'
            + '<span class="pw-spacer"></span>'
            + '<button type="button" class="pw-btn is-sm is-alert" data-note-delete="'
            + current.id + '">Delete note</button>'
            + '</div></div>'
          : '<div class="pw-empty"><h3>No note selected</h3></div>')
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Notifications
  // =========================================================================

  function renderNotifications() {
    var list = qs('#pw-notiflist');
    if (!S.notifications.length) {
      list.innerHTML = '<div class="pw-empty"><h3>Nothing new</h3></div>';
      return;
    }
    list.innerHTML = S.notifications.map(function (entry) {
      return '<div class="pw-notif' + (entry.unread ? ' is-unread' : '') + '">'
        + '<span class="pw-notif-icon is-' + esc(entry.kind) + '">'
        + icon(notifIcon(entry.kind)) + '</span>'
        + '<span class="pw-notif-main"><b>' + esc(entry.title) + '</b>'
        + '<p>' + esc(entry.body) + '</p>'
        + '<span class="pw-notif-when">' + esc(entry.when) + '</span>'
        + (entry.opens
            ? '<span class="pw-notif-actions">'
              + '<button type="button" class="pw-btn is-sm" data-notif-open="'
              + entry.id + '">Open</button></span>'
            : '')
        + '</span></div>';
    }).join('');
  }

  function notifIcon(kind) {
    if (kind === 'mail') { return 'mail'; }
    if (kind === 'security') { return 'alert'; }
    if (kind === 'file') { return 'folder'; }
    if (kind === 'auth') { return 'shield'; }
    if (kind === 'message') { return 'chat'; }
    return 'info';
  }

  var TOAST_LIMIT = 3;

  function showToast(entry) {
    var host = qs('#pw-toasts');

    // Bounded on purpose. A workstation that stacks nine cards down the
    // screen is not conveying urgency, it is hiding the work. Older toasts
    // drop off; nothing is lost, because every one of them is still in the
    // notification panel.
    while (host.children.length >= TOAST_LIMIT) {
      host.removeChild(host.firstChild);
    }

    var node = document.createElement('div');
    node.className = 'pw-toast';
    node.innerHTML = '<span class="pw-notif-icon is-' + esc(entry.kind) + '">'
      + icon(notifIcon(entry.kind)) + '</span>'
      + '<span class="pw-toast-main"><b>' + esc(entry.title) + '</b>'
      + '<p>' + esc(entry.body) + '</p></span>'
      + (entry.opens
          ? '<button type="button" class="pw-btn is-sm" data-notif-open="'
            + entry.id + '">Open</button>' : '')
      + '<button type="button" class="pw-toast-close" aria-label="Dismiss">&times;</button>';
    host.appendChild(node);

    node.querySelector('.pw-toast-close').addEventListener('click', function () {
      retireToast(node);
    });

    var handle = setTimeout(function () { retireToast(node); }, 9000);
    timers.push(handle);
  }

  // A toast slides out rather than blinking off, and is removed after. It is
  // still a child of the stack while it leaves, so it still counts against
  // TOAST_LIMIT -- which is the conservative side of that trade: the bound on
  // how many cards can be on screen at once stays exactly what it was.
  function retireToast(node) {
    if (!node.parentNode || node.classList.contains('is-leaving')) { return; }

    if (prefersReducedMotion()) {
      node.parentNode.removeChild(node);
      return;
    }

    node.classList.add('is-leaving');
    var handle = setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, 200);
    timers.push(handle);
  }

  // =========================================================================
  // Action handling
  // =========================================================================

  function closestData(target, attribute) {
    var node = target;
    while (node && node !== document) {
      if (node.getAttribute && node.hasAttribute(attribute)) {
        return { node: node, value: node.getAttribute(attribute) };
      }
      node = node.parentNode;
    }
    return null;
  }

  function bindWindow(node, appId) {
    node.addEventListener('mousedown', function () { focusApp(appId); });
    node.addEventListener('focusin', function () { focusApp(appId); });

    qsa('[data-win]', node).forEach(function (button) {
      button.addEventListener('click', function (event) {
        event.stopPropagation();
        var action = button.getAttribute('data-win');
        if (action === 'close') { closeApp(appId); }
        else if (action === 'minimise') { minimiseApp(appId); }
        else {
          WIN[appId].maximized = !WIN[appId].maximized;
          render();
        }
      });
    });

    var bar = qs('.pw-winbar', node);
    bar.addEventListener('pointerdown', function (event) {
      if (!canDrag() || WIN[appId].maximized) { return; }
      if (closestData(event.target, 'data-win')) { return; }
      event.preventDefault();
      var start = { x: event.clientX, y: event.clientY,
                    left: WIN[appId].x, top: WIN[appId].y };
      var size = areaSize();
      bar.setPointerCapture(event.pointerId);

      function move(moveEvent) {
        WIN[appId].x = clamp(start.left + (moveEvent.clientX - start.x),
                             -WIN[appId].w + 120, size.w - 80);
        WIN[appId].y = clamp(start.top + (moveEvent.clientY - start.y),
                             0, size.h - 40);
        node.style.left = WIN[appId].x + 'px';
        node.style.top = WIN[appId].y + 'px';
      }
      function up() {
        bar.removeEventListener('pointermove', move);
        bar.removeEventListener('pointerup', up);
      }
      bar.addEventListener('pointermove', move);
      bar.addEventListener('pointerup', up);
    });

    bar.addEventListener('dblclick', function () {
      WIN[appId].maximized = !WIN[appId].maximized;
      render();
    });
  }

  function handleClick(event) {
    var hit;

    // -- rail ------------------------------------------------------------
    hit = closestData(event.target, 'data-app');
    if (hit) {
      var appId = hit.value;
      if (WIN[appId] && WIN[appId].open && !WIN[appId].minimized
          && topWindow() === appId) {
        minimiseApp(appId);
      } else {
        openApp(appId);
      }
      return;
    }

    // -- mail --------------------------------------------------------------
    hit = closestData(event.target, 'data-mail-folder');
    if (hit) { APP.mail.folder = hit.value; APP.mail.search = ''; render(); return; }

    hit = closestData(event.target, 'data-mail-open');
    if (hit) { openMessage(hit.value); return; }

    hit = closestData(event.target, 'data-mail-back');
    if (hit) { APP.mail.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-mail-headers');
    if (hit) {
      APP.mail.headers = !APP.mail.headers;
      if (APP.mail.headers) {
        observe('inspect_headers:' + hit.value,
                'Opened the full header on a message');
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-mail-inspect-link');
    if (hit) {
      var wasShown = APP.mail.linkShown === hit.value;
      APP.mail.linkShown = wasShown ? null : hit.value;
      if (!wasShown) {
        observe('inspect_link:' + hit.value.split(':')[0],
                'Checked where a link in a message goes');
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-mail-link');
    if (hit) { browserNavigate(hit.value); return; }

    hit = closestData(event.target, 'data-att-inspect');
    if (hit) {
      var attKey = 'att:' + hit.value;
      var open = APP.mail.linkShown === attKey;
      APP.mail.linkShown = open ? null : attKey;
      if (!open) {
        observe('inspect_attachment:' + hit.value.split(':')[0],
                'Looked at the details of an attachment');
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-att-download');
    if (hit) { downloadAttachment(hit.value); return; }

    hit = closestData(event.target, 'data-mail-reply');
    if (hit) {
      APP.mail.composing = hit.value;
      APP.mail.draft = defaultReply(findMail(hit.value));
      render();
      return;
    }

    hit = closestData(event.target, 'data-mail-cancel');
    if (hit) { APP.mail.composing = null; APP.mail.draft = ''; render(); return; }

    hit = closestData(event.target, 'data-mail-send');
    if (hit) { sendReply(hit.value); return; }

    hit = closestData(event.target, 'data-mail-forward');
    if (hit) { forwardMessage(hit.value); return; }

    hit = closestData(event.target, 'data-mail-report');
    if (hit) { reportMessage(hit.value); return; }

    hit = closestData(event.target, 'data-mail-delete');
    if (hit) { deleteMessage(hit.value); return; }

    // -- browser ------------------------------------------------------------
    hit = closestData(event.target, 'data-tab-close');
    if (hit) {
      event.stopPropagation();
      APP.browser.tabs.splice(Number(hit.value), 1);
      APP.browser.active = Math.max(0, APP.browser.active - 1);
      render();
      return;
    }

    hit = closestData(event.target, 'data-tab-select');
    if (hit) { APP.browser.active = Number(hit.value); render(); return; }

    hit = closestData(event.target, 'data-tab-new');
    if (hit) {
      APP.browser.tabs.push({
        url: WORLD.browser.home, history: [WORLD.browser.home], index: 0,
        signedIn: {}, pending: null, accountOverride: null, urlDraft: null
      });
      APP.browser.active = APP.browser.tabs.length - 1;
      render();
      return;
    }

    hit = closestData(event.target, 'data-nav');
    if (hit) {
      var tab = ensureTab();
      if (hit.value === 'back' && tab.index > 0) {
        tab.index -= 1; tab.url = tab.history[tab.index]; tab.urlDraft = null;
      } else if (hit.value === 'forward' && tab.index < tab.history.length - 1) {
        tab.index += 1; tab.url = tab.history[tab.index]; tab.urlDraft = null;
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-go');
    if (hit) { browserNavigate(hit.value); return; }

    hit = closestData(event.target, 'data-signin-retry');
    if (hit) {
      var retryTab = ensureTab();
      delete retryTab.signedIn[retryTab.url];
      render();
      return;
    }

    hit = closestData(event.target, 'data-pay-release');
    if (hit) { releasePayment(); return; }

    hit = closestData(event.target, 'data-pay-reset');
    if (hit) {
      ensureTab().accountOverride = null;
      render();
      return;
    }

    hit = closestData(event.target, 'data-support');
    if (hit) { supportAction(hit.value); return; }

    // -- files ---------------------------------------------------------------
    hit = closestData(event.target, 'data-file-location');
    if (hit) { APP.files.location = hit.value; APP.files.selected = null; render(); return; }

    hit = closestData(event.target, 'data-file-select');
    if (hit) {
      APP.files.selected = hit.value;
      APP.files.renaming = false;
      observe('inspect_file:' + hit.value);
      render();
      return;
    }

    hit = closestData(event.target, 'data-file-open');
    if (hit) { openFile(hit.value); return; }

    hit = closestData(event.target, 'data-file-rename');
    if (hit) { APP.files.renaming = hit.value; render(); return; }

    hit = closestData(event.target, 'data-file-rename-save');
    if (hit) {
      var input = qs('#pw-file-rename');
      var entry = findFile(hit.value);
      if (input && entry && input.value.trim()) {
        entry.file.name = input.value.trim();
        entry.file.displayName = entry.file.state === 'unavailable'
          ? entry.file.name + '.demo_locked' : null;
        record('action', 'Renamed a file to ' + entry.file.name, 'Files');
      }
      APP.files.renaming = false;
      render();
      return;
    }

    hit = closestData(event.target, 'data-file-delete');
    if (hit) { deleteFile(hit.value); return; }

    // -- messages -------------------------------------------------------------
    hit = closestData(event.target, 'data-conv-open');
    if (hit) {
      APP.messages.conversation = hit.value;
      APP.messages.mobileDetail = true;
      markConversationRead(hit.value);
      observe('open_conversation:' + hit.value);
      render();
      return;
    }

    hit = closestData(event.target, 'data-conv-back');
    if (hit) { APP.messages.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-conv-verify');
    if (hit) { verifyThroughMessages(hit.value); return; }

    hit = closestData(event.target, 'data-msg-send');
    if (hit) {
      var box = qs('#pw-msg-input');
      var text = box ? box.value.trim() : '';
      if (text) {
        appendMessage(hit.value, WORLD.learner.name, text);
        APP.messages.draft = '';
        record('action', 'Sent a message', hit.value);
      }
      render();
      return;
    }

    // -- authenticator ----------------------------------------------------------
    hit = closestData(event.target, 'data-mfa-details');
    if (hit) {
      APP.authenticator.details[hit.value] = !APP.authenticator.details[hit.value];
      if (APP.authenticator.details[hit.value]) {
        observe('inspect_mfa:' + hit.value.split('-').slice(0, 2).join('-'),
                'Opened the details on an approval request');
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-auth-history');
    if (hit) {
      observe('open_auth_history', 'Checked your own approval history');
      render();
      return;
    }

    hit = closestData(event.target, 'data-mfa-approve');
    if (hit) { resolvePrompt(hit.value, true); return; }

    hit = closestData(event.target, 'data-mfa-deny');
    if (hit) { resolvePrompt(hit.value, false); return; }

    // -- directory ---------------------------------------------------------------
    hit = closestData(event.target, 'data-dir-open');
    if (hit) {
      APP.directory.selected = hit.value;
      APP.directory.mobileDetail = true;
      APP.directory.call = null;
      observe('open_contact:' + hit.value, 'Opened a Directory record');
      render();
      return;
    }

    hit = closestData(event.target, 'data-dir-back');
    if (hit) { APP.directory.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-dir-call');
    if (hit) { callContact(hit.value); return; }

    // -- notes ---------------------------------------------------------------------
    hit = closestData(event.target, 'data-note-open');
    if (hit) { APP.notes.selected = hit.value; observe('open_notes'); render(); return; }

    hit = closestData(event.target, 'data-note-new');
    if (hit) {
      var id = 'note-' + Date.now();
      S.notes.unshift({ id: id, title: 'New note', updated: nowLabel(), body: '' });
      APP.notes.selected = id;
      record('action', 'Started a new note', 'Notes');
      render();
      return;
    }

    hit = closestData(event.target, 'data-note-delete');
    if (hit) {
      S.notes = S.notes.filter(function (note) { return note.id !== hit.value; });
      APP.notes.selected = S.notes.length ? S.notes[0].id : null;
      render();
      return;
    }

    // -- notifications ---------------------------------------------------------------
    hit = closestData(event.target, 'data-notif-open');
    if (hit) {
      var target = null;
      S.notifications.forEach(function (entry) {
        if (entry.id === hit.value) { entry.unread = false; target = entry.opens; }
      });
      if (target) { openApp(target.app, target); }
      render();
      return;
    }
  }

  // =========================================================================
  // Consequential learner actions
  // =========================================================================

  function downloadAttachment(key) {
    var parts = key.split(':');
    var message = findMail(parts[0]);
    if (!message) { return; }
    var attachment = message.surface.attachments[Number(parts[1])];
    if (!attachment) { return; }

    var downloads = null;
    S.files.forEach(function (location) {
      if (location.id === 'loc-downloads') { downloads = location; }
    });
    if (!downloads) { return; }

    var existing = downloads.files.filter(function (file) {
      return file.name === attachment.name;
    })[0];

    if (!existing) {
      downloads.files.unshift({
        id: 'f-dl-' + parts[0] + '-' + parts[1],
        name: attachment.name,
        kind: attachment.kind === 'spreadsheet-macro' ? 'spreadsheet' : attachment.kind,
        size: attachment.size,
        modified: nowLabel(),
        state: 'downloaded',
        source: message.surface.from_address,
        hostileOpen: message.analysis && message.analysis.disposition === 'hostile'
      });
    }

    record('action', 'Downloaded ' + attachment.name,
           'From ' + message.surface.from_address);
    markResolved(message.id);

    if (message.id === 'm-rate-card') {
      decide('d-ransom-download', { where: 'Mail' });
    }

    pushNotification({
      kind: 'system',
      title: 'Download complete',
      body: attachment.name + ' is in your Downloads folder.',
      opens: { app: 'files', location_id: 'loc-downloads' }
    });
    render();
  }

  function openFile(fileId) {
    var entry = findFile(fileId);
    if (!entry) { return; }
    var file = entry.file;

    if (file.state === 'unavailable') {
      pushNotification({
        kind: 'file',
        title: 'Cannot open ' + file.name,
        body: file.note || 'The file could not be read.',
        opens: null
      });
      render();
      return;
    }

    if (file.hostileOpen) {
      confirmDialog(
        'Open ' + file.name + '?',
        'This workbook wants to run its own content when it opens.',
        function () {
          record('action', 'Opened ' + file.name, entry.location.name);
          decide('d-ransom-open', {
            where: 'Files → ' + entry.location.name,
            evidence: relevantEvidenceFor('m-rate-card')
          });
        });
      return;
    }

    record('action', 'Opened ' + (file.displayName || file.name), entry.location.name);
    pushNotification({
      kind: 'system',
      title: file.name,
      body: 'Opened in the document viewer.',
      opens: null
    });
    render();
  }

  function deleteFile(fileId) {
    var entry = findFile(fileId);
    if (!entry) { return; }
    confirmDialog('Delete ' + entry.file.name + '?',
      'It will be removed from ' + entry.location.name + '.',
      function () {
        entry.location.files = entry.location.files.filter(function (file) {
          return file.id !== fileId;
        });
        APP.files.selected = null;
        record('action', 'Deleted ' + entry.file.name, entry.location.name);
        render();
      });
  }

  function reportMessage(messageId) {
    var message = findMail(messageId);
    if (!message) { return; }

    message.folder = 'reported';
    message.reported = true;
    message.unread = false;
    APP.mail.selected = null;
    markResolved(messageId);
    record('action', 'Reported: ' + message.surface.subject, 'Mail');

    var hostile = message.analysis && message.analysis.disposition === 'hostile';
    var decisionId = hostile
      ? (REPORT_DECISION[messageId] || 'd-phish-report')
      : 'd-report-legitimate';

    decide(decisionId, {
      where: 'Mail',
      evidence: relevantEvidenceFor(messageId)
    });
  }

  function deleteMessage(messageId) {
    var message = findMail(messageId);
    if (!message) { return; }
    message.folder = 'deleted';
    message.unread = false;
    APP.mail.selected = null;
    markResolved(messageId);
    record('action', 'Deleted: ' + message.surface.subject, 'Mail');

    if (message.analysis && message.analysis.disposition === 'hostile') {
      S.deletedHostile += 1;
      if (messageId === 'm-payroll-restructure') {
        decide('d-phish-delete', { where: 'Mail',
                                   evidence: relevantEvidenceFor(messageId) });
        return;
      }
    }
    render();
  }

  function forwardMessage(messageId) {
    var message = findMail(messageId);
    if (!message) { return; }
    message.forwarded = true;
    record('action', 'Forwarded: ' + message.surface.subject, 'Mail');
    pushNotification({
      kind: 'mail', title: 'Message forwarded',
      body: message.surface.subject, opens: null
    });
    render();
  }

  function sendReply(messageId) {
    var message = findMail(messageId);
    var box = qs('#pw-compose-body');
    if (!message) { return; }
    var text = (box ? box.value : APP.mail.draft).trim();

    message.repliedAt = nowLabel();
    APP.mail.composing = null;
    APP.mail.draft = '';
    markResolved(messageId);
    record('action', 'Replied to ' + message.surface.from_name,
           message.surface.subject);

    // The reply lands in Sent as its own message, so the mailbox stays
    // coherent afterwards.
    S.mail.push({
      id: 'm-sent-' + Date.now(),
      arrival: 'sent', folder: 'sent', delivered: true, unread: false,
      read: true, reported: false, repliedAt: null,
      received: nowLabel(), order: 300 + S.mail.length,
      surface: {
        subject: 'Re: ' + message.surface.subject,
        from_name: WORLD.learner.name,
        from_address: WORLD.learner.email,
        reply_to: null,
        to: message.surface.from_address,
        body: [text || '(no text)'],
        links: [], attachments: []
      },
      analysis: { disposition: 'legitimate', family: null, why: '' }
    });

    var decisionId = REPLY_DECISION[messageId];
    if (decisionId) {
      decide(decisionId, {
        where: 'Mail',
        evidence: relevantEvidenceFor(messageId)
      });
    } else {
      render();
    }
  }

  function verifyThroughMessages(conversationId) {
    var conversation = null;
    S.conversations.forEach(function (entry) {
      if (entry.id === conversationId) { conversation = entry; }
    });
    if (!conversation || !conversation.verification_reply) { return; }

    var script = conversation.verification_reply;
    appendMessage(conversationId, WORLD.learner.name, script.sent);
    observe('verify_message:' + conversationId,
            'Asked ' + conversation.name + ' on a known channel');

    var handle = setTimeout(function () {
      appendMessage(conversationId, script.reply.from, script.reply.text);
      pushNotification({
        kind: 'message', title: script.reply.from,
        body: script.reply.text.slice(0, 72) + '…',
        opens: { app: 'messages', conversation_id: conversationId }
      });
      render();
    }, S.fast ? 700 : 3200);
    timers.push(handle);

    if (conversationId === 'conv-arjun-rao' && isLive('m-invoice-amend')) {
      decide('d-bec-verify', { where: 'Messages',
                               evidence: relevantEvidenceFor('m-invoice-amend') });
    } else if (conversationId === 'conv-priya-menon' && isLive('m-payroll-restructure')) {
      decide('d-phish-verify', { where: 'Messages',
                                 evidence: relevantEvidenceFor('m-payroll-restructure') });
    } else {
      render();
    }
  }

  function callContact(contactId) {
    var contact = null;
    WORLD.directory.forEach(function (entry) {
      if (entry.id === contactId) { contact = entry; }
    });
    if (!contact || !contact.callback) { return; }

    APP.directory.call = { id: contactId, text: contact.callback };
    observe('call_contact:' + contactId, 'Called ' + contact.name + ' on the '
            + 'number held in the Directory');
    record('action', 'Called ' + contact.name, contact.extension);

    if (contactId === 'dir-calderwood' && isLive('m-invoice-amend')) {
      decide('d-bec-verify', { where: 'Directory',
                               evidence: relevantEvidenceFor('m-invoice-amend') });
    } else if (contactId === 'dir-priya-menon' && isLive('m-payroll-restructure')) {
      decide('d-phish-verify', { where: 'Directory',
                                 evidence: relevantEvidenceFor('m-payroll-restructure') });
    } else {
      render();
    }
  }

  /* "Live" = delivered and not already reported or deleted. Used so a
   * verification action only counts as verification of something that is
   * actually in front of the learner. */
  function isLive(messageId) {
    var message = findMail(messageId);
    return !!(message && message.delivered && !message.reported
      && message.folder !== 'deleted');
  }

  function alreadyDecided(decisionId) {
    return S.decisions.some(function (entry) { return entry.id === decisionId; });
  }

  function resolvePrompt(uid, approved) {
    var prompt = null;
    S.prompts.forEach(function (entry) { if (entry.uid === uid) { prompt = entry; } });
    if (!prompt || prompt.status !== 'pending') { return; }

    prompt.status = approved ? 'approved' : 'denied';
    markResolved(prompt.id);
    record('action', (approved ? 'Approved' : 'Denied') + ' the request for '
           + prompt.surface.app, prompt.surface.location);

    var hostile = prompt.analysis && prompt.analysis.disposition === 'hostile';
    var evidence = (prompt.analysis && prompt.analysis.evidence) || [];

    if (hostile) {
      decide(approved ? 'd-mfa-approve-hostile' : 'd-mfa-deny-hostile',
             { where: 'Authenticator', evidence: evidence });
    } else {
      // The legitimate prompt belongs to the learner's own remote-access
      // sign-in, so resolving it settles the browser page too.
      APP.browser.tabs.forEach(function (tab) {
        if (tab.signedIn['access.northbridge.example'] === 'pending') {
          tab.signedIn['access.northbridge.example'] = approved ? 'done' : 'denied';
        }
      });
      // Your own approvals belong in your own history. The hostile paths get
      // their activity row from their authored chain; this one has no chain,
      // so it records itself.
      S.authHistory.unshift({
        id: 'auth-' + prompt.uid,
        app: prompt.surface.app,
        result: approved ? 'Approved by you' : 'Denied by you',
        device: prompt.surface.device,
        location: prompt.surface.location,
        when: nowLabel()
      });
      S.vpnConnected = approved;
      if (approved && S.tasks['task-remote-access']) {
        S.tasks['task-remote-access'].state = 'done';
        S.tasks['task-remote-access'].note = 'Remote access session started.';
      }
      decide(approved ? 'd-mfa-approve-legit' : 'd-mfa-deny-legit',
             { where: 'Authenticator', evidence: evidence });
    }
  }

  function releasePayment() {
    var tab = ensureTab();
    var page = WORLD.browser.pages[tab.url];
    if (!page || !page.invoice) { return; }

    var field = qs('#pw-pay-account');
    var value = field ? field.value.trim() : page.invoice.account_of_record;
    var changed = value !== page.invoice.account_of_record;

    confirmDialog('Release ' + page.invoice.amount + ' for '
      + page.invoice.reference + '?',
      changed
        ? 'The settlement account has been changed from the one held on file.'
        : 'The payment goes to the account of record.',
      function () {
        tab.signedIn['payments-released'] = value;
        record('action', 'Released ' + page.invoice.reference,
               'Supplier payments');
        if (changed) {
          decide('d-bec-authorize', {
            where: 'Browser → Supplier payments',
            evidence: relevantEvidenceFor('m-invoice-amend')
          });
        } else {
          pushNotification({
            kind: 'system', title: 'Payment released',
            body: page.invoice.reference + ' · account of record',
            opens: null
          });
          render();
        }
      });
  }

  function supportAction(action) {
    if (action === 'isolate') {
      S.networkDisconnected = true;
      if (S.incidents['inc-files']) { S.incidents['inc-files'].contained = true; }
      record('action', 'Disconnected the workstation from the network',
             'Service Desk');
      if (S.incidents['inc-files'] && !alreadyDecided('d-ransom-isolate')) {
        decide('d-ransom-isolate', { where: 'Browser → Service Desk' });
      } else {
        pushNotification({
          kind: 'system', title: 'Network disconnected',
          body: 'This workstation is off the network.', opens: null
        });
        render();
      }
      return;
    }

    record('action', 'Raised an incident with the Service Desk', 'Service Desk');
    pushNotification({
      kind: 'system', title: 'Incident raised',
      body: 'The Service Desk has your case reference.', opens: null
    });
    appendMessage('conv-lena-fischer', 'Lena Fischer',
                  'Thanks — I can see your ticket. Someone is picking it up now.');
    render();
  }

  // =========================================================================
  // Sign-in submission
  //
  // The password field is never read. Nothing is serialised and no request is
  // made. The field is cleared on submit so the typed value does not survive
  // even in the DOM.
  // =========================================================================

  function handleSubmit(event) {
    var form = event.target;
    if (!form.hasAttribute || !form.hasAttribute('data-signin')) { return; }
    event.preventDefault();

    var kind = form.getAttribute('data-signin');
    var tab = ensureTab();
    var passwordField = qs('#pw-signin-pass', form);
    if (passwordField) { passwordField.value = ''; }

    if (kind === 'vpn-legit') {
      tab.signedIn[tab.url] = 'pending';
      record('action', 'Started a remote access sign-in', tab.url);
      addPrompt('mfa-vpn');
      if (S.tasks['task-remote-access']) {
        S.tasks['task-remote-access'].state = 'outstanding';
        S.tasks['task-remote-access'].note = 'Remote access waiting for approval.';
      }
      render();
      return;
    }

    if (kind === 'payroll-legit') {
      tab.signedIn[tab.url] = 'done';
      record('action', 'Signed in to the payroll portal', tab.url);
      render();
      return;
    }

    // The hostile destination. What is recorded is the decision, not a value.
    tab.signedIn[tab.url] = 'submitted';
    record('action', 'Signed in on ' + tab.url, 'Browser');
    decide('d-phish-credentials', {
      where: 'Browser → ' + tab.url,
      evidence: relevantEvidenceFor('m-payroll-restructure')
    });
  }

  // =========================================================================
  // Generic confirm dialog
  // =========================================================================

  var confirmCallback = null;
  var confirmReturnFocus = null;

  function confirmDialog(title, body, onConfirm) {
    confirmCallback = onConfirm;
    confirmReturnFocus = document.activeElement;
    qs('#pw-confirm-title').textContent = title;
    qs('#pw-confirm-body').textContent = body;
    qs('#pw-confirm-scrim').hidden = false;
    qs('#pw-confirm-ok').focus();
  }

  function closeConfirm() {
    qs('#pw-confirm-scrim').hidden = true;
    confirmCallback = null;
    if (confirmReturnFocus && document.contains(confirmReturnFocus)) {
      confirmReturnFocus.focus();
    }
    confirmReturnFocus = null;
  }

  // =========================================================================
  // End training
  // =========================================================================

  function outstandingSummary() {
    var outstanding = Object.keys(S.tasks).map(function (id) { return S.tasks[id]; })
      .filter(function (task) { return task.state === 'outstanding'; });
    if (!outstanding.length) { return 'Nothing is outstanding.'; }
    return outstanding.length + ' item'
      + (outstanding.length === 1 ? ' is' : 's are') + ' still outstanding: '
      + outstanding.map(function (task) { return task.label; }).join('; ') + '.';
  }

  function endSession() {
    S.ended = true;
    timers.forEach(function (handle) { clearTimeout(handle); });
    timers = [];
    if (deliveryTimer) { clearTimeout(deliveryTimer); }

    var payload = {
      focus: S.focus,
      mode: S.mode,
      assessmentId: S.assessmentId,
      endedAt: nowLabel(),
      durationMinutes: simMinutes() - CLOCK_START_MIN,
      timeline: S.timeline,
      decisions: S.decisions,
      chains: S.chains,
      incidents: S.incidents,
      tasks: S.tasks,
      observed: Object.keys(S.observed),
      hostileDelivered: S.mail.filter(function (m) {
        return m.delivered && m.analysis && m.analysis.disposition === 'hostile';
      }).map(function (m) { return m.id; }),
      hostilePrompts: S.prompts.filter(function (p) {
        return p.analysis && p.analysis.disposition === 'hostile';
      }).length,
      deletedHostile: S.deletedHostile,
      filesImpacted: S.files.reduce(function (total, location) {
        return total + location.files.filter(function (f) {
          return f.state === 'unavailable';
        }).length;
      }, 0),
      evidenceUniverse: buildEvidenceUniverse()
    };

    try {
      window.sessionStorage.setItem('rewindsec.prototype.run',
                                    JSON.stringify(payload));
    } catch (err) { /* private mode: the debrief falls back to its fixture */ }

    window.location.href = '/prototype/results';
  }

  /* Every piece of decision-relevant evidence that the workplace actually
   * made available during this run, with whether it was inspected. This is
   * the available-versus-observed distinction, reduced to what the debrief
   * needs. */
  function buildEvidenceUniverse() {
    var out = [];
    var seen = {};

    function add(item) {
      if (seen[item.id]) { return; }
      seen[item.id] = true;
      out.push({
        id: item.id, label: item.label, where: item.where,
        observed: !!S.observed[item.action]
      });
    }

    S.mail.forEach(function (message) {
      if (!message.delivered) { return; }
      if (message.analysis && message.analysis.evidence) {
        message.analysis.evidence.forEach(add);
      }
    });
    S.prompts.forEach(function (prompt) {
      if (prompt.analysis && prompt.analysis.evidence) {
        prompt.analysis.evidence.forEach(add);
      }
    });
    return out;
  }

  // =========================================================================
  // Prototype developer panel wiring
  // =========================================================================

  function bindDevPanel() {
    var focusSelect = qs('#pw-dev-focus');
    var modeSelect = qs('#pw-dev-mode');
    if (focusSelect) { focusSelect.value = S.focus; }
    if (modeSelect) { modeSelect.value = S.mode; }

    var restart = qs('#pw-dev-restart');
    if (restart) {
      restart.addEventListener('click', function () {
        window.location.href = '/prototype/workstation?focus='
          + encodeURIComponent(focusSelect.value)
          + '&mode=' + encodeURIComponent(modeSelect.value);
      });
    }

    var reset = qs('#pw-dev-reset');
    if (reset) {
      reset.addEventListener('click', function () {
        try { window.sessionStorage.removeItem('rewindsec.prototype.run'); }
        catch (err) { /* nothing to clear */ }
        window.location.href = '/prototype/workstation?focus=' + S.focus
          + '&mode=' + S.mode;
      });
    }

    var next = qs('#pw-dev-next');
    if (next) { next.addEventListener('click', function () { deliverNext(); }); }

    var all = qs('#pw-dev-all');
    if (all) {
      all.addEventListener('click', function () {
        while (S.queueIndex < S.queue.length) { deliverNext(); }
      });
    }

    var fast = qs('#pw-dev-fast');
    if (fast) {
      fast.checked = S.fast;
      fast.addEventListener('change', function () { S.fast = fast.checked; });
    }

    qsa('[data-dev-inject]').forEach(function (button) {
      button.addEventListener('click', function () {
        var kind = button.getAttribute('data-dev-inject');
        if (kind === 'notification') {
          pushNotification({
            kind: 'system', title: 'Backup completed',
            body: 'Documents and Desktop backed up.', opens: null
          });
        } else if (kind === 'mfa') {
          addPrompt('mfa-unexpected');
        } else if (kind === 'legit-mfa') {
          addPrompt('mfa-vpn');
        } else if (kind === 'message') {
          appendMessage('conv-tom-brennan', 'Tom Brennan',
                        'Are you around for ten minutes before the stand-up?');
          pushNotification({
            kind: 'message', title: 'Tom Brennan',
            body: 'Are you around for ten minutes before the stand-up?',
            opens: { app: 'messages', conversation_id: 'conv-tom-brennan' }
          });
        }
        render();
      });
    });

    qsa('[data-dev-chain]').forEach(function (button) {
      button.addEventListener('click', function () {
        var decisionId = button.getAttribute('data-dev-chain');
        var evidenceSource = {
          'd-phish-credentials': 'm-payroll-restructure',
          'd-ransom-open': 'm-rate-card',
          'd-bec-authorize': 'm-invoice-amend'
        }[decisionId];
        if (evidenceSource) { deliverMail(evidenceSource, null, true); }
        if (decisionId === 'd-mfa-approve-hostile') { addPrompt('mfa-unexpected'); }
        decide(decisionId, {
          where: 'Prototype tooling',
          evidence: evidenceSource ? relevantEvidenceFor(evidenceSource) : []
        });
      });
    });
  }

  // =========================================================================
  // Boot
  // =========================================================================

  function bindShell() {
    document.addEventListener('click', handleClick);
    document.addEventListener('submit', handleSubmit);

    document.addEventListener('input', function (event) {
      var node = event.target;
      if (node.id === 'pw-mail-search') { APP.mail.search = node.value; render(); }
      else if (node.id === 'pw-compose-body') { APP.mail.draft = node.value; }
      else if (node.id === 'pw-url-input') { ensureTab().urlDraft = node.value; }
      else if (node.id === 'pw-dir-search') { APP.directory.search = node.value; render(); }
      else if (node.id === 'pw-msg-input') { APP.messages.draft = node.value; }
      else if (node.id === 'pw-note-title' || node.id === 'pw-note-body') {
        S.notes.forEach(function (note) {
          if (note.id === APP.notes.selected) {
            if (node.id === 'pw-note-title') { note.title = node.value; }
            else { note.body = node.value; }
            note.updated = nowLabel();
          }
        });
      } else if (node.id === 'pw-pay-account') {
        ensureTab().accountOverride = node.value;
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter') { return; }
      if (event.target.id === 'pw-url-input') {
        event.preventDefault();
        browserNavigate(event.target.value);
      } else if (event.target.id === 'pw-msg-input') {
        event.preventDefault();
        var current = APP.messages.conversation;
        var text = event.target.value.trim();
        if (text) {
          appendMessage(current, WORLD.learner.name, text);
          APP.messages.draft = '';
          record('action', 'Sent a message', current);
          render();
        }
      }
    });

    // Escape closes non-blocking surfaces only. The comparison screen owns
    // its own key handling and deliberately does not close on Escape.
    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') { return; }
      if (!qs('#pw-confirm-scrim').hidden) { closeConfirm(); return; }
      if (!qs('#pw-end-scrim').hidden) { closeEndDialog(); return; }
      if (!qs('#pw-notifpanel').hidden) { toggleNotifications(false); return; }
    });

    qs('#pw-notif-btn').addEventListener('click', function () {
      toggleNotifications(qs('#pw-notifpanel').hidden);
    });
    qs('#pw-notif-close').addEventListener('click', function () {
      toggleNotifications(false);
    });
    qs('#pw-notif-clear').addEventListener('click', function () {
      S.notifications.forEach(function (entry) { entry.unread = false; });
      render();
    });

    qs('#pw-end-btn').addEventListener('click', function () {
      qs('#pw-end-detail').textContent = outstandingSummary();
      qs('#pw-end-scrim').hidden = false;
      qs('#pw-end-confirm').focus();
    });
    qs('#pw-end-cancel').addEventListener('click', closeEndDialog);
    qs('#pw-end-confirm').addEventListener('click', endSession);

    qs('#pw-confirm-cancel').addEventListener('click', closeConfirm);
    qs('#pw-confirm-ok').addEventListener('click', function () {
      var callback = confirmCallback;
      closeConfirm();
      if (callback) { callback(); }
    });

    // A window keeps the geometry it was given until something changes it,
    // so shrinking the viewport used to leave one hanging off the right edge
    // of the desk. Clamp every open window back inside the work area first,
    // then draw.
    window.addEventListener('resize', function () { reflowWindows(); render(); });
  }

  function closeEndDialog() {
    qs('#pw-end-scrim').hidden = true;
    qs('#pw-end-btn').focus();
  }

  function toggleNotifications(open) {
    qs('#pw-notifpanel').hidden = !open;
    qs('#pw-notif-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      S.notifications.forEach(function (entry) { entry.unread = false; });
      render();
      qs('#pw-notif-close').focus();
    } else {
      renderTopBar();
    }
  }

  function boot(world) {
    WORLD = world;

    var focus = param('focus') || 'mixed';
    if (!WORLD.timelines[focus]) { focus = 'mixed'; }
    var mode = param('mode') || 'simulation';
    if (!modeFlags(mode)) { mode = 'simulation'; }

    S = buildState(focus, mode, param('assessment'));
    APP = defaultAppState();

    record('event', 'Session started',
           modeLabel(mode) + ' · ' + focus + ' focus');

    bindShell();
    bindDevPanel();
    openApp('mail');
    render();

    setInterval(function () {
      if (!S.ended) { renderTopBar(); }
    }, 5000);

    scheduleNextDelivery(S.mode === 'assessment' ? 6000 : 14000);
  }

  fetch('/prototype/api/world', { headers: { Accept: 'application/json' } })
    .then(function (response) { return response.json(); })
    .then(boot)
    .catch(function (error) {
      var area = qs('#pw-workarea');
      if (area) {
        area.innerHTML = '<div class="pw-empty" style="padding-top:4rem">'
          + '<h3>The workstation could not load its world</h3>'
          + '<p>The fixture endpoint /prototype/api/world did not respond.</p>'
          + '</div>';
      }
      if (window.console) { window.console.error(error); }
    });
}());
