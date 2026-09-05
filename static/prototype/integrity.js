/* RewindSec 2.0 UI prototype — learner integrity controls.
 *
 * One controller for the whole learner surface, rather than a handler per
 * field. It runs only where the *server* said the page is a learner surface
 * (``<body data-integrity="learner">``), so a trainer screen cannot acquire
 * these restrictions by accident and a learner screen cannot lose them by
 * someone forgetting to decorate a newly added input.
 *
 * What it does
 * ------------
 * 1. Cancels ``copy``, ``cut`` and ``paste`` anywhere on a learner surface
 *    except inside a region explicitly marked ``data-clipboard="allow"``.
 *    Notes carries that marker, and so does the prototype developer panel.
 * 2. Notices a PrintScreen key event and explains, once, why capturing the
 *    workspace is not part of the exercise.
 *
 * What it deliberately is not
 * ---------------------------
 * This is deterrence, not prevention. A web page cannot stop the Snipping
 * Tool, an OS capture shortcut, a browser extension, a second machine or a
 * phone camera, and neither the code nor the copy in this file pretends
 * otherwise.
 *
 * Privacy boundary
 * ----------------
 * Nothing here reads, stores, transmits or inspects clipboard contents, and
 * nothing here records keystrokes. The clipboard event is cancelled before
 * anything could be read from it; ``clipboardData`` is never touched. The
 * keyboard listener looks at one modifier combination and three key names and
 * keeps nothing. Production may later record *that* a blocked action happened
 * (``clipboard_copy_blocked`` and friends, with session context only) -- that
 * telemetry is not built here, and if it ever is, it must carry no content.
 */
(function () {
  'use strict';

  var root = document.body;
  if (!root || root.getAttribute('data-integrity') !== 'learner') { return; }

  /* Regions where the clipboard works normally. Notes is the one learner
   * application with the marker: a learner who needs to keep something has
   * somewhere to keep it, which is what makes the restriction everywhere else
   * reasonable rather than merely obstructive. */
  var ALLOW = '[data-clipboard="allow"]';

  var CLIPBOARD_NOTICE = 'Copy and paste are disabled in the training '
    + 'workspace. Use Notes if you need to keep information.';

  var SCREENSHOT_TITLE = 'Screenshots are disabled during RewindSec training';
  var SCREENSHOT_BODY = 'Screen capture is not part of this exercise. Everyone '
    + 'is assessed on what they did in the workspace, so material carried out '
    + 'of it cannot count. If you need to keep track of something, use Notes.';
  var SCREENSHOT_LIMIT = 'RewindSec cannot detect or block every capture method '
    + 'your device offers. This is a rule of the exercise, not a technical '
    + 'guarantee.';

  // -----------------------------------------------------------------------
  // Scope
  // -----------------------------------------------------------------------

  function element(node) {
    if (!node) { return null; }
    if (node.nodeType === 1) { return node; }
    return node.parentElement || null;
  }

  /* Where the action happened decides it. The element the event was raised on
   * is the answer whenever there is one; only when the event arrives on the
   * document or the body -- no useful target -- does the currently focused
   * element stand in for it.
   *
   * The order matters. Asking "is anything in Notes focused?" first would let
   * a caret parked in a note authorise a copy taken from Mail. */
  function permitted(node) {
    var target = element(node);
    if (target && target !== document.body
        && target !== document.documentElement) {
      return !!target.closest(ALLOW);
    }
    var focused = element(document.activeElement);
    if (!focused || focused === document.body) { return false; }
    return !!focused.closest(ALLOW);
  }

  // -----------------------------------------------------------------------
  // The notice
  // -----------------------------------------------------------------------
  //
  // Restrained on purpose: a small line of text at the foot of the screen
  // saying what happened and where to put information instead. It is not an
  // error, the learner has not done anything wrong, and it must not read as
  // an accusation.

  var noticeNode = null;
  var noticeTimer = null;

  function showNotice(text) {
    if (!noticeNode) {
      noticeNode = document.createElement('div');
      noticeNode.className = 'pw-int-notice';
      // polite, not assertive: it must not interrupt a screen reader
      // mid-sentence for something this small.
      noticeNode.setAttribute('role', 'status');
      noticeNode.setAttribute('aria-live', 'polite');
      document.body.appendChild(noticeNode);
    }
    // Repeated attempts refresh one notice rather than stacking copies of it.
    noticeNode.textContent = text;
    noticeNode.classList.add('is-on');
    window.clearTimeout(noticeTimer);
    noticeTimer = window.setTimeout(function () {
      noticeNode.classList.remove('is-on');
    }, 4200);
  }

  // -----------------------------------------------------------------------
  // Clipboard
  // -----------------------------------------------------------------------
  //
  // Cancelling the clipboard events themselves covers every route to them:
  // the keyboard shortcut, the browser's Edit menu, and the right-click
  // context menu, all of which dispatch these same events. A page cannot
  // remove individual items from the native context menu, so this -- rather
  // than suppressing the menu wholesale -- is the practical way to reach
  // context-menu clipboard behaviour without taking away the rest of the menu.

  function blockClipboard(event) {
    if (permitted(event.target)) { return; }
    // Cancel first. Nothing below reads event.clipboardData, and nothing
    // anywhere in this file does.
    event.preventDefault();
    event.stopPropagation();
    showNotice(CLIPBOARD_NOTICE);
  }

  ['copy', 'cut', 'paste'].forEach(function (name) {
    document.addEventListener(name, blockClipboard, true);
  });

  /* Dragging text is the same transfer by another route. Cancelling it keeps
   * the rule consistent; it does not affect window dragging, which is built
   * on pointer events rather than HTML5 drag and drop. */
  ['dragstart', 'drop'].forEach(function (name) {
    document.addEventListener(name, function (event) {
      if (permitted(event.target)) { return; }
      event.preventDefault();
      showNotice(CLIPBOARD_NOTICE);
    }, true);
  });

  /* Belt and braces for the keyboard path, for browsers that would not raise
   * the clipboard event at all. Nothing else is intercepted: this handler
   * only ever acts on Ctrl/Cmd with one of three keys, so typing, keyboard
   * navigation, select-all, undo and every assistive-technology shortcut
   * behave exactly as they did before. No key is recorded. */
  document.addEventListener('keydown', function (event) {
    if (!(event.ctrlKey || event.metaKey) || event.altKey) { return; }
    var key = (event.key || '').toLowerCase();
    if (key !== 'c' && key !== 'x' && key !== 'v') { return; }
    if (permitted(document.activeElement)) { return; }
    event.preventDefault();
    showNotice(CLIPBOARD_NOTICE);
  }, true);

  // -----------------------------------------------------------------------
  // Screenshot deterrence
  // -----------------------------------------------------------------------

  var scrim = null;
  var dismissBtn = null;
  var returnFocus = null;
  var lastSeen = 0;

  function buildModal() {
    scrim = document.createElement('div');
    scrim.className = 'pw-int-scrim';
    scrim.hidden = true;
    scrim.innerHTML = ''
      + '<div class="pw-int-dialog" role="dialog" aria-modal="true"'
      + ' aria-labelledby="pw-int-title" aria-describedby="pw-int-body">'
      + '  <h2 id="pw-int-title"></h2>'
      + '  <p id="pw-int-body"></p>'
      + '  <p class="pw-int-limit"></p>'
      + '  <div class="pw-int-foot">'
      + '    <button type="button" class="pw-btn is-primary"'
      + ' id="pw-int-dismiss">Continue working</button>'
      + '  </div>'
      + '</div>';
    document.body.appendChild(scrim);

    scrim.querySelector('#pw-int-title').textContent = SCREENSHOT_TITLE;
    scrim.querySelector('#pw-int-body').textContent = SCREENSHOT_BODY;
    scrim.querySelector('.pw-int-limit').textContent = SCREENSHOT_LIMIT;

    dismissBtn = scrim.querySelector('#pw-int-dismiss');
    dismissBtn.addEventListener('click', closeModal);

    // Dismissible, and keyboard-dismissible: this is information, not a
    // penalty, and trapping someone behind it would be the wrong shape.
    scrim.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') { closeModal(); return; }
      if (event.key !== 'Tab') { return; }
      // One focusable control, so focus simply stays on it.
      event.preventDefault();
      dismissBtn.focus();
    });
  }

  function openModal() {
    if (!scrim) { buildModal(); }
    if (!scrim.hidden) { return; }
    returnFocus = document.activeElement;
    scrim.hidden = false;
    dismissBtn.focus();
  }

  function closeModal() {
    if (!scrim || scrim.hidden) { return; }
    scrim.hidden = true;
    if (returnFocus && document.contains(returnFocus)) { returnFocus.focus(); }
    returnFocus = null;
  }

  /* Where the browser surfaces it at all. Windows commonly delivers only the
   * keyup for this key, and some platforms and layouts never deliver it, so
   * both edges are watched and neither is relied upon. */
  function isPrintScreen(event) {
    return event.key === 'PrintScreen' || event.code === 'PrintScreen'
      || event.keyCode === 44;
  }

  function onPrintScreen(event) {
    if (!isPrintScreen(event)) { return; }
    var now = Date.now();
    // keydown and keyup for one press are one attempt, not two.
    if (now - lastSeen < 900) { return; }
    lastSeen = now;
    openModal();
  }

  document.addEventListener('keydown', onPrintScreen, true);
  document.addEventListener('keyup', onPrintScreen, true);

  window.RewindSecIntegrity = {
    scope: 'learner',
    allowSelector: ALLOW,
    // Exposed so the prototype tooling can demonstrate the notice without a
    // reviewer having to trigger a real capture attempt.
    showScreenshotNotice: openModal
  };
}());
