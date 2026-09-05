/* PROVISIONAL — the safer-alternative comparison screen.
 *
 * Architecture §12 does not freeze this feature. This whole file, plus
 * comparison.css and the `#pwc-mount` element in the workstation template,
 * is the feature. The workstation calls it through one guarded call site:
 *
 *     if (window.RewindSecComparison) {
 *         await window.RewindSecComparison.show(payload);
 *     }
 *
 * Delete this file and the call becomes a no-op. Nothing else changes: the
 * consequences that led here already happened, are already in the world
 * state, and are already on the debrief.
 *
 * Rules this implementation exists to hold:
 *   - it blocks. There is no Escape, no backdrop dismissal and no close
 *     control. The only way out is Continue.
 *   - it never says "rewind", "restore", "baseline" or "try again", and it
 *     never implies the world was put back.
 *   - it shows no score, no points, and no correct/incorrect verdict.
 *   - it is suppressed entirely during an Assessment attempt; that decision
 *     belongs to the caller, which is why this module has no mode logic.
 */
(function () {
  'use strict';

  var mount = document.getElementById('pwc-mount');
  if (!mount) { return; }

  var lastFocused = null;
  var releaseTrap = null;

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function list(items, className) {
    if (!items || !items.length) { return ''; }
    var out = '<ul class="' + className + '">';
    for (var i = 0; i < items.length; i += 1) {
      out += '<li>' + esc(items[i]) + '</li>';
    }
    return out + '</ul>';
  }

  function evidenceRows(items) {
    if (!items || !items.length) {
      return '<div class="pwc-ev"><span class="pwc-ev-main">'
        + '<b>No decision-relevant evidence was recorded for this one.</b>'
        + '</span></div>';
    }
    var out = '';
    for (var i = 0; i < items.length; i += 1) {
      var item = items[i];
      out += '<div class="pwc-ev' + (item.observed ? ' is-seen' : '') + '">'
        + '<span class="pwc-ev-state" aria-hidden="true">'
        + (item.observed
            ? '<svg><use href="#i-check"></use></svg>'
            : '<svg><use href="#i-eye"></use></svg>')
        + '</span>'
        + '<span class="pwc-ev-main"><b>' + esc(item.label) + '</b>'
        + '<span>' + esc(item.where) + '</span></span>'
        + '<span class="pwc-ev-tag">'
        + (item.observed ? 'Looked at' : 'Not opened')
        + '</span></div>';
    }
    return out;
  }

  /* Keeps keyboard focus inside the dialog while it is open. A blocking
   * screen that a screen-reader user can tab out of is not blocking. */
  function trapFocus(container) {
    function focusables() {
      return container.querySelectorAll(
        'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])');
    }
    function onKeydown(event) {
      if (event.key !== 'Tab') { return; }
      var items = focusables();
      if (!items.length) { return; }
      var first = items[0];
      var last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener('keydown', onKeydown, true);
    return function () {
      document.removeEventListener('keydown', onKeydown, true);
    };
  }

  function render(payload) {
    var eyebrow = payload.eyebrow || 'What happened, and what else was possible';
    return ''
      + '<div class="pwc" role="dialog" aria-modal="true"'
      + ' aria-labelledby="pwc-title" id="pwc-dialog">'
      + '  <div class="pwc-head">'
      + '    <p class="pwc-eyebrow"><span class="pw-dot" aria-hidden="true"></span>'
      + esc(eyebrow) + '</p>'
      + '    <h2 id="pwc-title">' + esc(payload.heading) + '</h2>'
      + (payload.subheading
          ? '<p>' + esc(payload.subheading) + '</p>' : '')
      + '  </div>'
      + '  <div class="pwc-body" tabindex="-1" id="pwc-body">'
      + '    <section class="pwc-section">'
      + '      <h3>What you did</h3>'
      + '      <p>' + esc(payload.what_you_did) + '</p>'
      + '    </section>'
      + '    <section class="pwc-section">'
      + '      <h3>What followed</h3>'
      + '      ' + list(payload.what_followed, 'pwc-chain')
      + '    </section>'
      + '    <section class="pwc-section">'
      + '      <h3>What was already available to you</h3>'
      + '      <div class="pwc-evidence">' + evidenceRows(payload.evidence) + '</div>'
      + '    </section>'
      + '    <section class="pwc-section">'
      + '      <h3>A process that holds up</h3>'
      + '      ' + list(payload.safer_process, 'pwc-steps')
      + '    </section>'
      + '    <section class="pwc-section">'
      + '      <h3>Where that would most likely have left you</h3>'
      + '      <div class="pwc-outcome">' + esc(payload.likely_outcome) + '</div>'
      + '    </section>'
      + '    <div class="pwc-persists">'
      + '      <svg aria-hidden="true"><use href="#i-info"></use></svg>'
      + '      <span>' + esc(payload.still_true) + '</span>'
      + '    </div>'
      + '  </div>'
      + '  <div class="pwc-foot">'
      + '    <p class="pwc-foot-note">Your workstation is exactly as you left'
      + ' it. Nothing here has been undone.</p>'
      + '    <button type="button" class="pw-btn is-primary is-lg" id="pwc-continue">'
      + 'Continue working</button>'
      + '  </div>'
      + '</div>';
  }

  function close() {
    mount.hidden = true;
    mount.innerHTML = '';
    if (releaseTrap) { releaseTrap(); releaseTrap = null; }
    if (lastFocused && document.contains(lastFocused)) {
      lastFocused.focus();
    }
    lastFocused = null;
  }

  window.RewindSecComparison = {
    /* Returns a promise that resolves when the learner presses Continue.
     * The caller pauses event delivery for exactly that long. */
    show: function (payload) {
      lastFocused = document.activeElement;
      mount.innerHTML = render(payload);
      mount.hidden = false;

      var dialog = document.getElementById('pwc-dialog');
      releaseTrap = trapFocus(dialog);

      var body = document.getElementById('pwc-body');
      if (body) { body.focus(); }

      return new Promise(function (resolve) {
        document.getElementById('pwc-continue')
          .addEventListener('click', function () {
            close();
            resolve();
          });
      });
    },

    isOpen: function () { return !mount.hidden; },

    /* Used only by the prototype's reset control. */
    forceClose: close
  };
}());
