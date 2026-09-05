/* Prototype developer panel — visibility and generic wiring.
 *
 * Explicitly not a learner feature. This file owns showing and hiding the
 * panel and the buttons that are the same on every prototype screen. The
 * workstation binds its own session controls to the same panel when it loads;
 * on screens where those controls make no sense, they are hidden rather than
 * left as dead buttons.
 *
 * Nothing here participates in the simulated experience.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'rewindsec.prototype.devpanel';
  var panel = document.getElementById('pw-dev');
  var toggle = document.getElementById('pw-dev-toggle');
  var hide = document.getElementById('pw-dev-hide');
  if (!panel || !toggle) { return; }

  function readStored() {
    try { return window.localStorage.getItem(STORAGE_KEY); }
    catch (err) { return null; }
  }

  function store(value) {
    try { window.localStorage.setItem(STORAGE_KEY, value); }
    catch (err) { /* private mode: the panel simply forgets between loads */ }
  }

  function setVisible(visible, remember) {
    panel.hidden = !visible;
    toggle.hidden = visible;
    // Only a deliberate toggle changes the stored preference. Applying
    // ?dev=0 for one screenshot must not silently hide the panel forever.
    if (remember) { store(visible ? 'open' : 'closed'); }
    if (visible) {
      var first = panel.querySelector('button, select, input, a');
      if (first) { first.focus(); }
    }
  }

  // ?dev=0 wins over the stored preference, so a screenshot run is one URL
  // away and does not have to be undone afterwards.
  var params = new URLSearchParams(window.location.search);
  var initial = params.get('dev') === '0' ? false
    : (readStored() === 'closed' ? false : true);
  setVisible(initial, false);

  toggle.addEventListener('click', function () { setVisible(true, true); });
  if (hide) { hide.addEventListener('click', function () { setVisible(false, true); }); }

  document.addEventListener('keydown', function (event) {
    if (event.ctrlKey && event.altKey && (event.key === 'p' || event.key === 'P')) {
      event.preventDefault();
      setVisible(panel.hidden, true);
    }
  });

  // Screens that are not the workstation have no session to drive. Hide the
  // session-scoped groups there rather than leaving buttons that do nothing.
  if (!document.getElementById('pw-workarea')) {
    var scoped = panel.querySelectorAll('[data-dev-scope="workstation"]');
    for (var i = 0; i < scoped.length; i += 1) { scoped[i].hidden = true; }
  }

  // The integrity controls exist only on learner surfaces, so the group that
  // demonstrates them is hidden on the trainer console rather than offering a
  // button that could not do anything.
  var isLearner = document.body.getAttribute('data-integrity') === 'learner';
  if (!isLearner) {
    var learnerOnly = panel.querySelectorAll('[data-dev-scope="learner"]');
    for (var j = 0; j < learnerOnly.length; j += 1) {
      learnerOnly[j].hidden = true;
    }
  }

  var shot = document.getElementById('pw-dev-screenshot');
  if (shot) {
    shot.addEventListener('click', function () {
      if (window.RewindSecIntegrity) {
        window.RewindSecIntegrity.showScreenshotNotice();
      }
    });
  }

  window.RewindSecDevPanel = {
    element: panel,
    show: function () { setVisible(true, true); },
    hide: function () { setVisible(false, true); }
  };
}());
