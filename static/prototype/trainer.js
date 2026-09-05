/* RewindSec 2.0 UI prototype — trainer assessment screen.
 *
 * Two interactions worth prototyping rather than describing:
 *
 * 1. Creating an assessment defined by *required scored interactions*.
 * 2. Assigning one to a student who already receives it through a group.
 *    Architecture §27 says the trainer must be told where the existing
 *    assignment came from and asked whether to assign again, and that a
 *    confirmed second assignment is preserved with its own provenance rather
 *    than merged into the first.
 *
 * The provenance lookup is a real server call — /prototype/api/assignment-
 * provenance — because "where does this already come from" is a question only
 * the server can answer, and wiring it that way now keeps the shape honest.
 * Everything the confirm button then does is prototype-local: nothing is
 * persisted.
 */
(function () {
  'use strict';

  function qs(selector) { return document.querySelector(selector); }
  function qsa(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  var kindSelect = qs('#pw-assign-kind');
  if (!kindSelect) { return; }

  var assessmentSelect = qs('#pw-assign-assessment');
  var studentSelect = qs('#pw-assign-student');
  var groupSelect = qs('#pw-assign-group');
  var studentField = qs('#pw-assign-student-field');
  var groupField = qs('#pw-assign-group-field');
  var status = qs('#pw-assign-status');
  var assignButton = qs('#pw-assign-btn');

  var scrim = qs('#pw-dup-scrim');
  var dupLead = qs('#pw-dup-lead');
  var dupSources = qs('#pw-dup-sources');
  var dupCancel = qs('#pw-dup-cancel');
  var dupConfirm = qs('#pw-dup-confirm');

  var log = qs('#pw-assign-log');
  var logList = qs('#pw-assign-loglist');

  var pending = null;
  var returnFocus = null;

  function selectedText(select) {
    return select.options[select.selectedIndex].textContent.trim();
  }

  function updateKind() {
    var group = kindSelect.value === 'group';
    studentField.hidden = group;
    groupField.hidden = !group;
  }

  kindSelect.addEventListener('change', updateKind);
  updateKind();

  // -- assignment log ------------------------------------------------------

  function appendLog(text) {
    log.hidden = false;
    var item = document.createElement('li');
    item.textContent = text;
    logList.appendChild(item);
  }

  /* Adds a visible row to the assessment's target cell. A second assignment
   * for the same student appears as its own row beside the group route,
   * because merging them would lose the answer to "why does this person have
   * this?". */
  function addTargetRow(assessmentId, label, source) {
    var cell = document.querySelector('[data-targets="' + assessmentId + '"]');
    if (!cell) { return; }
    var placeholder = cell.querySelector('.pw-muted');
    if (placeholder) { placeholder.parentNode.removeChild(placeholder); }
    var row = document.createElement('div');
    row.innerHTML = '<span class="pw-prov-source is-' + esc(source) + '">'
      + esc(source) + '</span> ' + esc(label)
      + ' <span class="pw-chip is-accent">new</span>';
    cell.appendChild(row);
  }

  // -- duplicate dialog -----------------------------------------------------

  function openDialog(payload) {
    pending = payload;
    returnFocus = document.activeElement;

    dupLead.textContent = payload.student.name + ' already receives “'
      + payload.assessment.name + '”. Assigning it again will not replace the '
      + 'route it already has.';

    dupSources.innerHTML = payload.existing_sources.map(function (source) {
      return '<li><b>' + esc(source.label) + '</b> — created '
        + esc(source.created) + ' by ' + esc(source.created_by)
        + ' (' + esc(source.assignment_id) + ')</li>';
    }).join('');

    scrim.hidden = false;
    dupConfirm.focus();
  }

  function closeDialog() {
    scrim.hidden = true;
    pending = null;
    if (returnFocus && document.contains(returnFocus)) { returnFocus.focus(); }
    returnFocus = null;
  }

  dupCancel.addEventListener('click', function () {
    status.textContent = 'Cancelled. Nothing was changed.';
    closeDialog();
  });

  dupConfirm.addEventListener('click', function () {
    var payload = pending;
    closeDialog();
    if (!payload) { return; }

    addTargetRow(payload.assessment.id, payload.student.name, 'direct');
    appendLog('“' + payload.assessment.name + '” assigned directly to '
      + payload.student.name + ' — kept separately from the existing route ('
      + payload.existing_sources.map(function (source) {
          return source.label;
        }).join('; ') + ').');
    status.textContent = payload.student.name + ' now holds '
      + (payload.existing_sources.length + 1)
      + ' separately provenanced assignments for this assessment.';
  });

  // Escape closes the dialog: it is an ordinary confirmation, not the
  // blocking learner-facing screen.
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !scrim.hidden) { closeDialog(); }
  });

  // Keep focus inside the dialog while it is open.
  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Tab' || scrim.hidden) { return; }
    var focusables = scrim.querySelectorAll('button');
    if (!focusables.length) { return; }
    var first = focusables[0];
    var last = focusables[focusables.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });

  // -- assign ---------------------------------------------------------------

  assignButton.addEventListener('click', function () {
    var assessmentId = assessmentSelect.value;
    var assessmentName = selectedText(assessmentSelect);

    if (kindSelect.value === 'group') {
      addTargetRow(assessmentId, selectedText(groupSelect), 'group');
      appendLog('“' + assessmentName + '” assigned to '
        + selectedText(groupSelect) + '.');
      status.textContent = 'Assigned to ' + selectedText(groupSelect)
        + '. Every member receives it through the group.';
      return;
    }

    var studentId = studentSelect.value;
    status.textContent = 'Checking existing assignments…';

    fetch('/prototype/api/assignment-provenance?assessment_id='
          + encodeURIComponent(assessmentId)
          + '&student_id=' + encodeURIComponent(studentId),
          { headers: { Accept: 'application/json' } })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (!data.ok) {
          status.textContent = 'Could not check: ' + (data.error || 'unknown');
          return;
        }
        if (data.duplicate) {
          status.textContent = 'This student already receives it. Confirm '
            + 'whether to assign again.';
          openDialog(data);
          return;
        }
        addTargetRow(assessmentId, data.student.name, 'direct');
        appendLog('“' + assessmentName + '” assigned directly to '
          + data.student.name + '.');
        status.textContent = 'Assigned to ' + data.student.name + '.';
      })
      .catch(function (error) {
        status.textContent = 'Could not reach the provenance check.';
        if (window.console) { window.console.error(error); }
      });
  });

  // -- create ----------------------------------------------------------------

  var createButton = qs('#pw-new-btn');
  if (createButton) {
    createButton.addEventListener('click', function () {
      var name = qs('#pw-new-name').value.trim();
      var focus = qs('#pw-new-focus').value;
      var interactions = qs('#pw-new-interactions').value;
      var target = qs('#pw-new-target').value;
      var newStatus = qs('#pw-new-status');

      if (!name) {
        newStatus.textContent = 'Give the assessment a name first.';
        qs('#pw-new-name').focus();
        return;
      }
      if (!interactions || Number(interactions) < 1) {
        newStatus.textContent = 'Required scored interactions must be at '
          + 'least 1.';
        qs('#pw-new-interactions').focus();
        return;
      }

      var id = 'as-proto-' + Date.now();
      var targetLabel = '';
      var targetSource = '';
      if (target) {
        var parts = target.split(':');
        targetSource = parts[0];
        targetLabel = qs('#pw-new-target')
          .options[qs('#pw-new-target').selectedIndex].textContent
          .replace(/^(Group|Student) — /, '').trim();
      }

      var row = document.createElement('tr');
      row.setAttribute('data-assessment-row', id);
      row.innerHTML = '<td><b>' + esc(name) + '</b>'
        + '<div class="pw-xsmall pw-muted">Created in this prototype session. '
        + 'Not persisted.</div></td>'
        + '<td><span class="pw-chip is-plain">'
        + esc(focus.charAt(0).toUpperCase() + focus.slice(1)) + '</span></td>'
        + '<td class="is-num">' + esc(interactions) + '</td>'
        + '<td class="pw-xsmall">Not scheduled</td>'
        + '<td class="pw-xsmall" data-targets="' + esc(id) + '">'
        + (targetLabel
            ? '<div><span class="pw-prov-source is-' + esc(targetSource) + '">'
              + esc(targetSource) + '</span> ' + esc(targetLabel) + '</div>'
            : '<span class="pw-muted">Not assigned</span>')
        + '</td>'
        + '<td><span class="pw-chip is-accent">Draft</span></td>';

      qs('#pw-assessment-rows').insertBefore(
        row, qs('#pw-assessment-rows').firstChild);

      // Make it assignable straight away, which is the whole point of having
      // created it.
      var option = document.createElement('option');
      option.value = id;
      option.textContent = name;
      assessmentSelect.appendChild(option);

      newStatus.textContent = '“' + name + '” created with '
        + interactions + ' required scored interactions'
        + (targetLabel ? ', assigned to ' + targetLabel : '') + '.';
    });
  }
}());
