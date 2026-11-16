// SPDX-License-Identifier: GPL-3.0-or-later
// whereami's one script: show the lookup as it happens, send what the
// visitor says about the switch, and try IPv6. Nothing is put into the
// page as HTML - only as text.
(function () {
  'use strict';

  var byId = function (id) { return document.getElementById(id); };
  var text = function (id, value) { byId(id).textContent = value === null || value === undefined ? '' : String(value); };
  var show = function (el, on) { el.hidden = !on; };

  // ---- the lookup -------------------------------------------------------
  var lookup = byId('lookup');
  var steps = byId('steps');
  var ticket = null;

  function step(words, state) {
    var waiting = byId('waiting');
    var li = document.createElement('li');
    li.textContent = words;
    if (state) { li.className = state; }
    steps.insertBefore(li, waiting);
    return li;
  }

  function finish(failed) {
    var waiting = byId('waiting');
    if (waiting) { waiting.remove(); }
    show(byId('again'), true);
    if (failed) { show(byId('answer'), false); }
  }

  function notice(el, words, kind) {
    el.textContent = words;
    el.className = 'notice' + (kind ? ' ' + kind : '');
    show(el, true);
  }

  function said(word) {
    var el = byId('said');
    if (!word) {
      notice(el, 'Nobody has said anything about this switch yet.', '');
      return;
    }
    var words = word.confirmed ? 'Confirmed' : 'Reported as a problem';
    words += ' by ' + word.username + ', ' + word.at;
    if (word.comment) { words += ': ' + word.comment; }
    notice(el, words, word.confirmed ? 'good' : 'problem');
  }

  // the log: every message of the lookup as it came, for finding out
  // why one went wrong. The ticket is left out - it is a key, not a fact.
  var log = byId('log');
  var started = Date.now();

  function record(message) {
    if (!log) { return; }
    var shown = {};
    Object.keys(message).forEach(function (name) {
      if (name !== 'ticket') { shown[name] = message[name]; }
    });
    log.textContent += '+' + ((Date.now() - started) / 1000).toFixed(2) + 's ' + JSON.stringify(shown) + '\n';
  }

  function handle(message) {
    if (message.type === 'lease') {
      step('Your address ' + message.ip + ' has a lease for the MAC ' + message.mac + '.');
    } else if (message.type === 'relay') {
      step('Your request came through ' + message.relay + ', VLAN ' + message.vlan +
           (message.port === null ? '' : ', module ' + message.module + ' port ' + message.port) + '.');
    } else if (message.type === 'done') {
      step('Found you.');
      ticket = message.ticket;
      text('switch', message.switch);
      text('interface', message.interface);
      text('layer', message.layer);
      text('vlan', message.vlan);
      text('alias', message.alias || '(none)');
      text('ip', message.ip);
      text('mac', message.mac);
      said(message.said);
      if (message.describable) {
        text('describe-port', message.interface);
        byId('description').value = message.alias || '';
        show(byId('describe'), true);
      }
      show(byId('answer'), true);
      finish(false);
    } else if (message.type === 'error') {
      step(message.message, 'failed');
      finish(true);
    }
  }

  if (lookup && window.EventSource) {
    var source = new EventSource(lookup.dataset.stream);
    var ended = false;
    source.onmessage = function (event) {
      var message = JSON.parse(event.data);
      record(message);
      handle(message);
      if (message.type === 'done' || message.type === 'error') {
        ended = true;
        source.close();
      }
    };
    source.onerror = function () {
      // the browser would ask again by itself: one lookup is enough
      source.close();
      if (!ended) {
        record({ type: 'cut off' });
        step('The lookup was cut off. Try again.', 'failed');
        finish(true);
      }
    };
  } else if (lookup) {
    step('This browser cannot show the lookup (no EventSource).', 'failed');
    finish(true);
  }

  // ---- what the visitor says --------------------------------------------
  function send(form, url, fields, result, done) {
    var body = new URLSearchParams();
    body.set('ticket', ticket || '');
    Object.keys(fields).forEach(function (name) { body.set(name, fields[name]); });
    var buttons = form.querySelectorAll('button');
    buttons.forEach(function (b) { b.disabled = true; });
    fetch(url, { method: 'POST', body: body, credentials: 'same-origin' })
      .then(function (response) {
        return response.json().then(function (answer) { return { ok: response.ok, answer: answer }; });
      })
      .then(function (got) {
        if (got.ok) { done(got.answer); } else { notice(result, got.answer.error || 'That was refused.', 'problem'); }
      })
      .catch(function () { notice(result, 'The server did not answer. Try again.', 'problem'); })
      .then(function () { buttons.forEach(function (b) { b.disabled = false; }); });
  }

  var confirmForm = byId('confirm');
  if (confirmForm) {
    confirmForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var verdict = event.submitter && event.submitter.value === 'problem' ? 'problem' : 'ok';
      var result = byId('confirm-result');
      send(confirmForm, lookup.dataset.confirm,
           { verdict: verdict, comment: byId('comment').value }, result,
           function (answer) {
             said(answer.said);
             notice(result, verdict === 'ok' ? 'Saved: ' + answer.switch + ' is confirmed.'
                                             : 'Saved: the problem with ' + answer.switch + ' is noted.', 'good');
           });
    });
  }

  var describeForm = byId('describe');
  if (describeForm) {
    describeForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var result = byId('describe-result');
      send(describeForm, lookup.dataset.describe,
           { description: byId('description').value }, result,
           function (answer) {
             text('alias', answer.description || '(none)');
             byId('description').value = answer.description;
             notice(result, 'The switch now says: ' + (answer.description || '(nothing)'), 'good');
           });
    });
  }

  // ---- IPv6 ---------------------------------------------------------------
  // Each address answers with the caller's address (JSON {"ip": ...} or
  // plain text). Reaching it at all is the test; the address is shown
  // when it looks like one.
  var looksLikeV6 = /^[0-9a-fA-F:.]{2,45}$/;

  function tryV6(id, url, words) {
    var li = byId(id);
    if (!li || !url) { return; }
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 6000);
    fetch(url, { cache: 'no-store', credentials: 'omit', signal: controller.signal })
      .then(function (response) { return response.text(); })
      .then(function (body) {
        var ip = body.trim();
        try { ip = String(JSON.parse(body).ip || ''); } catch (e) { /* plain text */ }
        li.className = '';
        li.textContent = words + ' works' + (looksLikeV6.test(ip) && ip.indexOf(':') !== -1 ? ' - you are ' + ip : '') + '.';
      })
      .catch(function () {
        li.className = 'failed';
        li.textContent = words + ' does NOT work.';
      })
      .then(function () { clearTimeout(timer); });
  }

  var v6 = byId('ipv6');
  if (v6) {
    tryV6('ipv6-own', v6.dataset.own, 'IPv6 to this server');
    tryV6('ipv6-outside', v6.dataset.outside, 'IPv6 to the internet');
  }
}());
