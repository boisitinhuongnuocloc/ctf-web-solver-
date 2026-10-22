'use strict';

/* ---------- helpers ---------- */

const $ = (sel) => document.querySelector(sel);

/* Interface strings. The active locale maps English source text to the
   translation; anything not translated falls through unchanged. */
let STRINGS = {};
const T = (s) => (STRINGS.ui && STRINGS.ui[s]) || s;

function el(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') node.className = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid.nodeType ? kid : String(kid));
  }
  return node;
}

async function api(method, path, opts) {
  const o = opts || {};
  const init = { method, headers: {}, credentials: 'same-origin' };
  if (o.json) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(o.json);
  }
  if (o.form) init.body = o.form;
  const res = await fetch('/api' + path, init);
  const type = res.headers.get('content-type') || '';
  let data;
  if (type.includes('json')) data = await res.json().catch(() => null);
  else data = await res.text();
  return { status: res.status, ok: res.ok, data };
}

/* What the operator is told when a request does not succeed. The response
   itself is unchanged; the console simply does not print it. */
function trouble(status) {
  if (status === 400) return T('Check the values entered and try again.');
  if (status === 401) return T('Your session has ended. Please sign in again.');
  if (status === 403) return T('You do not have permission to do that.');
  if (status === 404) return T('Nothing matching was found.');
  if (status === 409) return T('That conflicts with an existing record.');
  if (status === 413) return T('That file is larger than the service accepts.');
  if (status === 429) return T('Too many requests. Please wait a moment.');
  return T('The service could not complete that request.');
}

function note(box, text, kind) {
  box.replaceChildren(el('p', { class: 'note ' + (kind || '') }, text));
}

function kv(pairs) {
  return el('dl', { class: 'kv' },
    pairs.filter((p) => p[1] !== undefined && p[1] !== null && p[1] !== '')
      .map(([k, v]) => [el('dt', {}, T(k)), el('dd', {}, String(v))]));
}

function field(spec) {
  const [name, label, kind, extra] = spec;
  let input;
  if (kind === 'select') {
    input = el('select', { name }, extra.map((o) => el('option', { value: o }, o)));
  } else if (kind === 'textarea') {
    input = el('textarea', { name, placeholder: extra || '' });
  } else if (kind === 'file') {
    input = el('input', { name, type: 'file' });
  } else if (kind === 'check') {
    input = el('input', { name, type: 'checkbox' });
  } else {
    input = el('input', { name, type: kind || 'text', placeholder: extra || '' });
  }
  return el('label', {}, T(label), input);
}

function readFields(wrap, specs) {
  const out = {};
  for (const [name, , kind] of specs) {
    const node = wrap.querySelector(`[name="${name}"]`);
    if (!node) continue;
    if (kind === 'file') out[name] = node.files[0] || null;
    else if (kind === 'check') out[name] = node.checked;
    else if (kind === 'number') out[name] = node.value === '' ? undefined : Number(node.value);
    else out[name] = node.value;
  }
  return out;
}

/* A panel: heading, short description, inputs, a button, and a rendered
   result. `done` draws the outcome; without one the operator just gets a
   confirmation line. */
function panel(title, hint, specs, run, buttonLabel, done) {
  const box = el('div', { class: 'result' });
  const wrap = el('div', { class: 'row' }, specs.map(field));
  const go = el('button', {
    onclick: async () => {
      go.disabled = true;
      box.replaceChildren(el('p', { class: 'note' }, T('Working') + '…'));
      try {
        const r = await run(readFields(wrap, specs), box);
        if (r === undefined) { box.replaceChildren(); return; }
        if (!r.ok) { note(box, trouble(r.status), 'err'); return; }
        if (done) done(r.data, box);
        else note(box, T('Done.'), 'ok');
      } catch (e) {
        note(box, T('The console could not send that request.'), 'err');
      } finally {
        go.disabled = false;
      }
    },
  }, T(buttonLabel || 'Run'));
  wrap.append(go);
  return el('section', { class: 'card' },
    el('h2', {}, T(title)),
    hint ? el('p', { class: 'muted' }, T(hint)) : null,
    wrap, box);
}

function table(cols, rows, onPick) {
  if (!rows || !rows.length) return el('p', { class: 'muted' }, T('Nothing to show.'));
  return el('table', {},
    el('thead', {}, el('tr', {}, cols.map((c) => el('th', {}, T(c))))),
    el('tbody', {}, rows.map((r) => el('tr', {
      class: onPick ? 'sel' : '',
      onclick: onPick ? () => onPick(r) : undefined,
    }, cols.map((c) => el('td', {}, r[c] === null || r[c] === undefined ? '' : String(r[c])))))));
}

function listing(load, cols, onPick) {
  const card = el('section', { class: 'card' });
  const draw = async () => {
    card.replaceChildren(el('p', { class: 'muted' }, T('Loading') + '…'));
    const r = await load();
    card.replaceChildren(r.ok
      ? table(cols, (r.data && r.data.items) || [], onPick)
      : el('p', { class: 'note err' }, trouble(r.status)));
  };
  return { card, draw };
}

/* ---------- session ---------- */

const state = { user: null, org: null, view: 'tickets', sub: 0, ticket: null };

async function boot() {
  const who = await api('GET', '/auth/whoami');
  if (who.status === 200) {
    state.user = who.data.user;
    state.org = who.data.org;
    enterApp();
  } else {
    $('#login').hidden = false;
  }
}

$('#login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const r = await api('POST', '/auth/login', {
    json: { org: f.org.value, email: f.email.value, pin: f.pin.value },
  });
  if (r.status !== 200) {
    $('#login-error').textContent = r.status === 401
      ? T('Those sign-in details were not accepted.')
      : trouble(r.status);
    return;
  }
  state.user = r.data.user;
  state.org = r.data.org;
  enterApp();
});

$('#logout').addEventListener('click', async () => {
  await api('POST', '/auth/logout');
  location.reload();
});

const SECTIONS = [
  ['tickets', 'Tickets', renderTickets],
  ['exports', 'Exports', renderExports],
  ['reports', 'Reports', renderReports],
  ['macros', 'Macros', renderMacros],
  ['imports', 'Imports', renderImports],
  ['webhooks', 'Webhooks', renderWebhooks],
  ['integrations', 'Integrations', renderIntegrations],
  ['notifications', 'Notifications', renderNotifications],
  ['profile', 'Profile', renderProfile],
  ['admin', 'Administration', renderAdmin],
];

function enterApp() {
  $('#login').hidden = true;
  $('#shell').hidden = false;
  $('#org-name').textContent = state.org.name;
  $('#user-name').textContent = state.user.name;

  const lang = $('#lang');
  for (const code of ['en', 'de', 'fr', 'ar']) lang.append(el('option', { value: code }, code));
  lang.addEventListener('change', async () => {
    const r = await api('GET', '/i18n/' + encodeURIComponent(lang.value));
    STRINGS = r.status === 200 && r.data && typeof r.data === 'object' ? r.data : {};
    document.documentElement.lang = lang.value;
    document.documentElement.dir = lang.value === 'ar' ? 'rtl' : 'ltr';
    repaint();
  });

  api('GET', '/avatars/placeholder').then((r) => {
    const seed = encodeURIComponent(state.user.email);
    const img = $('#avatar');
    img.src = `https://picsum.photos/seed/${seed}/52`;
    if (r.status === 200) img.style.background = r.data.color;
  });

  const nav = $('#nav');
  for (const [key, label] of SECTIONS) {
    nav.append(el('a', { 'data-key': key, onclick: () => go(key) }, T(label)));
  }
  go('tickets');

  /* load the default locale so the console uses display names, not column names */
  api('GET', '/i18n/en').then((r) => {
    if (r.status === 200 && r.data && typeof r.data === 'object') { STRINGS = r.data; repaint(); }
  });
}

/* Re-label the chrome and redraw the current section in the active language. */
function repaint() {
  $('#logout').textContent = T('Sign out');
  $('#lang').title = T('Interface language');
  const nav = $('#nav');
  for (const [key, label] of SECTIONS) {
    const a = nav.querySelector(`[data-key="${key}"]`);
    if (a) a.textContent = T(label);
  }
  go(state.view);
}

/* A section is a set of screens, not one long scroll. */
function tabs(view, title, items) {
  view.append(el('h1', {}, T(title)));
  const bar = el('nav', { class: 'tabs' });
  const body = el('div', {});
  view.append(bar, body);
  const pick = (i) => {
    state.sub = i;
    [...bar.children].forEach((a, n) => a.classList.toggle('on', n === i));
    body.replaceChildren();
    items[i][1](body);
    /* the first card repeats the tab it sits under; drop the duplicate heading */
    const dedupe = () => {
      const h = body.querySelector('.card > h2');
      if (h && h.textContent === T(items[i][0])) h.remove();
    };
    dedupe();
    setTimeout(dedupe, 250);
  };
  items.forEach(([label], i) => bar.append(el('a', { onclick: () => pick(i) }, T(label))));
  pick(Math.min(state.sub || 0, items.length - 1));
}

function go(key) {
  if (state.view !== key) state.sub = 0;
  state.view = key;
  for (const a of $('#nav').children) a.classList.toggle('on', a.dataset.key === key);
  const section = SECTIONS.find((s) => s[0] === key);
  const view = $('#view');
  view.replaceChildren();
  section[2](view);
}

/* ---------- tickets ---------- */

const STATUSES = ['open', 'pending', 'solved', 'closed'];
const PRIORITIES = ['low', 'normal', 'high', 'urgent'];

function renderTickets(view) {
  tabs(view, 'Tickets', [
    ['Queue', (b) => ticketQueue(b, view)],
    ['New ticket', (b) => b.append(newTicketPanel(null))],
  ]);
}

async function ticketQueue(view, root) {
  const list = el('section', { class: 'card' });
  view.append(list);

  const filters = el('div', { class: 'row' },
    field(['status', 'Status', 'select', [''].concat(STATUSES)]),
    field(['limit', 'Per page', 'number']),
    field(['offset', 'Offset', 'number']));
  filters.append(el('button', { class: 'sec', onclick: () => load() }, T('Refresh')));

  async function load() {
    const f = readFields(filters, [['status'], ['limit', '', 'number'], ['offset', '', 'number']]);
    const q = new URLSearchParams();
    if (f.status) q.set('status', f.status);
    if (f.limit) q.set('limit', f.limit);
    if (f.offset) q.set('offset', f.offset);
    const r = await api('GET', '/tickets?' + q);
    list.replaceChildren(
      el('h2', {}, T('Queue')),
      filters,
      r.ok ? table(['id', 'subject', 'status', 'priority', 'created_at'], r.data.items,
                   (row) => openTicket(root || view, row.id))
           : el('p', { class: 'note err' }, trouble(r.status)));
  }
  await load();
}

function newTicketPanel(onDone) {
  return panel('New ticket', 'Open a new case in the queue.', [
    ['subject', 'Subject', 'text'],
    ['priority', 'Priority', 'select', PRIORITIES],
    ['body', 'Description', 'textarea'],
  ], async (v) => {
    const r = await api('POST', '/tickets', { json: v });
    if (r.ok && onDone) onDone();
    return r;
  }, 'Create', (d, box) => note(box, T('Case opened') + ' #' + d.id + '.', 'ok'));
}

async function openTicket(view, id) {
  const r = await api('GET', '/tickets/' + id);
  if (!r.ok) {
    view.replaceChildren(el('p', { class: 'note err' }, trouble(r.status)));
    return;
  }
  const t = r.data;
  view.replaceChildren();

  view.append(el('p', {}, el('button', { class: 'sec', onclick: () => go('tickets') },
    '← ' + T('Back to queue'))));

  const saved = state.sub;
  state.sub = 0;
  tabs(view, `#${t.id} · ${t.subject}`, [
    ['Details', (b) => ticketDetails(b, t)],
    ['Conversation', (b) => ticketConversation(b, t)],
    ['Attachments', (b) => ticketAttachments(b, t)],
    ['Support PIN', (b) => ticketPin(b, t)],
    ['Export', (b) => ticketExport(b, t)],
  ]);
  state.sub = saved;
}

function ticketDetails(view, t) {
  view.append(el('section', { class: 'card' },
    el('h2', {}, T('Details')),
    el('p', { class: 'body-text' }, t.body || el('span', { class: 'muted' }, T('No description.'))),
    kv([['status', T(t.status)], ['priority', T(t.priority)], ['channel', t.channel],
        ['created_at', t.created_at], ['updated_at', t.updated_at]]),
    el('p', {}, (t.tags || []).map((tag) => el('span', { class: 'tag' }, tag)))));

  view.append(panel('Update ticket', 'Change the status, priority or owner of this case.', [
    ['status', 'Status', 'select', STATUSES],
    ['priority', 'Priority', 'select', PRIORITIES],
    ['assignee_id', 'Assignee ID', 'number'],
  ], (v) => api('PATCH', '/tickets/' + t.id, { json: v }), 'Save',
     (_d, box) => note(box, T('Changes saved.'), 'ok')));

  view.append(panel('Add tag', 'Label this case so it can be grouped in reports.', [
    ['tag', 'Tag', 'text', 'registry'],
  ], (v) => api('POST', `/tickets/${t.id}/tags`, { json: v }), 'Add',
     (_d, box) => note(box, T('Tag added.'), 'ok')));
}

function ticketConversation(view, t) {
  const thread = el('div', {});
  view.append(el('section', { class: 'card' }, el('h2', {}, T('Conversation')), thread));

  async function load() {
    const c = await api('GET', `/tickets/${t.id}/comments`);
    const items = c.ok ? c.data.items : [];
    thread.replaceChildren(...(items.length ? items.map((row) =>
      el('div', { class: 'cmt' + (row.is_private ? ' priv' : '') },
        el('div', { class: 'meta' },
          `${row.author_name || T('Staff')} · ${row.created_at}` +
          (row.is_private ? ' · ' + T('internal note') : '')),
        el('div', { html: row.body_html || '' })))
      : [el('p', { class: 'muted' }, T('No messages yet.'))]));
  }
  load();

  view.append(panel('Reply', 'Reply to the requester, or leave a note only staff can see.', [
    ['body', 'Message', 'textarea'],
    ['is_private', 'Internal note', 'check'],
  ], async (v) => {
    const res = await api('POST', `/tickets/${t.id}/comments`, { json: v });
    if (res.ok) load();
    return res;
  }, 'Post', (_d, box) => note(box, T('Reply posted.'), 'ok')));
}

function ticketAttachments(view, t) {
  view.append(panel('Attach a file', 'Attach a scan or a screenshot to this case.', [
    ['file', 'File', 'file'],
    ['caption', 'Caption', 'text', 'Scanned deed, page 1'],
  ], (v) => {
    if (!v.file) { throw new Error('no file'); }
    const fd = new FormData();
    fd.append('caption', v.caption);
    fd.append('file', v.file, v.file.name);
    return api('POST', `/tickets/${t.id}/attachments`, { form: fd });
  }, 'Upload', (_d, box) => note(box, T('File attached.'), 'ok')));

  view.append(panel('Attachment details', 'Look up a stored file by its filename.', [
    ['file', 'Stored filename', 'text'],
    ['workspace', 'Workspace', 'text', state.org.slug],
  ], (v) => api('GET', '/attachments/details?' + new URLSearchParams({
    file: v.file, workspace: v.workspace || state.org.slug,
  })), 'Look up', (d, box) => box.replaceChildren(
    kv([['filename', d.filename], ['content_type', d.content_type], ['byte_size', d.byte_size]]))));
}

function ticketPin(view, t) {
  view.append(panel('Issue support PIN', 'Issue a one-time code to read out to a caller.', [],
    () => api('POST', `/tickets/${t.id}/support-pin`), 'Issue', (d, box) => box.replaceChildren(
      el('p', { class: 'pin' }, d.pin),
      el('p', { class: 'muted' }, T('Read this code to the caller to verify their identity.')))));

  view.append(panel('Verify support PIN', 'Check a code the caller has read back to you.', [
    ['pin', 'PIN', 'text'],
  ], (v) => api('POST', `/tickets/${t.id}/support-pin/verify`, { json: v }), 'Verify',
     (d, box) => note(box, d && d.valid ? T('Code accepted.') : T('That code is not valid.'),
                      d && d.valid ? 'ok' : 'err')));
}

function ticketExport(view, t) {
  view.append(panel('Export', 'Queue a certified copy of this case for rendering.', [
    ['title', 'Document title', 'text', t.subject],
    ['page_size', 'Page size', 'select', ['A4', 'LETTER', 'A5', 'LEGAL']],
  ], (v) => api('POST', `/tickets/${t.id}/export`, { json: v }), 'Queue PDF',
     (d, box) => box.replaceChildren(
       el('p', { class: 'note ok' }, T('Document queued.')),
       kv([['id', d.id], ['state', d.state]]))));

  view.append(el('section', { class: 'card' },
    el('h2', {}, T('Download PDF')),
    el('p', { class: 'muted' }, T('The most recent rendered copy of this case.')),
    el('p', {}, el('a', { href: `/api/tickets/${t.id}/export.pdf?page_size=A4` },
      T('Download rendered document')))));
}

/* ---------- other sections ---------- */

function renderExports(view) {
  tabs(view, 'Exports', [['Recent documents', async (b) => {
    const l = listing(() => api('GET', '/exports'),
      ['id', 'ticket_id', 'title', 'state', 'created_at']);
    b.append(l.card); await l.draw();
  }]]);
}

function renderReports(view) {
  tabs(view, 'Reports', [
    ['Ticket volume', (b) => b.append(panel('Ticket volume', 'Cases opened per day.', [
      ['sort', 'Sort', 'text', 'day DESC'],
    ], (v) => api('GET', '/reports/volume?' + new URLSearchParams(v.sort ? { sort: v.sort } : {})),
       'Load', (d, box) => box.replaceChildren(table(['day', 'opened'], d.items || d.rows || []))))],
    ['SLA policies', (b) => b.append(panel('SLA policies', 'Response targets by priority.', [],
      () => api('GET', '/reports/sla'), 'Load',
      (d, box) => box.replaceChildren(
        table(['priority', 'first_reply_mins', 'resolve_mins'], d.items || []))))],
    ['CSV downloads', (b) => b.append(el('section', { class: 'card' },
      el('h2', {}, T('CSV downloads')),
      el('p', { class: 'muted' }, T('Download the current figures as spreadsheets.')),
      el('p', {},
        el('a', { href: '/api/reports/volume.csv' }, 'volume.csv'), ' · ',
        el('a', { href: '/api/reports/agents.csv' }, 'agents.csv'))))],
  ]);
}

function renderMacros(view) {
  tabs(view, 'Macros', [
    ['Saved macros', async (b) => {
      const r = await api('GET', '/macros');
      b.append(el('section', { class: 'card' },
        el('h2', {}, T('Saved macros')),
        r.ok ? table(['id', 'name', 'template_id', 'created_at'], r.data.items)
             : el('p', { class: 'note err' }, trouble(r.status))));
    }],
    ['Create macro', async (b) => {
      const r = await api('GET', '/macros');
      b.append(panel('Create macro', 'Save a reusable reply template.', [
        ['name', 'Name', 'text'],
        ['template_id', 'Template', 'select', r.ok ? r.data.templates : []],
      ], (v) => api('POST', '/macros', { json: v }), 'Create',
         (_d, box) => note(box, T('Template saved.'), 'ok')));
    }],
    ['Suggested macros', (b) => b.append(panel('Suggested macros',
      'Templates suggested for the current queue.', [],
      () => api('GET', '/macros/suggested'), 'Suggest',
      (d, box) => box.replaceChildren(el('ul', {}, (d.items || []).map((m) =>
        el('li', {}, m.name || m.template_id || String(m)))))))],
    ['Preview macro', (b) => b.append(panel('Preview macro',
      'See how a template reads before sending it.', [
      ['id', 'Macro ID', 'number'],
      ['ticket_id', 'Ticket ID', 'number'],
      ['team', 'Team', 'text', 'counter'],
      ['detail', 'Detail', 'text'],
    ], (v) => api('POST', `/macros/${v.id}/preview`, {
      json: { ticket_id: v.ticket_id, team: v.team, detail: v.detail },
    }), 'Preview', (d, box) => box.replaceChildren(
      el('div', { class: 'preview body-text' }, d.body || ''))))],
  ]);
}

function renderImports(view) {
  tabs(view, 'Imports', [
    ['Import tickets from CSV', (b) => b.append(panel('Import tickets from CSV',
      'Bulk load cases from a spreadsheet export.', [
      ['file', 'CSV file', 'file'],
      ['delimiter', 'Delimiter', 'select', [',', ';', '|', '\t']],
    ], (v) => {
      if (!v.file) { throw new Error('no file'); }
      const fd = new FormData();
      fd.append('delimiter', v.delimiter);
      fd.append('file', v.file, v.file.name);
      return api('POST', '/imports/tickets', { form: fd });
    }, 'Import', (d, box) => note(box,
      T('Imported') + ' ' + (d.imported !== undefined ? d.imported : '') + ' ' + T('records.'), 'ok')))],
    ['Import knowledge base', (b) => b.append(panel('Import knowledge base',
      'Load knowledge base articles from a zip archive.', [
      ['file', 'Zip archive of .md articles', 'file'],
    ], (v) => {
      if (!v.file) { throw new Error('no file'); }
      const fd = new FormData();
      fd.append('file', v.file, v.file.name);
      return api('POST', '/imports/kb', { form: fd });
    }, 'Import', (d, box) => note(box,
      T('Imported') + ' ' + (d.imported !== undefined ? d.imported : '') + ' ' + T('articles.'), 'ok')))],
  ]);
}

function renderWebhooks(view) {
  const l = listing(() => api('GET', '/webhooks'), ['id', 'url', 'event', 'active', 'created_at']);
  tabs(view, 'Webhooks', [
    ['Endpoints', async (b) => { b.append(l.card); await l.draw(); }],
    ['Register endpoint', (b) => b.append(panel('Register endpoint',
      'Notify another system when cases change.', [
      ['url', 'Delivery URL', 'text', 'https://example.com/hooks/tessera'],
      ['event', 'Event', 'select', ['ticket.created', 'ticket.updated', 'ticket.solved', 'comment.created']],
    ], (v) => api('POST', '/webhooks', { json: v }), 'Register', (d, box) => box.replaceChildren(
      el('p', { class: 'note ok' }, T('Endpoint registered.')),
      el('p', { class: 'muted' }, T('Verification request sent.') + ' ' +
        (d.verification && d.verification.status
          ? T('The endpoint answered with status') + ' ' + d.verification.status + '.'
          : T('The endpoint did not answer.'))))))],
    ['Send test delivery', (b) => b.append(panel('Send test delivery',
      'Send a sample delivery to check the endpoint.', [
      ['id', 'Webhook ID', 'number'],
    ], (v) => api('POST', `/webhooks/${v.id}/test`), 'Send',
       (_d, box) => note(box, T('Test delivery sent.'), 'ok')))],
    ['Delete endpoint', (b) => b.append(panel('Delete endpoint',
      'Stop sending deliveries to an endpoint.', [
      ['id', 'Webhook ID', 'number'],
    ], (v) => api('DELETE', `/webhooks/${v.id}`), 'Delete',
       (_d, box) => note(box, T('Endpoint removed.'), 'ok')))],
  ]);
}

function renderIntegrations(view) {
  const l = listing(() => api('GET', '/integrations'), ['id', 'provider', 'enabled', 'created_at']);
  tabs(view, 'Integrations', [
    ['Connected systems', async (b) => { b.append(l.card); await l.draw(); }],
    ['Connect provider', (b) => b.append(panel('Connect provider',
      'Connect an external system to this workspace.', [
      ['provider', 'Provider', 'select', ['crm', 'pager', 'chat']],
      ['account', 'Account', 'text'],
      ['region', 'Region', 'text'],
      ['queue', 'Queue', 'text'],
    ], (v) => api('POST', '/integrations', {
      json: { provider: v.provider, config: { account: v.account, region: v.region, queue: v.queue } },
    }), 'Connect', (_d, box) => note(box, T('Provider connected.'), 'ok')))],
    ['Push ticket to CRM', (b) => b.append(panel('Push ticket to CRM',
      'Copy a case into the registry CRM.', [
      ['ticketId', 'Ticket ID', 'number'],
      ['title', 'Title override', 'text'],
    ], (v) => api('POST', `/integrations/crm/push/${v.ticketId}`, { json: { title: v.title } }),
       'Push', (_d, box) => note(box, T('Sent to the CRM.'), 'ok')))],
  ]);
}

function renderNotifications(view) {
  const l = listing(() => api('GET', '/notifications'),
    ['id', 'kind', 'payload', 'read_at', 'created_at']);
  tabs(view, 'Notifications', [
    ['Inbox', async (b) => { b.append(l.card); await l.draw(); }],
    ['Open notification', (b) => b.append(panel('Open notification',
      'Open a single notification.', [
      ['id', 'Notification ID', 'number'],
    ], (v) => api('GET', '/notifications/' + v.id), 'Open',
       (d, box) => box.replaceChildren(kv([['kind', d.kind], ['created_at', d.created_at],
         ['payload', typeof d.payload === 'string' ? d.payload : JSON.stringify(d.payload)]]))))],
    ['Mark as read', (b) => b.append(panel('Mark as read',
      'Clear a notification from the inbox.', [
      ['id', 'Notification ID', 'number'],
    ], (v) => api('POST', `/notifications/${v.id}/read`), 'Mark read',
       (_d, box) => note(box, T('Marked as read.'), 'ok')))],
  ]);
}

function renderProfile(view) {
  tabs(view, 'Profile', [
    ['Signed in as', (b) => b.append(el('section', { class: 'card' },
      el('h2', {}, T('Signed in as')),
      kv([['Name', state.user.name], ['Email', state.user.email], ['role', T(state.user.role)],
          ['Workspace', state.org.name]]),
      el('img', { class: 'thumb', alt: '',
        src: `https://picsum.photos/seed/${encodeURIComponent(state.user.email)}/180` })))],
    ['Upload avatar', (b) => b.append(panel('Upload avatar', 'Upload a badge photograph.', [
      ['file', 'Image', 'file'],
    ], (v) => {
      if (!v.file) { throw new Error('no file'); }
      const fd = new FormData();
      fd.append('file', v.file, v.file.name);
      return api('POST', '/avatars', { form: fd });
    }, 'Upload', (_d, box) => note(box, T('Photograph updated.'), 'ok')))],
    ['Placeholder colour', (b) => b.append(panel('Placeholder colour',
      'The colour shown until a photograph is uploaded.', [],
      () => api('GET', '/avatars/placeholder'), 'Load', (d, box) => box.replaceChildren(
        el('span', { class: 'swatch', style: `background:${d.color}` }),
        el('span', { class: 'muted' }, ' ' + d.color))))],
  ]);
}

function renderAdmin(view) {
  const cols = { users: ['id', 'name', 'email', 'role'], rules: ['id', 'name', 'position'],
                 tokens: ['id', 'name', 'prefix', 'revoked'], invites: ['id', 'email', 'created_at'] };
  tabs(view, 'Administration', [
    ['Workspace', (b) => {
      b.append(el('p', { class: 'muted' }, T('These controls require the admin role.')));
      b.append(panel('Workspace settings', 'Current workspace configuration.', [],
        () => api('GET', '/admin/org'), 'Load', (d, box) => box.replaceChildren(
          kv([['Name', d.name], ['slug', d.slug], ['Plan', d.plan], ['created_at', d.created_at]]))));
      b.append(panel('Update workspace', 'Rename the workspace or change its plan.', [
        ['name', 'Name', 'text'],
        ['plan', 'Plan', 'select', ['standard', 'pro', 'enterprise']],
      ], (v) => api('PATCH', '/admin/org', { json: v }), 'Save',
         (_d, box) => note(box, T('Changes saved.'), 'ok')));
    }],
    ['Members', (b) => b.append(panel('Members', 'Staff accounts in this workspace.', [],
      () => api('GET', '/admin/users'), 'Load',
      (d, box) => box.replaceChildren(table(cols.users, d.items || []))))],
    ['Automation rules', (b) => {
      b.append(panel('Automation rules', 'Rules applied automatically to incoming cases.', [],
        () => api('GET', '/admin/rules'), 'Load',
        (d, box) => box.replaceChildren(table(cols.rules, d.items || []))));
      b.append(panel('Create rule', 'Add a rule that updates cases automatically.', [
        ['name', 'Name', 'text'],
        ['match_field', 'When field', 'select', ['status', 'priority', 'channel']],
        ['match_value', 'Equals', 'text'],
        ['set_field', 'Set field', 'select', ['status', 'priority']],
        ['set_value', 'To', 'text'],
        ['position', 'Position', 'number'],
      ], (v) => api('POST', '/admin/rules', { json: v }), 'Create',
         (_d, box) => note(box, T('Rule created.'), 'ok')));
      b.append(panel('Delete rule', 'Remove an automation rule.', [
        ['id', 'Rule ID', 'number'],
      ], (v) => api('DELETE', '/admin/rules/' + v.id), 'Delete',
         (_d, box) => note(box, T('Rule removed.'), 'ok')));
    }],
    ['API tokens', (b) => {
      b.append(panel('API tokens', 'Tokens issued for machine access.', [],
        () => api('GET', '/admin/tokens'), 'Load',
        (d, box) => box.replaceChildren(table(cols.tokens, d.items || []))));
      b.append(panel('Issue token', 'Issue a token for machine access.', [
        ['name', 'Label', 'text'],
      ], (v) => api('POST', '/admin/tokens', { json: v }), 'Issue', (d, box) => box.replaceChildren(
        el('p', { class: 'note ok' }, T('Token issued. It is shown once.')),
        el('p', { class: 'pin' }, d.token || ''))));
      b.append(panel('Revoke token', 'Withdraw a token immediately.', [
        ['id', 'Token ID', 'number'],
      ], (v) => api('POST', `/admin/tokens/${v.id}/revoke`), 'Revoke',
         (_d, box) => note(box, T('Token withdrawn.'), 'ok')));
    }],
    ['Invitations', (b) => {
      b.append(panel('Invitations', 'Outstanding invitations.', [],
        () => api('GET', '/admin/invites'), 'Load',
        (d, box) => box.replaceChildren(table(cols.invites, d.items || []))));
      b.append(panel('Invite teammate', 'Invite a colleague to this workspace.', [
        ['email', 'Email', 'text'],
      ], (v) => api('POST', '/admin/invites', { json: v }), 'Invite',
         (_d, box) => note(box, T('Invitation sent.'), 'ok')));
    }],
    ['Single sign-on', (b) => b.append(el('section', { class: 'card' },
      el('h2', {}, T('Single sign-on')),
      el('p', { class: 'muted' }, T('Return to the identity provider to finish signing in.')),
      el('p', {}, el('a', { href: '/api/admin/sso/continue?next=/' }, T('Resume SSO sign-in')))))],
  ]);
}

boot();
