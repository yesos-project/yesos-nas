'use strict';
// YesOS NAS admin panel. Data from the kernel is inserted with textContent
// only (never innerHTML), so file and user names cannot inject markup.
(function () {
  const $ = (id) => document.getElementById(id);
  let csrf = '';
  let me = '';
  let myIp = '';
  let timer = null;
  let reload = () => {};
  let uptimeNow = 0;

  // ---------- helpers ----------
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        if (k === 'class') n.className = attrs[k];
        else if (k === 'text') n.textContent = attrs[k];
        else n.setAttribute(k, attrs[k]);
      }
    }
    for (const c of kids) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  }

  function bytes(n) {
    if (n == null) return '-';
    const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
  }

  function duration(s) {
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    if (d) return d + ' d ' + h + ' h';
    if (h) return h + ' h ' + m + ' min';
    return m + ' min ' + (s % 60) + ' s';
  }

  const badge = (text, kind) => el('span', { class: 'badge badge-' + kind, text: text });
  const yesno = (v, yes, no, bad) => v ? badge(yes, 'ok') : badge(no, bad ? 'bad' : 'warn');

  function kv(pairs) {
    const dl = el('dl', { class: 'kv' });
    for (const [k, v] of pairs) dl.append(el('dt', { text: k }), el('dd', null, v));
    return dl;
  }

  function card(title, body, extra) {
    return el('section', { class: 'card' },
      el('div', { class: 'card-head' }, el('span', { text: title }), extra || null),
      body.classList && body.classList.contains('table-wrap') ? body : el('div', { class: 'card-body' }, body));
  }

  function bar(used, total) {
    const pct = total ? Math.min(100, Math.round(100 * used / total)) : 0;
    const fill = el('span');
    fill.style.width = pct + '%';
    return el('div', null, el('div', { class: 'bar' }, fill),
      el('div', { class: 'muted', text: bytes(used) + ' of ' + bytes(total) + ' (' + pct + ' %)' }));
  }

  function table(cols, rows, emptyText) {
    if (!rows.length) return el('div', { class: 'empty', text: emptyText || 'No items.' });
    const thead = el('tr');
    for (const c of cols) thead.append(el('th', { class: c.num ? 'num' : '', text: c.title }));
    const tbody = el('tbody');
    for (const r of rows) {
      const tr = el('tr');
      for (const c of cols) {
        const v = c.get(r);
        tr.append(el('td', { class: (c.num ? 'num' : '') + (c.wrap ? ' wrap' : '') }, v instanceof Node ? v : String(v)));
      }
      tbody.append(tr);
    }
    return el('div', { class: 'table-wrap' }, el('table', null, el('thead', null, thead), tbody));
  }

  // ---------- API ----------
  function api(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    if (opts.method === 'POST') opts.headers = Object.assign({ 'X-CSRF-Token': csrf }, opts.headers || {});
    return fetch('/api/' + path, opts).then((r) => {
      if (r.status === 401) {
        window.location.replace('/login');
        throw new Error('session');
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  // ---------- actions ----------
  function toast(text, ok) {
    let box = $('toasts');
    if (!box) {
      box = el('div', { id: 'toasts', class: 'toasts', role: 'status', 'aria-live': 'polite' });
      document.body.append(box);
    }
    const t = el('div', { class: 'toast ' + (ok ? 'toast-ok' : 'toast-bad'), text: text });
    box.append(t);
    setTimeout(() => t.remove(), ok ? 4000 : 7000);
  }

  // fetch() rejects nothing for 4xx in api(); actions need the JSON body, so use fetch directly.
  function post(name, fields) {
    return fetch('/api/action/' + name, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
      body: new URLSearchParams(fields).toString(),
    }).then((r) => {
      if (r.status === 401) { window.location.replace('/login'); throw new Error('session'); }
      return r.json().catch(() => ({ ok: false, message: 'Invalid response (' + r.status + ').' }));
    }).then((j) => {
      toast(j.message || (j.ok ? 'Done.' : 'Error.'), j.ok);
      reload();
      return j.ok;
    }).catch((e) => {
      if (e.message !== 'session') toast('The NAS does not answer.', false);
      return false;
    });
  }

  function button(text, kind, onClick, disabled) {
    const b = el('button', { class: 'btn btn-sm' + (kind ? ' btn-' + kind : ''), type: 'button', text: text });
    if (disabled) b.disabled = true;
    b.addEventListener('click', onClick);
    return b;
  }

  // Modal form. spec: [{ name, label, type: text|password|select|checkbox, options, max, value, hint }]
  function dialog(title, spec, submitText, onSubmit, danger) {
    const dlg = el('dialog', { class: 'dlg' });
    const form = el('form', { method: 'dialog' });
    form.append(el('h2', { text: title }));
    const inputs = {};
    for (const f of spec) {
      if (f.type === 'text-only') { form.append(el('p', { class: 'dlg-text', text: f.label })); continue; }
      const id = 'f-' + f.name + '-' + Math.random().toString(36).slice(2, 8);
      let input;
      if (f.type === 'select') {
        input = el('select', { id: id, name: f.name });
        for (const [v, t] of f.options) {
          const o = el('option', { value: v, text: t });
          if (v === f.value) o.selected = true;
          input.append(o);
        }
      } else if (f.type === 'file') {
        input = el('input', { id: id, name: f.name, type: 'file', accept: f.accept || '' });
      } else if (f.type === 'checkbox') {
        input = el('input', { id: id, name: f.name, type: 'checkbox' });
        if (f.value) input.checked = true;
        form.append(el('label', { class: 'check', for: id }, input, ' ' + f.label));
        inputs[f.name] = input;
        continue;
      } else {
        input = el('input', { id: id, name: f.name, type: f.type || 'text', maxlength: String(f.max || 63), autocomplete: f.type === 'password' ? 'new-password' : 'off' });
        if (f.value) input.value = f.value;
        if (f.placeholder) input.placeholder = f.placeholder;
      }
      form.append(el('label', { for: id, text: f.label }), input);
      if (f.hint) form.append(el('div', { class: 'hint', text: f.hint }));
      inputs[f.name] = input;
    }
    const err = el('p', { class: 'form-error', role: 'alert' });
    const ok = el('button', { class: 'btn ' + (danger ? 'btn-danger' : 'btn-primary'), type: 'submit', text: submitText });
    const cancel = el('button', { class: 'btn', type: 'button', text: 'Cancel' });
    cancel.addEventListener('click', () => dlg.close());
    form.append(err, el('div', { class: 'dlg-actions' }, cancel, ok));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const values = {};
      for (const k in inputs) {
        const i = inputs[k];
        values[k] = i.type === 'checkbox' ? (i.checked ? 'on' : 'off') : (i.type === 'file' ? i.files[0] : i.value);
      }
      const problem = onSubmit.validate ? onSubmit.validate(values) : '';
      if (problem) { err.textContent = problem; return; }
      ok.disabled = true;
      Promise.resolve(onSubmit(values)).then((done) => {
        ok.disabled = false;
        if (done !== false) dlg.close();
      });
      for (const k in inputs) if (inputs[k].type === 'password') inputs[k].value = '';
    });
    dlg.addEventListener('close', () => dlg.remove());
    dlg.append(form);
    document.body.append(dlg);
    dlg.showModal();
    const first = form.querySelector('input,select');
    if (first) first.focus();
  }

  function confirmAction(title, text, okText, run) {
    dialog(title, [{ type: 'text-only', label: text }], okText, run, true);
  }

  const ROLES = [['admin', 'Administrator'], ['rw', 'Read and write'], ['ro', 'Read-only']];
  const roleName = (r) => (ROLES.find((x) => x[0] === r) || [r, r])[1];

  // ---------- pages ----------
  const pages = {
    overview: { title: 'Overview', api: 'overview', poll: 5000, render: renderOverview },
    disks: { title: 'Disks', api: 'storage', render: renderDisks },
    files: { title: 'File system', api: 'storage', render: renderFiles },
    shares: { title: 'Shared folders', api: 'shares', render: renderShares },
    snapshots: { title: 'Snapshots', api: 'snapshots', render: renderSnapshots },
    users: { title: 'Users', api: 'users', render: renderUsers },
    devices: { title: 'Devices', api: 'devices', poll: 5000, render: renderDevices },
    network: { title: 'Network and services', api: 'network', poll: 5000, render: renderNetwork },
    security: { title: 'Security', api: 'security', render: renderSecurity },
    log: { title: 'Activity log', api: 'audit', poll: 10000, render: renderAudit },
  };

  function vaultLockButton(v) {
    if (!v.initialized || !v.unlocked) return null;
    return button('Lock vault', 'danger', () => confirmAction('Lock the vault',
      'The vault key will be erased from the key hart. Opening it again needs the passphrase at the console (vault unlock).',
      'Lock', () => post('vault_lock', {})));
  }

  function renderOverview(d) {
    const p = d.pool || {};
    const v = d.vault || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('System', kv([
        ['Name', d.hostname],
        ['Uptime', duration(d.uptime_sec)],
        ['Harts', d.harts + ' (kernel, key hart, PMP cells)'],
        ['Memory', bytes(d.ram_bytes)],
        ['Heap in use', bytes(d.heap_used_bytes)],
        ['IP', d.ip || '-'],
      ])),
      card('Storage', p.mounted
        ? el('div', null, el('div', { class: 'big', text: bytes(p.total_bytes - p.used_bytes) + ' free' }),
            bar(p.used_bytes, p.total_bytes), el('div', { class: 'muted', text: p.files + ' files · RedSea v' + p.version }))
        : el('div', null, badge('No volume mounted', 'bad'))),
      card('Vault', kv([
        ['State', !v.initialized ? badge('Not created', 'warn') : (v.unlocked ? badge('Unlocked', 'warn') : badge('Locked', 'ok'))],
        ['Lockout after failed attempts', v.lockout_sec ? v.lockout_sec + ' s' : 'no'],
      ]), vaultLockButton(v)),
      card('Security', kv([
        ['PMP', yesno(d.pmp_proven, 'Locked, proven with Z3', 'Verified at boot only')],
        ['Integrity', d.integrity_alarm ? badge('ALARM', 'bad') : yesno(d.integrity_armed, 'Watching', 'Not armed')],
      ])),
      card('Access', kv([
        ['NAS clients', String(d.clients)],
        ['Web sessions', String(d.web_sessions)],
      ])));
    return grid;
  }

  function renderDisks(d) {
    const disks = table([
      { title: 'Device', get: (x) => x.device },
      { title: 'Model', get: (x) => x.model, wrap: true },
      { title: 'Serial', get: (x) => x.serial || '-' },
      { title: 'Capacity', get: (x) => bytes(x.bytes), num: true },
      { title: 'S.M.A.R.T.', get: (x) => badge('Not available', 'info') },
    ], d.disks, 'No disks.');
    const p = d.pool || {};
    const vol = p.mounted ? kv([
      ['Label', p.label],
      ['Format', 'RedSea v' + p.version + ' (contiguous extents, CRC64)'],
      ['Usage', bar(p.used_bytes, p.total_bytes)],
      ['Directory entries', p.dir_entries + ' of ' + p.dir_entries_max],
    ]) : badge('No volume mounted', 'bad');
    const fk = d.fsck || {};
    const fsckBody = fk.files == null ? el('p', { class: 'muted', text: 'Not checked yet.' }) : kv([
      ['Result', fk.errors ? badge(fk.errors + ' error(s)', 'bad') : badge('OK', 'ok')],
      ['Scope', fk.data_checked ? 'Structure and the data of every file (CRC)' : 'Structure only (at boot)'],
      ['Files', String(fk.files) + (fk.shared_extents ? ' · ' + fk.shared_extents + ' extents shared by snapshots' : '')],
      ...(fk.data_checked ? [['CRC', (fk.crc_ok + fk.crc_legacy) + ' good' + (fk.crc_legacy ? ' (' + fk.crc_legacy + ' with the old CRC)' : '') +
                               (fk.crc_bad ? ', ' + fk.crc_bad + ' BAD' : '') + (fk.unreadable ? ', ' + fk.unreadable + ' unreadable' : '')]] : []),
      ['Lost space', fk.lost_sectors ? bytes(fk.lost_sectors * 512) : 'none'],
      ...(fk.first_problem ? [['First problem', fk.first_problem]] : []),
      ['Duration', fk.duration_ms + ' ms'],
    ]);
    const fsckCard = card('File system check', fsckBody,
      button('Check now', 'primary', () => post('fs_check', {})));
    return el('div', null, card('Disks', disks), card('Volume', vol), fsckCard,
      el('p', { class: 'muted', text: 'virtio-blk exposes no S.M.A.R.T. data; the NAS does not make it up.' }));
  }

  function renderFiles(d) {
    const files = d.files || [];
    const box = el('div');
    const filter = el('input', { type: 'search', placeholder: 'Filter by name', 'aria-label': 'Filter' });
    const count = el('span', { class: 'muted' });
    const holder = el('div');
    function draw() {
      const q = filter.value.toLowerCase();
      const rows = files.filter((f) => f.name.toLowerCase().includes(q));
      count.textContent = rows.length + ' of ' + files.length;
      holder.replaceChildren(table([
        { title: 'Path', get: (f) => f.name, wrap: true },
        { title: 'Size', get: (f) => bytes(f.bytes), num: true },
        { title: '', get: (f) => f.encrypted ? badge('encrypted', 'ok') : (f.readonly ? badge('read-only', 'info') : '') },
      ], rows, 'No file matches.'));
    }
    filter.addEventListener('input', draw);
    draw();
    box.append(el('section', { class: 'card' },
      el('div', { class: 'card-head' }, el('span', { text: 'Files on RedSea' }), count),
      el('div', { class: 'toolbar' }, filter), holder));
    return box;
  }

  function renderShares(d) {
    const addShare = button('Add folder', 'primary', () => dialog('New shared folder', [
      { name: 'name', label: 'Name', max: 31, hint: 'Letters, digits, hyphen or underscore.' },
      { name: 'path', label: 'Path', max: 63, placeholder: '/share/photos', hint: 'Absolute, outside /SYS and /vault.' },
      { name: 'comment', label: 'Comment (optional)', max: 63 },
      { name: 'readonly', label: 'Read-only', type: 'checkbox' },
    ], 'Save', (v) => post('share_add', v)));
    const folders = table([
      { title: 'Name', get: (s) => s.name },
      { title: 'Path', get: (s) => s.path },
      { title: 'Access', get: (s) => s.readonly ? badge('read-only', 'info') : badge('read/write', 'ok') },
      { title: 'Comment', get: (s) => s.comment, wrap: true },
      { title: '', get: (s) => el('div', { class: 'row-actions' },
          button('Edit', '', () => dialog('Edit ' + s.name, [
            { name: 'path', label: 'Path', max: 63, value: s.path },
            { name: 'comment', label: 'Comment', max: 63, value: s.comment },
            { name: 'readonly', label: 'Read-only', type: 'checkbox', value: s.readonly },
          ], 'Save', (v) => post('share_add', Object.assign({ name: s.name }, v)))),
          button('Delete', 'danger', () => confirmAction('Delete folder',
            '"' + s.name + '" will no longer be published. The files are not deleted.', 'Delete',
            () => post('share_delete', { name: s.name })))) },
    ], d.shares, 'No shared folders.');
    const davBase = 'https://' + location.hostname + ':8443';
    const dav = table([
      { title: 'URL', get: (s) => davBase + s.path, wrap: true },
      { title: 'Access', get: (s) => s.access },
      { title: 'Accounts', get: (s) => s.who, wrap: true },
    ], d.webdav);
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'NAS protocol folders' }),
          el('div', { class: 'row-actions' },
            d.auth_required ? badge('account required', 'ok') : badge('no authentication', 'warn'), addShare)),
        folders),
      card('WebDAV', dav),
      el('div', { class: 'notice notice-info', text:
        'WebDAV asks for the user name and password of a NAS account and only works encrypted (HTTPS, port 8443); ' +
        'on port 8080 it is refused. Read-only accounts cannot upload, delete or create folders. ' +
        'The vault (/vault) is never exposed over WebDAV.' }));
  }

  const pwRule = (v) => (v.password.length < 8 || v.password.length > 31) ? 'The password must have 8 to 31 characters.'
    : (v.password !== v.repeat ? 'The passwords do not match.' : '');

  const openSnapshots = new Set();
  const AUTO_CHOICES = [['0', 'Off'], ['60', 'Every hour'], ['360', 'Every 6 hours'], ['720', 'Every 12 hours'],
                        ['1440', 'Every day'], ['10080', 'Every week']];

  function renderSnapshots(d) {
    const create = button('Create snapshot', 'primary', () => dialog('New snapshot', [
      { type: 'text-only', label: 'The current state of share, media and the vault (encrypted) is kept. No data is copied: ' +
        'only what changes or is deleted afterwards takes space.' },
      { name: 'comment', label: 'Note (optional)', max: 63, placeholder: 'before reorganizing photos' },
    ], 'Create', (v) => post('snapshot_create', { comment: v.comment, value: new Date().toLocaleString() })));
    const room = d.dir_entries_free >= d.entries_needed;
    const rows = d.snapshots;
    const t = table([
      { title: '#', get: (s) => s.id, num: true },
      { title: 'Type', get: (s) => s.automatic ? badge('automatic', 'info') : badge('manual', 'ok') },
      { title: 'Created', get: (s) => (s.client_time || '-') + (s.created_by ? ' · ' + s.created_by : ''), wrap: true },
      { title: 'Note', get: (s) => s.note || '', wrap: true },
      { title: 'Files', get: (s) => s.files_count, num: true },
      { title: 'Size', get: (s) => bytes(s.bytes), num: true },
      { title: 'Own space', get: (s) => bytes(s.unique_bytes), num: true },
      { title: '', get: (s) => el('div', { class: 'row-actions' },
          button(openSnapshots.has(s.id) ? 'Hide files' : 'Show files', '', () => {
            if (openSnapshots.has(s.id)) openSnapshots.delete(s.id); else openSnapshots.add(s.id);
            reload();
          }),
          button('Restore all', '', () => confirmAction('Restore snapshot ' + s.id,
            'The ' + s.files_count + ' files of this snapshot will replace their current versions. ' +
            'Files created afterwards are left alone.', 'Restore', () => post('snapshot_restore', { name: String(s.id), path: '' }))),
          button('Delete', 'danger', () => confirmAction('Delete snapshot ' + s.id,
            bytes(s.unique_bytes) + ' will be freed. This cannot be undone.', 'Delete',
            () => post('snapshot_delete', { name: String(s.id) })))) },
    ], rows, 'No snapshots yet.');
    const parts = [
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Snapshots in /backup' }), create),
        t),
    ];
    for (const sn of d.snapshots) {
      if (!openSnapshots.has(sn.id)) continue;
      parts.push(card('Files of snapshot ' + sn.id, table([
        { title: 'Original path', get: (f) => f.path, wrap: true },
        { title: 'Size', get: (f) => bytes(f.bytes), num: true },
        { title: '', get: (f) => f.encrypted ? badge('encrypted', 'ok') : '' },
        { title: '', get: (f) => button('Restore', '', () => confirmAction('Restore file',
            '"' + f.path + '" will go back to its version in snapshot ' + sn.id + '.', 'Restore',
            () => post('snapshot_restore', { name: String(sn.id), path: f.path }))) },
      ], sn.files, 'Empty snapshot.')));
    }
    const a = d.auto;
    const autoText = a.interval_minutes
      ? 'Every ' + (a.interval_minutes >= 60 ? (a.interval_minutes / 60) + ' h' : a.interval_minutes + ' min') +
        ', the last ' + a.keep + ' are kept. Next in ' + duration(a.next_in_sec) + '.'
      : 'Off.';
    parts.push(el('div', { class: 'grid' },
      card('Automatic', el('div', null,
        el('p', { text: autoText }),
        el('p', { class: 'muted', text: 'The interval counts from NAS boot (it has no wall clock). ' +
          'Manual snapshots are never deleted automatically.' })),
        button('Configure', '', () => dialog('Automatic snapshots', [
          { name: 'interval', label: 'Frequency', type: 'select', options: AUTO_CHOICES, value: String(a.interval_minutes) },
          { name: 'keep', label: 'Keep the last', max: 3, value: String(a.keep) },
        ], 'Save', (v) => post('snapshot_auto', { value: v.interval + ':' + v.keep })))),
      card('Capacity', kv([
        ['Free entries', String(d.dir_entries_free)],
        ['A new one needs', String(d.entries_needed) + (room ? '' : ' (no room)')],
        ['Includes', 'share, media, vault (encrypted); never SYS'],
        ['Browse over WebDAV', 'https://' + location.hostname + ':8443/dav/backup/'],
      ]))));
    return el('div', null, ...parts);
  }

  function renderUsers(d) {
    const add = button('Add user', 'primary', () => {
      const submit = (v) => post('user_add', { name: v.name, password: v.password, role: v.role });
      submit.validate = (v) => !/^[A-Za-z0-9._-]{1,31}$/.test(v.name) ? 'Name: 1-31 letters, digits, dot, hyphen or underscore.' : pwRule(v);
      dialog('New user', [
        { name: 'name', label: 'Name', max: 31 },
        { name: 'password', label: 'Password', type: 'password', max: 31, hint: '8 to 31 characters.' },
        { name: 'repeat', label: 'Repeat the password', type: 'password', max: 31 },
        { name: 'role', label: 'Role', type: 'select', options: ROLES, value: 'rw' },
      ], 'Create', submit);
    });
    const toggle = button(d.auth_required ? 'Allow access without an account' : 'Require an account', d.auth_required ? '' : 'primary',
      () => d.auth_required
        ? confirmAction('Turn off authentication', 'The NAS protocol will accept admitted clients without a user name or password.',
            'Turn off', () => post('auth_required', { value: 'off' }))
        : post('auth_required', { value: 'on' }));
    const t = table([
      { title: 'User', get: (u) => u.name === me ? el('span', null, u.name, ' ', badge('you', 'info')) : u.name },
      { title: 'Role', get: (u) => badge(roleName(u.role), u.role === 'admin' ? 'info' : 'ok') },
      { title: 'WebDAV', get: (u) => (u.webdav || '-') + (u.webdav_write ? '' : ' (read)'), wrap: true },
      { title: 'Failed attempts', get: (u) => u.failed_attempts, num: true },
      { title: 'State', get: (u) => u.locked ? badge('locked 30 s', 'bad') : badge('active', 'ok') },
      { title: '', get: (u) => {
          const self = u.name === me;
          return el('div', { class: 'row-actions' },
            button('Password', '', () => {
              const fields = [];
              if (self) fields.push({ name: 'current', label: 'Current password', type: 'password', max: 31 });
              fields.push({ name: 'password', label: 'New password', type: 'password', max: 31 },
                          { name: 'repeat', label: 'Repeat the new password', type: 'password', max: 31 });
              const submit = (v) => post('user_password', { name: u.name, password: v.password, current: v.current || '' });
              submit.validate = pwRule;
              dialog('Password of ' + u.name, fields, 'Change', submit);
            }),
            button('Role', '', () => dialog('Role of ' + u.name, [
              { name: 'role', label: 'Role', type: 'select', options: ROLES, value: u.role },
            ], 'Save', (v) => post('user_role', { name: u.name, role: v.role })), self),
            button('Delete', 'danger', () => confirmAction('Delete user',
              'The account "' + u.name + '" will be deleted and its sessions closed.', 'Delete',
              () => post('user_delete', { name: u.name })), self));
        } },
    ], d.users, 'No accounts.');
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'NAS accounts' }), el('div', { class: 'row-actions' }, toggle, add)),
        t),
      el('p', { class: 'muted', text: 'Passwords are stored as Argon2id with a random salt. ' +
        'NAS protocol: ' + (d.auth_required ? 'requires a user name and password.' : 'accepts admitted clients without an account.') }));
  }

  function renderDevices(d) {
    const st = { admitted: ['admitted', 'ok'], pending: ['pending', 'warn'], blocked: ['blocked', 'bad'] };
    const admitForm = (ip, name) => {
      const submit = (v) => post('device_admit', v);
      submit.validate = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v.ip) ? '' : 'Enter an IPv4 address, for example 192.168.1.20.';
      dialog('Admit device', [
        { name: 'ip', label: 'IP', max: 15, value: ip || '', placeholder: '192.168.1.20' },
        { name: 'name', label: 'Name (optional)', max: 31, value: name || '' },
      ], 'Admit', submit);
    };
    const t = table([
      { title: 'IP', get: (x) => x.ip === myIp ? el('span', null, x.ip, ' ', badge('this device', 'info')) : x.ip },
      { title: 'Name', get: (x) => x.name || '-' },
      { title: 'State', get: (x) => badge(st[x.status][0], st[x.status][1]) },
      { title: 'User', get: (x) => x.user || '-' },
      { title: 'Idle', get: (x) => duration(x.idle_sec), num: true },
      { title: 'Read', get: (x) => bytes(x.bytes_read), num: true },
      { title: 'Written', get: (x) => bytes(x.bytes_written), num: true },
      { title: '', get: (x) => el('div', { class: 'row-actions' },
          x.status !== 'admitted' ? button('Admit', 'primary', () => admitForm(x.ip, x.name)) : null,
          x.status !== 'blocked' ? button('Block', 'danger', () => confirmAction('Block device',
            x.ip + ' will not be able to use the NAS or sign in to the panel.', 'Block',
            () => post('device_block', { ip: x.ip })), x.ip === myIp) : null) },
    ], d.devices, 'No known devices yet.');
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Devices' }),
          button('Admit device', 'primary', () => admitForm('', ''))),
        t),
      el('p', { class: 'muted', text: 'Only admitted devices can use the NAS protocol and sign in to the panel. ' +
        'Admission does not survive a NAS reboot.' }));
  }

  function renderAudit(d) {
    const t = table([
      { title: 'Ago', get: (e) => duration(Math.max(0, uptimeNow - e.uptime_sec)), num: true },
      { title: 'User', get: (e) => e.user },
      { title: 'Device', get: (e) => e.ip },
      { title: 'Action', get: (e) => e.text, wrap: true },
      { title: 'Result', get: (e) => e.ok ? badge('done', 'ok') : badge('refused', 'bad') },
    ], d.entries, 'No changes made from the panel yet.');
    return el('div', null, card('Changes made from the panel', t),
      el('p', { class: 'muted', text: 'The last 64 are kept in memory (lost on reboot) and are also printed on the console.' }));
  }

  function renderNetwork(d) {
    const fw = d.firewall || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('virtio-net interface', d.present ? kv([
        ['Link', yesno(d.link_up, 'Up', 'Down', true)],
        ['MAC', d.mac], ['IPv4', d.ip], ['Netmask', d.netmask], ['Gateway', d.gateway],
      ]) : badge('No interface', 'bad')),
      card('Traffic', kv([
        ['Received', bytes(d.rx_bytes) + ' · ' + d.rx_packets + ' packets'],
        ['Sent', bytes(d.tx_bytes) + ' · ' + d.tx_packets + ' packets'],
        ['Dropped', String(d.rx_drops)],
      ])),
      card('LAN firewall', kv([
        ['State', yesno(fw.enabled, 'Active', 'Inactive', true)],
        ['Policy', fw.lan_only ? 'Private networks only (RFC 1918)' : 'Open'],
        ['Incoming WAN blocked', String(fw.wan_rx_blocked)],
        ['Outgoing WAN blocked', String(fw.wan_tx_blocked)],
        ['LAN packets accepted', String(fw.lan_accepted)],
      ])));
    const svc = table([
      { title: 'Service', get: (s) => s.name },
      { title: 'Protocol', get: (s) => s.proto.toUpperCase() },
      { title: 'Port', get: (s) => s.port, num: true },
    ], d.services);
    return el('div', null, grid, el('div', { class: 'card-gap' }), card('Services', svc));
  }

  function renderSecurity(d) {
    const v = d.vault || {};
    const i = d.integrity || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('Isolation', kv([
        ['PMP', { 'locked, Z3-proven': badge('Locked, proven with Z3', 'ok'),
                  'locked, boot-verified': badge('Locked, verified at boot', 'warn') }[d.pmp] || badge('Not configured', 'bad')],
        ['Harts with a locked PMP', String(d.pmp_harts)],
        ['PMP cells', String(d.cells)], ['Key hart', yesno(d.keyhart, 'Holding the key', 'Not available', true)],
      ])),
      card('Vault', kv([
        ['State', !v.initialized ? badge('Not created', 'warn') : (v.unlocked ? badge('Unlocked', 'warn') : badge('Locked', 'ok'))],
        ['Encryption', 'XChaCha20-Poly1305, key in vector registers of the key hart'],
      ]), vaultLockButton(v)),
      card('Integrity', kv([
        ['Image', i.image === 'matches build' ? badge('Matches the build', 'ok') : badge(i.image || '-', 'bad')],
        ['Monitor', i.alarm ? badge('ALARM', 'bad') : yesno(i.armed, 'Armed', 'Not armed')],
        ['Watched blocks', String(i.chunks) + ' × 64 KiB'],
        ['Full passes', String(i.full_passes)],
      ])),
      card('Other', kv([
        ['Hardware entropy (Zkr)', yesno(d.entropy_hw, 'Yes', 'No: weak seed', true)],
        ['Console PIN', yesno(d.console_pin, 'Set', 'Not set')],
        ['Build', d.dev_remote_build ? badge('DEV_REMOTE: unauthenticated remote commands', 'bad') : badge('Production', 'ok')],
        ['Panel transport', d.transport_encrypted ? badge('TLS 1.3', 'ok') : badge('Unencrypted', 'bad')],
      ])));
    return el('div', null, grid, el('div', { class: 'notice notice-info', text:
      'The panel only works over HTTPS: ' + (d.transport || 'TLS 1.3') + '. ' +
      'The certificate is self-signed; its SHA-256 fingerprint is shown at the console by the tls command. ' +
      'The private key is in SYS/TLS.KEY, unencrypted: anyone with the disk could impersonate the NAS.' }));
  }

  // ---------- router ----------
  function current() {
    const k = (location.hash.replace(/^#\//, '') || 'overview').split('/')[0];
    return pages[k] ? k : 'overview';
  }

  function show() {
    const key = current();
    const pg = pages[key];
    clearInterval(timer);
    timer = null;
    document.querySelectorAll('.sidebar a').forEach((a) => a.classList.toggle('active', a.dataset.page === key));
    $('sidebar').classList.remove('open');
    $('page-title').textContent = pg.title;
    document.title = pg.title + ' - YesOS NAS';
    const load = () => api(pg.api).then((d) => {
      if (current() !== key) return;
      if (d.uptime_sec != null) uptimeNow = d.uptime_sec;
      $('page').replaceChildren(pg.render(d));
      $('page-meta').textContent = 'Updated ' + new Date().toLocaleTimeString();
    }).catch((e) => {
      if (e.message !== 'session') {
        $('page').replaceChildren(el('div', { class: 'notice notice-bad', text: 'The data could not be read (' + e.message + ').' }));
      }
    });
    $('page').replaceChildren(el('div', { class: 'muted', text: 'Loading...' }));
    reload = load;
    if (key === 'log') {
      api('overview').then((o) => { uptimeNow = o.uptime_sec; load(); }).catch(() => load());
    } else {
      load();
    }
    if (pg.poll) {
      timer = setInterval(() => { if (!document.hidden) load(); }, pg.poll);
    }
  }

  $('nav-toggle').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('logout').addEventListener('click', () => {
    api('logout', { method: 'POST' }).finally(() => window.location.replace('/login'));
  });
  window.addEventListener('hashchange', show);

  fetch('/api/access', { credentials: 'same-origin' }).then((r) => r.json()).then((a) => { myIp = a.ip; }).catch(() => {});
  api('session').then((s) => {
    csrf = s.csrf;
    me = s.user;
    $('whoami').textContent = s.user;
    show();
    return api('overview');
  }).then((o) => {
    $('hostname').textContent = o.hostname || 'YesOS NAS';
  }).catch(() => {});
})();
