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
      el('div', { class: 'muted', text: bytes(used) + ' de ' + bytes(total) + ' (' + pct + ' %)' }));
  }

  function table(cols, rows, emptyText) {
    if (!rows.length) return el('div', { class: 'empty', text: emptyText || 'Sin elementos.' });
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
      return r.json().catch(() => ({ ok: false, message: 'Respuesta no válida (' + r.status + ').' }));
    }).then((j) => {
      toast(j.message || (j.ok ? 'Hecho.' : 'Error.'), j.ok);
      reload();
      return j.ok;
    }).catch((e) => {
      if (e.message !== 'session') toast('El NAS no responde.', false);
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
    const cancel = el('button', { class: 'btn', type: 'button', text: 'Cancelar' });
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

  const ROLES = [['admin', 'Administrador'], ['rw', 'Lectura y escritura'], ['ro', 'Solo lectura']];
  const roleName = (r) => (ROLES.find((x) => x[0] === r) || [r, r])[1];

  // ---------- pages ----------
  const pages = {
    panel: { title: 'Panel', api: 'overview', poll: 5000, render: renderOverview },
    discos: { title: 'Discos', api: 'storage', render: renderDisks },
    archivos: { title: 'Sistema de archivos', api: 'storage', render: renderFiles },
    compartidas: { title: 'Carpetas compartidas', api: 'shares', render: renderShares },
    instantaneas: { title: 'Instantáneas', api: 'snapshots', render: renderSnapshots },
    usuarios: { title: 'Usuarios', api: 'users', render: renderUsers },
    dispositivos: { title: 'Dispositivos', api: 'devices', poll: 5000, render: renderDevices },
    red: { title: 'Red y servicios', api: 'network', poll: 5000, render: renderNetwork },
    seguridad: { title: 'Seguridad', api: 'security', render: renderSecurity },
    registro: { title: 'Registro de actividad', api: 'audit', poll: 10000, render: renderAudit },
  };

  function vaultLockButton(v) {
    if (!v.initialized || !v.unlocked) return null;
    return button('Bloquear bóveda', 'danger', () => confirmAction('Bloquear la bóveda',
      'La clave de la bóveda se borrará del key hart. Para volver a abrirla hará falta la frase de paso en la consola (vault unlock).',
      'Bloquear', () => post('vault_lock', {})));
  }

  function renderOverview(d) {
    const p = d.pool || {};
    const v = d.vault || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('Sistema', kv([
        ['Nombre', d.hostname],
        ['Encendido', duration(d.uptime_sec)],
        ['Harts', d.harts + ' (kernel, key hart, celdas PMP)'],
        ['Memoria', bytes(d.ram_bytes)],
        ['Heap en uso', bytes(d.heap_used_bytes)],
        ['IP', d.ip || '-'],
      ])),
      card('Almacenamiento', p.mounted
        ? el('div', null, el('div', { class: 'big', text: bytes(p.total_bytes - p.used_bytes) + ' libres' }),
            bar(p.used_bytes, p.total_bytes), el('div', { class: 'muted', text: p.files + ' archivos · RedSea v' + p.version }))
        : el('div', null, badge('Sin volumen montado', 'bad'))),
      card('Bóveda', kv([
        ['Estado', !v.initialized ? badge('No creada', 'warn') : (v.unlocked ? badge('Desbloqueada', 'warn') : badge('Bloqueada', 'ok'))],
        ['Bloqueo por intentos', v.lockout_sec ? v.lockout_sec + ' s' : 'no'],
      ]), vaultLockButton(v)),
      card('Seguridad', kv([
        ['PMP', yesno(d.pmp_proven, 'Bloqueado, probado con Z3', 'Solo verificado al arrancar')],
        ['Integridad', d.integrity_alarm ? badge('ALARMA', 'bad') : yesno(d.integrity_armed, 'Vigilando', 'No armada')],
      ])),
      card('Acceso', kv([
        ['Clientes NAS', String(d.clients)],
        ['Sesiones web', String(d.web_sessions)],
      ])));
    return grid;
  }

  function renderDisks(d) {
    const disks = table([
      { title: 'Dispositivo', get: (x) => x.device },
      { title: 'Modelo', get: (x) => x.model, wrap: true },
      { title: 'Serie', get: (x) => x.serial || '-' },
      { title: 'Capacidad', get: (x) => bytes(x.bytes), num: true },
      { title: 'S.M.A.R.T.', get: (x) => badge('No disponible', 'info') },
    ], d.disks, 'No hay discos.');
    const p = d.pool || {};
    const vol = p.mounted ? kv([
      ['Etiqueta', p.label],
      ['Formato', 'RedSea v' + p.version + ' (extensiones contiguas, CRC64)'],
      ['Uso', bar(p.used_bytes, p.total_bytes)],
      ['Entradas de directorio', p.dir_entries + ' de ' + p.dir_entries_max],
    ]) : badge('Sin volumen montado', 'bad');
    const fk = d.fsck || {};
    const fsckBody = fk.files == null ? el('p', { class: 'muted', text: 'Todavía no se ha comprobado.' }) : kv([
      ['Resultado', fk.errors ? badge(fk.errors + ' error(es)', 'bad') : badge('Correcto', 'ok')],
      ['Alcance', fk.data_checked ? 'Estructura y datos de cada archivo (CRC)' : 'Solo estructura (al arrancar)'],
      ['Archivos', String(fk.files) + (fk.shared_extents ? ' · ' + fk.shared_extents + ' extensiones compartidas por instantáneas' : '')],
      ...(fk.data_checked ? [['CRC', (fk.crc_ok + fk.crc_legacy) + ' correctos' + (fk.crc_legacy ? ' (' + fk.crc_legacy + ' con CRC antiguo)' : '') +
                               (fk.crc_bad ? ', ' + fk.crc_bad + ' MAL' : '') + (fk.unreadable ? ', ' + fk.unreadable + ' ilegibles' : '')]] : []),
      ['Espacio perdido', fk.lost_sectors ? bytes(fk.lost_sectors * 512) : 'ninguno'],
      ...(fk.first_problem ? [['Primer problema', fk.first_problem]] : []),
      ['Duración', fk.duration_ms + ' ms'],
    ]);
    const fsckCard = card('Comprobación del sistema de archivos', fsckBody,
      button('Comprobar ahora', 'primary', () => post('fs_check', {})));
    return el('div', null, card('Discos', disks), card('Volumen', vol), fsckCard,
      el('p', { class: 'muted', text: 'virtio-blk no expone datos S.M.A.R.T.; el NAS no los inventa.' }));
  }

  function renderFiles(d) {
    const files = d.files || [];
    const box = el('div');
    const filter = el('input', { type: 'search', placeholder: 'Filtrar por nombre', 'aria-label': 'Filtrar' });
    const count = el('span', { class: 'muted' });
    const holder = el('div');
    function draw() {
      const q = filter.value.toLowerCase();
      const rows = files.filter((f) => f.name.toLowerCase().includes(q));
      count.textContent = rows.length + ' de ' + files.length;
      holder.replaceChildren(table([
        { title: 'Ruta', get: (f) => f.name, wrap: true },
        { title: 'Tamaño', get: (f) => bytes(f.bytes), num: true },
        { title: '', get: (f) => f.encrypted ? badge('cifrado', 'ok') : (f.readonly ? badge('solo lectura', 'info') : '') },
      ], rows, 'Ningún archivo coincide.'));
    }
    filter.addEventListener('input', draw);
    draw();
    box.append(el('section', { class: 'card' },
      el('div', { class: 'card-head' }, el('span', { text: 'Archivos en RedSea' }), count),
      el('div', { class: 'toolbar' }, filter), holder));
    return box;
  }

  function renderShares(d) {
    const addShare = button('Añadir carpeta', 'primary', () => dialog('Nueva carpeta compartida', [
      { name: 'name', label: 'Nombre', max: 31, hint: 'Letras, números, guion o guion bajo.' },
      { name: 'path', label: 'Ruta', max: 63, placeholder: '/share/fotos', hint: 'Absoluta, fuera de /SYS y /vault.' },
      { name: 'comment', label: 'Comentario (opcional)', max: 63 },
      { name: 'readonly', label: 'Solo lectura', type: 'checkbox' },
    ], 'Guardar', (v) => post('share_add', v)));
    const smb = table([
      { title: 'Nombre', get: (s) => s.name },
      { title: 'Ruta', get: (s) => s.path },
      { title: 'Acceso', get: (s) => s.readonly ? badge('solo lectura', 'info') : badge('lectura/escritura', 'ok') },
      { title: 'Comentario', get: (s) => s.comment, wrap: true },
      { title: '', get: (s) => el('div', { class: 'row-actions' },
          button('Editar', '', () => dialog('Editar ' + s.name, [
            { name: 'path', label: 'Ruta', max: 63, value: s.path },
            { name: 'comment', label: 'Comentario', max: 63, value: s.comment },
            { name: 'readonly', label: 'Solo lectura', type: 'checkbox', value: s.readonly },
          ], 'Guardar', (v) => post('share_add', Object.assign({ name: s.name }, v)))),
          button('Eliminar', 'danger', () => confirmAction('Eliminar carpeta',
            'Se dejará de publicar "' + s.name + '". Los archivos no se borran.', 'Eliminar',
            () => post('share_delete', { name: s.name })))) },
    ], d.shares, 'No hay carpetas compartidas.');
    const davBase = 'https://' + location.hostname + ':8443';
    const dav = table([
      { title: 'URL', get: (s) => davBase + s.path, wrap: true },
      { title: 'Acceso', get: (s) => s.access },
      { title: 'Cuentas', get: (s) => s.who, wrap: true },
    ], d.webdav);
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Carpetas del protocolo NAS' }),
          el('div', { class: 'row-actions' },
            d.auth_required ? badge('requiere usuario', 'ok') : badge('sin autenticación', 'warn'), addShare)),
        smb),
      card('WebDAV', dav),
      el('div', { class: 'notice notice-info', text:
        'WebDAV pide usuario y contraseña de una cuenta del NAS y solo funciona cifrado (HTTPS, puerto 8443); ' +
        'por el puerto 8080 se rechaza. Las cuentas de solo lectura no pueden subir, borrar ni crear carpetas. ' +
        'La bóveda (/vault) nunca se expone por WebDAV.' }));
  }

  const pwRule = (v) => (v.password.length < 8 || v.password.length > 31) ? 'La contraseña debe tener entre 8 y 31 caracteres.'
    : (v.password !== v.repeat ? 'Las contraseñas no coinciden.' : '');

  const openSnapshots = new Set();
  const AUTO_CHOICES = [['0', 'Desactivadas'], ['60', 'Cada hora'], ['360', 'Cada 6 horas'], ['720', 'Cada 12 horas'],
                        ['1440', 'Cada día'], ['10080', 'Cada semana']];

  function renderSnapshots(d) {
    const create = button('Crear instantánea', 'primary', () => dialog('Nueva instantánea', [
      { type: 'text-only', label: 'Se guardará el estado actual de share, media y la bóveda (cifrada). No se copian datos: ' +
        'solo ocupa espacio lo que cambie o se borre después.' },
      { name: 'comment', label: 'Nota (opcional)', max: 63, placeholder: 'antes de reorganizar fotos' },
    ], 'Crear', (v) => post('snapshot_create', { comment: v.comment, value: new Date().toLocaleString() })));
    const room = d.dir_entries_free >= d.entries_needed;
    const rows = d.snapshots;
    const t = table([
      { title: '#', get: (s) => s.id, num: true },
      { title: 'Tipo', get: (s) => s.automatic ? badge('automática', 'info') : badge('manual', 'ok') },
      { title: 'Creada', get: (s) => (s.client_time || '-') + (s.created_by ? ' · ' + s.created_by : ''), wrap: true },
      { title: 'Nota', get: (s) => s.note || '', wrap: true },
      { title: 'Archivos', get: (s) => s.files_count, num: true },
      { title: 'Tamaño', get: (s) => bytes(s.bytes), num: true },
      { title: 'Espacio propio', get: (s) => bytes(s.unique_bytes), num: true },
      { title: '', get: (s) => el('div', { class: 'row-actions' },
          button(openSnapshots.has(s.id) ? 'Ocultar archivos' : 'Ver archivos', '', () => {
            if (openSnapshots.has(s.id)) openSnapshots.delete(s.id); else openSnapshots.add(s.id);
            reload();
          }),
          button('Restaurar todo', '', () => confirmAction('Restaurar la instantánea ' + s.id,
            'Los ' + s.files_count + ' archivos de esta instantánea sustituirán a sus versiones actuales. ' +
            'Los archivos creados después no se tocan.', 'Restaurar', () => post('snapshot_restore', { name: String(s.id), path: '' }))),
          button('Eliminar', 'danger', () => confirmAction('Eliminar la instantánea ' + s.id,
            'Se liberarán ' + bytes(s.unique_bytes) + '. Esta acción no se puede deshacer.', 'Eliminar',
            () => post('snapshot_delete', { name: String(s.id) })))) },
    ], rows, 'Todavía no hay instantáneas.');
    const parts = [
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Instantáneas en /backup' }), create),
        t),
    ];
    for (const sn of d.snapshots) {
      if (!openSnapshots.has(sn.id)) continue;
      parts.push(card('Archivos de la instantánea ' + sn.id, table([
        { title: 'Ruta original', get: (f) => f.path, wrap: true },
        { title: 'Tamaño', get: (f) => bytes(f.bytes), num: true },
        { title: '', get: (f) => f.encrypted ? badge('cifrado', 'ok') : '' },
        { title: '', get: (f) => button('Restaurar', '', () => confirmAction('Restaurar archivo',
            '"' + f.path + '" volverá a la versión de la instantánea ' + sn.id + '.', 'Restaurar',
            () => post('snapshot_restore', { name: String(sn.id), path: f.path }))) },
      ], sn.files, 'Instantánea vacía.')));
    }
    const a = d.auto;
    const autoText = a.interval_minutes
      ? 'Cada ' + (a.interval_minutes >= 60 ? (a.interval_minutes / 60) + ' h' : a.interval_minutes + ' min') +
        ', se conservan las últimas ' + a.keep + '. Próxima en ' + duration(a.next_in_sec) + '.'
      : 'Desactivadas.';
    parts.push(el('div', { class: 'grid' },
      card('Automáticas', el('div', null,
        el('p', { text: autoText }),
        el('p', { class: 'muted', text: 'El intervalo cuenta desde que arranca el NAS (no tiene reloj de pared). ' +
          'Las instantáneas manuales nunca se borran solas.' })),
        button('Configurar', '', () => dialog('Instantáneas automáticas', [
          { name: 'interval', label: 'Frecuencia', type: 'select', options: AUTO_CHOICES, value: String(a.interval_minutes) },
          { name: 'keep', label: 'Conservar las últimas', max: 3, value: String(a.keep) },
        ], 'Guardar', (v) => post('snapshot_auto', { value: v.interval + ':' + v.keep })))),
      card('Capacidad', kv([
        ['Entradas libres', String(d.dir_entries_free)],
        ['Necesita una nueva', String(d.entries_needed) + (room ? '' : ' (no cabe)')],
        ['Incluye', 'share, media, vault (cifrada); nunca SYS'],
        ['Ver por WebDAV', 'https://' + location.hostname + ':8443/dav/backup/'],
      ]))));
    return el('div', null, ...parts);
  }

  function renderUsers(d) {
    const add = button('Añadir usuario', 'primary', () => {
      const submit = (v) => post('user_add', { name: v.name, password: v.password, role: v.role });
      submit.validate = (v) => !/^[A-Za-z0-9._-]{1,31}$/.test(v.name) ? 'Nombre: 1-31 letras, números, punto, guion o guion bajo.' : pwRule(v);
      dialog('Nuevo usuario', [
        { name: 'name', label: 'Nombre', max: 31 },
        { name: 'password', label: 'Contraseña', type: 'password', max: 31, hint: 'Entre 8 y 31 caracteres.' },
        { name: 'repeat', label: 'Repite la contraseña', type: 'password', max: 31 },
        { name: 'role', label: 'Rol', type: 'select', options: ROLES, value: 'rw' },
      ], 'Crear', submit);
    });
    const toggle = button(d.auth_required ? 'Permitir acceso sin usuario' : 'Exigir usuario', d.auth_required ? '' : 'primary',
      () => d.auth_required
        ? confirmAction('Desactivar la autenticación', 'El protocolo NAS aceptará clientes admitidos sin usuario ni contraseña.',
            'Desactivar', () => post('auth_required', { value: 'off' }))
        : post('auth_required', { value: 'on' }));
    const t = table([
      { title: 'Usuario', get: (u) => u.name === me ? el('span', null, u.name, ' ', badge('tú', 'info')) : u.name },
      { title: 'Rol', get: (u) => badge(roleName(u.role), u.role === 'admin' ? 'info' : 'ok') },
      { title: 'WebDAV', get: (u) => (u.webdav || '-') + (u.webdav_write ? '' : ' (lectura)'), wrap: true },
      { title: 'Intentos fallidos', get: (u) => u.failed_attempts, num: true },
      { title: 'Estado', get: (u) => u.locked ? badge('bloqueado 30 s', 'bad') : badge('activo', 'ok') },
      { title: '', get: (u) => {
          const self = u.name === me;
          return el('div', { class: 'row-actions' },
            button('Contraseña', '', () => {
              const fields = [];
              if (self) fields.push({ name: 'current', label: 'Contraseña actual', type: 'password', max: 31 });
              fields.push({ name: 'password', label: 'Nueva contraseña', type: 'password', max: 31 },
                          { name: 'repeat', label: 'Repite la nueva contraseña', type: 'password', max: 31 });
              const submit = (v) => post('user_password', { name: u.name, password: v.password, current: v.current || '' });
              submit.validate = pwRule;
              dialog('Contraseña de ' + u.name, fields, 'Cambiar', submit);
            }),
            button('Rol', '', () => dialog('Rol de ' + u.name, [
              { name: 'role', label: 'Rol', type: 'select', options: ROLES, value: u.role },
            ], 'Guardar', (v) => post('user_role', { name: u.name, role: v.role })), self),
            button('Eliminar', 'danger', () => confirmAction('Eliminar usuario',
              'Se borrará la cuenta "' + u.name + '" y se cerrarán sus sesiones.', 'Eliminar',
              () => post('user_delete', { name: u.name })), self));
        } },
    ], d.users, 'No hay cuentas.');
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Cuentas del NAS' }), el('div', { class: 'row-actions' }, toggle, add)),
        t),
      el('p', { class: 'muted', text: 'Contraseñas guardadas como Argon2id con sal aleatoria. ' +
        'Protocolo NAS: ' + (d.auth_required ? 'exige usuario y contraseña.' : 'acepta clientes admitidos sin usuario.') }));
  }

  function renderDevices(d) {
    const st = { admitted: ['admitido', 'ok'], pending: ['pendiente', 'warn'], blocked: ['bloqueado', 'bad'] };
    const admitForm = (ip, name) => {
      const submit = (v) => post('device_admit', v);
      submit.validate = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v.ip) ? '' : 'Escribe una IPv4, por ejemplo 192.168.1.20.';
      dialog('Admitir dispositivo', [
        { name: 'ip', label: 'IP', max: 15, value: ip || '', placeholder: '192.168.1.20' },
        { name: 'name', label: 'Nombre (opcional)', max: 31, value: name || '' },
      ], 'Admitir', submit);
    };
    const t = table([
      { title: 'IP', get: (x) => x.ip === myIp ? el('span', null, x.ip, ' ', badge('este equipo', 'info')) : x.ip },
      { title: 'Nombre', get: (x) => x.name || '-' },
      { title: 'Estado', get: (x) => badge(st[x.status][0], st[x.status][1]) },
      { title: 'Usuario', get: (x) => x.user || '-' },
      { title: 'Inactivo', get: (x) => duration(x.idle_sec), num: true },
      { title: 'Leído', get: (x) => bytes(x.bytes_read), num: true },
      { title: 'Escrito', get: (x) => bytes(x.bytes_written), num: true },
      { title: '', get: (x) => el('div', { class: 'row-actions' },
          x.status !== 'admitted' ? button('Admitir', 'primary', () => admitForm(x.ip, x.name)) : null,
          x.status !== 'blocked' ? button('Bloquear', 'danger', () => confirmAction('Bloquear dispositivo',
            x.ip + ' no podrá usar el NAS ni iniciar sesión en el panel.', 'Bloquear',
            () => post('device_block', { ip: x.ip })), x.ip === myIp) : null) },
    ], d.devices, 'Ningún dispositivo conocido todavía.');
    return el('div', null,
      el('section', { class: 'card' },
        el('div', { class: 'card-head' }, el('span', { text: 'Dispositivos' }),
          button('Admitir dispositivo', 'primary', () => admitForm('', ''))),
        t),
      el('p', { class: 'muted', text: 'Solo los dispositivos admitidos pueden usar el protocolo NAS y entrar al panel. ' +
        'La admisión no persiste tras reiniciar el NAS.' }));
  }

  function renderAudit(d) {
    const t = table([
      { title: 'Hace', get: (e) => duration(Math.max(0, uptimeNow - e.uptime_sec)), num: true },
      { title: 'Usuario', get: (e) => e.user },
      { title: 'Equipo', get: (e) => e.ip },
      { title: 'Acción', get: (e) => e.text, wrap: true },
      { title: 'Resultado', get: (e) => e.ok ? badge('hecho', 'ok') : badge('rechazado', 'bad') },
    ], d.entries, 'Todavía no hay cambios hechos desde el panel.');
    return el('div', null, card('Cambios hechos desde el panel', t),
      el('p', { class: 'muted', text: 'Se guardan los últimos 64 en memoria (se pierden al reiniciar) y también se imprimen en la consola.' }));
  }

  function renderNetwork(d) {
    const fw = d.firewall || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('Interfaz virtio-net', d.present ? kv([
        ['Enlace', yesno(d.link_up, 'Activo', 'Caído', true)],
        ['MAC', d.mac], ['IPv4', d.ip], ['Máscara', d.netmask], ['Puerta de enlace', d.gateway],
      ]) : badge('Sin interfaz', 'bad')),
      card('Tráfico', kv([
        ['Recibido', bytes(d.rx_bytes) + ' · ' + d.rx_packets + ' paquetes'],
        ['Enviado', bytes(d.tx_bytes) + ' · ' + d.tx_packets + ' paquetes'],
        ['Descartados', String(d.rx_drops)],
      ])),
      card('Cortafuegos LAN', kv([
        ['Estado', yesno(fw.enabled, 'Activo', 'Inactivo', true)],
        ['Política', fw.lan_only ? 'Solo redes privadas (RFC 1918)' : 'Abierta'],
        ['WAN entrante bloqueado', String(fw.wan_rx_blocked)],
        ['WAN saliente bloqueado', String(fw.wan_tx_blocked)],
        ['Paquetes LAN aceptados', String(fw.lan_accepted)],
      ])));
    const svc = table([
      { title: 'Servicio', get: (s) => s.name },
      { title: 'Protocolo', get: (s) => s.proto.toUpperCase() },
      { title: 'Puerto', get: (s) => s.port, num: true },
    ], d.services);
    return el('div', null, grid, el('div', { class: 'card-gap' }), card('Servicios', svc));
  }

  function renderSecurity(d) {
    const v = d.vault || {};
    const i = d.integrity || {};
    const grid = el('div', { class: 'grid' });
    grid.append(
      card('Aislamiento', kv([
        ['PMP', { 'locked, Z3-proven': badge('Bloqueado, probado con Z3', 'ok'),
                  'locked, boot-verified': badge('Bloqueado, verificado al arrancar', 'warn') }[d.pmp] || badge('Sin configurar', 'bad')],
        ['Harts con PMP bloqueado', String(d.pmp_harts)],
        ['Celdas PMP', String(d.cells)], ['Key hart', yesno(d.keyhart, 'Custodiando la clave', 'No disponible', true)],
      ])),
      card('Bóveda', kv([
        ['Estado', !v.initialized ? badge('No creada', 'warn') : (v.unlocked ? badge('Desbloqueada', 'warn') : badge('Bloqueada', 'ok'))],
        ['Cifrado', 'XChaCha20-Poly1305, clave en registros vectoriales del key hart'],
      ]), vaultLockButton(v)),
      card('Integridad', kv([
        ['Imagen', i.image === 'matches build' ? badge('Coincide con la compilación', 'ok') : badge(i.image || '-', 'bad')],
        ['Monitor', i.alarm ? badge('ALARMA', 'bad') : yesno(i.armed, 'Armado', 'No armado')],
        ['Bloques vigilados', String(i.chunks) + ' × 64 KiB'],
        ['Pasadas completas', String(i.full_passes)],
      ])),
      card('Otros', kv([
        ['Entropía por hardware (Zkr)', yesno(d.entropy_hw, 'Sí', 'No: semilla débil', true)],
        ['PIN de consola', yesno(d.console_pin, 'Configurado', 'Sin configurar')],
        ['Compilación', d.dev_remote_build ? badge('DEV_REMOTE: comandos remotos sin autenticar', 'bad') : badge('Producción', 'ok')],
        ['Transporte del panel', d.transport_encrypted ? badge('TLS 1.3', 'ok') : badge('Sin cifrar', 'bad')],
      ])));
    return el('div', null, grid, el('div', { class: 'notice notice-info', text:
      'El panel solo funciona por HTTPS: ' + (d.transport || 'TLS 1.3') + '. ' +
      'El certificado es autofirmado; su huella SHA-256 se ve en la consola con el comando tls. ' +
      'La clave privada está en SYS/TLS.KEY sin cifrar: quien tenga el disco podría suplantar al NAS.' }));
  }

  // ---------- router ----------
  function current() {
    const k = (location.hash.replace(/^#\//, '') || 'panel').split('/')[0];
    return pages[k] ? k : 'panel';
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
      $('page-meta').textContent = 'Actualizado ' + new Date().toLocaleTimeString();
    }).catch((e) => {
      if (e.message !== 'session') {
        $('page').replaceChildren(el('div', { class: 'notice notice-bad', text: 'No se pudieron leer los datos (' + e.message + ').' }));
      }
    });
    $('page').replaceChildren(el('div', { class: 'muted', text: 'Cargando...' }));
    reload = load;
    if (key === 'registro') {
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
