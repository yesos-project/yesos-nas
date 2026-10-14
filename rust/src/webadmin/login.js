'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('login-form');
  const err = $('error');
  const btn = $('submit');

  function showError(msg) {
    err.textContent = msg;
  }

  fetch('/api/access', { credentials: 'same-origin' })
    .then((r) => r.json())
    .then((a) => {
      if (!a.admitted) {
        $('admit-cmd').textContent = 'nas admit ' + a.ip;
        $('admission').classList.remove('hidden');
      }
      if (a.retry_sec > 0) showError('Demasiados intentos. Espera ' + a.retry_sec + ' s.');
    })
    .catch(() => {});

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const user = $('user').value.trim();
    const pass = $('pass').value;
    if (!user || !pass) {
      showError('Escribe usuario y contraseña.');
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Verificando...';
    showError('');
    const body = new URLSearchParams({ user: user, pass: pass });
    fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
      .then((r) => r.json().then((j) => ({ status: r.status, body: j })))
      .then((res) => {
        $('pass').value = '';
        if (res.status === 200 && res.body.ok) {
          window.location.replace('/');
          return;
        }
        const e = res.body.error;
        if (e === 'not_admitted') {
          showError('Este equipo no está admitido en el NAS.');
          $('admission').classList.remove('hidden');
        } else if (e === 'not_admin') {
          showError('Esta cuenta no tiene rol de administrador.');
        } else if (e === 'throttled') {
          showError('Demasiados intentos fallidos. Espera ' + res.body.retry_sec + ' s.');
        } else if (e === 'bad_credentials') {
          showError('Usuario o contraseña incorrectos.');
        } else {
          showError('No se pudo iniciar sesión (' + (e || res.status) + ').');
        }
      })
      .catch(() => showError('El NAS no responde.'))
      .finally(() => {
        btn.disabled = false;
        btn.textContent = 'Iniciar sesión';
      });
  });
})();
