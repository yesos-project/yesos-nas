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
      if (a.retry_sec > 0) showError('Too many attempts. Wait ' + a.retry_sec + ' s.');
    })
    .catch(() => {});

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const user = $('user').value.trim();
    const pass = $('pass').value;
    if (!user || !pass) {
      showError('Enter your user name and password.');
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Checking...';
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
          showError('This device is not admitted on the NAS.');
          $('admission').classList.remove('hidden');
        } else if (e === 'not_admin') {
          showError('This account does not have the admin role.');
        } else if (e === 'throttled') {
          showError('Too many failed attempts. Wait ' + res.body.retry_sec + ' s.');
        } else if (e === 'bad_credentials') {
          showError('Wrong user name or password.');
        } else {
          showError('Could not log in (' + (e || res.status) + ').');
        }
      })
      .catch(() => showError('The NAS does not answer.'))
      .finally(() => {
        btn.disabled = false;
        btn.textContent = 'Log in';
      });
  });
})();
