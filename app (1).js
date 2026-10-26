/* =====================================================================
   app.js  -  SecureGate application logic
   1. Identification   : unique usernames
   2. Authentication   : password (salt + pepper) THEN TOTP code (2FA)
   3. Authorization    : role-based access control (RBAC), enforced in code
   4. Security/access  : lockout, session timeout, replay protection, audit log
   All user-supplied text is written with textContent (never innerHTML) to
   prevent cross-site scripting.
   ===================================================================== */
(() => {
  'use strict';

  const { CONFIG, b64, b32encode, randomBytes, hashPassword, timingSafeEqual, verifyTotp } = SGCrypto;

  /* ------------------------------------------------------------------ */
  /* RBAC: roles -> permissions                                          */
  /* ------------------------------------------------------------------ */
  const ROLES = {
    admin:  { label: 'Administrator', perms: ['content:read', 'content:write', 'users:manage', 'audit:view'] },
    editor: { label: 'Editor',        perms: ['content:read', 'content:write'] },
    user:   { label: 'Standard user', perms: ['content:read'] }
  };

  /* ------------------------------------------------------------------ */
  /* Small helpers                                                       */
  /* ------------------------------------------------------------------ */
  const $ = (id) => document.getElementById(id);
  const now = () => Date.now();
  const normUser = (s) => String(s || '').trim().toLowerCase();
  const USER_RE = /^[a-z0-9_]{3,20}$/;
  const DUMMY_SALT = randomBytes(CONFIG.SALT_BYTES); // used so unknown users cost the same time

  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids) if (kid != null) n.append(kid);
    return n;
  }

  const store = {
    get(key, fallback) {
      try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
      catch { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem(key, JSON.stringify(value)); return true; }
      catch { return false; }
    }
  };
  const getUsers = () => store.get('sg_users', {});
  const saveUsers = (u) => store.set('sg_users', u);

  const sess = {
    get() { try { return JSON.parse(sessionStorage.getItem('sg_session')); } catch { return null; } },
    set(v) { try { sessionStorage.setItem('sg_session', JSON.stringify(v)); } catch { /* ignore */ } },
    clear() { try { sessionStorage.removeItem('sg_session'); } catch { /* ignore */ } }
  };

  /* ------------------------------------------------------------------ */
  /* Audit log                                                           */
  /* ------------------------------------------------------------------ */
  function audit(event, username, detail = '', level = '') {
    const log = store.get('sg_audit', []);
    log.unshift({ t: now(), event, user: username || '-', detail, level });
    store.set('sg_audit', log.slice(0, 200));
  }

  /* ------------------------------------------------------------------ */
  /* View + notice handling                                              */
  /* ------------------------------------------------------------------ */
  const VIEWS = ['view-login', 'view-2fa', 'view-register', 'view-enroll', 'view-dashboard'];
  function show(id) {
    for (const v of VIEWS) $(v).classList.toggle('hidden', v !== id);
    window.scrollTo(0, 0);
  }

  let noticeTimer;
  function notice(text, kind = '') {
    const n = $('notice');
    n.textContent = text;
    n.className = 'notice ' + kind;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => n.classList.add('hidden'), 7000);
  }
  const clearNotice = () => $('notice').classList.add('hidden');

  function setError(id, text) {
    const p = $(id);
    p.textContent = text || '';
    p.classList.toggle('hidden', !text);
  }

  function busy(btn, on, label) {
    btn.disabled = on;
    if (label) btn.textContent = on ? 'Please wait...' : label;
  }

  /* ------------------------------------------------------------------ */
  /* Password policy                                                     */
  /* ------------------------------------------------------------------ */
  const COMMON = ['password', 'passw0rd', '12345678', '123456789', 'qwertyuiop', 'letmein123', 'welcome123', 'admin1234'];
  const RULES = [
    { text: 'At least 10 characters', test: (p) => p.length >= 10 },
    { text: 'An uppercase letter',    test: (p) => /[A-Z]/.test(p) },
    { text: 'A lowercase letter',     test: (p) => /[a-z]/.test(p) },
    { text: 'A number',               test: (p) => /\d/.test(p) },
    { text: 'A symbol (e.g. ! @ # $)', test: (p) => /[^A-Za-z0-9]/.test(p) }
  ];
  function policyProblems(pass, username) {
    const bad = RULES.filter((r) => !r.test(pass)).map((r) => r.text);
    const low = pass.toLowerCase();
    if (COMMON.some((c) => low.includes(c))) bad.push('Not a commonly used password');
    if (username && username.length >= 3 && low.includes(username)) bad.push('Must not contain your username');
    return bad;
  }
  function renderRules() {
    const p = $('reg-pass').value;
    const ul = $('pw-rules');
    ul.replaceChildren(...RULES.map((r) => el('li', { class: r.test(p) ? 'pass' : '', text: r.text })));
  }

  /* ------------------------------------------------------------------ */
  /* Lockout helpers                                                     */
  /* ------------------------------------------------------------------ */
  const isLocked = (u) => u.lockUntil && u.lockUntil > now();
  const minsLeft = (u) => Math.max(1, Math.ceil((u.lockUntil - now()) / 60000));

  function registerFailure(users, user, reason) {
    user.failed = (user.failed || 0) + 1;
    audit('LOGIN_FAILED', user.username, reason, 'fail');
    if (user.failed >= CONFIG.MAX_ATTEMPTS) {
      user.failed = 0;
      user.lockUntil = now() + CONFIG.LOCK_MS;
      audit('ACCOUNT_LOCKED', user.username, `${CONFIG.MAX_ATTEMPTS} failed attempts`, 'fail');
    }
    saveUsers(users);
  }

  /* ------------------------------------------------------------------ */
  /* REGISTRATION (identification + enrolment)                           */
  /* ------------------------------------------------------------------ */
  let regPending = null; // kept in memory only until 2FA is confirmed

  async function onRegister(e) {
    e.preventDefault();
    setError('reg-error', '');
    const username = normUser($('reg-user').value);
    const pass = $('reg-pass').value;
    const pass2 = $('reg-pass2').value;

    if (!USER_RE.test(username)) return setError('reg-error', 'Username must be 3-20 characters: letters, numbers or underscore.');
    const problems = policyProblems(pass, username);
    if (problems.length) return setError('reg-error', 'Password still needs: ' + problems.join('; ') + '.');
    if (pass !== pass2) return setError('reg-error', 'The two passwords do not match.');

    const users = getUsers();
    if (users[username]) return setError('reg-error', 'That username is already taken.');

    const btn = $('reg-btn');
    busy(btn, true, 'Create account');
    try {
      const salt = randomBytes(CONFIG.SALT_BYTES);           // unique salt per user
      const hash = await hashPassword(pass, salt);           // salt + pepper + PBKDF2
      const secret = b32encode(randomBytes(20));             // 160-bit TOTP secret
      regPending = {
        username,
        salt: b64.enc(salt),
        hash: b64.enc(hash),
        totpSecret: secret,
        // First account ever created becomes the administrator; everyone else is a standard user.
        role: Object.keys(users).length === 0 ? 'admin' : 'user'
      };
      $('enroll-user').textContent = username;
      $('enroll-secret').textContent = secret.match(/.{1,4}/g).join(' ');
      $('enroll-code').value = '';
      setError('enroll-error', '');
      $('reg-pass').value = $('reg-pass2').value = '';
      renderRules();
      show('view-enroll');
      $('enroll-code').focus();
    } finally {
      busy(btn, false, 'Create account');
    }
  }

  async function onEnroll(e) {
    e.preventDefault();
    setError('enroll-error', '');
    if (!regPending) return show('view-register');
    const btn = $('enroll-btn');
    busy(btn, true, 'Confirm and finish');
    try {
      const step = await verifyTotp(regPending.totpSecret, $('enroll-code').value.trim(), 0);
      if (step === null) return setError('enroll-error', 'That code is not correct. Check the key and your phone clock, then try again.');

      const users = getUsers();
      if (users[regPending.username]) { regPending = null; return show('view-register'); }
      users[regPending.username] = {
        username: regPending.username,
        salt: regPending.salt,
        hash: regPending.hash,
        totpSecret: regPending.totpSecret,
        lastStep: step,            // this code can never be used again
        role: regPending.role,
        failed: 0,
        lockUntil: 0,
        created: now(),
        lastLogin: null
      };
      saveUsers(users);
      audit('REGISTERED', regPending.username, `role=${regPending.role}, 2FA enabled`, 'ok');
      const name = regPending.username;
      regPending = null;
      $('login-user').value = name;
      show('view-login');
      notice('Account created with two-factor enabled. Sign in with your password, then wait for the next 6-digit code.', 'ok');
    } finally {
      busy(btn, false, 'Confirm and finish');
    }
  }

  /* ------------------------------------------------------------------ */
  /* LOGIN step 1: identification + password                             */
  /* ------------------------------------------------------------------ */
  let pending = null; // { username, exp } password step passed, waiting for 2FA

  async function onLogin(e) {
    e.preventDefault();
    clearNotice();
    setError('login-error', '');
    const username = normUser($('login-user').value);
    const pass = $('login-pass').value;
    if (!username || !pass) return setError('login-error', 'Enter your username and password.');

    const btn = $('login-btn');
    busy(btn, true, 'Continue');
    try {
      const users = getUsers();
      const user = USER_RE.test(username) ? users[username] : undefined;

      if (user && isLocked(user)) {
        audit('LOGIN_BLOCKED', username, 'account locked', 'fail');
        return setError('login-error', `Too many failed attempts. Try again in about ${minsLeft(user)} minute(s).`);
      }

      // Always run the (slow) hash, even for unknown users, so response time does not reveal who exists.
      const salt = user ? b64.dec(user.salt) : DUMMY_SALT;
      const hash = await hashPassword(pass, salt);
      const ok = !!user && timingSafeEqual(hash, b64.dec(user.hash));

      if (!ok) {
        if (user) registerFailure(users, user, 'wrong password');
        else audit('LOGIN_FAILED', username, 'unknown user', 'fail');
        // One generic message for both cases: no username enumeration.
        return setError('login-error', 'Invalid username or password.');
      }

      pending = { username, exp: now() + CONFIG.PENDING_MS };
      audit('PASSWORD_OK', username, 'waiting for 2FA');
      $('login-pass').value = '';
      $('twofa-user').textContent = username;
      $('twofa-code').value = '';
      setError('twofa-error', '');
      show('view-2fa');
      $('twofa-code').focus();
    } finally {
      busy(btn, false, 'Continue');
    }
  }

  /* ------------------------------------------------------------------ */
  /* LOGIN step 2: second factor (TOTP)                                  */
  /* ------------------------------------------------------------------ */
  async function onTwoFA(e) {
    e.preventDefault();
    setError('twofa-error', '');
    if (!pending || pending.exp < now()) {
      pending = null;
      show('view-login');
      return notice('Verification timed out. Please sign in again.', 'warn');
    }
    const btn = $('twofa-btn');
    busy(btn, true, 'Verify and sign in');
    try {
      const users = getUsers();
      const user = users[pending.username];
      if (!user) { pending = null; return show('view-login'); }
      if (isLocked(user)) { pending = null; show('view-login'); return notice('Account is locked. Try again later.', 'bad'); }

      const step = await verifyTotp(user.totpSecret, $('twofa-code').value.trim(), user.lastStep || 0);
      if (step === null) {
        registerFailure(users, user, 'wrong 2FA code');
        if (isLocked(user)) {
          pending = null;
          show('view-login');
          return notice(`Too many failed attempts. Account locked for ${minsLeft(user)} minute(s).`, 'bad');
        }
        return setError('twofa-error', 'Invalid or already-used code.');
      }

      user.lastStep = step;       // replay protection
      user.failed = 0;
      user.lockUntil = 0;
      user.lastLogin = now();
      saveUsers(users);
      audit('LOGIN_SUCCESS', user.username, 'password + 2FA', 'ok');
      pending = null;
      sess.set({ username: user.username, started: now() });
      lastActive = now();
      enterDashboard();
    } finally {
      busy(btn, false, 'Verify and sign in');
    }
  }

  /* ------------------------------------------------------------------ */
  /* SESSION + AUTHORIZATION                                             */
  /* ------------------------------------------------------------------ */
  let lastActive = now();

  function currentUser() {
    const s = sess.get();
    if (!s) return null;
    const u = getUsers()[s.username];
    return u || null; // role is re-read from storage on every check
  }

  const can = (user, perm) => !!user && !!ROLES[user.role] && ROLES[user.role].perms.includes(perm);

  // Server-style guard used inside every protected action, not just in the UI.
  function requirePerm(perm) {
    const user = currentUser();
    if (!can(user, perm)) {
      audit('ACCESS_DENIED', user ? user.username : '-', perm, 'fail');
      notice(`403 - Access denied. Your role does not include "${perm}".`, 'bad');
      return null;
    }
    return user;
  }

  function logout(message, kind = 'ok') {
    const s = sess.get();
    if (s) audit('LOGOUT', s.username, message || 'user signed out');
    sess.clear();
    pending = null;
    show('view-login');
    if (message) notice(message, kind);
  }

  setInterval(() => {
    if (sess.get() && now() - lastActive > CONFIG.IDLE_MS) logout('You were signed out after a period of inactivity.', 'warn');
  }, 5000);
  for (const evt of ['click', 'keydown', 'touchstart']) {
    document.addEventListener(evt, () => { lastActive = now(); }, { passive: true });
  }

  /* ------------------------------------------------------------------ */
  /* DASHBOARD                                                           */
  /* ------------------------------------------------------------------ */
  function enterDashboard() {
    clearNotice();
    renderDashboard();
    show('view-dashboard');
  }

  function renderDashboard() {
    const me = currentUser();
    if (!me) return logout('Your session is no longer valid.', 'warn');

    $('who-name').textContent = me.username;
    $('who-role').textContent = ROLES[me.role].label;
    $('idle-min').textContent = String(CONFIG.IDLE_MS / 60000);
    $('perm-list').replaceChildren(...ROLES[me.role].perms.map((p) => el('li', { text: p })));

    const grid = $('cards');
    grid.replaceChildren(
      can(me, 'content:read')  ? contentCard()      : lockedCard('Announcements', 'content:read'),
      can(me, 'content:write') ? publishCard()      : lockedCard('Publish announcement', 'content:write'),
      can(me, 'users:manage')  ? usersCard(me)      : lockedCard('User management', 'users:manage'),
      can(me, 'audit:view')    ? auditCard()        : lockedCard('Audit log', 'audit:view')
    );
  }

  function lockedCard(title, perm) {
    return el('div', { class: 'card locked' },
      el('h3', { text: title + '  (locked)' }),
      el('p', { text: `Requires permission "${perm}".` }),
      el('button', { type: 'button', class: 'ghost small', text: 'Try to open anyway', onclick: () => { requirePerm(perm); renderDashboard(); } })
    );
  }

  /* ---- content:read ---- */
  function contentCard() {
    const posts = store.get('sg_posts', []);
    const box = el('div', { class: 'card' }, el('h3', { text: 'Announcements' }));
    if (!posts.length) box.append(el('p', { class: 'muted', text: 'Nothing posted yet.' }));
    for (const p of posts.slice(0, 8)) {
      box.append(el('div', { class: 'post' },
        el('div', { class: 'meta', text: `${p.author} - ${new Date(p.t).toLocaleString()}` }),
        el('p', { text: p.text })
      ));
    }
    return box;
  }

  /* ---- content:write ---- */
  function publishCard() {
    const ta = el('textarea', { maxlength: '280', 'aria-label': 'Announcement text', placeholder: 'Write an announcement (max 280 characters)' });
    const btn = el('button', { type: 'button', class: 'primary', text: 'Publish' });
    btn.addEventListener('click', () => {
      const user = requirePerm('content:write');
      if (!user) return renderDashboard();
      const text = ta.value.trim().slice(0, 280);
      if (!text) return;
      const posts = store.get('sg_posts', []);
      posts.unshift({ author: user.username, text, t: now() });
      store.set('sg_posts', posts.slice(0, 50));
      audit('CONTENT_PUBLISHED', user.username, `${text.length} chars`);
      renderDashboard();
    });
    return el('div', { class: 'card' }, el('h3', { text: 'Publish announcement' }), ta, btn);
  }

  /* ---- users:manage ---- */
  function setRole(username, role) {
    const admin = requirePerm('users:manage');
    if (!admin) return renderDashboard();
    if (!ROLES[role]) return;
    if (username === admin.username) { notice('You cannot change your own role.', 'warn'); return renderDashboard(); }
    const users = getUsers();
    if (!users[username]) return;
    users[username].role = role;
    saveUsers(users);
    audit('ROLE_CHANGED', admin.username, `${username} -> ${role}`);
    renderDashboard();
  }

  function unlockUser(username) {
    const admin = requirePerm('users:manage');
    if (!admin) return renderDashboard();
    const users = getUsers();
    if (!users[username]) return;
    users[username].lockUntil = 0;
    users[username].failed = 0;
    saveUsers(users);
    audit('ACCOUNT_UNLOCKED', admin.username, username);
    renderDashboard();
  }

  function deleteUser(username) {
    const admin = requirePerm('users:manage');
    if (!admin) return renderDashboard();
    if (username === admin.username) { notice('You cannot delete your own account.', 'warn'); return; }
    if (!window.confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    const users = getUsers();
    delete users[username];
    saveUsers(users);
    audit('USER_DELETED', admin.username, username);
    renderDashboard();
  }

  function resetAll() {
    const admin = requirePerm('users:manage');
    if (!admin) return;
    if (!window.confirm('Erase ALL accounts, posts and logs stored in this browser?')) return;
    for (const k of ['sg_users', 'sg_posts', 'sg_audit']) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
    sess.clear();
    show('view-login');
    notice('All demo data erased. The next account you register becomes the administrator.', 'ok');
  }

  function usersCard(me) {
    const users = Object.values(getUsers()).sort((a, b) => a.created - b.created);
    const body = el('tbody');
    for (const u of users) {
      const self = u.username === me.username;
      const select = el('select', { 'aria-label': `Role for ${u.username}`, disabled: self });
      for (const [key, r] of Object.entries(ROLES)) {
        const opt = el('option', { value: key, text: r.label });
        if (u.role === key) opt.selected = true;
        select.append(opt);
      }
      select.addEventListener('change', () => setRole(u.username, select.value));

      const actions = el('div', { class: 'actions' });
      if (isLocked(u)) actions.append(el('button', { type: 'button', class: 'ghost', text: 'Unlock', onclick: () => unlockUser(u.username) }));
      if (!self) actions.append(el('button', { type: 'button', class: 'ghost danger', text: 'Delete', onclick: () => deleteUser(u.username) }));

      body.append(el('tr', {},
        el('td', { text: u.username + (self ? ' (you)' : '') }),
        el('td', {}, select),
        el('td', { text: isLocked(u) ? 'Locked' : 'Active' }),
        el('td', { text: u.lastLogin ? new Date(u.lastLogin).toLocaleString() : 'Never' }),
        el('td', {}, actions)
      ));
    }
    const table = el('table', {},
      el('thead', {}, el('tr', {}, ...['User', 'Role', 'Status', 'Last sign-in', ''].map((h) => el('th', { text: h })))),
      body
    );
    return el('div', { class: 'card wide' },
      el('h3', { text: 'User management' }),
      el('div', { class: 'table-wrap' }, table),
      el('p', {}, el('button', { type: 'button', class: 'ghost danger small', text: 'Erase all demo data', onclick: resetAll }))
    );
  }

  /* ---- audit:view ---- */
  function auditCard() {
    const log = store.get('sg_audit', []).slice(0, 15);
    const body = el('tbody');
    for (const r of log) {
      body.append(el('tr', {},
        el('td', { text: new Date(r.t).toLocaleString() }),
        el('td', { class: r.level === 'fail' ? 'ev-fail' : r.level === 'ok' ? 'ev-ok' : '', text: r.event }),
        el('td', { text: r.user }),
        el('td', { text: r.detail })
      ));
    }
    const table = el('table', {},
      el('thead', {}, el('tr', {}, ...['Time', 'Event', 'User', 'Detail'].map((h) => el('th', { text: h })))),
      body
    );
    return el('div', { class: 'card wide' }, el('h3', { text: 'Audit log (latest 15)' }), el('div', { class: 'table-wrap' }, table));
  }

  /* ------------------------------------------------------------------ */
  /* Wiring                                                              */
  /* ------------------------------------------------------------------ */
  document.addEventListener('DOMContentLoaded', () => {
    $('form-login').addEventListener('submit', onLogin);
    $('form-2fa').addEventListener('submit', onTwoFA);
    $('form-register').addEventListener('submit', onRegister);
    $('form-enroll').addEventListener('submit', onEnroll);
    $('logout-btn').addEventListener('click', () => logout('You have been signed out.'));
    $('reg-pass').addEventListener('input', renderRules);

    $('twofa-cancel').addEventListener('click', () => { pending = null; show('view-login'); });
    $('enroll-cancel').addEventListener('click', () => { regPending = null; show('view-register'); });

    $('copy-secret').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('enroll-secret').textContent.replace(/\s/g, ''));
        notice('Setup key copied.', 'ok');
      } catch { notice('Could not copy. Please select the key and copy it manually.', 'warn'); }
    });

    for (const b of document.querySelectorAll('[data-go]')) {
      b.addEventListener('click', () => { clearNotice(); setError('login-error'); setError('reg-error'); show(b.dataset.go); });
    }
    for (const b of document.querySelectorAll('[data-toggle]')) {
      b.addEventListener('click', () => {
        const input = $(b.dataset.toggle);
        const reveal = input.type === 'password';
        input.type = reveal ? 'text' : 'password';
        b.textContent = reveal ? 'Hide' : 'Show';
      });
    }

    renderRules();

    // Restore an existing session within the same tab, if still valid.
    if (sess.get() && currentUser()) enterDashboard();
    else { sess.clear(); show('view-login'); }
  });
})();
