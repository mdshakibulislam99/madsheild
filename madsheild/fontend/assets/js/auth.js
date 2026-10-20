/* =========================================================
   MadSheild — Authentication client
   Handles register, login, session persistence
   and auth-aware UI updates.
   ========================================================= */
(() => {
  'use strict';

  const TOKEN_KEY = 'madshield_token';
  const USER_KEY = 'madshield_user';

  const API_BASE = '/api/v1/auth';

  /* ---------- state ---------- */
  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getUser() {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (_) { return null; }
  }

  function setAuth(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function isAuthenticated() {
    return !!getToken();
  }

  /* ---------- api ---------- */
  function formatDetail(detail) {
    if (detail == null) return null;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      const parts = detail.map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          const loc = Array.isArray(item.loc)
            ? item.loc.filter((p) => p !== 'body').join('.')
            : '';
          const msg = item.msg || item.message || JSON.stringify(item);
          return loc ? `${loc}: ${msg}` : String(msg);
        }
        return String(item);
      }).filter(Boolean);
      return parts.join(' ') || null;
    }
    if (typeof detail === 'object') {
      if (typeof detail.msg === 'string') return detail.msg;
      if (typeof detail.message === 'string') return detail.message;
      try { return JSON.stringify(detail); } catch (_) { return String(detail); }
    }
    return String(detail);
  }

  async function request(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });
    let body;
    try { body = await res.json(); } catch (_) { body = {}; }
    if (!res.ok) {
      const message = formatDetail(body.detail) || `Request failed (${res.status})`;
      const err = new Error(message);
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return body;
  }

  async function register(identifier, password) {
    const data = await request('/register', {
      method: 'POST',
      body: JSON.stringify({ identifier, password }),
    });
    setAuth(data.access_token, data.user);
    return data.user;
  }

  async function login(identifier, password) {
    const data = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ identifier, password }),
    });
    setAuth(data.access_token, data.user);
    return data.user;
  }

  async function fetchMe() {
    return request('/me', { headers: { Authorization: `Bearer ${getToken()}` } });
  }

  async function logout() {
    try { await request('/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
    clearAuth();
  }

  /* ---------- UI ---------- */
  function displayFirstName(user) {
    const raw = String(user.identifier || user.email || '').trim();
    if (!raw) return 'there';
    let name = raw;
    const at = name.indexOf('@');
    if (at > 0) name = name.slice(0, at);
    const parts = name.split(/[._\-\s]+/).filter(Boolean);
    const first = parts.length ? parts[0] : name;
    const cleaned = first.replace(/[0-9]+$/, '') || first;
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  }

  function updateAuthUI() {
    const user = getUser();
    const authBtns = document.querySelector('.auth-btns');
    if (!authBtns) return;

    const registerLink = authBtns.querySelector('#navRegister');
    const loginLink = authBtns.querySelector('#navLogin');
    const existing = authBtns.querySelector('.auth-user-wrap');
    if (existing) existing.remove();

    if (!user) {
      if (registerLink) registerLink.style.display = '';
      if (loginLink) loginLink.style.display = '';
      return;
    }

    // Logged in: hide Register / Log in, show only greeting + logout icon.
    if (registerLink) registerLink.style.display = 'none';
    if (loginLink) loginLink.style.display = 'none';

    const wrap = document.createElement('div');
    wrap.className = 'auth-user-wrap';
    wrap.style.display = 'flex';
    wrap.style.alignItems = 'center';
    wrap.style.gap = '0.75rem';

    const greeting = document.createElement('span');
    greeting.style.fontSize = '0.95rem';
    greeting.style.color = '#1E1B4B';
    greeting.style.fontWeight = '500';
    greeting.textContent = `Hi, ${displayFirstName(user)}`;

    const btn = document.createElement('a');
    btn.href = '#';
    btn.title = 'Log out';
    btn.setAttribute('aria-label', 'Log out');
    btn.style.display = 'inline-flex';
    btn.style.alignItems = 'center';
    btn.style.justifyContent = 'center';
    btn.style.width = '36px';
    btn.style.height = '36px';
    btn.style.borderRadius = '50%';
    btn.style.color = '#1E1B4B';
    btn.style.transition = 'background 0.18s ease';
    btn.innerHTML =
      '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>' +
      '<polyline points="16 17 21 12 16 7"/>' +
      '<line x1="21" y1="12" x2="9" y2="12"/></svg>';
    btn.addEventListener('mouseenter', () => { btn.style.background = 'rgba(30, 27, 75, 0.08)'; });
    btn.addEventListener('mouseleave', () => { btn.style.background = 'transparent'; });
    btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      logout();
      window.location.href = '/';
    });

    wrap.append(greeting, btn);
    authBtns.appendChild(wrap);
  }

  /* ---------- export ---------- */
  window.MadSheildAuth = {
    getToken,
    getUser,
    setAuth,
    clearAuth,
    isAuthenticated,
    register,
    login,
    fetchMe,
    logout,
    updateAuthUI,
  };

  // Auto-refresh UI when module loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updateAuthUI);
  } else {
    updateAuthUI();
  }

})();
