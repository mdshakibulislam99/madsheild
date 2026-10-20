(function () {
  'use strict';

  // Shared header / navigation markup injected synchronously into the
  // page's #shared-header placeholder. Must run before any page script
  // that references nav elements (e.g. app.js uses scanNav/historyNav).
  const HEADER_HTML =
    '<nav class="navbar shared-nav" aria-label="Main navigation">\n' +
    '  <a class="logo" href="/"><img src="assets/images/logo_2.png" alt="MadSheild" class="brand-logo"></a>\n' +
    '  <ul class="nav-links">\n' +
    '    <li><a href="/" data-page="home">Home</a></li>\n' +
    '    <li><a href="/scan.html" id="scanNav" data-page="scan">Scan</a></li>\n' +
    '    <li><a href="/history.html" id="historyNav" data-page="history">History</a></li>\n' +
    '    <li><a href="/#features" data-page="features">Features</a></li>\n' +
    '  </ul>\n' +
    '  <div class="auth-btns">\n' +
    '    <a href="/register.html" class="btn btn-text" id="navRegister">Register</a>\n' +
    '    <a href="/login.html" class="btn btn-primary" id="navLogin">Log in</a>\n' +
    '  </div>\n' +
    '</nav>';

  function setActive() {
    const path = window.location.pathname;
    const links = document.querySelectorAll('#shared-header .nav-links a[data-page]');
    links.forEach((link) => {
      const page = link.getAttribute('data-page');
      let active = false;
      if (page === 'home') {
        active = path === '/' || path === '/home.html' || path === '';
      } else if (page === 'scan') {
        active = path === '/scan.html';
      } else if (page === 'history') {
        active = path === '/history.html';
      }
      link.classList.toggle('active', active);
    });
  }

  function inject() {
    const placeholder = document.getElementById('shared-header');
    if (!placeholder) return;
    placeholder.insertAdjacentHTML('afterbegin', HEADER_HTML);
    setActive();
    // Update auth-aware UI (shows "Hi, name + logout icon" when signed in)
    if (window.MadSheildAuth && typeof window.MadSheildAuth.updateAuthUI === 'function') {
      window.MadSheildAuth.updateAuthUI();
    }
  }

  inject();
})();

