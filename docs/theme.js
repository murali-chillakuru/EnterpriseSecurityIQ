// PostureIQ Documentation — Theme Controller
// Light/Dark toggle with system preference detection and localStorage persistence.

(function () {
  'use strict';

  const STORAGE_KEY = 'postureiq-theme';
  const DARK = 'dark';
  const LIGHT = 'light';

  function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? DARK : LIGHT;
  }

  function getStoredTheme() {
    try { return localStorage.getItem(STORAGE_KEY); } catch { return null; }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const btn = document.querySelector('.theme-toggle');
    if (btn) {
      btn.setAttribute('aria-label', theme === DARK ? 'Switch to light theme' : 'Switch to dark theme');
      btn.innerHTML = theme === DARK
        ? '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-1 0v-1A.5.5 0 0 1 8 1zm0 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm6.5-2.5a.5.5 0 0 1 0-1h1a.5.5 0 0 1 0 1h-1zm-13 0a.5.5 0 0 1 0-1h1a.5.5 0 0 1 0 1h-1zM8 13a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-1 0v-1A.5.5 0 0 1 8 13zm-3.5-1.8a.5.5 0 0 1-.7.7l-.7-.7a.5.5 0 0 1 .7-.7l.7.7zm7.7.7a.5.5 0 0 1-.7-.7l.7-.7a.5.5 0 0 1 .7.7l-.7.7zM3.8 4.5a.5.5 0 0 1-.7-.7l.7-.7a.5.5 0 0 1 .7.7l-.7.7zm8.4-.7a.5.5 0 0 1-.7.7l-.7-.7a.5.5 0 0 1 .7-.7l.7.7z"/></svg> Light'
        : '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M6 .278a.77.77 0 0 1 .08.858A6 6 0 0 0 6 4a6 6 0 0 0 9.863 4.592.77.77 0 0 1 1.065.853A8 8 0 1 1 5.145.228a.77.77 0 0 1 .855.05z"/></svg> Dark';
    }
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || LIGHT;
    const next = current === DARK ? LIGHT : DARK;
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* noop */ }
    applyTheme(next);
  }

  // Initialize on load
  const stored = getStoredTheme();
  applyTheme(stored || getSystemTheme());

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (e) {
    if (!getStoredTheme()) applyTheme(e.matches ? DARK : LIGHT);
  });

  // Bind toggle button
  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.addEventListener('click', toggleTheme);
    // Re-apply to update button icon
    applyTheme(getStoredTheme() || getSystemTheme());
  });
})();
