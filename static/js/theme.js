(function () {
  const KEY = 'safenet-theme';
  const DEFAULT = 'dark';

  function get() {
    try { return localStorage.getItem(KEY) || DEFAULT; } catch { return DEFAULT; }
  }

  function set(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem(KEY, t); } catch (_) {}
    document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: t } }));
  }

  function init() {
    set(get());
    document.getElementById('theme-toggle')?.addEventListener('click', () => {
      set(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  window.SafeNetTheme = { setTheme: set, getTheme: get };
})();
