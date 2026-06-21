(function () {
  'use strict';

  const NAV_ROUTES = [
    { key: 'admin', paths: ['/admin'] },
    { key: 'dashboard', paths: ['/dashboard'] },
    { key: 'history', paths: ['/history'] },
    { key: 'webcam', paths: ['/webcam'] },
    { key: 'scan', paths: ['/scan', '/result', '/upload'] },
    { key: 'home', paths: ['/'] },
  ];

  function getNavKey(path) {
    if (['/login', '/register', '/logout'].some((p) => path === p || path.startsWith(p + '/'))) {
      return null;
    }
    for (const route of NAV_ROUTES) {
      if (route.key === 'home') {
        if (path === '/' || path === '') return 'home';
        continue;
      }
      if (route.paths.some((p) => path === p || path.startsWith(p + '/'))) {
        return route.key;
      }
    }
    return null;
  }

  function initIcons() {
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function initNavbar() {
    const path = window.location.pathname;
    const key = getNavKey(path);

    document.querySelectorAll('.site-nav .nav-link').forEach((link) => {
      const isActive = !!key && link.dataset.nav === key;
      link.classList.toggle('active', isActive);
      if (isActive) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });

    const toggler = document.querySelector('.nav-toggler');
    const collapse = document.getElementById('navMain');
    if (toggler && collapse) {
      collapse.addEventListener('shown.bs.collapse', () => {
        toggler.setAttribute('aria-expanded', 'true');
        initIcons();
      });
      collapse.addEventListener('hidden.bs.collapse', () => {
        toggler.setAttribute('aria-expanded', 'false');
        initIcons();
      });
    }
  }

  function initFlash() {
    document.querySelectorAll('.alert-item .alert-close').forEach((btn) => {
      btn.addEventListener('click', () => btn.closest('.alert-item')?.remove());
    });
    document.querySelectorAll('.flash-stack .alert-item').forEach((el) => {
      setTimeout(() => {
        el.style.opacity = '0';
        el.style.transition = 'opacity 0.2s';
        setTimeout(() => el.remove(), 200);
      }, 5000);
    });
  }

  function initCounters() {
    document.querySelectorAll('[data-counter]').forEach((el) => {
      const target = parseFloat(el.dataset.counter);
      const suffix = el.dataset.suffix || '';
      const decimals = parseInt(el.dataset.decimals || '0', 10);
      const duration = 1200;
      const start = performance.now();

      function tick(now) {
        const t = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = (target * eased).toFixed(decimals) + suffix;
        if (t < 1) requestAnimationFrame(tick);
      }

      const io = new IntersectionObserver(
        (entries) => {
          if (entries[0].isIntersecting) {
            requestAnimationFrame(tick);
            io.disconnect();
          }
        },
        { threshold: 0.2 }
      );
      io.observe(el);
    });
  }

  function initPasswordToggle() {
    document.querySelectorAll('.toggle-pw').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = btn.closest('.input-wrap')?.querySelector('input');
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        const icon = btn.querySelector('[data-lucide]');
        if (icon) icon.setAttribute('data-lucide', show ? 'eye-off' : 'eye');
        if (typeof lucide !== 'undefined') lucide.createIcons();
      });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initIcons();
    initNavbar();
    initFlash();
    initCounters();
    initPasswordToggle();
  });

  document.addEventListener('themechange', initIcons);
})();
