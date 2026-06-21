/**
 * Subtle parallax + scroll reveal + navbar motion (vanilla JS)
 */
(function () {
  'use strict';

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function initNavbarScroll() {
    const nav = document.querySelector('.site-nav');
    if (!nav) return;

    let lastY = 0;
    let hidden = false;

    function onScroll() {
      const y = window.scrollY;
      const scrolled = y > 12;
      nav.classList.toggle('scrolled', scrolled);
      document.documentElement.style.setProperty(
        '--navbar-height',
        scrolled ? '56px' : '64px'
      );

      const isMobile = window.matchMedia('(max-width: 991.98px)').matches;

      // Slight hide on scroll down, show on scroll up (desktop only)
      if (!reduced && !isMobile && y > 80) {
        if (y > lastY + 4 && !hidden) {
          nav.classList.add('nav-hide');
          hidden = true;
        } else if (y < lastY - 4 && hidden) {
          nav.classList.remove('nav-hide');
          hidden = false;
        }
      } else {
        nav.classList.remove('nav-hide');
        hidden = false;
      }

      lastY = y;
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  function initParallax() {
    const items = document.querySelectorAll('[data-parallax]');
    if (!items.length || reduced) return;

    function update() {
      const vh = window.innerHeight;
      items.forEach((el) => {
        const speed = parseFloat(el.dataset.parallax) || 0.15;
        const rect = el.getBoundingClientRect();
        const center = rect.top + rect.height / 2;
        const dist = (center - vh / 2) / vh;
        const y = dist * speed * 40;
        el.style.transform = `translate3d(0, ${y.toFixed(2)}px, 0)`;
      });
    }

    let ticking = false;
    window.addEventListener(
      'scroll',
      () => {
        if (!ticking) {
          requestAnimationFrame(() => {
            update();
            ticking = false;
          });
          ticking = true;
        }
      },
      { passive: true }
    );
    window.addEventListener('resize', update, { passive: true });
    update();
  }

  function initReveal() {
    const els = document.querySelectorAll('.reveal');
    if (!els.length) return;

    if (reduced) {
      els.forEach((el) => el.classList.add('is-visible'));
      return;
    }

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -32px 0px' }
    );

    els.forEach((el) => io.observe(el));
  }

  function initAutoReveal() {
    document.querySelectorAll('.page-header, .section .card, .stat-card').forEach((el, i) => {
      if (!el.classList.contains('reveal')) {
        el.classList.add('reveal');
        if (i % 3 === 1) el.classList.add('reveal-delay-1');
        if (i % 3 === 2) el.classList.add('reveal-delay-2');
      }
    });
    initReveal();
  }

  document.addEventListener('DOMContentLoaded', () => {
    initNavbarScroll();
    initParallax();
    initAutoReveal();
  });
})();
