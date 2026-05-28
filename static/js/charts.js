window.SafeNetCharts = (function () {
  'use strict';

  function colors() {
    const s = getComputedStyle(document.documentElement);
    return {
      text: s.getPropertyValue('--text-secondary').trim() || '#a1a1aa',
      grid: s.getPropertyValue('--border').trim() || '#27272a',
      accent: s.getPropertyValue('--accent').trim() || '#3b82f6',
      success: s.getPropertyValue('--success').trim() || '#22c55e',
      warning: s.getPropertyValue('--warning').trim() || '#eab308',
      danger: s.getPropertyValue('--danger').trim() || '#ef4444',
      muted: s.getPropertyValue('--bg-muted').trim() || '#27272a',
    };
  }

  const baseScale = () => {
    const c = colors();
    return {
      x: { ticks: { color: c.text, font: { size: 12 } }, grid: { color: c.grid } },
      y: { ticks: { color: c.text, font: { size: 12 } }, grid: { color: c.grid } },
    };
  };

  function lineChart(id, labels, scans, threats) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return null;
    const c = colors();
    return new Chart(el, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'Scans', data: scans, borderColor: c.accent, backgroundColor: 'transparent', tension: 0.35, borderWidth: 2, pointRadius: 0 },
          { label: 'Threats', data: threats, borderColor: c.danger, backgroundColor: 'transparent', tension: 0.35, borderWidth: 2, pointRadius: 0 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: c.text, boxWidth: 12, font: { size: 12 } } } },
        scales: baseScale(),
      },
    });
  }

  function doughnutChart(id, labels, values, palette) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return null;
    const c = colors();
    const cols = palette || [c.success, c.warning, c.danger];
    return new Chart(el, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: cols, borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: { legend: { position: 'bottom', labels: { color: c.text, padding: 12, font: { size: 12 } } } },
      },
    });
  }

  function barChart(id, labels, values) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return null;
    const c = colors();
    return new Chart(el, {
      type: 'bar',
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: c.accent, borderRadius: 4 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: baseScale(),
      },
    });
  }

  function riskGauge(id, score) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return null;
    const c = colors();
    let fill = c.success;
    if (score > 70) fill = c.danger;
    else if (score > 40) fill = c.warning;
    return new Chart(el, {
      type: 'doughnut',
      data: { datasets: [{ data: [score, 100 - score], backgroundColor: [fill, c.muted], borderWidth: 0 }] },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        circumference: 270,
        rotation: 225,
        cutout: '80%',
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      },
    });
  }

  document.addEventListener('themechange', () => {
    if (typeof Chart !== 'undefined') {
      Chart.helpers.each(Chart.instances, (i) => i.update());
    }
  });

  return { lineChart, doughnutChart, barChart, riskGauge, getThemeColors: colors };
})();
