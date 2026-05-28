/**
 * Admin panel charts
 */
document.addEventListener('DOMContentLoaded', () => {
  if (!window.adminData) return;
  const d = window.adminData;

  SafeNetCharts.barChart(
    'admin-threat-chart',
    ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    d.malicious_trend
  );

  const growthCanvas = document.getElementById('admin-users-chart');
  if (growthCanvas && typeof Chart !== 'undefined') {
    const c = SafeNetCharts.getThemeColors();
    new Chart(growthCanvas, {
      type: 'line',
      data: {
        labels: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'Now'],
        datasets: [{
          label: 'Users',
          data: d.users_growth,
          borderColor: c.cyan,
          backgroundColor: c.cyan + '33',
          fill: true,
          tension: 0.4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { ticks: { color: c.text }, grid: { color: 'rgba(148,163,184,0.1)' } },
          x: { ticks: { color: c.text }, grid: { display: false } },
        },
      },
    });
  }
});
