/**
 * Result page charts
 */
document.addEventListener('DOMContentLoaded', () => {
  const gaugeCanvas = document.getElementById('risk-gauge-chart');
  const probCanvas = document.getElementById('probability-chart');

  if (gaugeCanvas && window.resultData) {
    SafeNetCharts.riskGauge('risk-gauge-chart', window.resultData.risk_score);
  }

  if (probCanvas && window.resultData) {
    const c = SafeNetCharts.getThemeColors();
    const components = window.resultData.components || {};
    const labels = ['ML', 'URL rules', 'SSL', 'Redirects', 'Domain age', 'Blacklist', 'Final'];
    const values = labels.map((label) => {
      const key = label === 'URL rules' ? 'security' : label.toLowerCase().replace(' ', '_');
      return Number(components[key] || 0);
    });
    new Chart(probCanvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Score contribution',
          data: values,
          backgroundColor: [c.accent + '99', c.warning + '99', c.danger + '99', c.warning + '88', c.accent + '77', c.danger + 'aa', c.success + '99'],
          borderRadius: 8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { max: 100, ticks: { color: c.text }, grid: { color: 'rgba(148,163,184,0.1)' } },
          x: { ticks: { color: c.text, maxRotation: 45, minRotation: 0 }, grid: { display: false } },
        },
      },
    });
  }
});
