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
    const prob = window.resultData.phishing_probability;
    new Chart(probCanvas, {
      type: 'bar',
      data: {
        labels: ['Safe', 'Suspicious', 'Malicious'],
        datasets: [{
          label: 'Probability %',
          data: [
            prob < 30 ? 100 - prob : 20,
            prob >= 30 && prob < 70 ? prob : 25,
            prob >= 70 ? prob : 15,
          ],
          backgroundColor: [c.green + '99', c.yellow + '99', c.red + '99'],
          borderRadius: 8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { max: 100, ticks: { color: c.text }, grid: { color: 'rgba(148,163,184,0.1)' } },
          x: { ticks: { color: c.text }, grid: { display: false } },
        },
      },
    });
  }
});
